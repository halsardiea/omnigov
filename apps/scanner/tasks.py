"""
Scanner Celery tasks — handles scan lifecycle as background jobs.
"""
import logging
import time

from celery import shared_task
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.conf import settings

logger = logging.getLogger(__name__)


def _send_ws_update(scan_task_id: int, data: dict):
    """Send a WebSocket message to the scan's channel group."""
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f'scan_{scan_task_id}',
        data,
    )


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_scan(self, scan_task_id: int):
    """
    Execute a full vulnerability scan via GVM.

    Lifecycle: connect → create target → start task → poll progress → retrieve report
    """
    from apps.scanner.models import ScanTask
    from apps.scanner.gvm_client import get_gvm_client

    scan_task = ScanTask.objects.get(id=scan_task_id)
    client = get_gvm_client()

    try:
        # 1. Connect to GVM
        logger.info(f"Scan #{scan_task_id}: Connecting to GVM...")
        client.connect()

        # 2. Mark scan as running
        scan_task.mark_running()
        _send_ws_update(scan_task_id, {
            'type': 'scan.progress',
            'progress': 0,
            'status': 'running',
            'message': 'Connecting to scanner...',
        })

        # 3. Create target in GVM
        target_id = client.create_target(
            name=f"OmniGov-{scan_task_id}-{scan_task.target}",
            hosts=scan_task.target,
        )
        scan_task.gvm_target_id = target_id
        scan_task.save(update_fields=['gvm_target_id'])

        # 4. Create and start the scan task
        gvm_task_id = client.create_and_start_task(target_id)
        scan_task.gvm_task_id = gvm_task_id
        scan_task.save(update_fields=['gvm_task_id'])

        _send_ws_update(scan_task_id, {
            'type': 'scan.progress',
            'progress': 5,
            'status': 'running',
            'message': 'Scan initiated, scanning in progress...',
        })

        # 5. Poll for progress
        poll_interval = settings.SCAN_POLL_INTERVAL
        while True:
            progress = client.get_task_progress(gvm_task_id)

            # Refresh from DB in case user stopped the scan
            scan_task.refresh_from_db()
            if scan_task.status == ScanTask.Status.STOPPED:
                client.stop_task(gvm_task_id)
                logger.info(f"Scan #{scan_task_id}: Stopped by user")
                _send_ws_update(scan_task_id, {
                    'type': 'scan.complete',
                    'status': 'stopped',
                    'message': 'Scan stopped by user.',
                })
                return

            # Update progress
            scan_task.progress = progress
            scan_task.save(update_fields=['progress', 'updated_at'])

            _send_ws_update(scan_task_id, {
                'type': 'scan.progress',
                'progress': progress,
                'status': 'running',
                'message': f'Scanning... {progress}% complete',
            })

            if progress >= 100:
                # Wait for GVM to finalize (status=Done)
                for _ in range(12):
                    if client.get_task_status(gvm_task_id) == 'Done':
                        break
                    time.sleep(5)
                break

            time.sleep(poll_interval)

        # 6. Retrieve the report
        logger.info(f"Scan #{scan_task_id}: Retrieving report...")
        xml_report = client.get_report(gvm_task_id)
        scan_task.raw_report_xml = xml_report
        scan_task.save(update_fields=['raw_report_xml'])
        scan_task.mark_completed()

        _send_ws_update(scan_task_id, {
            'type': 'scan.progress',
            'progress': 100,
            'status': 'completed',
            'message': 'Scan complete. Parsing findings...',
        })

        # 7. Trigger AI interceptor pipeline
        from apps.interceptor.tasks import process_scan_findings
        process_scan_findings.apply(args=[scan_task_id])

        logger.info(f"Scan #{scan_task_id}: Complete. AI pipeline triggered.")
        
    except Exception as exc:
        logger.exception(f"Scan #{scan_task_id}: Failed with error: {exc}")
        scan_task.mark_failed(str(exc))
        _send_ws_update(scan_task_id, {
            'type': 'scan.error',
            'status': 'failed',
            'message': f'Scan failed: {str(exc)[:200]}',
        })
        raise self.retry(exc=exc)

    finally:
        try:
            client.disconnect()
        except Exception:
            pass
