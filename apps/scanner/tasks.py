# ---
# LOCATION : apps/scanner/tasks.py
# PURPOSE  : Orchestrates the full scan lifecycle against GVM/OpenVAS:
#            connect → create target → start task → poll progress → retrieve XML report
#            → hand off to the interceptor pipeline.
#            This module is called by the detached worker process spawned in
#            runtime.py — it never runs inside the web server.
#
# CONNECTS TO:
#   - apps/scanner/gvm_client.py        → get_gvm_client() returns either MockGVMClient
#                                          or RealGVMClient depending on GVM_USE_MOCK
#   - apps/scanner/models.py            → ScanTask lifecycle methods (mark_running, etc.)
#                                          and status reads drive the polling loop
#   - apps/interceptor/tasks.py         → process_scan_findings_pipeline() called after
#                                          the XML report is stored in raw_report_xml
#   - apps/scanner/runtime.py           → spawns the OS process that runs _run_scan_pipeline
#   - omnigov/settings/base.py          → SCAN_POLL_INTERVAL controls the sleep between
#                                          GVM status polls
# ---
"""Scanner task orchestration and scan lifecycle helpers."""
import logging
import time

from celery import shared_task
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.conf import settings

logger = logging.getLogger(__name__)


# Pushes a real-time status message to the browser via Django Channels.
# Uses async_to_sync so this synchronous function can call the async channel layer.
def _send_ws_update(scan_task_id: int, data: dict):
    """Send a WebSocket message to the scan's channel group."""
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f'scan_{scan_task_id}',
        data,
    )


# Translates a numeric progress percentage (0–100) to the human-readable
# message shown in the scan progress bar on the detail page.
def _progress_message(progress: int) -> str:
    if progress < 15:
        return 'Target discovery and reachability validation in progress...'
    if progress < 60:
        return 'Scanner collection and evidence gathering in progress...'
    if progress < 85:
        return 'Normalizing findings and preparing the remediation register...'
    return 'Finalizing the scan and preparing the report payload...'


def _run_scan_pipeline(scan_task_id: int, *, resume: bool = False):
    """Start or resume a scan against GVM and run downstream analysis."""
    from apps.scanner.models import ScanTask
    from apps.scanner.gvm_client import get_gvm_client
    from apps.interceptor.tasks import process_scan_findings_pipeline

    scan_task = ScanTask.objects.get(id=scan_task_id)

    if scan_task.raw_report_xml:
        logger.info('Scan #%s: XML report already captured, resuming analysis pipeline', scan_task_id)
        process_scan_findings_pipeline(scan_task_id)
        return ScanTask.objects.get(id=scan_task_id)

    client = get_gvm_client()

    try:
        logger.info('Scan #%s: Connecting to GVM...', scan_task_id)
        client.connect()

        if scan_task.status == ScanTask.Status.STOPPED:
            logger.info('Scan #%s: stop already requested before worker start', scan_task_id)
            return scan_task

        if not resume or not scan_task.gvm_task_id:
            scan_task.mark_running()
            _send_ws_update(scan_task_id, {
                'type': 'scan.progress',
                'progress': 0,
                'status': 'running',
                'message': 'Connecting to scanner...',
            })

            target_id = client.create_target(
                name=f'OmniGov-{scan_task_id}-{scan_task.target}',
                hosts=scan_task.target,
            )
            scan_task.gvm_target_id = target_id
            scan_task.save(update_fields=['gvm_target_id', 'updated_at'])

            logger.info(
                'Scan #%s: Starting GVM task with scan profile %s',
                scan_task_id,
                scan_task.scan_config,
            )
            gvm_task_id = client.create_and_start_task(target_id, scan_task.scan_config)
            scan_task.gvm_task_id = gvm_task_id
            scan_task.save(update_fields=['gvm_task_id', 'updated_at'])
        else:
            gvm_task_id = scan_task.gvm_task_id
            logger.info('Scan #%s: Resuming existing GVM task %s', scan_task_id, gvm_task_id)
            if scan_task.status == ScanTask.Status.PENDING:
                scan_task.mark_running()

        _send_ws_update(scan_task_id, {
            'type': 'scan.progress',
            'progress': max(scan_task.progress or 0, 5),
            'status': 'running',
            'message': 'Scan initiated, scanning in progress...',
        })

        poll_interval = settings.SCAN_POLL_INTERVAL
        while True:
            progress = client.get_task_progress(gvm_task_id)
            task_status = client.get_task_status(gvm_task_id)

            scan_task.refresh_from_db()
            if scan_task.status == ScanTask.Status.STOPPED:
                client.stop_task(gvm_task_id)
                logger.info('Scan #%s: Stopped by user', scan_task_id)
                _send_ws_update(scan_task_id, {
                    'type': 'scan.complete',
                    'status': 'stopped',
                    'message': 'Scan stopped by user.',
                })
                return scan_task

            if scan_task.status != ScanTask.Status.RUNNING:
                scan_task.status = ScanTask.Status.RUNNING

            scan_task.progress = max(scan_task.progress or 0, progress)
            scan_task.save(update_fields=['status', 'progress', 'updated_at'])

            _send_ws_update(scan_task_id, {
                'type': 'scan.progress',
                'progress': scan_task.progress,
                'status': 'running',
                'message': _progress_message(scan_task.progress),
            })

            if task_status == 'Done' or progress >= 100:
                scan_task.progress = 100
                scan_task.save(update_fields=['progress', 'updated_at'])
                break

            if task_status == 'Stopped':
                scan_task.mark_stopped()
                _send_ws_update(scan_task_id, {
                    'type': 'scan.complete',
                    'status': 'stopped',
                    'message': 'Scan stopped by scanner.',
                })
                return scan_task

            time.sleep(poll_interval)

        logger.info('Scan #%s: Retrieving report...', scan_task_id)
        xml_report = client.get_report(gvm_task_id)
        scan_task.raw_report_xml = xml_report
        scan_task.save(update_fields=['raw_report_xml', 'updated_at'])
        scan_task.mark_completed()

        _send_ws_update(scan_task_id, {
            'type': 'scan.progress',
            'progress': 100,
            'status': 'completed',
            'message': 'Scan complete. Parsing findings...',
        })

        process_scan_findings_pipeline(scan_task_id)
        logger.info('Scan #%s: Complete. Analysis pipeline finished.', scan_task_id)
        return ScanTask.objects.get(id=scan_task_id)
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_scan(self, scan_task_id: int):
    """
    Execute a full vulnerability scan via GVM.

    Lifecycle: connect → create target → start task → poll progress → retrieve report
    """
    try:
        return _run_scan_pipeline(scan_task_id)
    except Exception as exc:
        from apps.scanner.models import ScanTask

        logger.exception(f"Scan #{scan_task_id}: Failed with error: {exc}")
        scan_task = ScanTask.objects.get(id=scan_task_id)
        scan_task.mark_failed(str(exc))
        _send_ws_update(scan_task_id, {
            'type': 'scan.error',
            'status': 'failed',
            'message': f'Scan failed: {str(exc)[:200]}',
        })
        if getattr(self.request, 'is_eager', False):
            raise
        raise self.retry(exc=exc)
