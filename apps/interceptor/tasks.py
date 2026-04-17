"""
Interceptor Celery tasks — parses scan findings and triggers report generation.

AI analysis has been stubbed out. This task now simply extracts TechnicalFinding
records from the raw OpenVAS XML and hands off to report generation.
"""
import logging

from celery import shared_task
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

logger = logging.getLogger(__name__)


def _send_ws_update(scan_task_id: int, data: dict):
    """Send a WebSocket message to the scan's channel group."""
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f'scan_{scan_task_id}',
        data,
    )


@shared_task(bind=True, max_retries=1, default_retry_delay=60)
def process_scan_findings(self, scan_task_id: int):
    """
    Parse findings from a completed scan and trigger report generation.

    Replaces the AI pipeline — creates TechnicalFinding records directly
    from the raw XML without AI analysis.
    """
    from apps.scanner.models import ScanTask
    from apps.interceptor.models import TechnicalFinding
    from apps.interceptor.xml_parser import parse_openvas_xml

    logger.info(f"Interceptor: Parsing findings for Scan #{scan_task_id}")

    _send_ws_update(scan_task_id, {
        'type': 'scan.progress',
        'progress': 100,
        'status': 'analyzing',
        'message': 'Parsing scan findings...',
    })

    try:
        scan_task = ScanTask.objects.get(id=scan_task_id)
        scan_task.mark_analyzing()

        xml_content = scan_task.raw_report_xml
        if not xml_content:
            scan_task.mark_analyzed()
            logger.warning(f"Scan #{scan_task_id}: No XML report data, skipping.")
            return

        raw_findings = parse_openvas_xml(xml_content)
        logger.info(f"Scan #{scan_task_id}: Parsed {len(raw_findings)} findings")

        for raw in raw_findings:
            TechnicalFinding.objects.create(
                scan_task=scan_task,
                name=raw.get('name', 'Unknown'),
                cve_ids=raw.get('cve_ids', []),
                cvss_score=raw.get('cvss_score'),
                severity=raw.get('severity', 'Log'),
                host=raw.get('host', ''),
                port=raw.get('port', ''),
                description=raw.get('description', ''),
                solution=raw.get('solution', ''),
                references=raw.get('references', []),
                nvt_oid=raw.get('nvt_oid', ''),
                qod=raw.get('qod'),
            )

        scan_task.mark_analyzed()
        logger.info(f"Scan #{scan_task_id}: {len(raw_findings)} findings saved. Generating reports...")

        from apps.reports.tasks import generate_reports
        generate_reports.apply(args=[scan_task_id])

        _send_ws_update(scan_task_id, {
            'type': 'scan.progress',
            'progress': 100,
            'status': 'analyzed',
            'message': f'{len(raw_findings)} findings parsed. Reports ready.',
        })

    except Exception as exc:
        logger.exception(f"Interceptor: Failed for Scan #{scan_task_id}: {exc}")
        from apps.scanner.models import ScanTask as ST
        try:
            scan_task = ST.objects.get(id=scan_task_id)
            scan_task.mark_failed(f"Finding processing failed: {str(exc)[:200]}")
        except Exception:
            pass

        _send_ws_update(scan_task_id, {
            'type': 'scan.error',
            'status': 'failed',
            'message': f'Processing failed: {str(exc)[:200]}',
        })
        raise self.retry(exc=exc)

