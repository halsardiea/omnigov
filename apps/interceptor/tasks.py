# ---
# LOCATION : apps/interceptor/tasks.py
# PURPOSE  : The post-scan analysis pipeline: takes the raw OpenVAS XML stored on
#            ScanTask.raw_report_xml, parses it into TechnicalFinding rows, runs each
#            finding through the control correlation engine, then triggers report generation.
#            This is the bridge between the scanner (raw XML) and the reports (PDFs/CSVs).
#
# CONNECTS TO:
#   - apps/interceptor/xml_parser.py    → parse_openvas_xml() converts XML to dicts
#   - apps/interceptor/correlation.py   → correlate_finding() maps each finding to
#                                          framework controls and generates analysis text
#   - apps/interceptor/models.py        → TechnicalFinding and FindingAnalysis rows
#                                          created here from parsed + correlated data
#   - apps/scanner/models.py            → ScanTask.raw_report_xml read; mark_analyzing()
#                                          and mark_analyzed() called
#   - apps/reports/tasks.py             → generate_reports_pipeline() called at the end
#                                          to produce PDFs/CSVs from the saved findings
#   - apps/scanner/consumers.py         → _send_ws_update() pushes analysis progress
#                                          events to the browser in real time
# ---
"""Interceptor Celery tasks — parse findings, correlate controls, and trigger reports."""
import logging

from celery import shared_task
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone

logger = logging.getLogger(__name__)


def _touch_scan(scan_task):
    scan_task.updated_at = timezone.now()
    scan_task.save(update_fields=['updated_at'])


def _send_ws_update(scan_task_id: int, data: dict):
    """Send a WebSocket message to the scan's channel group."""
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f'scan_{scan_task_id}',
        data,
    )


# Merges the per-framework correlation results from multiple frameworks into a
# single unified payload that gets stored in FindingAnalysis.matched_controls.
# This is needed because a scan can target multiple frameworks simultaneously —
# the merger de-duplicates controls and picks the highest-confidence analysis.
def _merge_framework_analysis_results(framework_results):
    matched_controls = []
    executive_parts = []
    remediation_parts = []
    raw_provider_response = {'framework_results': {}}
    best_confidence = 0.0
    used_ai = False
    fallback_summary = ''
    fallback_remediation = ''

    for framework, analysis_payload in framework_results:
        confidence = analysis_payload.get('confidence_score') or 0.0
        if confidence > best_confidence:
            best_confidence = confidence
        if analysis_payload.get('analysis_method') == 'ai_hybrid':
            used_ai = True

        if not fallback_summary and analysis_payload.get('executive_summary'):
            fallback_summary = analysis_payload['executive_summary']
        if not fallback_remediation and analysis_payload.get('technical_remediation'):
            fallback_remediation = analysis_payload['technical_remediation']

        framework_controls = []
        for control in analysis_payload.get('matched_controls', []):
            framework_controls.append({
                **control,
                'framework_id': framework.id,
                'framework_name': framework.name,
                'framework_version': framework.version,
            })

        raw_provider_response['framework_results'][str(framework.id)] = {
            'matched_controls': framework_controls,
            'executive_summary': analysis_payload.get('executive_summary', ''),
            'technical_remediation': analysis_payload.get('technical_remediation', ''),
            'analysis_method': analysis_payload.get('analysis_method', 'heuristic'),
            'confidence_score': analysis_payload.get('confidence_score'),
            'raw_provider_response': analysis_payload.get('raw_provider_response', {}),
        }

        if framework_controls:
            matched_controls.extend(framework_controls)
            executive_parts.append(f"{framework.name} {framework.version}: {analysis_payload.get('executive_summary', '').strip()}")
            remediation_parts.append(f"{framework.name} {framework.version}: {analysis_payload.get('technical_remediation', '').strip()}")

    matched_controls.sort(key=lambda item: item.get('score', 0), reverse=True)

    return {
        'matched_controls': matched_controls,
        'executive_summary': ' '.join(part for part in executive_parts if part.strip()) or fallback_summary,
        'technical_remediation': ' '.join(dict.fromkeys(part for part in remediation_parts if part.strip())) or fallback_remediation,
        'analysis_method': 'ai_hybrid' if used_ai else 'heuristic',
        'confidence_score': best_confidence if best_confidence > 0 else None,
        'raw_provider_response': raw_provider_response,
    }


def process_scan_findings_pipeline(scan_task_id: int):
    """Parse findings, correlate controls, and generate reports."""
    from apps.scanner.models import ScanTask
    from apps.interceptor.models import TechnicalFinding, FindingAnalysis
    from apps.interceptor.correlation import correlate_finding
    from apps.interceptor.xml_parser import parse_openvas_xml
    from apps.reports.tasks import generate_reports_pipeline

    logger.info(f"Interceptor: Parsing findings for Scan #{scan_task_id}")

    _send_ws_update(scan_task_id, {
        'type': 'scan.progress',
        'progress': 100,
        'status': 'analyzing',
        'message': 'Parsing scan findings and correlating selected framework controls...',
    })

    scan_task = ScanTask.objects.get(id=scan_task_id)
    scan_task.mark_analyzing()

    xml_content = scan_task.raw_report_xml
    if not xml_content:
        scan_task.mark_analyzed()
        logger.warning(f"Scan #{scan_task_id}: No XML report data, skipping.")
        return scan_task

    raw_findings = parse_openvas_xml(xml_content)
    logger.info(f"Scan #{scan_task_id}: Parsed {len(raw_findings)} findings")

    TechnicalFinding.objects.filter(scan_task=scan_task).delete()
    frameworks = scan_task.selected_framework_list

    for raw in raw_findings:
        finding = TechnicalFinding.objects.create(
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

        framework_results = []
        for framework in frameworks:
            framework_controls = list(framework.controls.all())
            framework_results.append(
                (framework, correlate_finding(finding, framework, controls=framework_controls)),
            )

        analysis_payload = _merge_framework_analysis_results(framework_results)
        FindingAnalysis.objects.create(
            technical_finding=finding,
            matched_controls=analysis_payload['matched_controls'],
            executive_summary=analysis_payload['executive_summary'],
            technical_remediation=analysis_payload['technical_remediation'],
            analysis_method=analysis_payload['analysis_method'],
            confidence_score=analysis_payload['confidence_score'],
            raw_provider_response=analysis_payload['raw_provider_response'],
        )
        _touch_scan(scan_task)

    logger.info(f"Scan #{scan_task_id}: {len(raw_findings)} findings saved and correlated. Generating reports...")

    generate_reports_pipeline(scan_task_id)
    scan_task.mark_analyzed()

    _send_ws_update(scan_task_id, {
        'type': 'scan.progress',
        'progress': 100,
        'status': 'analyzed',
        'message': f'{len(raw_findings)} findings parsed and correlated. Reports ready.',
    })
    return scan_task


@shared_task(bind=True, max_retries=1, default_retry_delay=60)
def process_scan_findings(self, scan_task_id: int):
    """
    Parse findings from a completed scan, correlate them to controls, and trigger reports.
    """
    try:
        return process_scan_findings_pipeline(scan_task_id)

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
        if getattr(self.request, 'is_eager', False):
            raise
        raise self.retry(exc=exc)

