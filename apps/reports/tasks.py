# ---
# LOCATION : apps/reports/tasks.py
# PURPOSE  : Generates the three report artefacts from a completed, analysed scan:
#            1. Executive PDF  — compliance score, control mapping summary
#            2. Technical PDF  — full finding details with remediation guidance
#            3. Findings CSV   — raw data export for further analysis
#            One set of reports is created per selected compliance framework.
#
# CONNECTS TO:
#   - apps/interceptor/tasks.py              → process_scan_findings_pipeline() calls
#                                               generate_reports_pipeline() as its last step
#   - apps/interceptor/correlation.py        → summarize_scan_alignment() computes the
#                                               compliance score used in both PDFs
#   - apps/interceptor/models.py             → TechnicalFinding rows read to build content
#   - apps/scanner/models.py                 → ScanTask metadata used in PDF headers
#   - apps/reports/models.py                 → Report rows created here; file bytes saved
#   - apps/reports/generators/pdf_generator  → generate_executive_pdf and
#                                               generate_technical_pdf called here
#   - apps/reports/generators/csv_generator  → generate_findings_csv called here
# ---
"""
Report generation Celery tasks.
"""
import logging
from datetime import datetime

from celery import shared_task
from django.core.files.base import ContentFile
from django.utils import timezone

logger = logging.getLogger(__name__)


def _touch_scan(scan_task):
    scan_task.updated_at = timezone.now()
    scan_task.save(update_fields=['updated_at'])


def generate_reports_pipeline(scan_task_id: int):
    """Generate executive, technical, and CSV reports for a scan."""
    from apps.scanner.models import ScanTask
    from apps.interceptor.models import TechnicalFinding
    from apps.interceptor.correlation import summarize_scan_alignment
    from apps.reports.models import Report
    from apps.reports.generators.pdf_generator import generate_executive_pdf, generate_technical_pdf
    from apps.reports.generators.csv_generator import generate_findings_csv

    scan_task = ScanTask.objects.select_related('created_by', 'framework').prefetch_related('selected_frameworks').get(id=scan_task_id)
    findings = list(TechnicalFinding.objects.filter(
        scan_task=scan_task,
    ).select_related('analysis').order_by('-cvss_score'))

    total = len(findings)
    if total == 0:
        logger.info(f"No findings for Scan #{scan_task_id}, skipping report generation.")
        return

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    frameworks = scan_task.selected_framework_list

    for framework in frameworks:
        alignment = summarize_scan_alignment(findings, framework)
        compliance_score = alignment['compliance_score']
        title_suffix = f" — {framework.name}" if len(frameworks) > 1 else ''

        try:
            exec_buf = generate_executive_pdf(scan_task, findings, framework, alignment)
            report = Report.objects.create(
                scan_task=scan_task,
                framework=framework,
                report_type='executive',
                title=f'Executive Report — {scan_task.name}{title_suffix}',
                format='pdf',
                generated_by=scan_task.created_by,
                compliance_score=compliance_score,
                findings_count=total,
            )
            report.file.save(
                # int() casts are explicit: only numeric IDs appear in the file path.
                # No user-controlled string (scan name, framework name) can influence it.
                f'executive_{int(scan_task_id)}_{int(framework.id)}_{timestamp}.pdf',
                ContentFile(exec_buf.read()),
            )
            logger.info(f"Executive PDF generated for Scan #{scan_task_id} framework #{framework.id}")
        except Exception as e:
            logger.error(f"Executive PDF generation failed for framework #{framework.id}: {e}")

        try:
            tech_buf = generate_technical_pdf(scan_task, findings, framework, alignment)
            report = Report.objects.create(
                scan_task=scan_task,
                framework=framework,
                report_type='technical',
                title=f'Technical Report — {scan_task.name}{title_suffix}',
                format='pdf',
                generated_by=scan_task.created_by,
                compliance_score=compliance_score,
                findings_count=total,
            )
            report.file.save(
                # int() casts are explicit: only numeric IDs appear in the file path
                f'technical_{int(scan_task_id)}_{int(framework.id)}_{timestamp}.pdf',
                ContentFile(tech_buf.read()),
            )
            logger.info(f"Technical PDF generated for Scan #{scan_task_id} framework #{framework.id}")
        except Exception as e:
            logger.error(f"Technical PDF generation failed for framework #{framework.id}: {e}")

        try:
            csv_buf = generate_findings_csv(scan_task, findings, framework)
            report = Report.objects.create(
                scan_task=scan_task,
                framework=framework,
                report_type='technical',
                title=f'CSV Export — {scan_task.name}{title_suffix}',
                format='csv',
                generated_by=scan_task.created_by,
                compliance_score=compliance_score,
                findings_count=total,
            )
            report.file.save(
                # int() casts are explicit: only numeric IDs appear in the file path
                f'findings_{int(scan_task_id)}_{int(framework.id)}_{timestamp}.csv',
                ContentFile(csv_buf.getvalue().encode('utf-8')),
            )
            logger.info(f"CSV export generated for Scan #{scan_task_id} framework #{framework.id}")
        except Exception as e:
            logger.error(f"CSV generation failed for framework #{framework.id}: {e}")

        _touch_scan(scan_task)


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def generate_reports(self, scan_task_id: int):
    """
    Generate all report types (executive PDF, technical PDF, CSV) for a scan.
    """
    try:
        return generate_reports_pipeline(scan_task_id)

    except Exception as exc:
        logger.exception(f"Report generation failed for Scan #{scan_task_id}: {exc}")
        if getattr(self.request, 'is_eager', False):
            raise
        raise self.retry(exc=exc)
