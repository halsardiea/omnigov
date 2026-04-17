"""
Report generation Celery tasks.
"""
import logging
from datetime import datetime

from celery import shared_task
from django.core.files.base import ContentFile

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def generate_reports(self, scan_task_id: int):
    """
    Generate all report types (executive PDF, technical PDF, CSV) for a scan.
    """
    from apps.scanner.models import ScanTask
    from apps.interceptor.models import TechnicalFinding
    from apps.reports.models import Report
    from apps.reports.generators.pdf_generator import generate_executive_pdf, generate_technical_pdf
    from apps.reports.generators.csv_generator import generate_findings_csv

    try:
        scan_task = ScanTask.objects.select_related('created_by', 'framework').get(id=scan_task_id)
        framework = scan_task.framework
        findings = TechnicalFinding.objects.filter(
            scan_task=scan_task,
        ).order_by('-cvss_score')

        total = findings.count()
        if total == 0:
            logger.info(f"No findings for Scan #{scan_task_id}, skipping report generation.")
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Executive PDF
        try:
            exec_buf = generate_executive_pdf(scan_task, findings, framework)
            report = Report.objects.create(
                scan_task=scan_task,
                report_type='executive',
                title=f'Executive Report — {scan_task.name}',
                format='pdf',
                compliance_score=_calc_score(findings),
                findings_count=total,
            )
            report.file.save(
                f'executive_{scan_task_id}_{timestamp}.pdf',
                ContentFile(exec_buf.read()),
            )
            logger.info(f"Executive PDF generated for Scan #{scan_task_id}")
        except Exception as e:
            logger.error(f"Executive PDF generation failed: {e}")

        # Technical PDF
        try:
            tech_buf = generate_technical_pdf(scan_task, findings, framework)
            report = Report.objects.create(
                scan_task=scan_task,
                report_type='technical',
                title=f'Technical Report — {scan_task.name}',
                format='pdf',
                compliance_score=_calc_score(findings),
                findings_count=total,
            )
            report.file.save(
                f'technical_{scan_task_id}_{timestamp}.pdf',
                ContentFile(tech_buf.read()),
            )
            logger.info(f"Technical PDF generated for Scan #{scan_task_id}")
        except Exception as e:
            logger.error(f"Technical PDF generation failed: {e}")

        # CSV Export
        try:
            csv_buf = generate_findings_csv(scan_task, findings, framework)
            report = Report.objects.create(
                scan_task=scan_task,
                report_type='technical',
                title=f'CSV Export — {scan_task.name}',
                format='csv',
                compliance_score=_calc_score(findings),
                findings_count=total,
            )
            report.file.save(
                f'findings_{scan_task_id}_{timestamp}.csv',
                ContentFile(csv_buf.getvalue().encode('utf-8')),
            )
            logger.info(f"CSV export generated for Scan #{scan_task_id}")
        except Exception as e:
            logger.error(f"CSV generation failed: {e}")

    except Exception as exc:
        logger.exception(f"Report generation failed for Scan #{scan_task_id}: {exc}")
        raise self.retry(exc=exc)


def _calc_score(findings) -> float:
    """Calculate a basic severity-weighted score (placeholder until AI is re-enabled)."""
    total = findings.count()
    if total == 0:
        return 100.0
    high_count = findings.filter(severity='High').count()
    return round(max(0.0, (1 - high_count / total) * 100), 1)
