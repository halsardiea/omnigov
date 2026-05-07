# ---
# LOCATION : apps/reports/models.py
# PURPOSE  : Stores the metadata and file reference for every generated compliance
#            report. The actual PDF/CSV bytes live on disk (MEDIA_ROOT/reports/),
#            this model is the pointer that lets views and download endpoints find them.
#
# CONNECTS TO:
#   - apps/reports/tasks.py      → generate_reports_pipeline() creates Report rows and
#                                   saves the PDF/CSV files via report.file.save()
#   - apps/reports/views.py      → ReportListView and ReportDownloadView read these rows
#   - apps/scanner/models.py     → Report.scan_task FK links every report back to the
#                                   scan that produced it
#   - apps/compliance/models.py  → Report.framework FK records which framework the
#                                   report was generated against
#   - omnigov/urls.py            → MEDIA_URL / MEDIA_ROOT settings control where
#                                   report files are stored and how they are served
# ---
from django.conf import settings
from django.db import models


# Represents a single generated output document: either an executive compliance
# summary (PDF) or a technical remediation plan (PDF) or a raw findings export (CSV).
class Report(models.Model):
    """Generated compliance or remediation report."""

    class ReportType(models.TextChoices):
        EXECUTIVE = 'executive', 'Executive Compliance Report'
        TECHNICAL = 'technical', 'Technical Remediation Plan'

    class Format(models.TextChoices):
        PDF = 'pdf', 'PDF'
        CSV = 'csv', 'CSV'

    scan_task = models.ForeignKey(
        'scanner.ScanTask',
        on_delete=models.CASCADE,
        related_name='reports',
    )
    framework = models.ForeignKey(
        'compliance.Framework',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='reports',
    )
    report_type = models.CharField(max_length=20, choices=ReportType.choices)
    title = models.CharField(max_length=200)
    # FileField stores only the relative path to the file; the bytes live
    # on disk under MEDIA_ROOT/reports/YYYY/MM/.
    file = models.FileField(upload_to='reports/%Y/%m/')
    format = models.CharField(max_length=10, choices=Format.choices, default=Format.PDF)
    # The compliance score (0–100) computed by summarize_scan_alignment() in correlation.py.
    # Used by the report list view to render a risk badge (Low / Moderate / High).
    compliance_score = models.FloatField(
        null=True, blank=True,
        help_text="Overall compliance score as percentage (0-100)"
    )
    findings_count = models.IntegerField(default=0)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='generated_reports',
    )
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'reports'
        ordering = ['-generated_at']
        verbose_name = 'Report'
        verbose_name_plural = 'Reports'

    def __str__(self):
        framework = self.effective_framework
        if framework is None:
            return f"{self.get_report_type_display()} — Scan #{self.scan_task_id}"
        return f"{self.get_report_type_display()} — {framework.name} — Scan #{self.scan_task_id}"

    @property
    def effective_framework(self):
        # Prefer the directly assigned framework; fall back to the scan's primary
        # framework so the report always has something meaningful to display.
        if self.framework_id:
            return self.framework
        return self.scan_task.primary_framework
