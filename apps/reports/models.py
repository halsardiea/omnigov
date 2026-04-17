from django.conf import settings
from django.db import models


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
    report_type = models.CharField(max_length=20, choices=ReportType.choices)
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='reports/%Y/%m/')
    format = models.CharField(max_length=10, choices=Format.choices, default=Format.PDF)
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
        return f"{self.get_report_type_display()} — Scan #{self.scan_task_id}"
