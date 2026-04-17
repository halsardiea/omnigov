from django.db import models


class TechnicalFinding(models.Model):
    """A single vulnerability finding extracted from an OpenVAS scan report."""

    class Severity(models.TextChoices):
        CRITICAL = 'Critical', 'Critical'
        HIGH = 'High', 'High'
        MEDIUM = 'Medium', 'Medium'
        LOW = 'Low', 'Low'
        LOG = 'Log', 'Log'

    scan_task = models.ForeignKey(
        'scanner.ScanTask',
        on_delete=models.CASCADE,
        related_name='findings',
    )
    name = models.CharField(max_length=500, help_text="Vulnerability name / NVT title")
    cve_ids = models.JSONField(default=list, help_text='List of CVE IDs, e.g. ["CVE-2023-1234"]')
    cvss_score = models.FloatField(null=True, blank=True)
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.LOG)
    host = models.CharField(max_length=100, help_text="Target host IP (stored locally, never sent to AI)")
    port = models.CharField(max_length=50, blank=True)
    description = models.TextField(blank=True)
    solution = models.TextField(blank=True, help_text="Suggested fix from the scanner")
    references = models.JSONField(default=list, help_text="URLs and reference links")
    nvt_oid = models.CharField(max_length=100, blank=True, help_text="OpenVAS NVT OID")
    qod = models.IntegerField(null=True, blank=True, help_text="Quality of Detection (0-100)")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'technical_findings'
        ordering = ['-cvss_score', 'severity']
        verbose_name = 'Technical Finding'
        verbose_name_plural = 'Technical Findings'

    def __str__(self):
        return f"[{self.severity}] {self.name[:80]}"
