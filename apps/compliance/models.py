# ---
# LOCATION : apps/compliance/models.py
# PURPOSE  : Stores the reference corpus for every supported compliance framework
#            (e.g. ISO 27001, GDPR, NIST CSF). The correlation engine in
#            apps/interceptor/correlation.py scores scan findings against these
#            controls to determine which regulatory requirements are at risk.
#
# CONNECTS TO:
#   - apps/interceptor/correlation.py  → rank_controls_for_finding() and
#                                         correlate_finding() iterate FrameworkControl
#                                         rows and score them against each finding
#   - apps/scanner/models.py           → ScanTask.framework and .selected_frameworks
#                                         are ForeignKey / M2M to Framework
#   - apps/reports/models.py           → Report.framework FK points to Framework
#   - apps/compliance/corpus.py        → the loader that populates Framework and
#                                         FrameworkControl from JSON fixture files
#   - apps/compliance/views.py         → FrameworkListView and FrameworkDetailView
#                                         display these models in the browser
# ---
from django.db import models


# Represents a top-level regulatory or security standard — e.g. 'ISO 27001' v2022.
# Each Framework has many FrameworkControl children that make up its full catalogue.
class Framework(models.Model):
    """Regulatory compliance framework (ISO 27001, GDPR, etc.)"""

    name = models.CharField(max_length=100)
    version = models.CharField(max_length=20)
    description = models.TextField()
    # Inactive frameworks are hidden from the scan creation form but preserved
    # in the database so historical scans do not lose their framework reference.
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'frameworks'
        ordering = ['name']
        unique_together = ['name', 'version']
        verbose_name = 'Compliance Framework'
        verbose_name_plural = 'Compliance Frameworks'

    def __str__(self):
        return f"{self.name} ({self.version})"

    @property
    def controls_count(self):
        return self.controls.count()


# A single auditable requirement within a framework.
# The 'keywords' JSON field is the primary signal the heuristic correlator uses
# to match a vulnerability finding to this control — richer keywords produce
# better correlation accuracy even without the AI enrichment step.
class FrameworkControl(models.Model):
    """Individual control within a compliance framework (the Reference Corpus)."""

    framework = models.ForeignKey(
        Framework,
        on_delete=models.CASCADE,
        related_name='controls',
    )
    control_id = models.CharField(
        max_length=50,
        help_text="Control identifier, e.g. A.5.1 or Art.32"
    )
    title = models.CharField(max_length=300)
    description = models.TextField(help_text="Full control requirement text")
    category = models.CharField(
        max_length=100,
        help_text="Control category, e.g. Access Control, Cryptography"
    )
    keywords = models.JSONField(
        default=list,
        help_text="Keywords for matching vulnerabilities to this control"
    )
    guidance = models.TextField(
        blank=True,
        help_text="Implementation guidance"
    )

    class Meta:
        db_table = 'framework_controls'
        ordering = ['framework', 'control_id']
        unique_together = ['framework', 'control_id']
        verbose_name = 'Framework Control'
        verbose_name_plural = 'Framework Controls'

    def __str__(self):
        return f"[{self.control_id}] {self.title}"
