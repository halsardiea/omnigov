# ---
# LOCATION : apps/interceptor/models.py
# PURPOSE  : Stores every vulnerability finding extracted from an OpenVAS scan
#            and the AI / heuristic analysis that maps it to framework controls.
#            These are the core data rows that drive the compliance scoring,
#            executive summaries, and technical remediation reports.
#
# CONNECTS TO:
#   - apps/interceptor/xml_parser.py    → parse_openvas_xml() returns raw dicts
#                                          that are turned into TechnicalFinding rows
#   - apps/interceptor/correlation.py   → correlate_finding() produces the payload
#                                          stored in FindingAnalysis.matched_controls
#   - apps/interceptor/tasks.py         → process_scan_findings_pipeline() creates
#                                          both TechnicalFinding and FindingAnalysis rows
#   - apps/scanner/models.py            → TechnicalFinding.scan_task FK ties findings
#                                          back to the ScanTask that produced them
#   - apps/scanner/views.py             → ScanDetailView queries TechnicalFinding filtered
#                                          by scan_task for the findings table on the page
#   - apps/reports/tasks.py             → generate_reports_pipeline() reads TechnicalFinding
#                                          and FindingAnalysis to build PDFs and CSVs
# ---
from django.db import models
from django.core.exceptions import ObjectDoesNotExist


# One row = one vulnerability detected on the scanned network.
# Immutable host/IP data is stored here (never sent to the AI service);
# the AI only receives the name, description, and solution text.
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

    @property
    def analysis_record(self):
        # Safe accessor — returns None if no FindingAnalysis row has been created yet
        # for this finding (e.g. the correlation pipeline has not completed).
        try:
            return self.analysis
        except ObjectDoesNotExist:
            return None


# One-to-one companion to TechnicalFinding.
# Stores the matched framework controls, executive summary, and remediation advice
# produced by either the heuristic scorer or the Claude AI enrichment step.
class FindingAnalysis(models.Model):
    """Persisted control-correlation and remediation analysis for a finding."""

    class Method(models.TextChoices):
        HEURISTIC = 'heuristic', 'Heuristic'
        AI_HYBRID = 'ai_hybrid', 'AI Hybrid'

    technical_finding = models.OneToOneField(
        'interceptor.TechnicalFinding',
        on_delete=models.CASCADE,
        related_name='analysis',
    )
    matched_controls = models.JSONField(
        default=list,
        help_text='Ordered list of matched framework controls with correlation metadata.',
    )
    executive_summary = models.TextField(blank=True)
    technical_remediation = models.TextField(blank=True)
    analysis_method = models.CharField(
        max_length=20,
        choices=Method.choices,
        default=Method.HEURISTIC,
    )
    confidence_score = models.FloatField(
        null=True,
        blank=True,
        help_text='Correlation confidence between 0.0 and 1.0',
    )
    raw_provider_response = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    technical_finding = models.OneToOneField(
        'interceptor.TechnicalFinding',
        on_delete=models.CASCADE,
        related_name='analysis',
    )
    matched_controls = models.JSONField(
        default=list,
        help_text='Ordered list of matched framework controls with correlation metadata.',
    )
    executive_summary = models.TextField(blank=True)
    technical_remediation = models.TextField(blank=True)
    analysis_method = models.CharField(
        max_length=20,
        choices=Method.choices,
        default=Method.HEURISTIC,
    )
    confidence_score = models.FloatField(
        null=True,
        blank=True,
        help_text='Correlation confidence between 0.0 and 1.0',
    )
    raw_provider_response = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'finding_analyses'
        ordering = ['technical_finding_id']
        verbose_name = 'Finding Analysis'
        verbose_name_plural = 'Finding Analyses'

    def __str__(self):
        return f"Analysis for finding #{self.technical_finding_id}"
