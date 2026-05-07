# ---
# LOCATION : apps/scanner/models.py
# PURPOSE  : Defines the two database models that form the backbone of the
#            scanning subsystem: ApprovedTargetRange (the security allowlist) and
#            ScanTask (the full lifecycle record of every scan job).
#            If this file were deleted, the entire scan workflow — from target
#            validation to report generation — would have no persistent state.
#
# CONNECTS TO:
#   - apps/scanner/views.py          → ScanCreateForm validates targets against
#                                       ApprovedTargetRange; ScanListView and
#                                       ScanDetailView read/update ScanTask
#   - apps/scanner/tasks.py          → _run_scan_pipeline() calls mark_running(),
#                                       mark_completed(), mark_failed(), mark_stopped()
#   - apps/scanner/runtime.py        → ensure_scan_worker() reads ScanTask.status and
#                                       .updated_at to decide if a worker needs spawning
#   - apps/interceptor/tasks.py      → process_scan_findings_pipeline() reads
#                                       .raw_report_xml and calls mark_analyzing(),
#                                       mark_analyzed()
#   - apps/interceptor/models.py     → TechnicalFinding.scan_task FK points here
#   - apps/reports/models.py         → Report.scan_task FK points here
#   - apps/compliance/models.py      → ScanTask.framework and .selected_frameworks
#                                       M2M/FK reference Framework
# ---
from django.conf import settings
from django.db import models
from django.utils import timezone


class ApprovedTargetRange(models.Model):
    """Admin-managed list of IP ranges that are permitted to be scanned.

    Only IP addresses that fall within one of these ranges can be submitted
    as a scan target — this prevents users from scanning external hosts or
    networks the organisation does not own.
    """

    cidr = models.CharField(
        max_length=43,
        help_text='CIDR notation, e.g. 192.168.1.0/24 or 10.0.0.0/8',
    )
    description = models.TextField(
        blank=True,
        help_text='Purpose of this target range (e.g. "Lab network")',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        on_delete=models.SET_NULL,
        related_name='approved_targets',
    )

    class Meta:
        db_table = 'approved_target_ranges'
        verbose_name = 'Approved Target Range'
        verbose_name_plural = 'Approved Target Ranges'

    def __str__(self):
        return f'{self.cidr} — {self.description or "no description"}'


class ScanTask(models.Model):
    """Represents a vulnerability scan job."""

    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Scan Completed'
        ANALYZING = 'analyzing', 'Correlating Findings'
        ANALYZED = 'analyzed', 'Correlation Complete'
        FAILED = 'failed', 'Failed'
        STOPPED = 'stopped', 'Stopped'

    name = models.CharField(max_length=200, help_text="Friendly scan name")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scans',
    )
    framework = models.ForeignKey(
        'compliance.Framework',
        on_delete=models.PROTECT,
        related_name='scan_tasks',
    )
    selected_frameworks = models.ManyToManyField(
        'compliance.Framework',
        blank=True,
        related_name='selected_scan_tasks',
    )
    target = models.CharField(max_length=500, help_text="Target IP or CIDR range")
    scan_config = models.CharField(max_length=50, default='full_and_fast')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    progress = models.IntegerField(default=0, help_text="Scan progress 0-100")

    # GVM-specific identifiers (populated when scan starts)
    gvm_task_id = models.CharField(max_length=100, blank=True)
    gvm_target_id = models.CharField(max_length=100, blank=True)
    gvm_report_id = models.CharField(max_length=100, blank=True)

    # Store the raw XML report from OpenVAS
    raw_report_xml = models.TextField(blank=True, help_text="Raw OpenVAS XML report")

    # Error tracking
    error_message = models.TextField(blank=True)

    # Timestamps
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scan_tasks'
        ordering = ['-created_at']
        verbose_name = 'Scan Task'
        verbose_name_plural = 'Scan Tasks'

    def __str__(self):
        return f"Scan #{self.pk} — {self.name} ({self.get_status_display()})"

    @property
    def selected_framework_list(self):
        # Returns the M2M frameworks if any were selected at scan creation;
        # falls back to the single legacy 'framework' FK for backward compatibility
        # with scan records created before multi-framework support was added.
        frameworks = list(self.selected_frameworks.all())
        if frameworks:
            return frameworks
        if self.framework_id:
            return [self.framework]
        return []

    @property
    def primary_framework(self):
        # The first framework in the list is treated as the primary one —
        # used as a fallback when a report needs exactly one framework label.
        if self.framework_id:
            return self.framework
        frameworks = self.selected_framework_list
        return frameworks[0] if frameworks else None

    @property
    def framework_names(self):
        return ', '.join(f"{framework.name} {framework.version}" for framework in self.selected_framework_list)

    @property
    def framework_count(self):
        return len(self.selected_framework_list)

    # --- Lifecycle state-transition helpers ---
    # Each method does only the minimum DB write needed for that transition
    # (using update_fields) so we never accidentally overwrite fields that
    # a concurrent process has just updated.

    def mark_running(self):
        self.status = self.Status.RUNNING
        self.started_at = timezone.now()
        self.save(update_fields=['status', 'started_at', 'updated_at'])

    def mark_completed(self):
        self.status = self.Status.COMPLETED
        self.progress = 100
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'progress', 'completed_at', 'updated_at'])

    def mark_analyzing(self):
        # Intermediate state: GVM scan is done, interceptor pipeline is now running.
        self.status = self.Status.ANALYZING
        self.save(update_fields=['status', 'updated_at'])

    def mark_analyzed(self):
        # Terminal success state: findings parsed, controls correlated, reports generated.
        self.status = self.Status.ANALYZED
        self.save(update_fields=['status', 'updated_at'])

    def mark_failed(self, error_msg: str = ''):
        self.status = self.Status.FAILED
        self.error_message = error_msg
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'error_message', 'completed_at', 'updated_at'])

    def mark_stopped(self):
        self.status = self.Status.STOPPED
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'completed_at', 'updated_at'])

    @property
    def findings_count(self):
        return self.findings.count()

    @property
    def high_findings_count(self):
        return self.findings.filter(severity='High').count()

    @property
    def duration(self):
        # Wall-clock time from scan start to completion — shown on the detail page.
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
