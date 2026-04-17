import ipaddress

from django.conf import settings
from django.db import models
from django.utils import timezone


class ApprovedTargetRange(models.Model):
    """Admin-approved IP ranges that users are allowed to scan (Target Locking)."""

    cidr = models.CharField(
        max_length=43,
        help_text="CIDR notation, e.g. 192.168.1.0/24 or 10.0.0.0/8"
    )
    description = models.TextField(blank=True, help_text="Purpose of this target range")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='approved_targets',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'approved_target_ranges'
        verbose_name = 'Approved Target Range'
        verbose_name_plural = 'Approved Target Ranges'

    def __str__(self):
        return f"{self.cidr} — {self.description[:50]}"

    @classmethod
    def is_target_approved(cls, target_ip: str) -> bool:
        """Check if a target IP or CIDR falls within an approved range."""
        try:
            target_network = ipaddress.ip_network(target_ip, strict=False)
        except ValueError:
            return False

        for approved in cls.objects.all():
            try:
                approved_network = ipaddress.ip_network(approved.cidr, strict=False)
                # Check if target is a subnet of (or equal to) an approved range
                if target_network.subnet_of(approved_network):
                    return True
            except ValueError:
                continue
        return False


class ScanTask(models.Model):
    """Represents a vulnerability scan job."""

    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Scan Completed'
        ANALYZING = 'analyzing', 'AI Analyzing'
        ANALYZED = 'analyzed', 'Analysis Complete'
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
        self.status = self.Status.ANALYZING
        self.save(update_fields=['status', 'updated_at'])

    def mark_analyzed(self):
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
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
