from django.db import models


class Framework(models.Model):
    """Regulatory compliance framework (ISO 27001, GDPR, etc.)"""

    name = models.CharField(max_length=100)
    version = models.CharField(max_length=20)
    description = models.TextField()
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
