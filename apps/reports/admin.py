from django.contrib import admin
from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['scan_task', 'report_type', 'format', 'compliance_score', 'findings_count', 'generated_at']
    list_filter = ['report_type', 'format']
    readonly_fields = ['generated_at']
