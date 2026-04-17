from django.contrib import admin
from .models import TechnicalFinding


@admin.register(TechnicalFinding)
class TechnicalFindingAdmin(admin.ModelAdmin):
    list_display = ['name', 'severity', 'cvss_score', 'host', 'scan_task', 'created_at']
    list_filter = ['severity', 'scan_task__status']
    search_fields = ['name', 'cve_ids', 'description']
    readonly_fields = ['created_at']
