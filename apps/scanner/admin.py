from django.contrib import admin
from .models import ScanTask, ApprovedTargetRange


@admin.register(ScanTask)
class ScanTaskAdmin(admin.ModelAdmin):
    list_display = ['name', 'target', 'status', 'framework', 'created_by', 'created_at']
    list_filter = ['status', 'framework']
    search_fields = ['name', 'target']
    readonly_fields = ['gvm_task_id', 'gvm_target_id', 'gvm_report_id', 'raw_report_xml', 'created_at', 'started_at', 'completed_at']


@admin.register(ApprovedTargetRange)
class ApprovedTargetRangeAdmin(admin.ModelAdmin):
    list_display = ['cidr', 'description', 'created_by', 'created_at']
    search_fields = ['cidr', 'description']
