# ---
# LOCATION : apps/scanner/admin.py
# PURPOSE  : Registers scanner models with Django's admin panel so administrators
#            can inspect scan jobs and manage the approved IP allowlist without
#            touching the database directly.
#
# CONNECTS TO:
#   - apps/scanner/models.py      → ScanTask and ApprovedTargetRange registered here
#   - apps/scanner/views.py       → ScanCreateForm validates targets against
#                                    ApprovedTargetRange rows created in this admin
#   - omnigov/urls.py             → /admin/ route gives access to this panel
# ---
from django.contrib import admin
from .models import ScanTask, ApprovedTargetRange


# Provides a readable scan overview in the admin — useful for support and audit.
# GVM IDs and raw XML are read-only to prevent accidental corruption of live scan data.
@admin.register(ScanTask)
class ScanTaskAdmin(admin.ModelAdmin):
    list_display = ['name', 'target', 'status', 'framework', 'created_by', 'created_at']
    list_filter = ['status', 'framework']
    search_fields = ['name', 'target']
    readonly_fields = ['gvm_task_id', 'gvm_target_id', 'gvm_report_id', 'raw_report_xml', 'created_at', 'started_at', 'completed_at']


@admin.register(ApprovedTargetRange)
class ApprovedTargetRangeAdmin(admin.ModelAdmin):
    # Admins define which IP ranges are allowed to be scanned.
    # Any scan target submitted by a user must fall inside one of these ranges.
    list_display = ['cidr', 'description', 'created_by', 'created_at']
    search_fields = ['cidr', 'description']
