# ---
# LOCATION : apps/reports/views.py
# PURPOSE  : Serves the generated report files to the user. Two responsibilities:
#            1. ReportListView — shows a summary table of all reports the user owns.
#            2. ReportDownloadView — delivers the actual PDF or CSV file as an
#               attachment after verifying the user has permission to access it.
#
# CONNECTS TO:
#   - apps/reports/models.py         → Report model — all queryset reads come from here
#   - apps/accounts/access.py        → user_can_view_all_data() and user_can_manage_scans()
#                                       scope the queryset and control UI permissions
#   - apps/reports/urls.py           → maps /reports/ and /reports/<pk>/download/ here
#   - apps/reports/tasks.py          → generates the Report rows and files consumed here
#   - omnigov/settings/base.py       → LOGGING dict routes security_logger events to
#                                       logs/security.log via the 'django.security' handler
# ---
import logging

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import FileResponse, Http404
from django.views.generic import ListView, View

from apps.accounts.access import user_can_manage_scans, user_can_view_all_data
from .models import Report

logger = logging.getLogger(__name__)

# Security audit events route to the dedicated security.log file
security_logger = logging.getLogger('django.security')


# Scopes the Report queryset to what the requesting user is allowed to see.
# Superusers see every report; regular users see only reports for scans they created.
# This filter is the single enforcement point for report-level data isolation.
def _report_queryset_for_user(user):
    queryset = Report.objects.select_related('framework', 'scan_task', 'scan_task__framework').order_by('-generated_at')
    if user_can_view_all_data(user):
        return queryset
    return queryset.filter(scan_task__created_by=user)


# Renders a summary table of all reports the user has access to.
# Annotates each report with a risk badge (Low/Moderate/High) based on its
# compliance_score so the user can quickly identify the most urgent items.
class ReportListView(LoginRequiredMixin, ListView):
    model = Report
    template_name = 'reports/report_list.html'
    context_object_name = 'reports'

    def get_queryset(self):
        return _report_queryset_for_user(self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        reports = list(context['reports'])
        for report in reports:
            report.risk_label, report.risk_badge_classes = self._risk_badge(report.compliance_score)

        executive_reports = [report for report in reports if report.report_type == Report.ReportType.EXECUTIVE]
        technical_reports = [report for report in reports if report.report_type == Report.ReportType.TECHNICAL]
        scored_reports = [report.compliance_score for report in reports if report.compliance_score is not None]

        context['reports'] = reports
        context['executive_reports'] = executive_reports
        context['technical_reports'] = technical_reports
        context['total_reports'] = len(reports)
        context['executive_count'] = len(executive_reports)
        context['technical_count'] = len(technical_reports)
        context['total_findings'] = sum(report.findings_count for report in reports)
        context['average_score'] = round(sum(scored_reports) / len(scored_reports), 1) if scored_reports else None
        context['can_manage_scans'] = user_can_manage_scans(self.request.user)
        return context

    @staticmethod
    def _risk_badge(score):
        if score is None:
            return (
                'Pending',
                'border-slate-400/20 bg-slate-400/10 text-slate-300',
            )
        if score >= 85:
            return (
                'Low',
                'border-green-400/20 bg-green-400/10 text-green-300',
            )
        if score >= 70:
            return (
                'Moderate',
                'border-amber-400/20 bg-amber-400/10 text-amber-300',
            )
        return (
            'High',
            'border-red-400/20 bg-red-400/10 text-red-300',
        )


# Serves the report file as a browser download.
# Uses _report_queryset_for_user() to confirm ownership before opening the file
# — a user who guesses a report PK they don't own receives a 404, not the file.
class ReportDownloadView(LoginRequiredMixin, View):
    def get(self, request, pk):
        try:
            report = _report_queryset_for_user(request.user).get(pk=pk)
        except Report.DoesNotExist:
            raise Http404

        if not report.file:
            raise Http404("Report file not found")

        content_type_map = {
            'pdf': 'application/pdf',
            'csv': 'text/csv',
        }
        content_type = content_type_map.get(report.format, 'application/octet-stream')
        filename = report.file.name.split('/')[-1]

        response = FileResponse(report.file.open('rb'), content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        # Log every download to the security audit trail for data-access accountability
        client_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', 'unknown'))
        security_logger.info(
            'Report %s (%s) downloaded by user %s from %s',
            pk, filename, request.user.id, client_ip,
        )
        return response
