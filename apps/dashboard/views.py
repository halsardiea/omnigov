# ---
# LOCATION : apps/dashboard/views.py
# PURPOSE  : Builds the KPI summary page shown immediately after login.
#            This is the first page every user sees — it aggregates scan counts,
#            finding severity totals, and recent activity into a single context
#            that the dashboard template renders as a stats grid.
#
# CONNECTS TO:
#   - apps/accounts/access.py      → user_can_manage_scans() controls whether the
#                                     'Start Scan' button is shown on the dashboard;
#                                     user_can_view_all_data() determines data scope
#   - apps/scanner/models.py       → ScanTask queryset — scoped to user or all
#   - apps/interceptor/models.py   → TechnicalFinding queryset for severity counts
#   - apps/reports/models.py       → Report queryset for the recent-reports panel
#   - apps/dashboard/urls.py       → maps '/' to this view
#   - templates/dashboard/home.html → template that consumes the context built here
# ---
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

from apps.accounts.access import user_can_manage_scans, user_can_view_all_data
from apps.scanner.models import ScanTask
from apps.interceptor.models import TechnicalFinding
from apps.reports.models import Report


# The dashboard home — a read-only KPI page that summarises what the user
# (or all users, for a superuser) has scanned, found, and reported.
# LoginRequiredMixin redirects unauthenticated visitors to /accounts/login/.
class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'dashboard/home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Superusers see organisation-wide data; regular staff see only their own.
        # This scope decision is enforced by user_can_view_all_data() from access.py
        # so the rule lives in one place and is never duplicated.
        if user_can_view_all_data(self.request.user):
            scan_queryset = ScanTask.objects.select_related('created_by', 'framework').prefetch_related('selected_frameworks')
            findings_queryset = TechnicalFinding.objects.all()
            report_queryset = Report.objects.select_related('scan_task', 'scan_task__framework')
            context['scan_scope_label'] = 'all scans'
            context['findings_scope_label'] = 'Across all scans'
        else:
            scan_queryset = ScanTask.objects.select_related('created_by', 'framework').prefetch_related('selected_frameworks').filter(created_by=self.request.user)
            findings_queryset = TechnicalFinding.objects.filter(scan_task__created_by=self.request.user)
            report_queryset = Report.objects.select_related('scan_task', 'scan_task__framework').filter(scan_task__created_by=self.request.user)
            context['scan_scope_label'] = 'your scans'
            context['findings_scope_label'] = 'Across your scans'

        # Recent scans panel — last 5 entries by creation date.
        context['recent_scans'] = scan_queryset.order_by('-created_at')[:5]

        # Summary stats — each value is a separate DB query but all are simple
        # COUNT aggregations that PostgreSQL / SQLite handle cheaply.
        context['total_scans'] = scan_queryset.count()
        # Active = any scan currently consuming scanner resources.
        context['active_scans'] = scan_queryset.filter(status__in=['running', 'pending', 'analyzing']).count()
        # Monitored targets = distinct CIDR ranges — shows network coverage breadth.
        context['monitored_targets'] = scan_queryset.values('target').distinct().count()
        context['total_findings'] = findings_queryset.count()
        context['high_findings'] = findings_queryset.filter(severity='High').count()
        context['critical_findings'] = findings_queryset.filter(severity='Critical').count()
        context['recent_reports'] = report_queryset.order_by('-generated_at')[:5]
        # Controls whether the 'Start Scan' action button appears on the dashboard.
        context['can_manage_scans'] = user_can_manage_scans(self.request.user)

        return context
