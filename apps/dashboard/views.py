from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

from apps.scanner.models import ScanTask
from apps.interceptor.models import TechnicalFinding
from apps.reports.models import Report


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'dashboard/home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Recent scans
        context['recent_scans'] = ScanTask.objects.select_related(
            'created_by', 'framework',
        ).order_by('-created_at')[:5]

        # Summary stats
        context['total_scans'] = ScanTask.objects.count()
        context['active_scans'] = ScanTask.objects.filter(status__in=['running', 'pending', 'analyzing']).count()
        context['total_findings'] = TechnicalFinding.objects.count()
        context['high_findings'] = TechnicalFinding.objects.filter(severity='High').count()
        context['critical_findings'] = TechnicalFinding.objects.filter(severity='Critical').count()
        context['recent_reports'] = Report.objects.select_related('scan_task').order_by('-generated_at')[:5]

        return context
