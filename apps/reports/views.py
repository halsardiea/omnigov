import logging

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import FileResponse, Http404
from django.views.generic import ListView, View

from .models import Report

logger = logging.getLogger(__name__)


class ReportListView(LoginRequiredMixin, ListView):
    model = Report
    template_name = 'reports/report_list.html'
    context_object_name = 'reports'

    def get_queryset(self):
        return Report.objects.select_related('scan_task', 'scan_task__framework').order_by('-generated_at')


class ReportDownloadView(LoginRequiredMixin, View):
    def get(self, request, pk):
        try:
            report = Report.objects.get(pk=pk)
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
        return response
