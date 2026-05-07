# ---
# LOCATION : apps/reports/urls.py
# PURPOSE  : URL patterns for report listing and secure file downloads.
#            Included by omnigov/urls.py under the '/reports/' prefix.
#
# CONNECTS TO:
#   - omnigov/urls.py            → includes this file under the 'reports' namespace
#   - apps/reports/views.py      → ReportListView and ReportDownloadView defined here
#   - apps/reports/models.py     → Report model whose files are served via the download view
# ---
from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    # /reports/ — shows all generated reports the user has permission to see.
    path('', views.ReportListView.as_view(), name='report-list'),
    # /reports/<pk>/download/ — serves the PDF or CSV file as an attachment
    #   after verifying the requesting user owns the parent scan.
    path('<int:pk>/download/', views.ReportDownloadView.as_view(), name='report-download'),
]
