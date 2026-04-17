from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('', views.ReportListView.as_view(), name='report-list'),
    path('<int:pk>/download/', views.ReportDownloadView.as_view(), name='report-download'),
]
