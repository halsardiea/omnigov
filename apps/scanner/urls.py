# ---
# LOCATION : apps/scanner/urls.py
# PURPOSE  : URL patterns for every scan-related page and API endpoint.
#            Included by omnigov/urls.py under the '/scanner/' prefix.
#
# CONNECTS TO:
#   - omnigov/urls.py            → includes this file under the 'scanner' namespace
#   - apps/scanner/views.py      → all view classes mapped here
#   - apps/scanner/routing.py    → the parallel WebSocket URL table (ws/scan/<id>/)
#                                  handled by ASGI, not this HTTP router
# ---
from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    # /scanner/ — lists all scans the current user has access to.
    path('', views.ScanListView.as_view(), name='scan-list'),
    # /scanner/create/ — form to submit a new scan job.
    path('create/', views.ScanCreateView.as_view(), name='scan-create'),
    # /scanner/<pk>/status/ — polled by the detail page to refresh progress
    #                          before the WebSocket connection is established.
    path('<int:pk>/status/', views.ScanStatusView.as_view(), name='scan-status'),
    # /scanner/<pk>/ — the full scan detail page: findings, reports, live progress.
    path('<int:pk>/', views.ScanDetailView.as_view(), name='scan-detail'),
    # /scanner/<pk>/stop/ — POST-only endpoint to request a running scan be halted.
    path('<int:pk>/stop/', views.ScanStopView.as_view(), name='scan-stop'),
]
