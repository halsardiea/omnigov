# ---
# LOCATION : apps/dashboard/urls.py
# PURPOSE  : Maps the application root URL (/) to the dashboard home page.
#            This is the first page a user sees after login.
#            Included by omnigov/urls.py under the '' (empty) prefix.
#
# CONNECTS TO:
#   - omnigov/urls.py            → includes this file last so it catches '/'
#   - apps/dashboard/views.py    → DashboardView assembles the KPI summary page
#   - omnigov/settings/base.py   → LOGIN_REDIRECT_URL = '/' points here
# ---
from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    # The root URL — renders the KPI dashboard with scan counts, finding
    # severity totals, and recent activity for the logged-in user.
    path('', views.DashboardView.as_view(), name='home'),
]
