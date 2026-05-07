# ---
# LOCATION : omnigov/urls.py
# PURPOSE  : The project-level URL router — every HTTP request enters here first
#            and is delegated to the appropriate app's own urls.py.
#            Deleting this file would make every URL in the application return 404.
#
# CONNECTS TO:
#   - apps/accounts/urls.py    → /accounts/login/, /accounts/profile/, /accounts/logout/
#   - apps/scanner/urls.py     → /scanner/, /scanner/create/, /scanner/<pk>/
#   - apps/compliance/urls.py  → /compliance/, /compliance/<pk>/
#   - apps/reports/urls.py     → /reports/, /reports/<pk>/download/
#   - apps/dashboard/urls.py   → / (root — the dashboard home page)
#   - omnigov/settings/base.py → ROOT_URLCONF points here; MEDIA_ROOT / STATIC_ROOT
#                                 used for dev file serving below
# ---
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # Django admin panel — only staff/superuser accounts can access this.
    path('admin/', admin.site.urls),
    # Authentication: login, logout, profile editing.
    path('accounts/', include('apps.accounts.urls', namespace='accounts')),
    # Scan management: create, view, stop, and poll progress.
    path('scanner/', include('apps.scanner.urls', namespace='scanner')),
    # Compliance framework catalogue and control browser.
    path('compliance/', include('apps.compliance.urls', namespace='compliance')),
    # Generated report list and secure file download.
    path('reports/', include('apps.reports.urls', namespace='reports')),
    # Dashboard home page — binds the root URL '' to avoid a blank landing page.
    path('', include('apps.dashboard.urls', namespace='dashboard')),
]

# In development Django serves uploaded report files (PDFs, CSVs) and static
# assets directly. In production Nginx handles this instead — see nginx/conf.d/.
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
