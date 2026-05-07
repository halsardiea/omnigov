# ---
# LOCATION : apps/compliance/urls.py
# PURPOSE  : URL patterns for the compliance framework catalogue.
#            Included by omnigov/urls.py under the '/compliance/' prefix.
#
# CONNECTS TO:
#   - omnigov/urls.py              → includes this file under the 'compliance' namespace
#   - apps/compliance/views.py     → FrameworkListView, FrameworkDetailView, load_fixtures
#   - apps/compliance/corpus.py    → load_fixtures view triggers corpus loading
# ---
from django.urls import path
from . import views

app_name = 'compliance'

urlpatterns = [
    # /compliance/ — lists all active frameworks and their control counts.
    path('', views.FrameworkListView.as_view(), name='framework-list'),
    # /compliance/<pk>/ — shows the full control catalogue for one framework.
    path('<int:pk>/', views.FrameworkDetailView.as_view(), name='framework-detail'),
    # /compliance/load-fixtures/ — admin-only POST that imports all framework
    #   corpora from local JSON files into the database.
    path('load-fixtures/', views.load_fixtures, name='load-fixtures'),
]
