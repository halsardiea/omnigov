from django.urls import path
from . import views

app_name = 'compliance'

urlpatterns = [
    path('', views.FrameworkListView.as_view(), name='framework-list'),
    path('<int:pk>/', views.FrameworkDetailView.as_view(), name='framework-detail'),
    path('load-fixtures/', views.load_fixtures, name='load-fixtures'),
]
