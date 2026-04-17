from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    path('', views.ScanListView.as_view(), name='scan-list'),
    path('create/', views.ScanCreateView.as_view(), name='scan-create'),
    path('<int:pk>/', views.ScanDetailView.as_view(), name='scan-detail'),
    path('<int:pk>/stop/', views.ScanStopView.as_view(), name='scan-stop'),
]
