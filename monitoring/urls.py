from django.urls import path
from . import views

urlpatterns = [
    path('health/', views.system_health_view, name='system_health'),
    path('logs/', views.api_logs_view, name='api_logs'),
    path('activities/', views.user_activity_view, name='user_activities'),
    path('dashboard/', views.dashboard_stats_view, name='dashboard_stats'),
]