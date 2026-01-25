from django.contrib import admin
from .models import APILog, SystemHealth, UserActivity


@admin.register(APILog)
class APILogAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'endpoint', 'method', 'status_code', 'timestamp', 'response_time', 'ip_address']
    list_filter = ['status_code', 'method', 'timestamp']
    search_fields = ['endpoint', 'user__email', 'ip_address']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(SystemHealth)
class SystemHealthAdmin(admin.ModelAdmin):
    list_display = ['service_name', 'status', 'cpu_usage', 'memory_usage', 'disk_usage', 'timestamp']
    list_filter = ['status', 'timestamp', 'service_name']
    readonly_fields = ['timestamp']


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'action', 'timestamp', 'ip_address']
    list_filter = ['action', 'timestamp']
    search_fields = ['user__email', 'action', 'ip_address']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'