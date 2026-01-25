from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()


class APILog(models.Model):
    """
    Model to store API request logs
    """
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    endpoint = models.CharField(max_length=200)
    method = models.CharField(max_length=10)
    status_code = models.IntegerField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    response_time = models.FloatField(null=True, blank=True)  # in seconds
    request_body = models.TextField(blank=True)
    response_body = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'API Log'
        verbose_name_plural = 'API Logs'

    def __str__(self):
        return f"{self.method} {self.endpoint} - {self.status_code}"


class SystemHealth(models.Model):
    """
    Model to store system health metrics
    """
    service_name = models.CharField(max_length=100)
    status = models.CharField(max_length=20)  # healthy, warning, critical
    details = models.TextField(blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    cpu_usage = models.FloatField(null=True, blank=True)
    memory_usage = models.FloatField(null=True, blank=True)
    disk_usage = models.FloatField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'System Health'
        verbose_name_plural = 'System Health'

    def __str__(self):
        return f"{self.service_name} - {self.status}"


class UserActivity(models.Model):
    """
    Model to track user activities
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=100)
    details = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    user_agent = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'User Activity'
        verbose_name_plural = 'User Activities'

    def __str__(self):
        return f"{self.user.email} - {self.action}"