from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from datetime import timedelta
from .models import APILog, SystemHealth, UserActivity
from django.contrib.auth import get_user_model
from django.db.models import Count, Avg
import psutil
import platform

User = get_user_model()


@api_view(['GET'])
@permission_classes([IsAdminUser])
def system_health_view(request):
    """
    Get system health metrics
    """
    # Get system stats
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent
    disk_percent = psutil.disk_usage('/').percent
    
    # Determine overall status
    if cpu_percent > 80 or memory_percent > 80 or disk_percent > 80:
        overall_status = 'critical'
    elif cpu_percent > 60 or memory_percent > 60 or disk_percent > 60:
        overall_status = 'warning'
    else:
        overall_status = 'healthy'
    
    # Create or update system health record
    SystemHealth.objects.create(
        service_name='Main Server',
        status=overall_status,
        cpu_usage=cpu_percent,
        memory_usage=memory_percent,
        disk_usage=disk_percent,
        details=f"CPU: {cpu_percent}%, Memory: {memory_percent}%, Disk: {disk_percent}%"
    )
    
    return Response({
        'status': overall_status,
        'cpu_usage': cpu_percent,
        'memory_usage': memory_percent,
        'disk_usage': disk_percent,
        'server_info': {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.architecture()[0],
            'hostname': platform.node(),
            'processor': platform.processor(),
        }
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def api_logs_view(request):
    """
    Get API logs with filtering options
    """
    # Get query parameters
    days = int(request.GET.get('days', 7))  # Default to last 7 days
    status_code = request.GET.get('status_code')
    user_id = request.GET.get('user_id')
    
    # Filter logs
    end_date = timezone.now()
    start_date = end_date - timedelta(days=days)
    
    logs = APILog.objects.filter(timestamp__gte=start_date)
    
    if status_code:
        logs = logs.filter(status_code=status_code)
    
    if user_id:
        logs = logs.filter(user_id=user_id)
    
    # Paginate results
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('page_size', 50))
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    
    total_count = logs.count()
    logs = logs[start_idx:end_idx]
    
    # Format response
    log_data = []
    for log in logs:
        log_data.append({
            'id': log.id,
            'user': log.user.email if log.user else None,
            'endpoint': log.endpoint,
            'method': log.method,
            'status_code': log.status_code,
            'ip_address': log.ip_address,
            'timestamp': log.timestamp.isoformat(),
            'response_time': log.response_time,
        })
    
    return Response({
        'count': total_count,
        'results': log_data,
        'current_page': page,
        'total_pages': (total_count + page_size - 1) // page_size,
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def user_activity_view(request):
    """
    Get user activity logs with filtering options
    """
    # Get query parameters
    days = int(request.GET.get('days', 7))  # Default to last 7 days
    user_id = request.GET.get('user_id')
    action = request.GET.get('action')
    
    # Filter activities
    end_date = timezone.now()
    start_date = end_date - timedelta(days=days)
    
    activities = UserActivity.objects.filter(timestamp__gte=start_date)
    
    if user_id:
        activities = activities.filter(user_id=user_id)
    
    if action:
        activities = activities.filter(action__icontains=action)
    
    # Paginate results
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('page_size', 50))
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    
    total_count = activities.count()
    activities = activities[start_idx:end_idx]
    
    # Format response
    activity_data = []
    for activity in activities:
        activity_data.append({
            'id': activity.id,
            'user': activity.user.email,
            'action': activity.action,
            'details': activity.details,
            'ip_address': activity.ip_address,
            'timestamp': activity.timestamp.isoformat(),
        })
    
    return Response({
        'count': total_count,
        'results': activity_data,
        'current_page': page,
        'total_pages': (total_count + page_size - 1) // page_size,
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
def dashboard_stats_view(request):
    """
    Get dashboard statistics
    """
    # Get stats for the last 30 days
    end_date = timezone.now()
    start_date = end_date - timedelta(days=30)
    
    # API logs stats
    api_logs = APILog.objects.filter(timestamp__gte=start_date)
    total_requests = api_logs.count()
    successful_requests = api_logs.filter(status_code__lt=400).count()
    error_requests = api_logs.filter(status_code__gte=400).count()
    avg_response_time = api_logs.aggregate(avg_time=Avg('response_time'))['avg_time']
    
    # Status code distribution
    status_codes = api_logs.values('status_code').annotate(count=Count('status_code'))
    
    # User activity stats
    user_activities = UserActivity.objects.filter(timestamp__gte=start_date)
    total_activities = user_activities.count()
    
    # Active users
    active_users = User.objects.filter(last_login__gte=start_date).count()
    total_users = User.objects.count()
    
    return Response({
        'period_start': start_date.isoformat(),
        'period_end': end_date.isoformat(),
        'api_stats': {
            'total_requests': total_requests,
            'successful_requests': successful_requests,
            'error_requests': error_requests,
            'success_rate': (successful_requests / total_requests * 100) if total_requests > 0 else 0,
            'avg_response_time': avg_response_time,
            'status_codes': list(status_codes),
        },
        'user_stats': {
            'total_users': total_users,
            'active_users': active_users,
            'total_activities': total_activities,
        }
    })