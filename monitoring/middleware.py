import time
import json
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.db import OperationalError
from .models import APILog, UserActivity

User = get_user_model()


class APILoggerMiddleware(MiddlewareMixin):
    """
    Middleware to log API requests
    """
    def process_request(self, request):
        request.start_time = time.time()

        # Store request body early before it gets consumed by views
        try:
            request.stored_body = request.body.decode('utf-8') if request.body else ''
        except UnicodeDecodeError:
            request.stored_body = str(request.body)

        return None

    def process_response(self, request, response):
        # Calculate response time
        if hasattr(request, 'start_time'):
            response_time = time.time() - request.start_time
        else:
            response_time = None

        # Skip logging for static files and admin panel
        if request.path.startswith('/static/') or request.path.startswith('/admin/'):
            return response

        # Get user if authenticated
        user = getattr(request, 'user', None)
        if user and not user.is_anonymous:
            user_obj = user
        else:
            user_obj = None

        # Get IP address
        ip_address = self.get_client_ip(request)

        # Get request body from stored value
        request_body = getattr(request, 'stored_body', '')

        # Get response body (only for certain status codes to avoid large payloads)
        response_body = ''
        if response.status_code >= 400:  # Only log response for error cases
            try:
                if hasattr(response, 'data'):  # DRF Response
                    response_body = json.dumps(response.data)
                else:
                    response_body = response.content.decode('utf-8')
            except Exception:
                response_body = ''

        # Create log entry - wrap in try-except to handle missing table gracefully
        try:
            APILog.objects.create(
                user=user_obj,
                endpoint=request.path,
                method=request.method,
                status_code=response.status_code,
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                response_time=response_time,
                request_body=request_body[:1000],  # Limit to 1000 chars
                response_body=response_body[:1000],  # Limit to 1000 chars
            )
        except OperationalError:
            # Silently ignore if the table doesn't exist yet
            pass

        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserActivityMiddleware(MiddlewareMixin):
    """
    Middleware to track user activities
    """
    def process_response(self, request, response):
        if hasattr(request, 'user') and request.user.is_authenticated:
            # Define actions to track
            tracked_actions = {
                'POST': ['auth/register/', 'auth/login/', 'auth/logout/', 'auth/profile/', 'auth/password/change/'],
                'PUT': ['auth/profile/'],
                'PATCH': ['auth/profile/'],
            }

            # Check if this request should be tracked
            should_track = False
            for method, endpoints in tracked_actions.items():
                if request.method == method:
                    for endpoint in endpoints:
                        if endpoint in request.path:
                            should_track = True
                            break
                    if should_track:
                        break

            if should_track:
                # Determine action based on endpoint
                action = f"{request.method} {request.path}"

                # Get IP address
                ip_address = self.get_client_ip(request)

                # Create activity log - wrap in try-except to handle missing table gracefully
                try:
                    UserActivity.objects.create(
                        user=request.user,
                        action=action,
                        ip_address=ip_address,
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    )
                except OperationalError:
                    # Silently ignore if the table doesn't exist yet
                    pass

        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip