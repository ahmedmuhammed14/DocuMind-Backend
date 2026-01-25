from django.urls import path, include
from .views import auth, admin

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', auth.register_view, name='register'),
    path('auth/login/', auth.login_view, name='login'),
    path('auth/logout/', auth.logout_view, name='logout'),

    # Email verification endpoints
    path('auth/verify-email/', auth.verify_email_view, name='verify_email'),
    path('auth/resend-verification/', auth.resend_verification_view, name='resend_verification'),

    # User profile endpoints
    path('auth/profile/', auth.user_profile_view, name='user_profile'),

    # Password management endpoints
    path('auth/password/reset/', auth.password_reset_view, name='password_reset'),
    path('auth/password/reset/confirm/', auth.password_reset_confirm_view, name='password_reset_confirm'),
    path('auth/password/change/', auth.password_change_view, name='password_change'),

    # Admin user management endpoints
    path('admin/users/', admin.list_users_view, name='admin_list_users'),
    path('admin/users/<uuid:user_id>/', admin.get_user_detail_view, name='admin_get_user'),
    path('admin/users/<uuid:user_id>/update/', admin.update_user_view, name='admin_update_user'),
    path('admin/users/<uuid:user_id>/delete/', admin.delete_user_view, name='admin_delete_user'),
    path('admin/users/<uuid:user_id>/reset-password/', admin.admin_password_reset_view, name='admin_reset_password'),

    # Add other API v1 endpoints here as needed
]