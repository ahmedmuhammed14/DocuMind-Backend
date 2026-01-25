from django.urls import path, include
from .views import auth

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', auth.register_view, name='register'),
    path('auth/login/', auth.login_view, name='login'),
    path('auth/logout/', auth.logout_view, name='logout'),

    # Password management endpoints
    path('auth/password/reset/', auth.password_reset_view, name='password_reset'),
    path('auth/password/reset/confirm/', auth.password_reset_confirm_view, name='password_reset_confirm'),
    path('auth/password/change/', auth.password_change_view, name='password_change'),

    # Add other API v1 endpoints here as needed
]