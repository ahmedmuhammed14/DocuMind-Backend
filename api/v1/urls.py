from django.urls import path, include
from .views import auth

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', auth.register_view, name='register'),
    path('auth/login/', auth.login_view, name='login'),
    path('auth/logout/', auth.logout_view, name='logout'),
    
    # Add other API v1 endpoints here as needed
]