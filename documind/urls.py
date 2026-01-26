from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# Schema view configuration
schema_view = get_schema_view(
    openapi.Info(
        title="DocuMind API",
        default_version='v1',
        description="Intelligent Document Search & Q&A Assistant API Documentation",
        terms_of_service="https://www.documind.ai/terms/",
        contact=openapi.Contact(email="support@documind.ai"),
        license=openapi.License(name="Proprietary License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/', include('api.v1.urls')),  # API version 1

    # API Schema and Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),

    # API Documentation
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', 
        schema_view.without_ui(cache_timeout=0), 
        name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), 
        name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), 
        name='schema-redoc'),

    # Monitoring and logging endpoints
    path('monitoring/', include('monitoring.urls')),

    # Optional: For Django REST Framework browsable API
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
