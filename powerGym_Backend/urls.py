from django.contrib import admin
from django.conf.urls.static import static 
from django.conf import settings
from django.urls import path, include
from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
   openapi.Info(
      title="PowerGym API",
      default_version='v0',
      description="API Documentation",
    #   terms_of_service="https://www.google.com/policies/terms/",
    #   contact=openapi.Contact(email="contact@snippets.local"),
    #   license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.DjangoModelPermissionsOrAnonReadOnly,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('powerGym_app.urls')),
    path('apidoc/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

