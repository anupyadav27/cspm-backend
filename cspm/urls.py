from django.urls import path, include
from cspm.health import health_check

urlpatterns = [
    path('health', health_check, name='health'),
    path('api/auth/', include("user_auth.urls")),
    path('api/', include("tenant_management.urls")),
    path('api/', include("assets_management.urls")),
    path('api/', include("threats_management.urls"))
]
