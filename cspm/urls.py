
from django.urls import path, include
urlpatterns = [
    path('api/auth/', include("user_auth.urls")),
    path('api/', include("tenant_management.urls")),
    path('api/', include("assets_management.urls")),
    path('api/', include("threats_management.urls"))
]
