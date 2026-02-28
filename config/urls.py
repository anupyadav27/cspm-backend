
from django.urls import path, include
urlpatterns = [
    path('api/auth/', include("user_auth.urls")),
    path('api/', include("tenant_management.urls")),

]
