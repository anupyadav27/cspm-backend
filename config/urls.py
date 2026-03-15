from django.urls import path, include
from config.health import health_check

urlpatterns = [
    # ── System ───────────────────────────────────────────────────────────────
    path('health', health_check, name='health'),

    # ── Authentication & User Management (auth portal) ───────────────────────
    path('api/auth/', include('user_auth.urls')),

    # ── Tenant Management ─────────────────────────────────────────────────────
    path('api/', include('tenant_management.urls')),

    # ── Onboarding / Cloud Accounts (existing views) ──────────────────────────
    path('api/onboarding/', include('onboarding_management.urls')),

    # ── Engine Proxies ────────────────────────────────────────────────────────
    # All engine proxy routes are under /api/engines/
    # Examples:
    #   GET /api/engines/inventory/assets/
    #   GET /api/engines/threat/threats/
    #   POST /api/engines/compliance/generate/
    path('api/engines/', include('engines.urls')),

    # ── Audit Logs ────────────────────────────────────────────────────────────
    path('api/audit-logs/', include('audit_logs.urls')),
]
