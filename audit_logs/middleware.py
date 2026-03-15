"""
Audit log middleware.
Automatically records significant API actions in the audit_logs table.

We skip logging for:
- GET requests on most read-only paths (too noisy)
- Health checks
- Static/media files
- CSRF token requests

We always log:
- All POST/PUT/PATCH/DELETE requests
- Auth events (login, logout, refresh)
"""
import logging
from .models import AuditLog

logger = logging.getLogger(__name__)

# Paths to skip entirely
SKIP_PATHS = {'/health', '/favicon.ico', '/static/', '/media/'}

# Path prefixes that indicate auth events
AUTH_PATHS = {
    '/api/auth/login': ('login', 'session', None),
    '/api/auth/logout': ('logout', 'session', None),
    '/api/auth/refresh': ('token_refresh', 'session', None),
    '/api/auth/invite': ('invite', 'user', None),
    '/api/auth/invite/accept': ('invite_accept', 'user', None),
    '/api/auth/change-password': ('change_password', 'user', None),
}


def _infer_action(method, path):
    """Infer action_type and resource_type from HTTP method + path."""
    # Auth-specific paths
    for prefix, (action, resource, _) in AUTH_PATHS.items():
        if path.startswith(prefix):
            return action, resource

    method_map = {
        'POST': 'create',
        'PUT': 'update',
        'PATCH': 'update',
        'DELETE': 'delete',
        'GET': 'read',
    }
    action = method_map.get(method, 'unknown')

    # Infer resource type from path segments
    segments = [s for s in path.strip('/').split('/') if s]
    resource = 'unknown'
    if len(segments) >= 2:
        resource = segments[1]  # e.g., /api/auth/users/ → 'users'
    elif len(segments) >= 1:
        resource = segments[0]

    return action, resource


class AuditLogMiddleware:
    """
    Django middleware that writes an AuditLog row after each significant request.
    Must be placed after AuthenticationMiddleware in MIDDLEWARE list.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Skip noisy paths
        path = request.path
        if any(path.startswith(p) for p in SKIP_PATHS):
            return response

        # Skip CSRF-only GET requests
        if request.method == 'GET' and path == '/api/auth/csrf/':
            return response

        # Only log mutating requests + auth events
        should_log = request.method in ('POST', 'PUT', 'PATCH', 'DELETE')

        # Also log GET for auth paths (login, logout, etc.)
        if not should_log and path.startswith('/api/auth/') and request.method == 'GET':
            if path.rstrip('/') in {'/api/auth/me', '/api/auth/sessions'}:
                should_log = False  # Too noisy
            else:
                should_log = True

        if not should_log:
            return response

        self._write_log(request, response)
        return response

    def _write_log(self, request, response):
        try:
            auth_ctx = getattr(request, 'auth_context', None)
            user = getattr(request, 'user', None)
            user_id = None
            user_email = None

            if auth_ctx:
                user_id = auth_ctx.get('user_id')
                user_email = auth_ctx.get('email')
            elif user and not getattr(user, 'is_anonymous', True):
                user_id = str(user.id)
                user_email = user.email

            action_type, resource_type = _infer_action(request.method, request.path)

            status = 'success'
            if response.status_code == 401:
                status = 'denied'
            elif response.status_code == 403:
                status = 'denied'
            elif response.status_code >= 400:
                status = 'failure'

            AuditLog.objects.create(
                user_id=user_id,
                user_email=user_email,
                action_type=action_type,
                resource_type=resource_type,
                tenant_id=request.GET.get('tenant_id') or request.POST.get('tenant_id'),
                status=status,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:512],
                request_method=request.method,
                request_path=request.path[:500],
                response_status=response.status_code,
                details={},
            )
        except Exception as exc:
            # Audit log failure must NEVER block the response
            logger.error("AuditLog write failed: %s", exc)

    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        # Validate
        if ip:
            try:
                from django.db.models import GenericIPAddressField
                import socket
                socket.inet_aton(ip)
                return ip
            except Exception:
                return None
        return None
