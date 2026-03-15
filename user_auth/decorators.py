"""
Decorators for operation-based access control on Django views (non-DRF).

Usage:

    # Single operation
    @has_operations('account:threats:read')
    def my_view(request):
        ...

    # Multiple operations (AND logic — all required)
    @has_operations('tenant:scans:read', 'tenant:scans:execute')
    def trigger_scan(request):
        ...

    # On class-based views — decorate dispatch() or specific HTTP methods:
    class MyView(View):
        @method_decorator(has_operations('account:threats:read'))
        def get(self, request, *args, **kwargs):
            ...
"""
import logging
from functools import wraps
from django.http import JsonResponse

logger = logging.getLogger(__name__)


def _auth_error(message, status_code):
    return JsonResponse(
        {'success': False, 'message': message, 'data': None, 'pagination': None},
        status=status_code
    )


def has_operations(*operation_keys, match='all'):
    """
    Decorator that checks if the authenticated user has the required operations.

    Args:
        *operation_keys: one or more operation key strings to check.
        match: 'all' (default) = all keys required | 'any' = at least one required.

    The request must have been processed by CookieTokenAuthentication first
    (i.e., auth_context must be attached to the request).
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            auth_context = getattr(request, 'auth_context', None)
            if not auth_context:
                return _auth_error('Authentication required.', 401)

            user_perms = set(auth_context.get('permissions', []))

            if match == 'all':
                missing = [k for k in operation_keys if k not in user_perms]
                if missing:
                    logger.warning(
                        "Access denied for user %s — missing operations: %s",
                        auth_context.get('email'), missing
                    )
                    return _auth_error(
                        f'Permission denied. Required operations: {", ".join(missing)}',
                        403
                    )
            elif match == 'any':
                if not user_perms.intersection(operation_keys):
                    return _auth_error(
                        f'Permission denied. Requires one of: {", ".join(operation_keys)}',
                        403
                    )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def authenticated(view_func):
    """Simple decorator — just requires authentication (no operation check)."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        auth_context = getattr(request, 'auth_context', None)
        if not auth_context:
            return _auth_error('Authentication required.', 401)
        return view_func(request, *args, **kwargs)
    return wrapper


def platform_admin_required(view_func):
    """Allows only platform admins (users with any platform: permission)."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        auth_context = getattr(request, 'auth_context', None)
        if not auth_context:
            return _auth_error('Authentication required.', 401)
        perms = auth_context.get('permissions', [])
        if not any(p.startswith('platform:') for p in perms):
            return _auth_error('Platform admin access required.', 403)
        return view_func(request, *args, **kwargs)
    return wrapper
