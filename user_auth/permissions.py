"""
DRF Permission classes for operation-based access control.

Usage in DRF views:
    class ThreatListView(APIView):
        authentication_classes = [CookieTokenAuthentication]
        permission_classes = [require_operation('account:threats:read')]

    # Multiple operations (AND logic — all must be present):
    permission_classes = [require_operation('tenant:scans:read'), require_operation('account:assets:read')]
"""
from rest_framework.permissions import BasePermission


class IsCSPMAuthenticated(BasePermission):
    """Checks that the request is authenticated (auth_context is set)."""
    message = 'Authentication required.'

    def has_permission(self, request, view):
        return bool(
            request.user
            and not request.user.is_anonymous
            and getattr(request, 'auth_context', None) is not None
        )


def require_operation(operation_key: str):
    """
    Factory that returns a DRF permission class requiring a specific operation.

    Example:
        permission_classes = [require_operation('account:threats:read')]
    """
    class _HasOperation(BasePermission):
        message = f'Operation required: {operation_key}'

        def has_permission(self, request, view):
            auth_context = getattr(request, 'auth_context', None)
            if not auth_context:
                return False
            return operation_key in auth_context.get('permissions', [])

    _HasOperation.__name__ = f'HasOperation[{operation_key}]'
    return _HasOperation


def require_any_operation(*operation_keys: str):
    """
    Factory that returns a DRF permission class requiring ANY of the given operations (OR logic).

    Example:
        permission_classes = [require_any_operation('platform:orgs:read', 'org:tenants:read')]
    """
    class _HasAnyOperation(BasePermission):
        message = f'One of these operations required: {", ".join(operation_keys)}'

        def has_permission(self, request, view):
            auth_context = getattr(request, 'auth_context', None)
            if not auth_context:
                return False
            user_perms = set(auth_context.get('permissions', []))
            return bool(user_perms.intersection(operation_keys))

    _HasAnyOperation.__name__ = f'HasAnyOperation[{"|".join(operation_keys)}]'
    return _HasAnyOperation


class IsPlatformAdmin(BasePermission):
    """Allows access only to platform-level admins (level 1)."""
    message = 'Platform admin access required.'

    def has_permission(self, request, view):
        auth_context = getattr(request, 'auth_context', None)
        if not auth_context:
            return False
        perms = auth_context.get('permissions', [])
        return any(p.startswith('platform:') for p in perms)


class TenantScopePermission(BasePermission):
    """
    Validates that the tenant_id in the request is within the user's allowed scope.
    Add this alongside require_operation for tenant-scoped endpoints.
    """
    message = 'Access to this tenant is not permitted.'

    def has_permission(self, request, view):
        auth_context = getattr(request, 'auth_context', None)
        if not auth_context:
            return False

        scope = auth_context.get('scope', {})

        # Platform admin: unrestricted
        if scope.get('org_ids') is None and scope.get('tenant_ids') is None:
            return True

        tenant_id = (
            request.GET.get('tenant_id')
            or (request.data.get('tenant_id') if hasattr(request, 'data') else None)
            or view.kwargs.get('tenant_id')
        )

        if not tenant_id:
            return True  # No tenant specified — let endpoint validate

        allowed_tenants = scope.get('tenant_ids')
        if allowed_tenants is None:
            return True  # All tenants allowed within org scope

        return tenant_id in allowed_tenants
