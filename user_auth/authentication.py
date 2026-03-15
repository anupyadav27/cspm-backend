"""
CookieTokenAuthentication — DRF authentication backend.

Flow:
1. Extract access_token from HTTP-only cookie
2. Use token_hint (first 8 chars) for indexed DB lookup
3. Verify full token hash (PBKDF2)
4. Read permissions_cache + scope_cache from session row
5. Attach auth_context to request (zero extra DB queries at runtime)
"""
import logging
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import UserSessions
from .utils.auth_utils import verify_token

logger = logging.getLogger(__name__)


class CookieTokenAuthentication(BaseAuthentication):
    """
    Authenticates requests using the access_token HTTP-only cookie.
    Sets request.auth_context with user info + cached permissions + scope.
    """

    def authenticate(self, request):
        token = request.COOKIES.get('access_token')
        if not token:
            return None

        token_hint = token[:8]

        try:
            sessions = UserSessions.objects.filter(
                token_hint=token_hint,
                revoked=False,
                expires_at__gt=timezone.now(),
            ).select_related('user')
        except Exception as exc:
            logger.error("Session DB lookup failed: %s", exc)
            return None

        for session in sessions:
            if verify_token(token, session.token):
                auth_context = _build_auth_context(session)
                request.auth_context = auth_context
                return (session.user, session)

        return None

    def authenticate_header(self, request):
        return 'Cookie realm="api"'


def _build_auth_context(session):
    """Build auth context dict from a valid session."""
    return {
        'user_id': str(session.user.id),
        'email': session.user.email,
        'first_name': session.user.first_name,
        'last_name': session.user.last_name,
        'permissions': session.permissions_cache or [],
        'scope': session.scope_cache or {
            'org_ids': None,
            'tenant_ids': None,
            'account_ids': None,
        },
        'session_id': str(session.id),
        'login_method': session.login_method,
    }


def resolve_user_permissions(user):
    """
    Resolve all operation keys for a user across all their roles.
    Used at login time to populate permissions_cache.
    Returns a sorted list of unique operation key strings.
    """
    from .models import UserRoles, RoleOperations, RolePermissions

    keys = set()

    role_ids = UserRoles.objects.filter(user=user).values_list('role_id', flat=True)

    # New: RoleOperations
    op_keys = RoleOperations.objects.filter(
        role_id__in=role_ids
    ).select_related('operation').values_list('operation__key', flat=True)
    keys.update(op_keys)

    # Legacy: RolePermissions
    perm_keys = RolePermissions.objects.filter(
        role_id__in=role_ids
    ).select_related('permission').values_list('permission__key', flat=True)
    keys.update(perm_keys)

    return sorted(keys)


def resolve_user_scope(user):
    """
    Resolve org/tenant/account access scope for a user.
    platform_admin has None scope = unrestricted.
    Returns dict: {org_ids, tenant_ids, account_ids}
    """
    from .models import UserRoles, UserAdminScope

    PLATFORM_ADMIN_LEVEL = 1
    ORG_ADMIN_LEVEL = 2

    user_role_rows = UserRoles.objects.filter(user=user).select_related('role')
    min_level = min((ur.role.level for ur in user_role_rows), default=5)

    # Platform admin = unrestricted
    if min_level <= PLATFORM_ADMIN_LEVEL:
        return {'org_ids': None, 'tenant_ids': None, 'account_ids': None}

    # Org admin: get their org scope
    if min_level <= ORG_ADMIN_LEVEL:
        org_ids = list(
            UserAdminScope.objects.filter(
                user=user, scope_type='org'
            ).values_list('scope_id', flat=True)
        )
        return {'org_ids': org_ids or None, 'tenant_ids': None, 'account_ids': None}

    # Tenant/Account admin
    tenant_ids = list(
        UserRoles.objects.filter(
            user=user, role__scope_level='tenant'
        ).exclude(tenant_id=None).values_list('tenant_id', flat=True)
    )
    tenant_scope_ids = list(
        UserAdminScope.objects.filter(
            user=user, scope_type='tenant'
        ).values_list('scope_id', flat=True)
    )
    tenant_ids = list(set(tenant_ids + tenant_scope_ids)) or None

    account_ids = list(
        UserAdminScope.objects.filter(
            user=user, scope_type='account'
        ).values_list('scope_id', flat=True)
    ) or None

    return {
        'org_ids': None,
        'tenant_ids': tenant_ids,
        'account_ids': account_ids,
    }
