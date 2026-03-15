"""
User management views.
GET  /api/auth/me/               — current user profile
PUT  /api/auth/me/               — update own profile
POST /api/auth/change-password/  — change own password
GET  /api/auth/users/            — list users (platform/org admin)
POST /api/auth/users/            — create user (platform admin)
GET  /api/auth/users/{id}/       — get user
PUT  /api/auth/users/{id}/       — update user
DEL  /api/auth/users/{id}/       — deactivate user
GET  /api/auth/users/{id}/roles/ — get user's roles
GET  /api/auth/sessions/         — list own sessions
DEL  /api/auth/sessions/{id}/    — revoke a session
"""
import json
import logging
from django.http import JsonResponse
from django.views import View
from django.utils import timezone

from user_auth.authentication import CookieTokenAuthentication
from user_auth.models import Users, UserSessions, UserRoles
from user_auth.serializers import (
    UserPublicSerializer, UserCreateSerializer, UserUpdateSerializer,
    ChangePasswordSerializer
)
from user_auth.decorators import authenticated, has_operations

logger = logging.getLogger(__name__)

auth_backend = CookieTokenAuthentication()


def _authenticate(request):
    result = auth_backend.authenticate(request)
    return result


def _ok(data=None, message="Success", status=200, pagination=None):
    return JsonResponse(
        {"success": True, "message": message, "data": data, "pagination": pagination},
        status=status
    )


def _err(message, status=400, data=None):
    return JsonResponse(
        {"success": False, "message": message, "data": data, "pagination": None},
        status=status
    )


class MeView(View):
    """GET/PUT /api/auth/me/ — current user profile."""

    def get(self, request):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)
        user, session = result

        roles_data = []
        for ur in UserRoles.objects.filter(user=user).select_related('role'):
            roles_data.append({
                'id': str(ur.role.id),
                'name': ur.role.name,
                'level': ur.role.level,
                'scope_level': ur.role.scope_level,
                'tenant_id': ur.tenant_id,
            })

        data = {
            "id": str(user.id),
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "name": user.get_full_name(),
            "status": user.status,
            "sso_provider": user.sso_provider,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "created_at": user.created_at.isoformat(),
            "roles": roles_data,
            "permissions": request.auth_context.get('permissions', []),
            "scope": request.auth_context.get('scope', {}),
        }
        return _ok(data, "Profile fetched successfully")

    def put(self, request):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)
        user, _ = result

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        allowed = ['first_name', 'last_name']
        for field in allowed:
            if field in body:
                setattr(user, field, body[field])
        user.save(update_fields=allowed)

        serializer = UserPublicSerializer(user)
        return _ok(serializer.data, "Profile updated successfully")


class ChangePasswordView(View):
    """POST /api/auth/change-password/"""

    def post(self, request):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)
        user, session = result

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        serializer = ChangePasswordSerializer(data=body)
        if not serializer.is_valid():
            return _err("Validation failed.", 400, serializer.errors)

        if not user.check_password(serializer.validated_data['current_password']):
            return _err("Current password is incorrect.", 400)

        user.set_password(serializer.validated_data['new_password'])
        user.save(update_fields=['password'])

        # Revoke all other sessions (force re-login)
        UserSessions.objects.filter(user=user).exclude(id=session.id).delete()

        return _ok(None, "Password changed successfully. Other sessions have been revoked.")


class UserListCreateView(View):
    """
    GET  /api/auth/users/  — list users
    POST /api/auth/users/  — create user
    """

    def get(self, request):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)
        user, _ = result

        auth_ctx = request.auth_context
        perms = auth_ctx.get('permissions', [])

        # Must have platform or org users:read
        if not any(p in perms for p in ['platform:users:read', 'org:users:read']):
            return _err("Permission denied.", 403)

        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('pageSize', 20)), 100)
        search = request.GET.get('search', '').strip()
        status_filter = request.GET.get('status', '')

        qs = Users.objects.all().order_by('-created_at')

        if search:
            from django.db.models import Q
            qs = qs.filter(
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        if status_filter:
            qs = qs.filter(status=status_filter)

        total = qs.count()
        offset = (page - 1) * page_size
        users_page = qs[offset:offset + page_size]

        data = UserPublicSerializer(users_page, many=True).data
        return _ok(
            data,
            "Users fetched successfully",
            pagination={"page": page, "pageSize": page_size, "total": total}
        )

    def post(self, request):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)

        auth_ctx = request.auth_context
        if 'platform:users:write' not in auth_ctx.get('permissions', []):
            return _err("Permission denied. Requires platform:users:write", 403)

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        serializer = UserCreateSerializer(data=body)
        if not serializer.is_valid():
            return _err("Validation failed.", 400, serializer.errors)

        if Users.objects.filter(email=serializer.validated_data['email']).exists():
            return _err("A user with this email already exists.", 409)

        new_user = serializer.save()
        return _ok(
            UserPublicSerializer(new_user).data,
            "User created successfully",
            status=201
        )


class UserDetailView(View):
    """
    GET  /api/auth/users/{user_id}/
    PUT  /api/auth/users/{user_id}/
    DELETE /api/auth/users/{user_id}/
    """

    def _get_user_or_404(self, user_id):
        try:
            return Users.objects.get(id=user_id)
        except Users.DoesNotExist:
            return None

    def get(self, request, user_id):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)
        requester, _ = result

        auth_ctx = request.auth_context
        perms = auth_ctx.get('permissions', [])

        # Can view self or with users:read permission
        if str(requester.id) != user_id and not any(
            p in perms for p in ['platform:users:read', 'org:users:read']
        ):
            return _err("Permission denied.", 403)

        target = self._get_user_or_404(user_id)
        if not target:
            return _err("User not found.", 404)

        roles_data = []
        for ur in UserRoles.objects.filter(user=target).select_related('role'):
            roles_data.append({
                'id': str(ur.role.id),
                'name': ur.role.name,
                'level': ur.role.level,
                'scope_level': ur.role.scope_level,
                'tenant_id': ur.tenant_id,
            })

        data = UserPublicSerializer(target).data
        data['roles'] = roles_data
        return _ok(data, "User fetched successfully")

    def put(self, request, user_id):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)
        requester, _ = result

        auth_ctx = request.auth_context
        perms = auth_ctx.get('permissions', [])

        is_self = str(requester.id) == user_id
        can_manage = any(p in perms for p in ['platform:users:write', 'org:users:write'])

        if not is_self and not can_manage:
            return _err("Permission denied.", 403)

        target = self._get_user_or_404(user_id)
        if not target:
            return _err("User not found.", 404)

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        allowed = ['first_name', 'last_name']
        if can_manage:
            allowed += ['status']

        changed = []
        for field in allowed:
            if field in body:
                setattr(target, field, body[field])
                changed.append(field)

        if changed:
            target.save(update_fields=changed)

        return _ok(UserPublicSerializer(target).data, "User updated successfully")

    def delete(self, request, user_id):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)

        auth_ctx = request.auth_context
        if 'platform:users:write' not in auth_ctx.get('permissions', []):
            return _err("Permission denied. Requires platform:users:write", 403)

        target = self._get_user_or_404(user_id)
        if not target:
            return _err("User not found.", 404)

        # Soft delete — deactivate
        target.status = 'inactive'
        target.save(update_fields=['status'])
        UserSessions.objects.filter(user=target).delete()

        return _ok(None, "User deactivated successfully.")


class UserRolesView(View):
    """GET /api/auth/users/{user_id}/roles/ — list a user's roles"""

    def get(self, request, user_id):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)
        requester, _ = result

        auth_ctx = request.auth_context
        perms = auth_ctx.get('permissions', [])

        if str(requester.id) != user_id and not any(
            p in perms for p in ['platform:users:read', 'org:users:read', 'tenant:users:read']
        ):
            return _err("Permission denied.", 403)

        try:
            target = Users.objects.get(id=user_id)
        except Users.DoesNotExist:
            return _err("User not found.", 404)

        roles_data = []
        for ur in UserRoles.objects.filter(user=target).select_related('role'):
            roles_data.append({
                'id': str(ur.id),
                'role_id': str(ur.role.id),
                'role_name': ur.role.name,
                'role_level': ur.role.level,
                'scope_level': ur.role.scope_level,
                'tenant_id': ur.tenant_id,
                'created_at': ur.created_at.isoformat(),
            })

        return _ok(roles_data, "User roles fetched successfully")


class SessionListView(View):
    """GET /api/auth/sessions/ — list authenticated user's own sessions"""

    def get(self, request):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)
        user, current_session = result

        sessions = UserSessions.objects.filter(
            user=user, revoked=False, expires_at__gt=timezone.now()
        ).order_by('-created_at')

        data = []
        for s in sessions:
            data.append({
                "id": str(s.id),
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "login_method": s.login_method,
                "created_at": s.created_at.isoformat(),
                "expires_at": s.expires_at.isoformat(),
                "is_current": str(s.id) == str(current_session.id),
                "location": {
                    "country": s.location_country,
                    "city": s.location_city,
                    "region": s.location_region,
                }
            })

        return _ok(data, "Sessions fetched successfully")


class SessionRevokeView(View):
    """DELETE /api/auth/sessions/{session_id}/ — revoke a specific session"""

    def delete(self, request, session_id):
        result = _authenticate(request)
        if not result:
            return _err("Authentication required.", 401)
        user, _ = result

        try:
            session = UserSessions.objects.get(id=session_id, user=user)
        except UserSessions.DoesNotExist:
            return _err("Session not found.", 404)

        session.delete()
        return _ok(None, "Session revoked successfully.")
