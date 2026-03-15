import json
import uuid
from django.utils import timezone
from django.contrib.auth.hashers import check_password
from django.conf import settings
from datetime import timedelta

from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from user_auth.models import Users, UserSessions
from user_auth.utils.auth_utils import generate_token, hash_token, verify_token
from user_auth.utils.cookie_utils import set_auth_cookies, clear_auth_cookies
from user_auth.authentication import resolve_user_permissions, resolve_user_scope
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_GET


@require_GET
@ensure_csrf_cookie
def csrf(request):
    return JsonResponse({"detail": "CSRF cookie set"})


def _get_user_roles_data(user):
    """Return list of role dicts for a user."""
    from user_auth.models import UserRoles
    roles = []
    for ur in UserRoles.objects.filter(user=user).select_related('role'):
        roles.append({
            'id': str(ur.role.id),
            'name': ur.role.name,
            'level': ur.role.level,
            'scope_level': ur.role.scope_level,
            'tenant_id': ur.tenant_id,
        })
    return roles


@method_decorator(ensure_csrf_cookie, name='dispatch')
class LoginView(APIView):
    def post(self, request):
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"success": False, "message": "Invalid JSON"}, status=400)

        email = data.get("email")
        password = data.get("password")
        remember_me = data.get("rememberMe", False)

        if not email or not password:
            return JsonResponse(
                {"success": False, "message": "Email and password are required."},
                status=400
            )

        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return JsonResponse(
                {"success": False, "message": "Invalid email or password."},
                status=401
            )

        if not user.password or not check_password(password, user.password):
            return JsonResponse(
                {"success": False, "message": "Invalid email or password."},
                status=401
            )

        if user.status == 'suspended':
            return JsonResponse(
                {"success": False, "message": "Your account has been suspended. Contact support."},
                status=403
            )

        # Revoke existing sessions
        UserSessions.objects.filter(user=user).delete()

        access_token = generate_token()
        refresh_token = generate_token() if remember_me else None

        hashed_access = hash_token(access_token)
        hashed_refresh = hash_token(refresh_token) if refresh_token else None

        access_lifetime = timedelta(minutes=getattr(settings, 'ACCESS_TOKEN_LIFETIME_MINUTES', 60))
        refresh_lifetime = timedelta(days=getattr(settings, 'REFRESH_TOKEN_LIFETIME_DAYS', 7))
        expires_at = timezone.now() + (refresh_lifetime if remember_me else access_lifetime)

        # Resolve and cache permissions + scope at login time
        permissions_cache = resolve_user_permissions(user)
        scope_cache = resolve_user_scope(user)

        UserSessions.objects.create(
            id=uuid.uuid4(),
            user=user,
            token=hashed_access,
            token_hint=access_token[:8],
            refresh_token=hashed_refresh,
            login_method="local",
            expires_at=expires_at,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            permissions_cache=permissions_cache,
            scope_cache=scope_cache,
        )

        user.last_login = timezone.now()
        user.status = 'active'
        user.save(update_fields=['last_login', 'status'])

        roles = _get_user_roles_data(user)

        response_data = {
            "success": True,
            "message": "Login successful",
            "expiresIn": f"{getattr(settings, 'ACCESS_TOKEN_LIFETIME_MINUTES', 60)}m",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "name": user.get_full_name(),
                "status": user.status,
                "roles": roles,
            },
        }

        response = JsonResponse(response_data)
        set_auth_cookies(response, access_token, refresh_token)
        response["Cache-Control"] = "no-store"
        return response


@method_decorator(ensure_csrf_cookie, name='dispatch')
class RefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            response = JsonResponse(
                {"success": False, "message": "No refresh token found"},
                status=401
            )
            clear_auth_cookies(response)
            return response

        # Use token_hint for fast lookup if refresh_token has a hint stored
        # Fall back to full scan (refresh tokens don't currently store hints)
        sessions = UserSessions.objects.filter(
            refresh_token__isnull=False,
            revoked=False,
            expires_at__gt=timezone.now()
        ).select_related('user')

        valid_session = None
        user = None

        for session in sessions:
            if session.refresh_token and verify_token(refresh_token, session.refresh_token):
                valid_session = session
                user = session.user
                break

        if not valid_session:
            response = JsonResponse(
                {"success": False, "message": "Invalid or expired refresh token"},
                status=401
            )
            clear_auth_cookies(response)
            return response

        new_access_token = generate_token()
        hashed_new_access = hash_token(new_access_token)

        # Refresh permissions cache on token refresh
        permissions_cache = resolve_user_permissions(user)
        scope_cache = resolve_user_scope(user)

        valid_session.token = hashed_new_access
        valid_session.token_hint = new_access_token[:8]
        valid_session.permissions_cache = permissions_cache
        valid_session.scope_cache = scope_cache
        valid_session.save(update_fields=["token", "token_hint", "permissions_cache", "scope_cache"])

        roles = _get_user_roles_data(user)

        response = JsonResponse({
            "success": True,
            "message": "Access token refreshed successfully",
            "expiresIn": f"{getattr(settings, 'ACCESS_TOKEN_LIFETIME_MINUTES', 60)}m",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "name": user.get_full_name(),
                "status": user.status,
                "roles": roles,
            },
        })
        set_auth_cookies(response, new_access_token)
        return response


@method_decorator(ensure_csrf_cookie, name='dispatch')
class LogoutView(APIView):
    def post(self, request):
        access_token = request.COOKIES.get("access_token")
        refresh_token = request.COOKIES.get("refresh_token")

        login_method = "local"
        deleted = False

        if access_token:
            token_hint = access_token[:8]
            sessions = UserSessions.objects.filter(token_hint=token_hint)
            for session in sessions:
                if verify_token(access_token, session.token):
                    login_method = session.login_method or "local"
                    session.delete()
                    deleted = True
                    break

        if not deleted and refresh_token:
            sessions = UserSessions.objects.filter(refresh_token__isnull=False)
            for session in sessions:
                if session.refresh_token and verify_token(refresh_token, session.refresh_token):
                    login_method = session.login_method or "local"
                    session.delete()
                    deleted = True
                    break

        is_sso = login_method == "saml"
        response_data = {
            "success": True,
            "message": "Logout successful",
            "sso": is_sso
        }

        if is_sso:
            response_data["redirectUrl"] = "/api/auth/saml/logout/"

        response = JsonResponse(response_data)

        clear_auth_cookies(response)
        return response
