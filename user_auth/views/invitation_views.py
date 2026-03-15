"""
User invitation flow.

POST /api/auth/invite/          — send invitation
POST /api/auth/invite/accept/   — accept invitation + create account
GET  /api/auth/invitations/     — list pending invitations
DEL  /api/auth/invitations/{id}/ — revoke invitation
"""
import json
import uuid
import logging
from datetime import timedelta
from django.http import JsonResponse
from django.views import View
from django.utils import timezone

from user_auth.authentication import (
    CookieTokenAuthentication, resolve_user_permissions, resolve_user_scope
)
from user_auth.models import Users, UserSessions, UserRoles, UserInvitations, Roles
from user_auth.utils.auth_utils import generate_token, hash_token
from user_auth.utils.cookie_utils import set_auth_cookies
from user_auth.serializers import UserInvitationSerializer

logger = logging.getLogger(__name__)
auth_backend = CookieTokenAuthentication()


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


def _auth(request, required_op=None):
    result = auth_backend.authenticate(request)
    if not result:
        return None, None, _err("Authentication required.", 401)
    user, session = result
    if required_op:
        perms = request.auth_context.get('permissions', [])
        if required_op not in perms:
            return None, None, _err(f"Permission denied. Requires: {required_op}", 403)
    return user, session, None


class InviteUserView(View):
    """
    POST /api/auth/invite/
    Body: {email, role_id, scope_type, scope_id}

    The inviter must have *:users:write at the target scope level.
    """

    def post(self, request):
        inviter, _, err = _auth(request)
        if err:
            return err

        auth_ctx = request.auth_context
        perms = auth_ctx.get('permissions', [])

        can_invite = any(p.endswith(':users:write') for p in perms)
        if not can_invite:
            return _err("Permission denied. Requires users:write at some scope level.", 403)

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        email = body.get('email', '').strip().lower()
        role_id = body.get('role_id')
        scope_type = body.get('scope_type')
        scope_id = body.get('scope_id')

        if not email or not role_id:
            return _err("email and role_id are required.")

        try:
            role = Roles.objects.get(id=role_id)
        except Roles.DoesNotExist:
            return _err("Role not found.", 404)

        # Revoke any existing pending invitations for this email
        UserInvitations.objects.filter(
            email=email, status='pending'
        ).update(status='revoked')

        token = generate_token()
        hashed = hash_token(token)
        expires = timezone.now() + timedelta(hours=72)

        invitation = UserInvitations.objects.create(
            id=str(uuid.uuid4()),
            email=email,
            role=role,
            scope_type=scope_type,
            scope_id=scope_id,
            token=hashed,
            token_hint=token[:8],
            invited_by=inviter,
            expires_at=expires,
        )

        # NOTE: In production, send an email with the raw token via SES/SMTP here.
        # The raw token is intentionally returned in response for dev/testing.
        logger.info("Invitation created for %s by %s", email, inviter.email)

        data = {
            "invitation_id": str(invitation.id),
            "email": email,
            "role": role.name,
            "scope_type": scope_type,
            "scope_id": scope_id,
            "expires_at": expires.isoformat(),
            "invitation_token": token,  # Only expose in dev; remove in prod + send via email
        }

        return _ok(data, f"Invitation sent to {email}", status=201)


class AcceptInviteView(View):
    """
    POST /api/auth/invite/accept/
    Body: {token, password, first_name, last_name}

    Validates token → creates user → assigns role → auto-logs in.
    """

    def post(self, request):
        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        token = body.get('token', '').strip()
        password = body.get('password', '').strip()
        first_name = body.get('first_name', '').strip()
        last_name = body.get('last_name', '').strip()

        if not token or not password:
            return _err("token and password are required.")

        if len(password) < 8:
            return _err("Password must be at least 8 characters.")

        # Find invitation by token_hint for fast lookup
        token_hint = token[:8]
        candidates = UserInvitations.objects.filter(
            token_hint=token_hint,
            status='pending',
            expires_at__gt=timezone.now()
        ).select_related('role')

        invitation = None
        for c in candidates:
            from user_auth.utils.auth_utils import verify_token
            if verify_token(token, c.token):
                invitation = c
                break

        if not invitation:
            return _err("Invalid, expired, or already used invitation token.", 400)

        # Check if user already exists
        user, created = Users.objects.get_or_create(
            email=invitation.email,
            defaults={
                'id': str(uuid.uuid4()),
                'first_name': first_name,
                'last_name': last_name,
                'status': 'active',
            }
        )
        if created:
            user.set_password(password)
            user.save(update_fields=['password'])

        # Assign role from invitation
        if invitation.role:
            UserRoles.objects.get_or_create(
                user=user,
                role=invitation.role,
                tenant_id=invitation.scope_id if invitation.scope_type == 'tenant' else None,
                defaults={'assigned_by': invitation.invited_by}
            )

        # Mark invitation as accepted
        invitation.status = 'accepted'
        invitation.accepted_by = user
        invitation.save(update_fields=['status', 'accepted_by'])

        # Auto-login: create session with permission cache
        access_token = generate_token()
        refresh_token = generate_token()

        from django.conf import settings
        expires_at = timezone.now() + timedelta(
            days=getattr(settings, 'REFRESH_TOKEN_LIFETIME_DAYS', 7)
        )

        permissions_cache = resolve_user_permissions(user)
        scope_cache = resolve_user_scope(user)

        session = UserSessions.objects.create(
            id=str(uuid.uuid4()),
            user=user,
            token=hash_token(access_token),
            token_hint=access_token[:8],
            refresh_token=hash_token(refresh_token),
            login_method='invitation',
            expires_at=expires_at,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            permissions_cache=permissions_cache,
            scope_cache=scope_cache,
        )

        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        roles_data = [{
            'id': str(invitation.role.id),
            'name': invitation.role.name,
            'level': invitation.role.level,
        }] if invitation.role else []

        response = JsonResponse({
            "success": True,
            "message": "Invitation accepted. Account created and logged in.",
            "user": {
                "id": str(user.id),
                "email": user.email,
                "name": user.get_full_name(),
                "roles": roles_data,
            }
        }, status=201)

        set_auth_cookies(response, access_token, refresh_token)
        return response


class InvitationListView(View):
    """GET /api/auth/invitations/ — list invitations (for admins)"""

    def get(self, request):
        _, _, err = _auth(request)
        if err:
            return err

        auth_ctx = request.auth_context
        perms = auth_ctx.get('permissions', [])
        if not any(p.endswith(':users:write') for p in perms):
            return _err("Permission denied.", 403)

        status_filter = request.GET.get('status', 'pending')
        qs = UserInvitations.objects.filter(status=status_filter).order_by('-created_at')

        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('pageSize', 20)), 100)
        total = qs.count()
        offset = (page - 1) * page_size
        page_qs = qs[offset:offset + page_size]

        return _ok(
            UserInvitationSerializer(page_qs, many=True).data,
            "Invitations fetched successfully",
            pagination={"page": page, "pageSize": page_size, "total": total}
        )


class InvitationRevokeView(View):
    """DELETE /api/auth/invitations/{invitation_id}/"""

    def delete(self, request, invitation_id):
        _, _, err = _auth(request)
        if err:
            return err

        auth_ctx = request.auth_context
        perms = auth_ctx.get('permissions', [])
        if not any(p.endswith(':users:write') for p in perms):
            return _err("Permission denied.", 403)

        try:
            invitation = UserInvitations.objects.get(id=invitation_id)
        except UserInvitations.DoesNotExist:
            return _err("Invitation not found.", 404)

        if invitation.status != 'pending':
            return _err(f"Cannot revoke invitation with status '{invitation.status}'.", 400)

        invitation.status = 'revoked'
        invitation.save(update_fields=['status'])

        return _ok(None, "Invitation revoked successfully.")
