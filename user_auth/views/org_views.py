"""
Organization management views.

GET  /api/auth/organizations/        — list orgs
POST /api/auth/organizations/        — create org (platform admin)
GET  /api/auth/organizations/{id}/   — get org
PUT  /api/auth/organizations/{id}/   — update org
DEL  /api/auth/organizations/{id}/   — delete org
"""
import json
import logging
from django.http import JsonResponse
from django.views import View

from user_auth.authentication import CookieTokenAuthentication
from user_auth.models import Organizations
from user_auth.serializers import OrganizationSerializer

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


class OrganizationListCreateView(View):
    def get(self, request):
        user, _, err = _auth(request, 'platform:orgs:read')
        if err:
            return err

        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('pageSize', 20)), 100)
        search = request.GET.get('search', '').strip()
        status_filter = request.GET.get('status', '')

        qs = Organizations.objects.all().order_by('-created_at')

        if search:
            from django.db.models import Q
            qs = qs.filter(
                Q(name__icontains=search) |
                Q(contact_email__icontains=search)
            )
        if status_filter:
            qs = qs.filter(status=status_filter)

        total = qs.count()
        offset = (page - 1) * page_size
        page_qs = qs[offset:offset + page_size]

        return _ok(
            OrganizationSerializer(page_qs, many=True).data,
            "Organizations fetched successfully",
            pagination={"page": page, "pageSize": page_size, "total": total}
        )

    def post(self, request):
        user, _, err = _auth(request, 'platform:orgs:write')
        if err:
            return err

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        if not body.get('name'):
            return _err("Organization name is required.")

        serializer = OrganizationSerializer(data=body)
        if not serializer.is_valid():
            return _err("Validation failed.", 400, serializer.errors)

        org = serializer.save(created_by=user)
        return _ok(OrganizationSerializer(org).data, "Organization created successfully", status=201)


class OrganizationDetailView(View):
    def _get_org(self, org_id):
        try:
            return Organizations.objects.get(id=org_id)
        except Organizations.DoesNotExist:
            return None

    def get(self, request, org_id):
        _, _, err = _auth(request, 'platform:orgs:read')
        if err:
            return err
        org = self._get_org(org_id)
        if not org:
            return _err("Organization not found.", 404)
        return _ok(OrganizationSerializer(org).data, "Organization fetched successfully")

    def put(self, request, org_id):
        user, _, err = _auth(request, 'platform:orgs:write')
        if err:
            return err
        org = self._get_org(org_id)
        if not org:
            return _err("Organization not found.", 404)

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        serializer = OrganizationSerializer(org, data=body, partial=True)
        if not serializer.is_valid():
            return _err("Validation failed.", 400, serializer.errors)

        org = serializer.save()
        return _ok(OrganizationSerializer(org).data, "Organization updated successfully")

    def delete(self, request, org_id):
        _, _, err = _auth(request, 'platform:orgs:write')
        if err:
            return err
        org = self._get_org(org_id)
        if not org:
            return _err("Organization not found.", 404)

        org_name = org.name
        org.status = 'inactive'
        org.save(update_fields=['status'])
        return _ok(None, f"Organization '{org_name}' deactivated successfully.")
