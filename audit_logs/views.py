"""
Audit log views.

GET /api/audit-logs/              — list audit logs (paginated, filterable)
GET /api/audit-logs/{id}/         — get single audit log entry
GET /api/audit-logs/export/       — export audit logs (xlsx)
"""
import logging
from django.http import JsonResponse, HttpResponse
from django.views import View
from django.db.models import Q

from audit_logs.models import AuditLog
from audit_logs.serializers import AuditLogSerializer
from user_auth.authentication import CookieTokenAuthentication

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


class AuditLogListView(View):
    """
    GET /api/audit-logs/
    Query params:
      page, pageSize, search, user_email, action_type, resource_type,
      status, tenant_id, from_date, to_date
    """

    def get(self, request):
        result = auth_backend.authenticate(request)
        if not result:
            return _err("Authentication required.", 401)
        user, _ = result

        perms = request.auth_context.get('permissions', [])
        if not any(p in perms for p in ['platform:audit:read', 'org:audit:read']):
            return _err("Permission denied. Requires audit:read.", 403)

        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('pageSize', 50)), 200)
        search = request.GET.get('search', '').strip()
        user_email = request.GET.get('user_email', '').strip()
        action_type = request.GET.get('action_type', '').strip()
        resource_type = request.GET.get('resource_type', '').strip()
        status_filter = request.GET.get('status', '').strip()
        tenant_id = request.GET.get('tenant_id', '').strip()
        from_date = request.GET.get('from_date', '').strip()
        to_date = request.GET.get('to_date', '').strip()

        qs = AuditLog.objects.all()

        if search:
            qs = qs.filter(
                Q(user_email__icontains=search) |
                Q(action_type__icontains=search) |
                Q(resource_type__icontains=search) |
                Q(resource_id__icontains=search) |
                Q(resource_name__icontains=search)
            )

        if user_email:
            qs = qs.filter(user_email__icontains=user_email)
        if action_type:
            qs = qs.filter(action_type=action_type)
        if resource_type:
            qs = qs.filter(resource_type=resource_type)
        if status_filter:
            qs = qs.filter(status=status_filter)
        if tenant_id:
            qs = qs.filter(tenant_id=tenant_id)
        if from_date:
            qs = qs.filter(created_at__date__gte=from_date)
        if to_date:
            qs = qs.filter(created_at__date__lte=to_date)

        # Org-level users can only see logs for their org/tenants
        if 'platform:audit:read' not in perms:
            scope = request.auth_context.get('scope', {})
            allowed_tenants = scope.get('tenant_ids')
            if allowed_tenants:
                qs = qs.filter(tenant_id__in=allowed_tenants)

        total = qs.count()
        offset = (page - 1) * page_size
        page_qs = qs[offset:offset + page_size]

        return _ok(
            AuditLogSerializer(page_qs, many=True).data,
            "Audit logs fetched successfully",
            pagination={"page": page, "pageSize": page_size, "total": total}
        )


class AuditLogDetailView(View):
    """GET /api/audit-logs/{log_id}/"""

    def get(self, request, log_id):
        result = auth_backend.authenticate(request)
        if not result:
            return _err("Authentication required.", 401)

        perms = request.auth_context.get('permissions', [])
        if not any(p in perms for p in ['platform:audit:read', 'org:audit:read']):
            return _err("Permission denied.", 403)

        try:
            log = AuditLog.objects.get(id=log_id)
        except AuditLog.DoesNotExist:
            return _err("Audit log not found.", 404)

        return _ok(AuditLogSerializer(log).data, "Audit log fetched successfully")


class AuditLogExportView(View):
    """GET /api/audit-logs/export/?format=xlsx"""

    def get(self, request):
        result = auth_backend.authenticate(request)
        if not result:
            return _err("Authentication required.", 401)

        perms = request.auth_context.get('permissions', [])
        if 'platform:audit:read' not in perms:
            return _err("Permission denied. Requires platform:audit:read.", 403)

        limit = min(int(request.GET.get('limit', 5000)), 10000)
        qs = AuditLog.objects.all().order_by('-created_at')[:limit]

        data = list(qs.values(
            'id', 'user_email', 'action_type', 'resource_type', 'resource_id',
            'status', 'tenant_id', 'ip_address', 'request_method',
            'request_path', 'response_status', 'created_at'
        ))

        labels = {
            'id': 'Log ID',
            'user_email': 'User Email',
            'action_type': 'Action',
            'resource_type': 'Resource Type',
            'resource_id': 'Resource ID',
            'status': 'Status',
            'tenant_id': 'Tenant ID',
            'ip_address': 'IP Address',
            'request_method': 'HTTP Method',
            'request_path': 'Request Path',
            'response_status': 'HTTP Status',
            'created_at': 'Timestamp',
        }

        from utils.exporters import export_to_excel
        buffer = export_to_excel(data, labels)
        response = HttpResponse(
            buffer,
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = 'attachment; filename="audit_logs.xlsx"'
        return response


class AuditActionTypesView(View):
    """GET /api/audit-logs/action-types/ — list distinct action types for filter dropdowns"""

    def get(self, request):
        result = auth_backend.authenticate(request)
        if not result:
            return _err("Authentication required.", 401)

        perms = request.auth_context.get('permissions', [])
        if not any(p in perms for p in ['platform:audit:read', 'org:audit:read']):
            return _err("Permission denied.", 403)

        actions = (
            AuditLog.objects
            .values_list('action_type', flat=True)
            .distinct()
            .order_by('action_type')
        )
        return _ok(list(actions), "Action types fetched successfully")
