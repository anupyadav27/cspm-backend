"""
RBAC Management Views.

Roles:
  GET  /api/auth/roles/                    — list roles
  POST /api/auth/roles/                    — create role
  GET  /api/auth/roles/{id}/               — get role detail (with operations)
  PUT  /api/auth/roles/{id}/               — update role
  DEL  /api/auth/roles/{id}/               — delete role

Operations (catalog):
  GET  /api/auth/operations/               — list all operations
  POST /api/auth/operations/               — create operation (platform admin)
  GET  /api/auth/operations/{id}/          — get operation
  PUT  /api/auth/operations/{id}/          — update operation
  DEL  /api/auth/operations/{id}/          — delete operation

Role-Operation assignments:
  GET  /api/auth/roles/{id}/operations/    — list operations on a role
  POST /api/auth/roles/{id}/operations/    — assign operation(s) to role
  DEL  /api/auth/roles/{id}/operations/    — remove operation(s) from role

User-Role assignments:
  POST /api/auth/users/{id}/roles/         — assign role to user
  DEL  /api/auth/users/{id}/roles/{rid}/   — remove role from user
"""
import json
import logging
from django.http import JsonResponse
from django.views import View

from user_auth.authentication import CookieTokenAuthentication
from user_auth.models import Roles, Operations, RoleOperations, UserRoles, Users
from user_auth.serializers import (
    RoleSerializer, RoleDetailSerializer,
    OperationsSerializer, UserRoleSerializer
)

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
    """Authenticate and optionally check operation."""
    result = auth_backend.authenticate(request)
    if not result:
        return None, None, _err("Authentication required.", 401)
    user, session = result
    if required_op:
        perms = request.auth_context.get('permissions', [])
        if required_op not in perms:
            return None, None, _err(f"Permission denied. Requires: {required_op}", 403)
    return user, session, None


# ─── ROLES ────────────────────────────────────────────────────────────────────

class RoleListCreateView(View):
    def get(self, request):
        user, _, err = _auth(request, 'platform:roles:read')
        if err:
            return err

        qs = Roles.objects.all().order_by('level', 'name')
        data = RoleSerializer(qs, many=True).data
        return _ok(data, "Roles fetched successfully")

    def post(self, request):
        user, _, err = _auth(request, 'platform:roles:write')
        if err:
            return err

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        required = ['name', 'level', 'scope_level']
        missing = [f for f in required if f not in body]
        if missing:
            return _err(f"Missing required fields: {', '.join(missing)}")

        if Roles.objects.filter(name=body['name']).exists():
            return _err(f"Role with name '{body['name']}' already exists.", 409)

        role = Roles.objects.create(
            name=body['name'],
            description=body.get('description', ''),
            level=body['level'],
            scope_level=body['scope_level'],
            tenant_scoped=body.get('tenant_scoped', False),
            created_by=user,
            updated_by=user,
        )

        # Optionally assign operation IDs on creation
        operation_ids = body.get('operation_ids', [])
        if operation_ids:
            ops = Operations.objects.filter(id__in=operation_ids)
            for op in ops:
                RoleOperations.objects.get_or_create(role=role, operation=op)

        return _ok(RoleDetailSerializer(role).data, "Role created successfully", status=201)


class RoleDetailView(View):
    def _get_role(self, role_id):
        try:
            return Roles.objects.get(id=role_id)
        except Roles.DoesNotExist:
            return None

    def get(self, request, role_id):
        _, _, err = _auth(request, 'platform:roles:read')
        if err:
            return err
        role = self._get_role(role_id)
        if not role:
            return _err("Role not found.", 404)
        return _ok(RoleDetailSerializer(role).data, "Role fetched successfully")

    def put(self, request, role_id):
        user, _, err = _auth(request, 'platform:roles:write')
        if err:
            return err

        role = self._get_role(role_id)
        if not role:
            return _err("Role not found.", 404)
        if role.is_system:
            return _err("System roles cannot be modified.", 400)

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        for field in ['name', 'description', 'level', 'scope_level', 'tenant_scoped']:
            if field in body:
                setattr(role, field, body[field])
        role.updated_by = user
        role.save()

        return _ok(RoleDetailSerializer(role).data, "Role updated successfully")

    def delete(self, request, role_id):
        _, _, err = _auth(request, 'platform:roles:write')
        if err:
            return err

        role = self._get_role(role_id)
        if not role:
            return _err("Role not found.", 404)
        if role.is_system:
            return _err("System roles cannot be deleted.", 400)

        role_name = role.name
        role.delete()
        return _ok(None, f"Role '{role_name}' deleted successfully")


class RoleOperationsView(View):
    """Manage operations assigned to a role."""

    def _get_role(self, role_id):
        try:
            return Roles.objects.get(id=role_id)
        except Roles.DoesNotExist:
            return None

    def get(self, request, role_id):
        _, _, err = _auth(request, 'platform:roles:read')
        if err:
            return err

        role = self._get_role(role_id)
        if not role:
            return _err("Role not found.", 404)

        ops = Operations.objects.filter(role_operations__role=role).order_by('scope_type', 'key')
        return _ok(OperationsSerializer(ops, many=True).data, "Role operations fetched successfully")

    def post(self, request, role_id):
        """Assign operations to role. Body: {operation_ids: [...]} or {operation_keys: [...]}"""
        _, _, err = _auth(request, 'platform:roles:write')
        if err:
            return err

        role = self._get_role(role_id)
        if not role:
            return _err("Role not found.", 404)

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        op_ids = body.get('operation_ids', [])
        op_keys = body.get('operation_keys', [])

        if not op_ids and not op_keys:
            return _err("Provide 'operation_ids' or 'operation_keys'.")

        ops_qs = Operations.objects.none()
        if op_ids:
            ops_qs = ops_qs | Operations.objects.filter(id__in=op_ids)
        if op_keys:
            ops_qs = ops_qs | Operations.objects.filter(key__in=op_keys)

        added = 0
        for op in ops_qs:
            _, created = RoleOperations.objects.get_or_create(role=role, operation=op)
            if created:
                added += 1

        return _ok(
            {"added": added, "total_in_role": role.role_operations.count()},
            f"{added} operation(s) assigned to role '{role.name}'"
        )

    def delete(self, request, role_id):
        """Remove operations from role. Body: {operation_ids: [...]} or {operation_keys: [...]}"""
        _, _, err = _auth(request, 'platform:roles:write')
        if err:
            return err

        role = self._get_role(role_id)
        if not role:
            return _err("Role not found.", 404)

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        op_ids = body.get('operation_ids', [])
        op_keys = body.get('operation_keys', [])

        deleted_count = 0
        if op_ids:
            deleted_count += RoleOperations.objects.filter(
                role=role, operation_id__in=op_ids
            ).delete()[0]
        if op_keys:
            deleted_count += RoleOperations.objects.filter(
                role=role, operation__key__in=op_keys
            ).delete()[0]

        return _ok(
            {"removed": deleted_count},
            f"{deleted_count} operation(s) removed from role '{role.name}'"
        )


# ─── OPERATIONS ───────────────────────────────────────────────────────────────

class OperationListCreateView(View):
    def get(self, request):
        _, _, err = _auth(request, 'platform:roles:read')
        if err:
            return err

        scope_type = request.GET.get('scope_type', '')
        qs = Operations.objects.filter(is_active=True).order_by('scope_type', 'key')
        if scope_type:
            qs = qs.filter(scope_type=scope_type)

        return _ok(OperationsSerializer(qs, many=True).data, "Operations fetched successfully")

    def post(self, request):
        _, _, err = _auth(request, 'platform:roles:write')
        if err:
            return err

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        required = ['key', 'name', 'scope_type']
        missing = [f for f in required if f not in body]
        if missing:
            return _err(f"Missing required fields: {', '.join(missing)}")

        if Operations.objects.filter(key=body['key']).exists():
            return _err(f"Operation with key '{body['key']}' already exists.", 409)

        op = Operations.objects.create(
            key=body['key'],
            name=body['name'],
            description=body.get('description', ''),
            scope_type=body['scope_type'],
        )
        return _ok(OperationsSerializer(op).data, "Operation created successfully", status=201)


class OperationDetailView(View):
    def _get_op(self, op_id):
        try:
            return Operations.objects.get(id=op_id)
        except Operations.DoesNotExist:
            return None

    def get(self, request, op_id):
        _, _, err = _auth(request, 'platform:roles:read')
        if err:
            return err
        op = self._get_op(op_id)
        if not op:
            return _err("Operation not found.", 404)
        return _ok(OperationsSerializer(op).data)

    def put(self, request, op_id):
        _, _, err = _auth(request, 'platform:roles:write')
        if err:
            return err
        op = self._get_op(op_id)
        if not op:
            return _err("Operation not found.", 404)

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        for field in ['name', 'description', 'scope_type', 'is_active']:
            if field in body:
                setattr(op, field, body[field])
        op.save()
        return _ok(OperationsSerializer(op).data, "Operation updated successfully")

    def delete(self, request, op_id):
        _, _, err = _auth(request, 'platform:roles:write')
        if err:
            return err
        op = self._get_op(op_id)
        if not op:
            return _err("Operation not found.", 404)
        op.delete()
        return _ok(None, "Operation deleted successfully")


# ─── USER-ROLE ASSIGNMENTS ────────────────────────────────────────────────────

class UserRoleAssignView(View):
    """
    POST /api/auth/users/{user_id}/roles/
    Body: {role_id, tenant_id (optional)}
    """

    def post(self, request, user_id):
        requester, _, err = _auth(request)
        if err:
            return err

        auth_ctx = request.auth_context
        perms = auth_ctx.get('permissions', [])
        if not any(p in perms for p in ['platform:users:write', 'org:users:write', 'tenant:users:write']):
            return _err("Permission denied.", 403)

        try:
            body = json.loads(request.body)
        except json.JSONDecodeError:
            return _err("Invalid JSON body.")

        if 'role_id' not in body:
            return _err("Missing required field: role_id")

        try:
            target_user = Users.objects.get(id=user_id)
        except Users.DoesNotExist:
            return _err("User not found.", 404)

        try:
            role = Roles.objects.get(id=body['role_id'])
        except Roles.DoesNotExist:
            return _err("Role not found.", 404)

        tenant_id = body.get('tenant_id')

        ur, created = UserRoles.objects.get_or_create(
            user=target_user,
            role=role,
            tenant_id=tenant_id,
            defaults={'assigned_by': requester}
        )

        if not created:
            return _ok(None, "User already has this role.")

        return _ok(
            {"user_id": user_id, "role_id": str(role.id), "role_name": role.name, "tenant_id": tenant_id},
            f"Role '{role.name}' assigned to user successfully",
            status=201
        )


class UserRoleRemoveView(View):
    """DELETE /api/auth/users/{user_id}/roles/{role_id}/"""

    def delete(self, request, user_id, role_id):
        _, _, err = _auth(request)
        if err:
            return err

        auth_ctx = request.auth_context
        perms = auth_ctx.get('permissions', [])
        if not any(p in perms for p in ['platform:users:write', 'org:users:write', 'tenant:users:write']):
            return _err("Permission denied.", 403)

        deleted, _ = UserRoles.objects.filter(
            user_id=user_id,
            role_id=role_id
        ).delete()

        if deleted == 0:
            return _err("User role assignment not found.", 404)

        return _ok(None, "Role removed from user successfully")
