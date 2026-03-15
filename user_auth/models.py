from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin, Group, Permission
from django.db import models
import uuid
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings


class UsersManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)


class Users(AbstractBaseUser, PermissionsMixin):
    """
    Core user model. Auth is email-based.
    status: active | inactive | pending | suspended
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.TextField(unique=True)
    password = models.TextField(blank=True, null=True)
    sso_provider = models.TextField(blank=True, null=True)
    sso_id = models.TextField(blank=True, null=True)
    first_name = models.TextField(blank=True, null=True)
    last_name = models.TextField(blank=True, null=True)
    status = models.TextField(blank=True, null=True, default='active')
    last_login = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    groups = models.ManyToManyField(Group, related_name="custom_users_groups", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="custom_users_permissions", blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UsersManager()

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def get_full_name(self):
        parts = [self.first_name, self.last_name]
        return " ".join(p for p in parts if p)

    def __str__(self):
        return self.email

    class Meta:
        managed = True
        db_table = 'users'
        indexes = [models.Index(fields=['email'])]


class UserSessions(models.Model):
    """
    Active sessions. token and refresh_token stored as hashed values.
    token_hint = first 8 chars of RAW token — indexed for O(1) lookup.
    permissions_cache = JSON list of operation keys e.g. ["account:threats:read", ...]
    scope_cache = JSON dict with org_ids, tenant_ids, account_ids lists.
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('Users', models.DO_NOTHING, related_name='sessions')
    token = models.TextField(unique=True)
    token_hint = models.CharField(max_length=16, blank=True, null=True, db_index=True)
    refresh_token = models.TextField(blank=True, null=True)
    ip_address = models.TextField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    login_method = models.TextField(blank=True, null=True)
    expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)
    location_country = models.TextField(blank=True, null=True)
    location_city = models.TextField(blank=True, null=True)
    location_region = models.TextField(blank=True, null=True)
    session_index = models.TextField(blank=True, null=True)
    permissions_cache = models.JSONField(default=list, blank=True, null=True)
    scope_cache = models.JSONField(default=dict, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        managed = True
        db_table = 'user_sessions'
        indexes = [
            models.Index(fields=['token_hint']),
            models.Index(fields=['user']),
        ]


class Organizations(models.Model):
    """
    Customer organizations (top of resource hierarchy).
    Platform → Organization → Tenant → Account
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=50, default='active')  # active | inactive | suspended
    plan = models.CharField(max_length=100, blank=True, null=True)  # free | starter | pro | enterprise
    contact_email = models.TextField(blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, blank=True, null=True,
        related_name='organizations_created'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'organizations'
        ordering = ['name']

    def __str__(self):
        return self.name


class Operations(models.Model):
    """
    Catalog of all operations/actions available in the system.
    key format: {scope}:{feature}:{action}  e.g. account:threats:read
    scope_type: platform | org | tenant | account
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(max_length=200, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    scope_type = models.CharField(max_length=50, default='account')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'operations'
        ordering = ['scope_type', 'key']

    def __str__(self):
        return self.key


class Permissions(models.Model):
    """
    Legacy permission model — key maps to Operations.key.
    Used by existing RolePermissions. New code should use Operations + RoleOperations.
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(max_length=200, unique=True)
    feature = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    tenant_scoped = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, blank=True, null=True,
        related_name='permissions_created'
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, blank=True, null=True,
        related_name='permissions_updated'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'permissions'
        ordering = ['feature', 'action']

    def __str__(self):
        return f"{self.feature}:{self.action}"


class Roles(models.Model):
    """
    RBAC Roles.
    level: 1=platform_admin, 2=org_admin, 3=group_admin, 4=tenant_admin, 5=account_admin
    scope_level: platform | organization | group | tenant | account
    tenant_scoped: True means this role is for a specific tenant context.
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    level = models.IntegerField(default=5)
    scope_level = models.CharField(max_length=50, default='account')
    tenant_scoped = models.BooleanField(default=False)
    is_system = models.BooleanField(default=False)  # True = built-in, cannot be deleted
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, blank=True, null=True,
        related_name='roles_created'
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, blank=True, null=True,
        related_name='roles_updated'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # M2M to Permissions (legacy)
    permissions = models.ManyToManyField(
        Permissions,
        through='RolePermissions',
        related_name='roles'
    )

    # M2M to Operations (new)
    operations = models.ManyToManyField(
        Operations,
        through='RoleOperations',
        related_name='roles'
    )

    class Meta:
        db_table = 'roles'
        ordering = ['level', 'name']

    def __str__(self):
        return self.name


class UserRoles(models.Model):
    """
    Assigns a role to a user. A user can have multiple roles.
    tenant_id: if role is tenant_scoped, this scopes it to a tenant.
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('Users', on_delete=models.CASCADE, db_column='user_id', related_name='user_roles')
    role = models.ForeignKey('Roles', on_delete=models.CASCADE, db_column='role_id', related_name='user_roles')
    tenant_id = models.TextField(blank=True, null=True)
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, blank=True, null=True,
        related_name='roles_assigned'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_roles'
        unique_together = (('user', 'role', 'tenant_id'),)
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['role']),
        ]


class RolePermissions(models.Model):
    """Legacy role→permission mapping."""
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.ForeignKey(Roles, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permissions, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'role_permissions'
        unique_together = ('role', 'permission')

    def __str__(self):
        return f"{self.role.name} -> {self.permission.key}"


class RoleOperations(models.Model):
    """
    Maps a role to its allowed operations.
    This is the primary RBAC grant table for new code.
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.ForeignKey(Roles, on_delete=models.CASCADE, related_name='role_operations')
    operation = models.ForeignKey(Operations, on_delete=models.CASCADE, related_name='role_operations')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'role_operations'
        unique_together = ('role', 'operation')

    def __str__(self):
        return f"{self.role.name} -> {self.operation.key}"


class UserAdminScope(models.Model):
    """
    For group_admin role: defines which specific resources the user can manage.
    scope_type: org | tenant | account
    scope_id: FK to the appropriate resource UUID
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('Users', on_delete=models.CASCADE, related_name='admin_scopes')
    scope_type = models.CharField(max_length=20)  # org | tenant | account
    scope_id = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_admin_scope'
        unique_together = ('user', 'scope_type', 'scope_id')
        indexes = [models.Index(fields=['user'])]


class UserInvitations(models.Model):
    """
    Pending user invitations.
    status: pending | accepted | expired | revoked
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.TextField()
    role = models.ForeignKey(Roles, on_delete=models.SET_NULL, blank=True, null=True)
    scope_type = models.CharField(max_length=20, blank=True, null=True)  # org|tenant|account
    scope_id = models.TextField(blank=True, null=True)
    token = models.TextField(unique=True)
    token_hint = models.CharField(max_length=16, blank=True, null=True, db_index=True)
    status = models.CharField(max_length=20, default='pending')
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, blank=True, null=True,
        related_name='invitations_sent'
    )
    accepted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, blank=True, null=True,
        related_name='invitations_accepted'
    )
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_invitations'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['token_hint']),
            models.Index(fields=['status']),
        ]
