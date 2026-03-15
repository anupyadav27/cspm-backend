from rest_framework import serializers
from .models import (
    Users, Roles, Permissions, Operations, RolePermissions,
    RoleOperations, UserRoles, UserAdminScope, UserInvitations,
    Organizations
)


class UserPublicSerializer(serializers.ModelSerializer):
    """Public-safe user fields (no password)."""
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = Users
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name', 'status',
                  'sso_provider', 'last_login', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_login']

    def get_full_name(self, obj):
        return obj.get_full_name()


class UserCreateSerializer(serializers.ModelSerializer):
    """Used for creating users (includes password write)."""
    password = serializers.CharField(write_only=True, required=True, min_length=8)

    class Meta:
        model = Users
        fields = ['id', 'email', 'password', 'first_name', 'last_name', 'status']
        read_only_fields = ['id']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = Users(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['first_name', 'last_name', 'status']


class OperationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Operations
        fields = ['id', 'key', 'name', 'description', 'scope_type', 'is_active',
                  'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class PermissionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permissions
        fields = ['id', 'key', 'feature', 'action', 'description', 'tenant_scoped',
                  'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class RoleSerializer(serializers.ModelSerializer):
    operations_count = serializers.SerializerMethodField()

    class Meta:
        model = Roles
        fields = ['id', 'name', 'description', 'level', 'scope_level',
                  'tenant_scoped', 'is_system', 'operations_count',
                  'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at', 'is_system']

    def get_operations_count(self, obj):
        return obj.role_operations.count()


class RoleDetailSerializer(RoleSerializer):
    """Full role with all operations."""
    operations = serializers.SerializerMethodField()

    class Meta(RoleSerializer.Meta):
        fields = RoleSerializer.Meta.fields + ['operations']

    def get_operations(self, obj):
        ops = Operations.objects.filter(role_operations__role=obj)
        return OperationsSerializer(ops, many=True).data


class UserRoleSerializer(serializers.ModelSerializer):
    role_name = serializers.CharField(source='role.name', read_only=True)
    role_level = serializers.IntegerField(source='role.level', read_only=True)
    role_scope = serializers.CharField(source='role.scope_level', read_only=True)

    class Meta:
        model = UserRoles
        fields = ['id', 'user', 'role', 'role_name', 'role_level', 'role_scope',
                  'tenant_id', 'created_at']
        read_only_fields = ['id', 'created_at']


class UserAdminScopeSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAdminScope
        fields = ['id', 'user', 'scope_type', 'scope_id', 'created_at']
        read_only_fields = ['id', 'created_at']


class UserInvitationSerializer(serializers.ModelSerializer):
    role_name = serializers.CharField(source='role.name', read_only=True)
    invited_by_email = serializers.CharField(source='invited_by.email', read_only=True)

    class Meta:
        model = UserInvitations
        fields = ['id', 'email', 'role', 'role_name', 'scope_type', 'scope_id',
                  'status', 'invited_by_email', 'expires_at', 'created_at', 'updated_at']
        read_only_fields = ['id', 'status', 'created_at', 'updated_at']


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organizations
        fields = ['id', 'name', 'description', 'status', 'plan',
                  'contact_email', 'region', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class InviteAcceptSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    password = serializers.CharField(required=True, min_length=8, write_only=True)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("New passwords do not match.")
        return data
