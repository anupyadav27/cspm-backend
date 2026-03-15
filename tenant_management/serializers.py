from rest_framework import serializers
from .models import Tenants, TenantUsers


class TenantSerializer(serializers.ModelSerializer):
    created_by_email = serializers.SerializerMethodField()

    class Meta:
        model = Tenants
        fields = [
            "id", "name", "description", "status", "plan",
            "contact_email", "region", "created_by_email",
            "created_at", "updated_at"
        ]
        read_only_fields = ["id", "created_at", "updated_at", "created_by_email"]

    def get_created_by_email(self, obj):
        return obj.created_by.email if obj.created_by else None


class TenantUsersSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()
    role_name = serializers.CharField(source='role.name', read_only=True)

    class Meta:
        model = TenantUsers
        fields = ['id', 'user', 'user_email', 'user_name', 'role', 'role_name', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at', 'user_email', 'user_name', 'role_name']

    def get_user_name(self, obj):
        return obj.user.get_full_name() if obj.user else None
