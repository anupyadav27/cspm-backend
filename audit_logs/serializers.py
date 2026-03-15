from rest_framework import serializers
from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    user_email = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = [
            'id', 'user_email', 'action_type', 'resource_type', 'resource_id',
            'resource_name', 'tenant_id', 'status', 'details',
            'ip_address', 'user_agent', 'request_method', 'request_path',
            'response_status', 'created_at',
        ]
        read_only_fields = fields

    def get_user_email(self, obj):
        return obj.user_email or (obj.user.email if obj.user else None)
