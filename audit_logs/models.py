"""
Audit logging model.
Tracks all significant actions for compliance + security.
"""
import uuid
from django.db import models
from django.conf import settings


class AuditLog(models.Model):
    """
    Immutable audit trail. Rows are never updated or deleted.

    action_type: create | read | update | delete | login | logout |
                 scan_trigger | invite | role_assign | etc.
    resource_type: user | tenant | role | operation | organization | scan | etc.
    status: success | failure | denied
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)

    # Who did it
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='audit_logs',
    )
    user_email = models.TextField(blank=True, null=True)    # snapshot in case user is deleted

    # What was done
    action_type = models.CharField(max_length=100)          # e.g., 'create', 'login'
    resource_type = models.CharField(max_length=100, blank=True, null=True)
    resource_id = models.TextField(blank=True, null=True)
    resource_name = models.TextField(blank=True, null=True)

    # Context
    tenant_id = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, default='success')  # success|failure|denied
    details = models.JSONField(default=dict, blank=True, null=True)

    # Request metadata
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    request_method = models.CharField(max_length=10, blank=True, null=True)
    request_path = models.TextField(blank=True, null=True)
    response_status = models.IntegerField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['action_type']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['tenant_id']),
            models.Index(fields=['created_at']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.user_email} | {self.action_type} | {self.resource_type}:{self.resource_id}"
