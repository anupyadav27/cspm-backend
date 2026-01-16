import uuid
from django.db import models
from tenant_management.models import Tenants
from threats_management.models import Threat

class Asset(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="assets",
        null=True,
        blank=True
    )
    name = models.TextField()
    resource_id = models.TextField()
    resource_type = models.TextField()
    provider = models.TextField(blank=True, null=True)
    region = models.TextField(blank=True, null=True)
    environment = models.TextField(blank=True, null=True)
    category = models.TextField(blank=True, null=True)
    lifecycle_state = models.TextField(blank=True, null=True)
    health_status = models.TextField(blank=True, null=True)
    metadata = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'assets'
        indexes = [
            models.Index(fields=['tenant', 'resource_type']),
            models.Index(fields=['tenant', 'environment']),
            models.Index(fields=['resource_id']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'resource_id'],
                name='unique_tenant_resource'
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.resource_id})"


class AssetTag(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(
        Asset,
        on_delete=models.CASCADE,
        related_name="tags"
    )
    tag_key = models.TextField()
    tag_value = models.TextField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'asset_tags'
        indexes = [
            models.Index(fields=['asset', 'tag_key']),
            models.Index(fields=['tag_key', 'tag_value']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['asset', 'tag_key'],
                name='unique_asset_tag_key'
            )
        ]

    def __str__(self):
        return f"{self.asset.name}: {self.tag_key}={self.tag_value}"


class AssetCompliance(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(
        Asset,
        on_delete=models.CASCADE,
        related_name="compliance_links"
    )
    compliance_id = models.TextField()
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'asset_compliance'
        indexes = [
            models.Index(fields=['asset']),
            models.Index(fields=['compliance_id']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['asset', 'compliance_id'],
                name='unique_asset_compliance'
            )
        ]


class AssetThreat(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(
        Asset,
        on_delete=models.CASCADE,
        related_name="threat_links"
    )
    threat = models.ForeignKey(
        Threat,
        on_delete=models.CASCADE,
        related_name="asset_links",
        db_column='threat_id',
        null=True,
        blank=True
    )
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'asset_threats'
        indexes = [
            models.Index(fields=['asset']),
            models.Index(fields=['threat']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['asset', 'threat'],
                name='unique_asset_threat'
            )
        ]


class Agent(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    agent_id = models.TextField(unique=True)
    hostname = models.TextField(blank=True, null=True)
    platform = models.TextField(blank=True, null=True)
    architecture = models.TextField(blank=True, null=True)
    agent_version = models.TextField(blank=True, null=True)
    metadata = models.JSONField(blank=True, null=True)
    first_seen = models.DateTimeField(blank=True, null=True)
    last_seen = models.DateTimeField(blank=True, null=True)
    status = models.TextField(blank=True, null=True)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="agents",
        null=True,
        blank=True
    )
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'agents'
        indexes = [
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['agent_id']),
        ]

    def __str__(self):
        return f"{self.hostname} ({self.agent_id})"