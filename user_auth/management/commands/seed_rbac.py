"""
Management command: seed_rbac

Seeds the 5 built-in roles and 56 operations into the database.
Also creates the RoleOperations mappings as per the RBAC spec.

Usage:
    python manage.py seed_rbac
    python manage.py seed_rbac --reset  # Clears existing and re-seeds
"""
from django.core.management.base import BaseCommand
from user_auth.models import Operations, Roles, RoleOperations


# 56 operations across 4 scopes
ALL_OPERATIONS = [
    # Platform scope (14)
    {'key': 'platform:orgs:read', 'name': 'View Organizations', 'scope_type': 'platform'},
    {'key': 'platform:orgs:write', 'name': 'Manage Organizations', 'scope_type': 'platform'},
    {'key': 'platform:users:read', 'name': 'View All Users', 'scope_type': 'platform'},
    {'key': 'platform:users:write', 'name': 'Manage All Users', 'scope_type': 'platform'},
    {'key': 'platform:roles:read', 'name': 'View Roles', 'scope_type': 'platform'},
    {'key': 'platform:roles:write', 'name': 'Manage Roles', 'scope_type': 'platform'},
    {'key': 'platform:settings:read', 'name': 'View Platform Settings', 'scope_type': 'platform'},
    {'key': 'platform:settings:write', 'name': 'Modify Platform Settings', 'scope_type': 'platform'},
    {'key': 'platform:billing:read', 'name': 'View Billing', 'scope_type': 'platform'},
    {'key': 'platform:billing:write', 'name': 'Modify Billing', 'scope_type': 'platform'},
    {'key': 'platform:audit:read', 'name': 'View Platform Audit Logs', 'scope_type': 'platform'},
    {'key': 'platform:engines:read', 'name': 'View Engine Status', 'scope_type': 'platform'},
    {'key': 'platform:engines:write', 'name': 'Manage Engines', 'scope_type': 'platform'},
    {'key': 'platform:engines:execute', 'name': 'Start/Stop Engines', 'scope_type': 'platform'},

    # Organization scope (12)
    {'key': 'org:tenants:read', 'name': 'View Tenants', 'scope_type': 'org'},
    {'key': 'org:tenants:write', 'name': 'Manage Tenants', 'scope_type': 'org'},
    {'key': 'org:users:read', 'name': 'View Org Users', 'scope_type': 'org'},
    {'key': 'org:users:write', 'name': 'Manage Org Users', 'scope_type': 'org'},
    {'key': 'org:settings:read', 'name': 'View Org Settings', 'scope_type': 'org'},
    {'key': 'org:settings:write', 'name': 'Modify Org Settings', 'scope_type': 'org'},
    {'key': 'org:billing:read', 'name': 'View Org Billing', 'scope_type': 'org'},
    {'key': 'org:audit:read', 'name': 'View Org Audit Logs', 'scope_type': 'org'},
    {'key': 'org:dashboard:read', 'name': 'View Org Dashboard', 'scope_type': 'org'},
    {'key': 'org:reports:read', 'name': 'View Org Reports', 'scope_type': 'org'},
    {'key': 'org:reports:write', 'name': 'Create Org Reports', 'scope_type': 'org'},
    {'key': 'org:policies:write', 'name': 'Manage Org Policies', 'scope_type': 'org'},

    # Tenant scope (14)
    {'key': 'tenant:accounts:read', 'name': 'View Accounts', 'scope_type': 'tenant'},
    {'key': 'tenant:accounts:write', 'name': 'Manage Accounts', 'scope_type': 'tenant'},
    {'key': 'tenant:users:read', 'name': 'View Tenant Users', 'scope_type': 'tenant'},
    {'key': 'tenant:users:write', 'name': 'Manage Tenant Users', 'scope_type': 'tenant'},
    {'key': 'tenant:settings:read', 'name': 'View Tenant Settings', 'scope_type': 'tenant'},
    {'key': 'tenant:settings:write', 'name': 'Modify Tenant Settings', 'scope_type': 'tenant'},
    {'key': 'tenant:scans:read', 'name': 'View Scan Results', 'scope_type': 'tenant'},
    {'key': 'tenant:scans:execute', 'name': 'Trigger Scans', 'scope_type': 'tenant'},
    {'key': 'tenant:schedules:read', 'name': 'View Scan Schedules', 'scope_type': 'tenant'},
    {'key': 'tenant:schedules:write', 'name': 'Manage Scan Schedules', 'scope_type': 'tenant'},
    {'key': 'tenant:dashboard:read', 'name': 'View Tenant Dashboard', 'scope_type': 'tenant'},
    {'key': 'tenant:reports:read', 'name': 'View Tenant Reports', 'scope_type': 'tenant'},
    {'key': 'tenant:policies:read', 'name': 'View Tenant Policies', 'scope_type': 'tenant'},
    {'key': 'tenant:policies:write', 'name': 'Manage Tenant Policies', 'scope_type': 'tenant'},

    # Account scope (16)
    {'key': 'account:dashboard:read', 'name': 'View Account Dashboard', 'scope_type': 'account'},
    {'key': 'account:assets:read', 'name': 'View Discovered Assets', 'scope_type': 'account'},
    {'key': 'account:threats:read', 'name': 'View Threat Findings', 'scope_type': 'account'},
    {'key': 'account:threats:write', 'name': 'Update Threat Status', 'scope_type': 'account'},
    {'key': 'account:compliance:read', 'name': 'View Compliance Results', 'scope_type': 'account'},
    {'key': 'account:compliance:write', 'name': 'Manage Compliance Rules', 'scope_type': 'account'},
    {'key': 'account:inventory:read', 'name': 'View Resource Inventory', 'scope_type': 'account'},
    {'key': 'account:datasec:read', 'name': 'View Data Security Findings', 'scope_type': 'account'},
    {'key': 'account:datasec:write', 'name': 'Manage Data Security Rules', 'scope_type': 'account'},
    {'key': 'account:secops:read', 'name': 'View SecOps Scan Results', 'scope_type': 'account'},
    {'key': 'account:secops:execute', 'name': 'Trigger SecOps Scans', 'scope_type': 'account'},
    {'key': 'account:scans:read', 'name': 'View Scan History', 'scope_type': 'account'},
    {'key': 'account:scans:execute', 'name': 'Trigger Account Scan', 'scope_type': 'account'},
    {'key': 'account:settings:read', 'name': 'View Account Settings', 'scope_type': 'account'},
    {'key': 'account:settings:write', 'name': 'Modify Account Config', 'scope_type': 'account'},
    {'key': 'account:credentials:write', 'name': 'Update Cloud Credentials', 'scope_type': 'account'},
]

# 5 system roles with their operation sets
ROLES = [
    {
        'name': 'platform_admin',
        'description': 'SaaS provider admin — full access to all orgs, tenants, accounts',
        'level': 1,
        'scope_level': 'platform',
        'operations': [op['key'] for op in ALL_OPERATIONS],  # All 56
    },
    {
        'name': 'org_admin',
        'description': 'Customer org admin — manages all tenants + accounts under their org',
        'level': 2,
        'scope_level': 'organization',
        'operations': [op['key'] for op in ALL_OPERATIONS if op['scope_type'] in ('org', 'tenant', 'account')],
    },
    {
        'name': 'group_admin',
        'description': 'Manages a selected group of orgs, tenants, or accounts',
        'level': 3,
        'scope_level': 'group',
        'operations': [op['key'] for op in ALL_OPERATIONS if op['scope_type'] in ('org', 'tenant', 'account')],
    },
    {
        'name': 'tenant_admin',
        'description': 'Manages one tenant and all accounts under it',
        'level': 4,
        'scope_level': 'tenant',
        'tenant_scoped': True,
        'operations': [op['key'] for op in ALL_OPERATIONS if op['scope_type'] in ('tenant', 'account')],
    },
    {
        'name': 'account_admin',
        'description': 'Manages one specific cloud account only',
        'level': 5,
        'scope_level': 'account',
        'tenant_scoped': True,
        'operations': [op['key'] for op in ALL_OPERATIONS if op['scope_type'] == 'account'],
    },
]


class Command(BaseCommand):
    help = 'Seed RBAC operations and roles into the database.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Delete existing system roles and operations before seeding.',
        )

    def handle(self, *args, **options):
        if options['reset']:
            self.stdout.write(self.style.WARNING('Resetting system roles and operations...'))
            Operations.objects.all().delete()
            Roles.objects.filter(is_system=True).delete()

        # 1. Seed operations
        self.stdout.write('Seeding operations...')
        op_objects = {}
        created_ops = 0
        for op_data in ALL_OPERATIONS:
            op, created = Operations.objects.update_or_create(
                key=op_data['key'],
                defaults={
                    'name': op_data['name'],
                    'scope_type': op_data['scope_type'],
                    'is_active': True,
                }
            )
            op_objects[op.key] = op
            if created:
                created_ops += 1

        self.stdout.write(f'  ✓ {created_ops} new operations, {len(ALL_OPERATIONS) - created_ops} already existed')

        # 2. Seed roles + role-operation mappings
        self.stdout.write('Seeding roles...')
        for role_data in ROLES:
            role, created = Roles.objects.update_or_create(
                name=role_data['name'],
                defaults={
                    'description': role_data['description'],
                    'level': role_data['level'],
                    'scope_level': role_data['scope_level'],
                    'tenant_scoped': role_data.get('tenant_scoped', False),
                    'is_system': True,
                }
            )

            # Assign operations
            role_ops_created = 0
            for key in role_data['operations']:
                if key in op_objects:
                    _, c = RoleOperations.objects.get_or_create(role=role, operation=op_objects[key])
                    if c:
                        role_ops_created += 1

            action = 'Created' if created else 'Updated'
            self.stdout.write(
                f'  ✓ {action} role "{role.name}" '
                f'(level={role.level}, {len(role_data["operations"])} operations, {role_ops_created} new assignments)'
            )

        self.stdout.write(self.style.SUCCESS('\n[DONE] RBAC seeding complete!'))
        self.stdout.write(f'   Total operations: {Operations.objects.count()}')
        self.stdout.write(f'   Total roles:      {Roles.objects.count()}')
        self.stdout.write(f'   Total assignments: {RoleOperations.objects.count()}')
