"""
Management command: create_platform_admin

Creates a platform_admin user with full access.

Usage:
    python manage.py create_platform_admin --email admin@example.com --password secret123
    python manage.py create_platform_admin  # prompts for input
"""
from django.core.management.base import BaseCommand
from django.utils import timezone


class Command(BaseCommand):
    help = 'Create a platform_admin user with full system access.'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, help='Admin email address')
        parser.add_argument('--password', type=str, help='Admin password')
        parser.add_argument('--first-name', type=str, default='Platform')
        parser.add_argument('--last-name', type=str, default='Admin')

    def handle(self, *args, **options):
        from user_auth.models import Users, Roles, UserRoles

        email = options.get('email') or input('Enter admin email: ').strip()
        password = options.get('password') or input('Enter admin password: ').strip()
        first_name = options.get('first_name', 'Platform')
        last_name = options.get('last_name', 'Admin')

        if not email or not password:
            self.stderr.write(self.style.ERROR('Email and password are required.'))
            return

        if len(password) < 8:
            self.stderr.write(self.style.ERROR('Password must be at least 8 characters.'))
            return

        # Get or create user
        user, created = Users.objects.get_or_create(
            email=email,
            defaults={
                'first_name': first_name,
                'last_name': last_name,
                'status': 'active',
                'is_staff': True,
                'is_superuser': True,
            }
        )

        if created:
            user.set_password(password)
            user.save(update_fields=['password'])
            self.stdout.write(f'✓ Created user: {email}')
        else:
            self.stdout.write(f'⚠ User already exists: {email}')

        # Assign platform_admin role
        try:
            role = Roles.objects.get(name='platform_admin')
        except Roles.DoesNotExist:
            self.stderr.write(
                self.style.ERROR(
                    'platform_admin role not found. Run: python manage.py seed_rbac first.'
                )
            )
            return

        ur, assigned = UserRoles.objects.get_or_create(
            user=user,
            role=role,
            tenant_id=None,
        )

        if assigned:
            self.stdout.write(f'✓ Assigned role: platform_admin')
        else:
            self.stdout.write('⚠ User already has platform_admin role')

        self.stdout.write(self.style.SUCCESS(f'\n✅ Platform admin ready: {email}'))
