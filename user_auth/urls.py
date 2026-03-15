from django.urls import path
from djangosaml2 import views as saml2_views

from user_auth.views.local_auth import LoginView, RefreshTokenView, LogoutView, csrf
from user_auth.views.saml_auth import SamlSuccessBridgeView
from user_auth.views.user_views import (
    MeView, ChangePasswordView,
    UserListCreateView, UserDetailView, UserRolesView,
    SessionListView, SessionRevokeView,
)
from user_auth.views.rbac_views import (
    RoleListCreateView, RoleDetailView, RoleOperationsView,
    OperationListCreateView, OperationDetailView,
    UserRoleAssignView, UserRoleRemoveView,
)
from user_auth.views.org_views import OrganizationListCreateView, OrganizationDetailView
from user_auth.views.invitation_views import (
    InviteUserView, AcceptInviteView, InvitationListView, InvitationRevokeView,
)

urlpatterns = [
    # ── CSRF ──────────────────────────────────────────────────────────────────
    path("csrf/", csrf, name="csrf"),

    # ── LOCAL AUTH ────────────────────────────────────────────────────────────
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', RefreshTokenView.as_view(), name='refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),

    # ── SAML AUTH ─────────────────────────────────────────────────────────────
    path('saml/login/', saml2_views.LoginView.as_view(), name='saml_login'),
    path('saml/acs/', saml2_views.AssertionConsumerServiceView.as_view(), name='saml_acs'),
    path('saml/acs/logout/', saml2_views.LogoutView.as_view(), name='saml_logout'),
    path('saml/metadata/', saml2_views.MetadataView.as_view(), name='saml_metadata'),
    path('saml/success/', SamlSuccessBridgeView.as_view(), name='saml_success'),

    # ── CURRENT USER ──────────────────────────────────────────────────────────
    path('me/', MeView.as_view(), name='me'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),

    # ── USER MANAGEMENT ───────────────────────────────────────────────────────
    path('users/', UserListCreateView.as_view(), name='user_list_create'),
    path('users/<str:user_id>/', UserDetailView.as_view(), name='user_detail'),
    path('users/<str:user_id>/roles/', UserRolesView.as_view(), name='user_roles_list'),
    path('users/<str:user_id>/assign-role/', UserRoleAssignView.as_view(), name='user_role_assign'),
    path('users/<str:user_id>/roles/<str:role_id>/', UserRoleRemoveView.as_view(), name='user_role_remove'),

    # ── SESSIONS ──────────────────────────────────────────────────────────────
    path('sessions/', SessionListView.as_view(), name='session_list'),
    path('sessions/<str:session_id>/', SessionRevokeView.as_view(), name='session_revoke'),

    # ── RBAC — ROLES ──────────────────────────────────────────────────────────
    path('roles/', RoleListCreateView.as_view(), name='role_list_create'),
    path('roles/<str:role_id>/', RoleDetailView.as_view(), name='role_detail'),
    path('roles/<str:role_id>/operations/', RoleOperationsView.as_view(), name='role_operations'),

    # ── RBAC — OPERATIONS ─────────────────────────────────────────────────────
    path('operations/', OperationListCreateView.as_view(), name='operation_list_create'),
    path('operations/<str:op_id>/', OperationDetailView.as_view(), name='operation_detail'),

    # ── ORGANIZATIONS ─────────────────────────────────────────────────────────
    path('organizations/', OrganizationListCreateView.as_view(), name='org_list_create'),
    path('organizations/<str:org_id>/', OrganizationDetailView.as_view(), name='org_detail'),

    # ── INVITATIONS ───────────────────────────────────────────────────────────
    path('invite/', InviteUserView.as_view(), name='invite'),
    path('invite/accept/', AcceptInviteView.as_view(), name='invite_accept'),
    path('invitations/', InvitationListView.as_view(), name='invitation_list'),
    path('invitations/<str:invitation_id>/', InvitationRevokeView.as_view(), name='invitation_revoke'),
]
