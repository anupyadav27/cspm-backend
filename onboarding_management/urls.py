
from django.urls import path
from . import views

urlpatterns = [
    path("cloud-accounts/", views.CloudAccountListView.as_view(), name="cloud-account-list"),
    path("cloud-accounts/<str:account_id>/", views.CloudAccountDetailView.as_view(), name="cloud-account-detail"),
    path("cloud-accounts/<str:account_id>/validate/", views.CloudAccountValidateView.as_view(), name="cloud-account-validate"),
    path("cloud-accounts/<str:account_id>/credentials/", views.CredentialStoreView.as_view(), name="cloud-account-credentials"),
    path("cloud-accounts/<str:account_id>/status/", views.AccountStatusView.as_view(), name="cloud-account-status"),
    path("cloud-accounts/<str:account_id>/activate/", views.AccountActivateView.as_view(), name="cloud-account-activate"),

    path("scan/trigger/", views.ScanTriggerView.as_view(), name="scan-trigger"),
    path("scan/<str:orchestration_id>/status/", views.ScanStatusView.as_view(), name="scan-status"),

    path("engine-health/", views.EngineHealthView.as_view(), name="engine-health"),

    path("dashboard-summary/", views.DashboardSummaryView.as_view(), name="dashboard-summary"),
]
