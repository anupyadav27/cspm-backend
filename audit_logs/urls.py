from django.urls import path
from .views import AuditLogListView, AuditLogDetailView, AuditLogExportView, AuditActionTypesView

urlpatterns = [
    path('', AuditLogListView.as_view(), name='audit_log_list'),
    path('export/', AuditLogExportView.as_view(), name='audit_log_export'),
    path('action-types/', AuditActionTypesView.as_view(), name='audit_action_types'),
    path('<str:log_id>/', AuditLogDetailView.as_view(), name='audit_log_detail'),
]
