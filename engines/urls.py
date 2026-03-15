"""
Engine proxy URL configuration.
All routes are under /api/engines/ prefix (set in config/urls.py).

Example full URLs:
  GET /api/engines/inventory/assets/
  GET /api/engines/threat/threats/
  POST /api/engines/threat/generate/
  GET /api/engines/compliance/dashboard/
  POST /api/engines/secops/scan/
  POST /api/engines/iam/scan/
"""
from django.urls import path

# ── Inventory Engine ──────────────────────────────────────────────────────────
from engines.views.inventory import (
    InventoryLatestSummaryView, InventoryScanSummaryView, InventoryScansListView,
    InventoryScanTriggerView, InventoryScanAsyncView, InventoryJobStatusView,
    InventoryAssetListView, InventoryAssetDetailView, InventoryAssetRelationshipsView,
    InventoryRelationshipsView, InventoryGraphView, InventoryDriftView,
    InventoryAccountView, InventoryServiceView,
)

# ── Threat Engine ─────────────────────────────────────────────────────────────
from engines.views.threat import (
    ThreatGenerateView, ThreatGenerateAsyncView, ThreatJobStatusView,
    ThreatListView, ThreatDetailView, ThreatMisconfigFindingsView, ThreatAssetsView,
    ThreatSummaryView, ThreatReportsView, ThreatReportDetailView,
    ThreatAnalysisRunView, ThreatAnalysisPrioritizedView,
    ThreatAnalysisDetailView, ThreatAnalysisListView,
    GraphBuildView, GraphSummaryView, GraphAttackPathsView, GraphInternetExposedView,
    GraphBlastRadiusView, GraphToxicCombinationsView, GraphResourceView,
    IntelFeedView, IntelFeedBatchView, IntelListView, IntelCorrelateView,
    HuntPredefinedView, HuntExecuteView, HuntQueriesView, HuntResultsView,
    ThreatMapGeographicView, ThreatMapAccountView, ThreatMapServiceView,
    ThreatAnalyticsTrendView, ThreatAnalyticsPatternsView,
    ThreatAnalyticsDistributionView, ThreatAnalyticsCorrelationView,
    ThreatRemediationQueueView, ThreatRemediationView,
    ThreatDriftView, ThreatResourcePostureView, ThreatResourceThreatsView,
    ThreatScanSummaryView,
)

# ── Compliance Engine ─────────────────────────────────────────────────────────
from engines.views.compliance import (
    ComplianceGenerateView, ComplianceGenerateFromCheckDbView,
    ComplianceGenerateEnterpriseView,
    ComplianceReportDetailView, ComplianceReportExportView,
    ComplianceReportsListView, ComplianceReportStatusView,
    ComplianceDashboardView, ComplianceFrameworksView,
    ComplianceFrameworkStatusView, ComplianceFrameworkDetailView,
    ComplianceFrameworkStructureView, ComplianceFrameworkControlsGroupedView,
    ComplianceFrameworkResourcesGroupedView, ComplianceControlDetailView,
    ComplianceResourceComplianceView, ComplianceResourceDrilldownView,
    ComplianceAccountView, ComplianceTrendsView, ComplianceControlsSearchView,
    ComplianceFrameworkDownloadPdfView, ComplianceFrameworkDownloadExcelView,
    ComplianceReportDownloadPdfView, ComplianceReportDownloadExcelView,
)

# ── IAM Engine ────────────────────────────────────────────────────────────────
from engines.views.iam import (
    IAMScanView, IAMFindingsView, IAMRuleDetailView,
    IAMModulesView, IAMModuleRulesView, IAMRuleIdsView,
)

# ── DataSec Engine ────────────────────────────────────────────────────────────
from engines.views.datasec import (
    DataSecScanView, DataSecFindingsView, DataSecReportsView,
    DataSecReportDetailView, DataSecDataAssetsView, DataSecSummaryView,
)

# ── SecOps Engine ─────────────────────────────────────────────────────────────
from engines.views.secops import (
    SecOpsScanUploadView, SecOpsScanLocalView, SecOpsScansListView,
    SecOpsScanDetailView, SecOpsScanFindingsView, SecOpsResultsView,
)

# ── Check Engine ──────────────────────────────────────────────────────────────
from engines.views.check import (
    CheckScanView, CheckFindingsView, CheckFindingDetailView,
    CheckReportView, CheckReportsListView, CheckRulesView,
    CheckRuleDetailView, CheckSummaryView,
)

# ── Discoveries Engine ────────────────────────────────────────────────────────
from engines.views.discoveries import (
    DiscoveryScanView, DiscoveryFindingsView, DiscoveryFindingDetailView,
    DiscoveryReportsView, DiscoveryReportDetailView,
    DiscoverySummaryView, DiscoveryJobStatusView,
)

# ── Rule Engine ───────────────────────────────────────────────────────────────
from engines.views.rule import (
    RulesListView, RuleDetailView, RuleCreateView,
    ProvidersListView, ProviderRulesView, RuleValidateView,
)

urlpatterns = [

    # ─────────────────────────────────────────────────────────────────────────
    # INVENTORY ENGINE  /api/engines/inventory/
    # ─────────────────────────────────────────────────────────────────────────
    path('inventory/runs/latest/summary/', InventoryLatestSummaryView.as_view()),
    path('inventory/runs/<str:scan_run_id>/summary/', InventoryScanSummaryView.as_view()),
    path('inventory/scans/', InventoryScansListView.as_view()),
    path('inventory/scan/', InventoryScanTriggerView.as_view()),
    path('inventory/scan/async/', InventoryScanAsyncView.as_view()),
    path('inventory/jobs/<str:job_id>/', InventoryJobStatusView.as_view()),
    path('inventory/assets/', InventoryAssetListView.as_view()),
    path('inventory/assets/<path:resource_uid>/relationships/', InventoryAssetRelationshipsView.as_view()),
    path('inventory/assets/<path:resource_uid>/', InventoryAssetDetailView.as_view()),
    path('inventory/relationships/', InventoryRelationshipsView.as_view()),
    path('inventory/graph/', InventoryGraphView.as_view()),
    path('inventory/drift/', InventoryDriftView.as_view()),
    path('inventory/accounts/<str:account_id>/', InventoryAccountView.as_view()),
    path('inventory/services/<str:service>/', InventoryServiceView.as_view()),

    # ─────────────────────────────────────────────────────────────────────────
    # THREAT ENGINE  /api/engines/threat/
    # ─────────────────────────────────────────────────────────────────────────
    path('threat/generate/', ThreatGenerateView.as_view()),
    path('threat/generate/async/', ThreatGenerateAsyncView.as_view()),
    path('threat/jobs/<str:job_id>/', ThreatJobStatusView.as_view()),
    path('threat/threats/', ThreatListView.as_view()),
    path('threat/threats/<str:threat_id>/', ThreatDetailView.as_view()),
    path('threat/threats/<str:threat_id>/misconfig-findings/', ThreatMisconfigFindingsView.as_view()),
    path('threat/threats/<str:threat_id>/assets/', ThreatAssetsView.as_view()),
    path('threat/threats/<str:threat_id>/remediation/', ThreatRemediationView.as_view()),
    path('threat/summary/', ThreatSummaryView.as_view()),
    path('threat/reports/', ThreatReportsView.as_view()),
    path('threat/reports/<str:scan_run_id>/', ThreatReportDetailView.as_view()),
    path('threat/scans/<str:scan_run_id>/summary/', ThreatScanSummaryView.as_view()),
    path('threat/analysis/run/', ThreatAnalysisRunView.as_view()),
    path('threat/analysis/prioritized/', ThreatAnalysisPrioritizedView.as_view()),
    path('threat/analysis/', ThreatAnalysisListView.as_view()),
    path('threat/analysis/<str:detection_id>/', ThreatAnalysisDetailView.as_view()),
    path('threat/map/geographic/', ThreatMapGeographicView.as_view()),
    path('threat/map/account/', ThreatMapAccountView.as_view()),
    path('threat/map/service/', ThreatMapServiceView.as_view()),
    path('threat/analytics/trend/', ThreatAnalyticsTrendView.as_view()),
    path('threat/analytics/patterns/', ThreatAnalyticsPatternsView.as_view()),
    path('threat/analytics/distribution/', ThreatAnalyticsDistributionView.as_view()),
    path('threat/analytics/correlation/', ThreatAnalyticsCorrelationView.as_view()),
    path('threat/remediation/queue/', ThreatRemediationQueueView.as_view()),
    path('threat/drift/', ThreatDriftView.as_view()),
    path('threat/resources/<path:resource_uid>/posture/', ThreatResourcePostureView.as_view()),
    path('threat/resources/<path:resource_uid>/threats/', ThreatResourceThreatsView.as_view()),

    # Security Graph
    path('graph/build/', GraphBuildView.as_view()),
    path('graph/summary/', GraphSummaryView.as_view()),
    path('graph/attack-paths/', GraphAttackPathsView.as_view()),
    path('graph/internet-exposed/', GraphInternetExposedView.as_view()),
    path('graph/blast-radius/<path:resource_uid>/', GraphBlastRadiusView.as_view()),
    path('graph/toxic-combinations/', GraphToxicCombinationsView.as_view()),
    path('graph/resource/<path:resource_uid>/', GraphResourceView.as_view()),

    # Threat Intel
    path('intel/feed/', IntelFeedView.as_view()),
    path('intel/feed/batch/', IntelFeedBatchView.as_view()),
    path('intel/', IntelListView.as_view()),
    path('intel/correlate/', IntelCorrelateView.as_view()),

    # Threat Hunting
    path('hunt/predefined/', HuntPredefinedView.as_view()),
    path('hunt/execute/', HuntExecuteView.as_view()),
    path('hunt/queries/', HuntQueriesView.as_view()),
    path('hunt/results/', HuntResultsView.as_view()),

    # ─────────────────────────────────────────────────────────────────────────
    # COMPLIANCE ENGINE  /api/engines/compliance/
    # ─────────────────────────────────────────────────────────────────────────
    path('compliance/generate/', ComplianceGenerateView.as_view()),
    path('compliance/generate/from-check-db/', ComplianceGenerateFromCheckDbView.as_view()),
    path('compliance/generate/enterprise/', ComplianceGenerateEnterpriseView.as_view()),
    path('compliance/reports/', ComplianceReportsListView.as_view()),
    path('compliance/reports/<str:report_id>/status/', ComplianceReportStatusView.as_view()),
    path('compliance/report/<str:report_id>/export/', ComplianceReportExportView.as_view()),
    path('compliance/report/<str:report_id>/download/pdf/', ComplianceReportDownloadPdfView.as_view()),
    path('compliance/report/<str:report_id>/download/excel/', ComplianceReportDownloadExcelView.as_view()),
    path('compliance/report/<str:report_id>/', ComplianceReportDetailView.as_view()),
    path('compliance/dashboard/', ComplianceDashboardView.as_view()),
    path('compliance/frameworks/', ComplianceFrameworksView.as_view()),
    path('compliance/framework/<str:framework>/status/', ComplianceFrameworkStatusView.as_view()),
    path('compliance/framework/<str:framework>/structure/', ComplianceFrameworkStructureView.as_view()),
    path('compliance/framework/<str:framework>/controls/grouped/', ComplianceFrameworkControlsGroupedView.as_view()),
    path('compliance/framework/<str:framework>/resources/grouped/', ComplianceFrameworkResourcesGroupedView.as_view()),
    path('compliance/framework/<str:framework>/download/pdf/', ComplianceFrameworkDownloadPdfView.as_view()),
    path('compliance/framework/<str:framework>/download/excel/', ComplianceFrameworkDownloadExcelView.as_view()),
    path('compliance/framework-detail/<str:framework>/', ComplianceFrameworkDetailView.as_view()),
    path('compliance/control-detail/<str:framework>/<str:control>/', ComplianceControlDetailView.as_view()),
    path('compliance/resource/<path:resource_uid>/compliance/', ComplianceResourceComplianceView.as_view()),
    path('compliance/resource/drilldown/', ComplianceResourceDrilldownView.as_view()),
    path('compliance/accounts/<str:account_id>/', ComplianceAccountView.as_view()),
    path('compliance/trends/', ComplianceTrendsView.as_view()),
    path('compliance/controls/search/', ComplianceControlsSearchView.as_view()),

    # ─────────────────────────────────────────────────────────────────────────
    # IAM ENGINE  /api/engines/iam/
    # ─────────────────────────────────────────────────────────────────────────
    path('iam/scan/', IAMScanView.as_view()),
    path('iam/findings/', IAMFindingsView.as_view()),
    path('iam/rules/<str:rule_id>/', IAMRuleDetailView.as_view()),
    path('iam/modules/', IAMModulesView.as_view()),
    path('iam/modules/<str:module>/rules/', IAMModuleRulesView.as_view()),
    path('iam/rule-ids/', IAMRuleIdsView.as_view()),

    # ─────────────────────────────────────────────────────────────────────────
    # DATASEC ENGINE  /api/engines/datasec/
    # ─────────────────────────────────────────────────────────────────────────
    path('datasec/scan/', DataSecScanView.as_view()),
    path('datasec/findings/', DataSecFindingsView.as_view()),
    path('datasec/reports/', DataSecReportsView.as_view()),
    path('datasec/reports/<str:report_id>/', DataSecReportDetailView.as_view()),
    path('datasec/data-assets/', DataSecDataAssetsView.as_view()),
    path('datasec/summary/', DataSecSummaryView.as_view()),

    # ─────────────────────────────────────────────────────────────────────────
    # SECOPS ENGINE  /api/engines/secops/
    # ─────────────────────────────────────────────────────────────────────────
    path('secops/scan/', SecOpsScanUploadView.as_view()),
    path('secops/scan-local/', SecOpsScanLocalView.as_view()),
    path('secops/scans/', SecOpsScansListView.as_view()),
    path('secops/scans/<str:scan_id>/findings/', SecOpsScanFindingsView.as_view()),
    path('secops/scans/<str:scan_id>/', SecOpsScanDetailView.as_view()),
    path('secops/results/<str:project_name>/', SecOpsResultsView.as_view()),

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK ENGINE  /api/engines/check/
    # ─────────────────────────────────────────────────────────────────────────
    path('check/scan/', CheckScanView.as_view()),
    path('check/findings/', CheckFindingsView.as_view()),
    path('check/findings/<str:finding_id>/', CheckFindingDetailView.as_view()),
    path('check/reports/', CheckReportsListView.as_view()),
    path('check/reports/<str:report_id>/', CheckReportView.as_view()),
    path('check/rules/', CheckRulesView.as_view()),
    path('check/rules/<str:rule_id>/', CheckRuleDetailView.as_view()),
    path('check/summary/', CheckSummaryView.as_view()),

    # ─────────────────────────────────────────────────────────────────────────
    # DISCOVERIES ENGINE  /api/engines/discoveries/
    # ─────────────────────────────────────────────────────────────────────────
    path('discoveries/scan/', DiscoveryScanView.as_view()),
    path('discoveries/findings/', DiscoveryFindingsView.as_view()),
    path('discoveries/findings/<str:finding_id>/', DiscoveryFindingDetailView.as_view()),
    path('discoveries/reports/', DiscoveryReportsView.as_view()),
    path('discoveries/reports/<str:report_id>/', DiscoveryReportDetailView.as_view()),
    path('discoveries/summary/', DiscoverySummaryView.as_view()),
    path('discoveries/jobs/<str:job_id>/', DiscoveryJobStatusView.as_view()),

    # ─────────────────────────────────────────────────────────────────────────
    # RULE ENGINE  /api/engines/rules/
    # ─────────────────────────────────────────────────────────────────────────
    path('rules/', RulesListView.as_view()),
    path('rules/create/', RuleCreateView.as_view()),
    path('rules/validate/', RuleValidateView.as_view()),
    path('rules/<str:rule_id>/', RuleDetailView.as_view()),
    path('rules/providers/', ProvidersListView.as_view()),
    path('rules/providers/<str:provider>/', ProviderRulesView.as_view()),
]
