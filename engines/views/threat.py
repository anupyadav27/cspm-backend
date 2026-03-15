"""
Threat Engine Proxy Views
Engine prefix: threat
Port: 8020

All paths proxied to: {ENGINE_BASE_URL}/threat/{path}
"""
from engines.proxy import EngineProxyView, SCAN_TIMEOUT


class ThreatGenerateView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'
    timeout = SCAN_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'api/v1/threat/generate', timeout=SCAN_TIMEOUT)


class ThreatGenerateAsyncView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def post(self, request):
        return self.proxy(request, 'api/v1/threat/generate/async')


class ThreatJobStatusView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request, job_id):
        return self.proxy(request, f'api/v1/threat/jobs/{job_id}')


class ThreatListView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/threats')


class ThreatDetailView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request, threat_id):
        return self.proxy(request, f'api/v1/threat/threats/{threat_id}')

    def patch(self, request, threat_id):
        return self.proxy(request, f'api/v1/threat/{threat_id}')


class ThreatMisconfigFindingsView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request, threat_id):
        return self.proxy(request, f'api/v1/threat/{threat_id}/misconfig-findings')


class ThreatAssetsView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:assets:read'

    def get(self, request, threat_id):
        return self.proxy(request, f'api/v1/threat/{threat_id}/assets')


class ThreatSummaryView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/summary')


class ThreatReportsView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/reports')


class ThreatReportDetailView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request, scan_run_id):
        return self.proxy(request, f'api/v1/threat/reports/{scan_run_id}')


class ThreatAnalysisRunView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'
    timeout = SCAN_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'api/v1/threat/analysis/run', timeout=SCAN_TIMEOUT)


class ThreatAnalysisPrioritizedView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/analysis/prioritized')


class ThreatAnalysisDetailView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request, detection_id):
        return self.proxy(request, f'api/v1/threat/analysis/{detection_id}')


class ThreatAnalysisListView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/analysis')


# ── Security Graph ─────────────────────────────────────────────────────────────

class GraphBuildView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'
    timeout = SCAN_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'api/v1/graph/build', timeout=SCAN_TIMEOUT)


class GraphSummaryView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/graph/summary')


class GraphAttackPathsView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/graph/attack-paths')


class GraphInternetExposedView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/graph/internet-exposed')


class GraphBlastRadiusView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request, resource_uid):
        return self.proxy(request, f'api/v1/graph/blast-radius/{resource_uid}')


class GraphToxicCombinationsView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/graph/toxic-combinations')


class GraphResourceView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request, resource_uid):
        return self.proxy(request, f'api/v1/graph/resource/{resource_uid}')


# ── Threat Intel ───────────────────────────────────────────────────────────────

class IntelFeedView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def post(self, request):
        return self.proxy(request, 'api/v1/intel/feed')


class IntelFeedBatchView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def post(self, request):
        return self.proxy(request, 'api/v1/intel/feed/batch')


class IntelListView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/intel')


class IntelCorrelateView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/intel/correlate')


# ── Threat Hunting ─────────────────────────────────────────────────────────────

class HuntPredefinedView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/hunt/predefined')


class HuntExecuteView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'
    timeout = 60

    def post(self, request):
        return self.proxy(request, 'api/v1/hunt/execute', timeout=60)


class HuntQueriesView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/hunt/queries')

    def post(self, request):
        return self.proxy(request, 'api/v1/hunt/queries')


class HuntResultsView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/hunt/results')


# ── Maps & Analytics ──────────────────────────────────────────────────────────

class ThreatMapGeographicView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/map/geographic')


class ThreatMapAccountView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/map/account')


class ThreatMapServiceView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/map/service')


class ThreatAnalyticsTrendView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/analytics/trend')


class ThreatAnalyticsPatternsView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/analytics/patterns')


class ThreatAnalyticsDistributionView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/analytics/distribution')


class ThreatAnalyticsCorrelationView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/analytics/correlation')


# ── Remediation ───────────────────────────────────────────────────────────────

class ThreatRemediationQueueView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/remediation/queue')


class ThreatRemediationView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request, threat_id):
        return self.proxy(request, f'api/v1/threat/{threat_id}/remediation')


# ── Drift & Posture ───────────────────────────────────────────────────────────

class ThreatDriftView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/threat/drift')


class ThreatResourcePostureView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:assets:read'

    def get(self, request, resource_uid):
        return self.proxy(request, f'api/v1/threat/resources/{resource_uid}/posture')


class ThreatResourceThreatsView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:threats:read'

    def get(self, request, resource_uid):
        return self.proxy(request, f'api/v1/threat/resources/{resource_uid}/threats')


class ThreatScanSummaryView(EngineProxyView):
    engine_prefix = 'threat'
    required_operation = 'account:scans:read'

    def get(self, request, scan_run_id):
        return self.proxy(request, f'api/v1/threat/scans/{scan_run_id}/summary')
