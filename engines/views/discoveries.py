"""
Discoveries Engine Proxy Views
Engine prefix: discoveries
Port: 8001
"""
from engines.proxy import EngineProxyView, SCAN_TIMEOUT


class DiscoveryScanView(EngineProxyView):
    engine_prefix = 'discoveries'
    required_operation = 'account:scans:execute'
    timeout = SCAN_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'api/v1/discovery', timeout=SCAN_TIMEOUT)


class DiscoveryFindingsView(EngineProxyView):
    engine_prefix = 'discoveries'
    required_operation = 'account:assets:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/discovery/findings')


class DiscoveryFindingDetailView(EngineProxyView):
    engine_prefix = 'discoveries'
    required_operation = 'account:assets:read'

    def get(self, request, finding_id):
        return self.proxy(request, f'api/v1/discovery/findings/{finding_id}')


class DiscoveryReportsView(EngineProxyView):
    engine_prefix = 'discoveries'
    required_operation = 'account:assets:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/discovery/reports')


class DiscoveryReportDetailView(EngineProxyView):
    engine_prefix = 'discoveries'
    required_operation = 'account:assets:read'

    def get(self, request, report_id):
        return self.proxy(request, f'api/v1/discovery/reports/{report_id}')


class DiscoverySummaryView(EngineProxyView):
    engine_prefix = 'discoveries'
    required_operation = 'account:assets:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/discovery/summary')


class DiscoveryJobStatusView(EngineProxyView):
    engine_prefix = 'discoveries'
    required_operation = 'account:scans:read'

    def get(self, request, job_id):
        return self.proxy(request, f'api/v1/discovery/jobs/{job_id}')
