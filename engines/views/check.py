"""
Check Engine Proxy Views
Engine prefix: check
Port: 8002
"""
from engines.proxy import EngineProxyView, SCAN_TIMEOUT


class CheckScanView(EngineProxyView):
    engine_prefix = 'check'
    required_operation = 'account:scans:execute'
    timeout = SCAN_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'api/v1/scan', timeout=SCAN_TIMEOUT)


class CheckFindingsView(EngineProxyView):
    engine_prefix = 'check'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/findings')


class CheckFindingDetailView(EngineProxyView):
    engine_prefix = 'check'
    required_operation = 'account:threats:read'

    def get(self, request, finding_id):
        return self.proxy(request, f'api/v1/findings/{finding_id}')


class CheckReportView(EngineProxyView):
    engine_prefix = 'check'
    required_operation = 'account:threats:read'

    def get(self, request, report_id):
        return self.proxy(request, f'api/v1/report/{report_id}')


class CheckReportsListView(EngineProxyView):
    engine_prefix = 'check'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/reports')


class CheckRulesView(EngineProxyView):
    engine_prefix = 'check'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/rules')


class CheckRuleDetailView(EngineProxyView):
    engine_prefix = 'check'
    required_operation = 'account:threats:read'

    def get(self, request, rule_id):
        return self.proxy(request, f'api/v1/rules/{rule_id}')


class CheckSummaryView(EngineProxyView):
    engine_prefix = 'check'
    required_operation = 'account:threats:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/summary')
