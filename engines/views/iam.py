"""
IAM Engine Proxy Views
Engine prefix: iam
Port: 8003
"""
from engines.proxy import EngineProxyView, SCAN_TIMEOUT


class IAMScanView(EngineProxyView):
    engine_prefix = 'iam'
    required_operation = 'account:scans:execute'
    timeout = SCAN_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'api/v1/iam-security/scan', timeout=SCAN_TIMEOUT)


class IAMFindingsView(EngineProxyView):
    engine_prefix = 'iam'
    required_operation = 'account:inventory:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/iam-security/findings')


class IAMRuleDetailView(EngineProxyView):
    engine_prefix = 'iam'
    required_operation = 'account:inventory:read'

    def get(self, request, rule_id):
        return self.proxy(request, f'api/v1/iam-security/rules/{rule_id}')


class IAMModulesView(EngineProxyView):
    engine_prefix = 'iam'
    required_operation = 'account:inventory:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/iam-security/modules')


class IAMModuleRulesView(EngineProxyView):
    engine_prefix = 'iam'
    required_operation = 'account:inventory:read'

    def get(self, request, module):
        return self.proxy(request, f'api/v1/iam-security/modules/{module}/rules')


class IAMRuleIdsView(EngineProxyView):
    engine_prefix = 'iam'
    required_operation = 'account:inventory:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/iam-security/rule-ids')
