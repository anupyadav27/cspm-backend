"""
Rule Engine Proxy Views
Engine prefix: rule (internal only, no ingress)
Port: 8011

NOTE: The rule engine has no ingress. It is accessed internally.
Ensure ENGINE_BASE_URL resolves correctly for internal routing.
"""
from engines.proxy import EngineProxyView


class RulesListView(EngineProxyView):
    engine_prefix = 'rule'
    required_operation = 'platform:settings:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/rules')


class RuleDetailView(EngineProxyView):
    engine_prefix = 'rule'
    required_operation = 'platform:settings:read'

    def get(self, request, rule_id):
        return self.proxy(request, f'api/v1/rules/{rule_id}')

    def put(self, request, rule_id):
        return self.proxy(request, f'api/v1/rules/{rule_id}')

    def delete(self, request, rule_id):
        return self.proxy(request, f'api/v1/rules/{rule_id}')


class RuleCreateView(EngineProxyView):
    engine_prefix = 'rule'
    required_operation = 'platform:settings:write'

    def post(self, request):
        return self.proxy(request, 'api/v1/rules')


class ProvidersListView(EngineProxyView):
    engine_prefix = 'rule'
    required_operation = 'platform:settings:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/providers')


class ProviderRulesView(EngineProxyView):
    engine_prefix = 'rule'
    required_operation = 'platform:settings:read'

    def get(self, request, provider):
        return self.proxy(request, f'api/v1/providers/{provider}/rules')


class RuleValidateView(EngineProxyView):
    engine_prefix = 'rule'
    required_operation = 'platform:settings:write'

    def post(self, request):
        return self.proxy(request, 'api/v1/rules/validate')
