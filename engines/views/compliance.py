"""
Compliance Engine Proxy Views
Engine prefix: compliance
Port: 8021
"""
from engines.proxy import EngineProxyView, SCAN_TIMEOUT


class ComplianceGenerateView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'
    timeout = SCAN_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'api/v1/compliance/generate', timeout=SCAN_TIMEOUT)


class ComplianceGenerateFromCheckDbView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'
    timeout = SCAN_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'api/v1/compliance/generate/from-check-db', timeout=SCAN_TIMEOUT)


class ComplianceGenerateEnterpriseView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'
    timeout = SCAN_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'api/v1/compliance/generate/enterprise', timeout=SCAN_TIMEOUT)


class ComplianceReportDetailView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request, report_id):
        return self.proxy(request, f'api/v1/compliance/report/{report_id}')

    def delete(self, request, report_id):
        return self.proxy(request, f'api/v1/compliance/reports/{report_id}')


class ComplianceReportExportView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'
    timeout = 60

    def get(self, request, report_id):
        return self.proxy(request, f'api/v1/compliance/report/{report_id}/export', timeout=60)


class ComplianceReportsListView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/compliance/reports')


class ComplianceReportStatusView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request, report_id):
        return self.proxy(request, f'api/v1/compliance/reports/{report_id}/status')


class ComplianceDashboardView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/compliance/dashboard')


class ComplianceFrameworksView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/compliance/frameworks/all')


class ComplianceFrameworkStatusView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request, framework):
        return self.proxy(request, f'api/v1/compliance/framework/{framework}/status')


class ComplianceFrameworkDetailView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request, framework):
        return self.proxy(request, f'api/v1/compliance/framework-detail/{framework}')


class ComplianceFrameworkStructureView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request, framework):
        return self.proxy(request, f'api/v1/compliance/framework/{framework}/structure')


class ComplianceFrameworkControlsGroupedView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request, framework):
        return self.proxy(request, f'api/v1/compliance/framework/{framework}/controls/grouped')


class ComplianceFrameworkResourcesGroupedView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request, framework):
        return self.proxy(request, f'api/v1/compliance/framework/{framework}/resources/grouped')


class ComplianceControlDetailView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request, framework, control):
        return self.proxy(request, f'api/v1/compliance/control-detail/{framework}/{control}')


class ComplianceResourceComplianceView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request, resource_uid):
        return self.proxy(request, f'api/v1/compliance/resource/{resource_uid}/compliance')


class ComplianceResourceDrilldownView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/compliance/resource/drilldown')


class ComplianceAccountView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request, account_id):
        return self.proxy(request, f'api/v1/compliance/accounts/{account_id}')


class ComplianceTrendsView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/compliance/trends')


class ComplianceControlsSearchView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'account:compliance:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/compliance/controls/search')


class ComplianceFrameworkDownloadPdfView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'tenant:reports:read'
    timeout = 60

    def get(self, request, framework):
        return self.proxy(request, f'api/v1/compliance/framework/{framework}/download/pdf', timeout=60)


class ComplianceFrameworkDownloadExcelView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'tenant:reports:read'
    timeout = 60

    def get(self, request, framework):
        return self.proxy(request, f'api/v1/compliance/framework/{framework}/download/excel', timeout=60)


class ComplianceReportDownloadPdfView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'tenant:reports:read'
    timeout = 60

    def get(self, request, report_id):
        return self.proxy(request, f'api/v1/compliance/report/{report_id}/download/pdf', timeout=60)


class ComplianceReportDownloadExcelView(EngineProxyView):
    engine_prefix = 'compliance'
    required_operation = 'tenant:reports:read'
    timeout = 60

    def get(self, request, report_id):
        return self.proxy(request, f'api/v1/compliance/report/{report_id}/download/excel', timeout=60)
