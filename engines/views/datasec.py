"""
DataSec Engine Proxy Views
Engine prefix: datasec
Port: 8003
"""
from engines.proxy import EngineProxyView, SCAN_TIMEOUT


class DataSecScanView(EngineProxyView):
    engine_prefix = 'datasec'
    required_operation = 'account:datasec:read'
    timeout = SCAN_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'api/v1/datasec/scan', timeout=SCAN_TIMEOUT)


class DataSecFindingsView(EngineProxyView):
    engine_prefix = 'datasec'
    required_operation = 'account:datasec:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/datasec/findings')


class DataSecReportsView(EngineProxyView):
    engine_prefix = 'datasec'
    required_operation = 'account:datasec:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/datasec/reports')


class DataSecReportDetailView(EngineProxyView):
    engine_prefix = 'datasec'
    required_operation = 'account:datasec:read'

    def get(self, request, report_id):
        return self.proxy(request, f'api/v1/datasec/reports/{report_id}')


class DataSecDataAssetsView(EngineProxyView):
    engine_prefix = 'datasec'
    required_operation = 'account:datasec:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/datasec/data-assets')


class DataSecSummaryView(EngineProxyView):
    engine_prefix = 'datasec'
    required_operation = 'account:datasec:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/datasec/summary')
