"""
Inventory Engine Proxy Views
Engine prefix: inventory
Port: 8022

All paths are proxied to: {ENGINE_BASE_URL}/inventory/{path}

Endpoint Map:
  GET  /api/engines/inventory/runs/latest/summary/
  GET  /api/engines/inventory/runs/{scan_run_id}/summary/
  GET  /api/engines/inventory/scans/
  POST /api/engines/inventory/scan/
  POST /api/engines/inventory/scan/async/
  GET  /api/engines/inventory/jobs/{job_id}/
  GET  /api/engines/inventory/assets/
  GET  /api/engines/inventory/assets/{resource_uid}/
  GET  /api/engines/inventory/assets/{resource_uid}/relationships/
  GET  /api/engines/inventory/relationships/
  GET  /api/engines/inventory/graph/
  GET  /api/engines/inventory/drift/
  GET  /api/engines/inventory/accounts/{account_id}/
  GET  /api/engines/inventory/services/{service}/
"""
from engines.proxy import EngineProxyView


class InventoryLatestSummaryView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/inventory/runs/latest/summary')


class InventoryScanSummaryView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request, scan_run_id):
        return self.proxy(request, f'api/v1/inventory/runs/{scan_run_id}/summary')


class InventoryScansListView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/inventory/scans')


class InventoryScanTriggerView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:scans:execute'
    timeout = 180

    def post(self, request):
        return self.proxy(request, 'api/v1/inventory/scan/discovery', timeout=180)


class InventoryScanAsyncView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:scans:execute'

    def post(self, request):
        return self.proxy(request, 'api/v1/inventory/scan/discovery/async')


class InventoryJobStatusView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request, job_id):
        return self.proxy(request, f'api/v1/inventory/jobs/{job_id}')


class InventoryAssetListView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/inventory/assets')


class InventoryAssetDetailView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request, resource_uid):
        return self.proxy(request, f'api/v1/inventory/assets/{resource_uid}')


class InventoryAssetRelationshipsView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request, resource_uid):
        return self.proxy(request, f'api/v1/inventory/assets/{resource_uid}/relationships')


class InventoryRelationshipsView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/inventory/relationships')


class InventoryGraphView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/inventory/graph')


class InventoryDriftView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/inventory/drift')


class InventoryAccountView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request, account_id):
        return self.proxy(request, f'api/v1/inventory/accounts/{account_id}')


class InventoryServiceView(EngineProxyView):
    engine_prefix = 'inventory'
    required_operation = 'account:inventory:read'

    def get(self, request, service):
        return self.proxy(request, f'api/v1/inventory/services/{service}')
