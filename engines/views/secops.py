"""
SecOps Engine Proxy Views
Engine prefix: secops
Port: 8000 (container)

Handles IaC/code security scanning.
File uploads for /scan endpoint use multipart/form-data.
"""
import logging
import requests
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from user_auth.authentication import CookieTokenAuthentication
from engines.proxy import EngineProxyView, UPLOAD_TIMEOUT

logger = logging.getLogger(__name__)


class SecOpsScanUploadView(EngineProxyView):
    """
    POST /api/engines/secops/scan/
    Accepts multipart/form-data with file upload.
    Forwards directly to engine secops /scan endpoint.
    """
    engine_prefix = 'secops'
    required_operation = 'account:secops:execute'
    timeout = UPLOAD_TIMEOUT

    def post(self, request):
        engine_base = getattr(settings, 'ENGINE_BASE_URL', '')
        url = f"{engine_base}/secops/scan"

        headers = self._build_forward_headers(request)
        # Remove content-type so requests sets it correctly for multipart
        headers.pop('Content-Type', None)

        try:
            files = {k: v for k, v in request.FILES.items()}
            data = {k: v[0] for k, v in request.POST.items()}

            resp = requests.post(
                url,
                headers=headers,
                files=files if files else None,
                data=data,
                timeout=UPLOAD_TIMEOUT,
            )
            return self._build_response(resp)
        except requests.Timeout:
            return JsonResponse({"success": False, "message": "SecOps engine timed out."}, status=504)
        except requests.ConnectionError:
            return JsonResponse({"success": False, "message": "SecOps engine unreachable."}, status=503)


class SecOpsScanLocalView(EngineProxyView):
    engine_prefix = 'secops'
    required_operation = 'account:secops:execute'
    timeout = UPLOAD_TIMEOUT

    def post(self, request):
        return self.proxy(request, 'scan-local', timeout=UPLOAD_TIMEOUT)


class SecOpsScansListView(EngineProxyView):
    engine_prefix = 'secops'
    required_operation = 'account:secops:read'

    def get(self, request):
        return self.proxy(request, 'api/v1/secops/scans')


class SecOpsScanDetailView(EngineProxyView):
    engine_prefix = 'secops'
    required_operation = 'account:secops:read'

    def get(self, request, scan_id):
        return self.proxy(request, f'api/v1/secops/scans/{scan_id}')


class SecOpsScanFindingsView(EngineProxyView):
    engine_prefix = 'secops'
    required_operation = 'account:secops:read'

    def get(self, request, scan_id):
        return self.proxy(request, f'api/v1/secops/scans/{scan_id}/findings')


class SecOpsResultsView(EngineProxyView):
    engine_prefix = 'secops'
    required_operation = 'account:secops:read'

    def get(self, request, project_name):
        return self.proxy(request, f'results/{project_name}')
