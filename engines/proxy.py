"""
Base engine proxy module.

All engine proxy views inherit from EngineProxyView, which:
1. Authenticates the request via CookieTokenAuthentication
2. Checks the required operation (has_operations)
3. Forwards the request to the appropriate engine
4. Returns the engine's response transparently

The proxy adds X-Auth-Context and X-User-ID headers so engines can optionally
trust user context on the internal network.
"""
import base64
import json
import logging

import requests
from django.conf import settings
from django.http import HttpResponse, JsonResponse, StreamingHttpResponse
from django.views import View

from user_auth.authentication import CookieTokenAuthentication

logger = logging.getLogger(__name__)

# Default timeouts (seconds)
DEFAULT_TIMEOUT = 30
SCAN_TIMEOUT = 180
UPLOAD_TIMEOUT = 120

# Streaming chunk size
CHUNK_SIZE = 8192


def _err(message, status=400):
    return JsonResponse(
        {"success": False, "message": message, "data": None, "pagination": None},
        status=status
    )


class EngineProxyView(View):
    """
    Base class for all engine proxy views.

    Subclasses must set:
        engine_prefix: str  — e.g., 'inventory', 'threat', 'compliance'
        required_operation: str | None  — operation key required, or None for auth-only
    """
    engine_prefix: str = ''
    required_operation: str | None = None
    timeout: int = DEFAULT_TIMEOUT

    _auth_backend = CookieTokenAuthentication()

    def dispatch(self, request, *args, **kwargs):
        # Authenticate
        result = self._auth_backend.authenticate(request)
        if not result:
            return _err("Authentication required.", 401)

        # Check required operation
        if self.required_operation:
            perms = request.auth_context.get('permissions', [])
            if self.required_operation not in perms:
                logger.warning(
                    "Access denied: user=%s operation=%s",
                    request.auth_context.get('email'), self.required_operation
                )
                return _err(
                    f"Permission denied. Required: {self.required_operation}",
                    403
                )

        return super().dispatch(request, *args, **kwargs)

    def proxy(self, request, path: str, extra_params: dict = None, timeout: int = None):
        """
        Forward request to engine and return its response.
        path: the path segment after the engine prefix (no leading slash needed).
        """
        engine_base = getattr(settings, 'ENGINE_BASE_URL', '')
        path = path.lstrip('/')
        url = f"{engine_base}/{self.engine_prefix}/{path}"

        params = dict(request.GET)
        if extra_params:
            params.update(extra_params)

        headers = self._build_forward_headers(request)
        method = request.method.upper()

        # Build request kwargs
        kwargs = {
            'url': url,
            'params': params,
            'headers': headers,
            'timeout': timeout or self.timeout,
            'allow_redirects': True,
        }

        # Forward body for write methods
        if method in ('POST', 'PUT', 'PATCH'):
            kwargs['data'] = request.body
            content_type = request.content_type or 'application/json'
            headers['Content-Type'] = content_type

        try:
            resp = requests.request(method, **kwargs)
            return self._build_response(resp)
        except requests.Timeout:
            logger.error("Engine timeout: %s %s", method, url)
            return _err(f"Engine {self.engine_prefix} timed out.", 504)
        except requests.ConnectionError:
            logger.error("Engine connection error: %s %s", method, url)
            return _err(f"Engine {self.engine_prefix} is unreachable.", 503)
        except Exception as exc:
            logger.exception("Engine proxy error: %s", exc)
            return _err("Proxy error: " + str(exc), 502)

    def _build_forward_headers(self, request) -> dict:
        """Build headers to forward to the engine."""
        headers = {}

        # Forward content type if present
        if request.content_type:
            headers['Content-Type'] = request.content_type

        # Add auth context as header for engine trust
        auth_ctx = getattr(request, 'auth_context', {})
        if auth_ctx:
            ctx_json = json.dumps({
                'user_id': auth_ctx.get('user_id'),
                'email': auth_ctx.get('email'),
                'permissions': auth_ctx.get('permissions', []),
                'scope': auth_ctx.get('scope', {}),
            })
            headers['X-Auth-Context'] = base64.b64encode(ctx_json.encode()).decode()
            headers['X-User-ID'] = auth_ctx.get('user_id', '')
            headers['X-User-Email'] = auth_ctx.get('email', '')

        # Forward useful request headers
        for h in ('Accept', 'Accept-Language', 'X-Request-ID'):
            val = request.META.get(f'HTTP_{h.upper().replace("-", "_")}')
            if val:
                headers[h] = val

        return headers

    def _build_response(self, resp: requests.Response) -> HttpResponse:
        """Convert requests.Response to Django HttpResponse."""
        content_type = resp.headers.get('Content-Type', 'application/json')

        response = HttpResponse(
            content=resp.content,
            status=resp.status_code,
            content_type=content_type,
        )

        # Forward relevant response headers
        forward_headers = [
            'Content-Disposition', 'X-Total-Count', 'X-Page', 'X-Page-Size',
            'ETag', 'Last-Modified', 'Cache-Control',
        ]
        for h in forward_headers:
            val = resp.headers.get(h)
            if val:
                response[h] = val

        return response
