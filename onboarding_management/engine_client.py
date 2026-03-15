
import os
import logging
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)

ENGINE_BASE_URL = os.getenv(
    "ENGINE_BASE_URL",
)

DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"

HEALTH_PATHS = {
    "onboarding":   "/onboarding/api/v1/health",
    "discoveries":  "/discoveries/api/v1/health/live",
    "check":        "/check/api/v1/health",
    "inventory":    "/inventory/health",
    "compliance":   "/compliance/api/v1/health",
    "threat":       "/threat/health",
    "iam":          "/iam/health",
    "datasec":      "/datasec/health",
    "secops":       "/secops/health",
    "gateway":      "/gateway/gateway/health",
}


class EngineError(Exception):

    def __init__(self, message, status_code=502, engine=None, detail=None):
        super().__init__(message)
        self.status_code = status_code
        self.engine = engine
        self.detail = detail


class EngineClient:


    def __init__(self, base_url=None, default_timeout=30):
        self.base_url = (base_url or ENGINE_BASE_URL).rstrip("/")
        self.default_timeout = default_timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _debug(self, message):
        logger.info(message)
        if DEBUG_MODE:
            print(f"[EngineClient] {message}")

    def _build_url(self, path):
        return f"{self.base_url}{path}"

    def _handle_response(self, response, engine_path):
        try:
            data = response.json()
        except Exception:
            data = {"raw": response.text}

        if response.status_code >= 500:
            self._debug(f"Engine 5xx error {response.status_code} at {engine_path}")
            raise EngineError(
                message=f"Engine error at {engine_path}",
                status_code=response.status_code,
                engine=engine_path,
                detail=data,
            )

        self._debug(f"Response {response.status_code} from {engine_path}")
        return data, response.status_code

    def get(self, engine_path, params=None, timeout=None):
        url = self._build_url(engine_path)
        timeout = timeout or self.default_timeout

        try:
            self._debug(f"GET {url} params={params}")
            response = self.session.get(url, params=params, timeout=timeout)
            return self._handle_response(response, engine_path)

        except Timeout:
            self._debug(f"Timeout at {engine_path}")
            raise EngineError("Engine timeout", 504, engine_path)

        except ConnectionError:
            self._debug(f"Connection error at {engine_path}")
            raise EngineError("Engine unreachable", 502, engine_path)

        except RequestException as e:
            self._debug(f"RequestException at {engine_path}: {str(e)}")
            raise EngineError(str(e), 502, engine_path)

    def post(self, engine_path, data=None, timeout=None):
        url = self._build_url(engine_path)
        timeout = timeout or 60

        try:
            self._debug(f"POST {url} body={data}")
            response = self.session.post(url, json=data, timeout=timeout)
            return self._handle_response(response, engine_path)

        except Timeout:
            self._debug(f"Timeout at {engine_path}")
            raise EngineError("Engine timeout", 504, engine_path)

        except ConnectionError:
            self._debug(f"Connection error at {engine_path}")
            raise EngineError("Engine unreachable", 502, engine_path)

        except RequestException as e:
            self._debug(f"RequestException at {engine_path}: {str(e)}")
            raise EngineError(str(e), 502, engine_path)

    def put(self, engine_path, data=None, timeout=None):
        url = self._build_url(engine_path)
        timeout = timeout or self.default_timeout

        try:
            self._debug(f"PUT {url} body={data}")
            response = self.session.put(url, json=data, timeout=timeout)
            return self._handle_response(response, engine_path)

        except (Timeout, ConnectionError, RequestException) as e:
            self._debug(f"Request failed at {engine_path}: {str(e)}")
            raise EngineError(str(e), 502, engine_path)

    def patch(self, engine_path, data=None, timeout=None):
        url = self._build_url(engine_path)
        timeout = timeout or self.default_timeout

        try:
            self._debug(f"PATCH {url} body={data}")
            response = self.session.patch(url, json=data, timeout=timeout)
            return self._handle_response(response, engine_path)

        except (Timeout, ConnectionError, RequestException) as e:
            self._debug(f"Request failed at {engine_path}: {str(e)}")
            raise EngineError(str(e), 502, engine_path)

    def delete(self, engine_path, timeout=None):
        url = self._build_url(engine_path)
        timeout = timeout or self.default_timeout

        try:
            self._debug(f"DELETE {url}")
            response = self.session.delete(url, timeout=timeout)
            return self._handle_response(response, engine_path)

        except (Timeout, ConnectionError, RequestException) as e:
            self._debug(f"Request failed at {engine_path}: {str(e)}")
            raise EngineError(str(e), 502, engine_path)

    def check_health(self, engine_name):
        path = HEALTH_PATHS.get(engine_name)
        if not path:
            return {
                "engine": engine_name,
                "status": "unknown",
                "error": "Unknown engine"
            }

        try:
            data, status_code = self.get(path, timeout=5)
            return {
                "engine": engine_name,
                "status": data.get("status", "unknown"),
                "healthy": status_code == 200,
                "details": data,
            }

        except EngineError:
            return {
                "engine": engine_name,
                "status": "unreachable",
                "healthy": False,
                "details": None,
            }

    def check_all_health(self):
        results = []
        for engine_name in HEALTH_PATHS:
            results.append(self.check_health(engine_name))
        return results


engine_client = EngineClient()