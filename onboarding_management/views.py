
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.http import JsonResponse
from django.views import View
from .engine_client import engine_client, EngineError

logger = logging.getLogger(__name__)


def engine_error_response(e):
    return JsonResponse(
        {
            "success": False,
            "message": str(e),
            "data": None,
            "pagination": None,
            "engine": e.engine,
            "detail": e.detail,
        },
        status=e.status_code,
    )


def success_response(data, message="Success", status=200, pagination=None):
    return JsonResponse(
        {
            "success": True,
            "message": message,
            "data": data,
            "pagination": pagination,
        },
        status=status,
    )


def error_response(message, status=400, data=None):

    return JsonResponse(
        {
            "success": False,
            "message": message,
            "data": data,
            "pagination": None,
        },
        status=status,
    )


class CloudAccountListView(View):


    def get(self, request):
        try:
            params = {}
            if request.GET.get("tenant_id"):
                params["tenant_id"] = request.GET["tenant_id"]
            if request.GET.get("provider"):
                params["provider_type"] = request.GET["provider"]

            data, status_code = engine_client.get(
                "/onboarding/api/v1/cloud-accounts",
                params=params,
            )
            return success_response(
                data=data,
                message="Cloud accounts fetched successfully",
            )
        except EngineError as e:
            return engine_error_response(e)

    def post(self, request):
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, Exception):
            return error_response("Invalid JSON body")

        required = ["account_id", "tenant_id", "account_name", "provider"]
        missing = [f for f in required if f not in body]
        if missing:
            return error_response(f"Missing required fields: {', '.join(missing)}")

        try:
            data, status_code = engine_client.post(
                "/onboarding/api/v1/cloud-accounts",
                data=body,
            )
            return success_response(
                data=data,
                message="Cloud account created successfully",
                status=201,
            )
        except EngineError as e:
            return engine_error_response(e)


class CloudAccountDetailView(View):

    def get(self, request, account_id):
        try:
            data, status_code = engine_client.get(
                f"/onboarding/api/v1/cloud-accounts/{account_id}",
            )
            return success_response(
                data=data,
                message="Cloud account fetched successfully",
            )
        except EngineError as e:
            return engine_error_response(e)

    def put(self, request, account_id):
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, Exception):
            return error_response("Invalid JSON body")

        try:
            data, status_code = engine_client.put(
                f"/onboarding/api/v1/cloud-accounts/{account_id}",
                data=body,
            )
            return success_response(
                data=data,
                message="Cloud account updated successfully",
            )
        except EngineError as e:
            return engine_error_response(e)

    def delete(self, request, account_id):
        try:
            data, status_code = engine_client.delete(
                f"/onboarding/api/v1/cloud-accounts/{account_id}",
            )
            return success_response(
                data=data,
                message="Cloud account deleted successfully",
            )
        except EngineError as e:
            return engine_error_response(e)

    def patch(self, request, account_id):
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, Exception):
            return error_response("Invalid JSON body")

        try:
            data, status_code = engine_client.patch(
                f"/onboarding/api/v1/cloud-accounts/{account_id}",
                data=body,
            )
            return success_response(
                data=data,
                message="Cloud account updated successfully",
            )
        except EngineError as e:
            return engine_error_response(e)


class CloudAccountValidateView(View):

    def post(self, request, account_id):
        try:
            data, status_code = engine_client.post(
                f"/onboarding/api/v1/cloud-accounts/{account_id}/validate-credentials",
            )
            return success_response(
                data=data,
                message="Credential validation completed",
            )
        except EngineError as e:
            return engine_error_response(e)


class CredentialStoreView(View):
    def post(self, request, account_id):
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, Exception):
            return error_response("Invalid JSON body")

        if "credential_type" not in body or "credentials" not in body:
            return error_response("Missing required fields: credential_type, credentials")

        try:
            data, status_code = engine_client.post(
                f"/onboarding/api/v1/accounts/{account_id}/credentials",
                data=body,
                timeout=60,
            )
            return success_response(
                data=data,
                message="Credentials stored and validated successfully",
                status=status_code,
            )
        except EngineError as e:
            return engine_error_response(e)

    def delete(self, request, account_id):
        try:
            data, status_code = engine_client.delete(
                f"/onboarding/api/v1/accounts/{account_id}/credentials",
            )
            return success_response(
                data=data,
                message="Credentials deleted successfully",
            )
        except EngineError as e:
            return engine_error_response(e)


class AccountStatusView(View):

    def get(self, request, account_id):
        try:
            data, status_code = engine_client.get(
                f"/onboarding/api/v1/cloud-accounts/{account_id}/status",
                timeout=10,
            )
            return success_response(
                data=data,
                message="Account status fetched",
            )
        except EngineError as e:
            return engine_error_response(e)


class AccountActivateView(View):

    def post(self, request, account_id):
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, Exception):
            body = {}

        try:
            data, status_code = engine_client.post(
                f"/onboarding/api/v1/cloud-accounts/{account_id}/validate",
                data=body,
                timeout=60,
            )
            return success_response(
                data=data,
                message="Account activated successfully",
                status=status_code,
            )
        except EngineError as e:
            return engine_error_response(e)


class ScanTriggerView(View):


    def post(self, request):
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, Exception):
            return error_response("Invalid JSON body")

        required = ["tenant_id", "provider", "hierarchy_id"]
        missing = [f for f in required if f not in body]
        if missing:
            return error_response(f"Missing required fields: {', '.join(missing)}")

        try:
            data, status_code = engine_client.post(
                "/gateway/gateway/orchestrate",
                data=body,
                timeout=120,
            )
            return success_response(
                data=data,
                message="Scan pipeline triggered successfully",
                status=status_code,
            )
        except EngineError as e:
            return engine_error_response(e)


class ScanStatusView(View):

    def get(self, request, orchestration_id):
        tenant_id = request.GET.get("tenant_id", "")
        
        status_endpoints = {
            "orchestration": f"/onboarding/api/v1/scan/orchestration/{orchestration_id}",
        }

        results = {}
        for engine_name, path in status_endpoints.items():
            try:
                data, sc = engine_client.get(path, params={"tenant_id": tenant_id}, timeout=10)
                results[engine_name] = data
            except EngineError:
                results[engine_name] = {"status": "unknown", "error": "Engine unreachable"}

        return success_response(
            data={
                "orchestration_id": orchestration_id,
                "engines": results,
            },
            message="Scan status fetched",
        )


class EngineHealthView(View):

    def get(self, request):
        results = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_engine = {
                executor.submit(engine_client.check_health, name): name
                for name in [
                    "onboarding", "discoveries", "check", "inventory",
                    "compliance", "threat", "iam", "datasec", "secops", "gateway",
                ]
            }
            for future in as_completed(future_to_engine):
                results.append(future.result())

        results.sort(key=lambda x: x["engine"])
        
        healthy_count = sum(1 for r in results if r.get("healthy"))
        total_count = len(results)

        return success_response(
            data={
                "engines": results,
                "summary": {
                    "total": total_count,
                    "healthy": healthy_count,
                    "unhealthy": total_count - healthy_count,
                    "all_healthy": healthy_count == total_count,
                },
            },
            message=f"{healthy_count}/{total_count} engines healthy",
        )

class DashboardSummaryView(View):

    def get(self, request):
        tenant_id = request.GET.get("tenant_id", "")
        scan_run_id = request.GET.get("scan_run_id", "")

        if not tenant_id:
            return error_response("tenant_id is required")

        summary = {}
        errors = []

        def fetch_inventory():
            try:
                data, _ = engine_client.get(
                    "/inventory/api/v1/inventory/runs/latest/summary",
                    params={"tenant_id": tenant_id},
                    timeout=10,
                )
                return "inventory", data
            except EngineError:
                return "inventory", None

        def fetch_threats():
            try:
                params = {"tenant_id": tenant_id}
                if scan_run_id:
                    params["scan_run_id"] = scan_run_id
                data, _ = engine_client.get(
                    "/threat/api/v1/threat/analytics/distribution",
                    params=params,
                    timeout=10,
                )
                return "threats", data
            except EngineError:
                return "threats", None

        def fetch_compliance():
            try:
                data, _ = engine_client.get(
                    "/compliance/api/v1/compliance/reports",
                    params={"tenant_id": tenant_id, "limit": 1},
                    timeout=10,
                )
                return "compliance", data
            except EngineError:
                return "compliance", None

        def fetch_accounts():
            try:
                data, _ = engine_client.get(
                    "/onboarding/api/v1/cloud-accounts",
                    timeout=10,
                )
                return "accounts", data
            except EngineError:
                return "accounts", None

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(fetch_inventory),
                executor.submit(fetch_threats),
                executor.submit(fetch_compliance),
                executor.submit(fetch_accounts),
            ]
            for future in as_completed(futures):
                key, data = future.result()
                if data is not None:
                    summary[key] = data
                else:
                    errors.append(key)
                    summary[key] = None

        return success_response(
            data={
                "tenant_id": tenant_id,
                "summary": summary,
                "unavailable_engines": errors,
            },
            message="Dashboard summary fetched",
        )
