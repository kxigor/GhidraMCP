import json
import time
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import anyio
import httpx


class BackendError(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.details = details or {}

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "message": str(self),
            "retryable": self.retryable,
            "details": self.details,
        }


class BackendClient:
    def __init__(self, base_url: str, *, client: httpx.AsyncClient | None = None):
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("--ghidra-server must be an HTTP(S) URL without a query or fragment")
        self._client = client or httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/", timeout=httpx.Timeout(15, connect=3), trust_env=False
        )
        self._owns_client = client is None
        self._server_info: dict | None = None
        self._checked_at = 0.0

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def server_info(self, *, refresh: bool = False) -> dict:
        if not refresh and self._server_info is not None and time.monotonic() - self._checked_at < 5:
            return self._server_info
        payload = await self._request("GET", "api/v2/server", timeout=2)
        if payload.get("api_version") != 2:
            raise BackendError(
                "API_VERSION_MISMATCH", "The backend does not support GhidraMCP API v2.",
                details={"expected": 2, "actual": payload.get("api_version")},
            )
        if not isinstance(payload.get("server_id"), str) or not payload["server_id"]:
            raise BackendError("BACKEND_PROTOCOL_ERROR", "The backend did not provide its server identity.")
        operations = payload.get("operations")
        if operations is not None and (not isinstance(operations, list) or not all(isinstance(name, str) for name in operations)):
            raise BackendError("BACKEND_PROTOCOL_ERROR", "The backend operation catalogue is invalid.")
        self._server_info = payload
        self._checked_at = time.monotonic()
        return payload

    async def execute(self, definition: dict, arguments: dict) -> dict:
        request_id = str(uuid4())
        metadata = {"request_id": request_id}
        if "program_id" in arguments:
            metadata["program_id"] = arguments["program_id"]
        try:
            info = await self.server_info()
            metadata["server_id"] = info["server_id"]
            operation = definition["name"]
            supported = info.get("operations")
            if supported is not None and operation not in supported:
                raise BackendError("UNSUPPORTED_CAPABILITY", f"Backend does not implement {operation}.")
            if operation == "get_server_info":
                return {**metadata, "data": info, "truncated": False, "warnings": []}
            if operation == "get_job":
                job = await self._request(
                    "GET", f"api/v2/requests/{arguments['job_id']}",
                    params={"wait_ms": arguments.get("wait_ms", 0)},
                )
                return self._job_result(job, metadata)
            if operation == "cancel_job":
                job = await self._request("POST", f"api/v2/requests/{arguments['job_id']}/cancel")
                return {**metadata, "data": self._job_data(job), "truncated": False, "warnings": []}
            timeout_ms = arguments.get("timeout_ms", 300000 if definition.get("detached") else 60000)
            payload = {
                "request_id": request_id,
                "arguments": arguments,
                "timeout_ms": timeout_ms,
                "wait_ms": 0 if definition.get("detached") else 1000,
            }
            submitted = False
            try:
                with anyio.fail_after(timeout_ms / 1000 + 5):
                    submitted = True
                    response = await self._request("POST", f"api/v2/operations/{operation}", json=payload)
                    if definition.get("detached"):
                        return self._job_result(response, metadata)
                    while response.get("state") in {"queued", "running", "cancelling"}:
                        await anyio.sleep(0.02)
                        response = await self._request(
                            "GET", f"api/v2/requests/{request_id}", params={"wait_ms": 1000}
                        )
                    return self._operation_result(response, metadata)
            except anyio.get_cancelled_exc_class():
                if submitted:
                    await self._cancel_shielded(request_id)
                raise
            except TimeoutError:
                if submitted:
                    await self._cancel_shielded(request_id)
                raise BackendError("TIMEOUT", "The operation exceeded its execution deadline.") from None
            except BackendError as error:
                if submitted and error.code == "BACKEND_UNAVAILABLE":
                    if not definition.get("detached"):
                        await self._cancel_shielded(request_id)
                    error.details.update({"request_id": request_id, "outcome_unknown": True})
                    error.retryable = definition.get("effect") == "read"
                raise
        except BackendError as error:
            return {**metadata, "error": error.as_dict()}

    async def _cancel_shielded(self, request_id: str) -> None:
        with anyio.move_on_after(2, shield=True):
            try:
                await self._request("POST", f"api/v2/requests/{request_id}/cancel", timeout=1.5)
            except BackendError:
                pass

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.TimeoutException as error:
            raise BackendError("BACKEND_UNAVAILABLE", "The backend HTTP request timed out.", retryable=True) from error
        except httpx.HTTPError as error:
            raise BackendError("BACKEND_UNAVAILABLE", "Cannot communicate with the Ghidra backend.", retryable=True) from error
        try:
            payload = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise BackendError(
                "BACKEND_PROTOCOL_ERROR", "The backend returned invalid JSON.",
                details={"http_status": response.status_code, "body_excerpt": response.text[:256]},
            ) from error
        if not isinstance(payload, dict):
            raise BackendError("BACKEND_PROTOCOL_ERROR", "The backend response must be a JSON object.")
        if not response.is_success:
            failure = payload.get("error")
            if isinstance(failure, dict) and isinstance(failure.get("code"), str):
                raise BackendError(
                    failure["code"], str(failure.get("message", "Backend operation failed.")),
                    retryable=bool(failure.get("retryable", False)), details=failure.get("details") or {},
                )
            raise BackendError(
                "BACKEND_PROTOCOL_ERROR", "The backend HTTP error has no structured error.",
                details={"http_status": response.status_code},
            )
        return payload

    @staticmethod
    def _operation_result(response: dict, metadata: dict) -> dict:
        state = response.get("state")
        if state == "succeeded" and isinstance(response.get("result"), dict):
            return {**metadata, **response["result"]}
        if state in {"failed", "cancelled", "timed_out"} and isinstance(response.get("error"), dict):
            outcome = {
                key: response[key]
                for key in ("server_id", "job_id", "operation", "state", "effects", "affected_programs", "affected_files")
                if key in response
            }
            return {**metadata, **outcome, "error": response["error"]}
        raise BackendError("BACKEND_PROTOCOL_ERROR", "The backend returned an invalid terminal operation result.")

    @staticmethod
    def _job_data(response: dict) -> dict:
        if response.get("state") not in {"queued", "running", "cancelling", "succeeded", "failed", "cancelled", "timed_out"}:
            raise BackendError("BACKEND_PROTOCOL_ERROR", "The backend returned an invalid job state.")
        return {**response, "job_id": response.get("job_id", response.get("request_id"))}

    @classmethod
    def _job_result(cls, response: dict, metadata: dict) -> dict:
        data = cls._job_data(response)
        result = {**metadata, "data": data, "truncated": False, "warnings": []}
        if isinstance(response.get("server_id"), str):
            result["server_id"] = response["server_id"]
        if data["state"] in {"failed", "cancelled", "timed_out"}:
            result["error"] = data.get("error") or BackendError("INTERNAL_ERROR", "The job failed without an error description.").as_dict()
        return result
