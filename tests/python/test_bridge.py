import asyncio
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unittest

import httpx

from ghidra_mcp.catalog import load_catalog
from ghidra_mcp.client import BackendClient
from ghidra_mcp.server import GhidraMCPServer


CATALOG = load_catalog()
ROOT = Path(__file__).resolve().parents[2]


def info(operations=None):
    return httpx.Response(200, json={
        "api_version": 2,
        "server_id": "test-server",
        "operations": operations if operations is not None else [item["name"] for item in CATALOG["tools"]],
    })


def succeeded(request, data):
    body = json.loads(request.content)
    return httpx.Response(200, json={
        "request_id": body["request_id"], "server_id": "test-server",
        "state": "succeeded", "result": {"program_id": body["arguments"].get("program_id"), "data": data},
    })


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    def service(self, handler):
        client = httpx.AsyncClient(base_url="http://test/", transport=httpx.MockTransport(handler))
        self.addAsyncCleanup(client.aclose)
        return GhidraMCPServer(BackendClient("http://test/", client=client), CATALOG)

    async def test_missing_program_id_never_reaches_backend(self):
        async def handler(request):
            self.fail("Invalid arguments reached backend")

        result = await self.service(handler).call_tool("read_memory", {"address": "0x1000", "length": 4})
        self.assertTrue(result.isError)
        self.assertEqual(result.structuredContent["error"]["code"], "INVALID_ARGUMENT")

    async def test_tools_list_matches_backend_capabilities_and_requires_identity(self):
        async def handler(request):
            return info(["read_memory", "rename_function", "get_gui_state"])

        listed = await self.service(handler).list_tools()
        self.assertEqual({tool.name for tool in listed}, {"read_memory", "rename_function", "get_gui_state"})
        by_name = {tool.name: tool for tool in listed}
        self.assertIn("program_id", by_name["read_memory"].inputSchema["required"])
        self.assertIn("program_id", by_name["rename_function"].inputSchema["required"])
        self.assertIn("tool_id", by_name["get_gui_state"].inputSchema["required"])
        self.assertTrue(by_name["read_memory"].annotations.readOnlyHint)
        self.assertFalse(by_name["rename_function"].annotations.readOnlyHint)

    async def test_concurrent_reads_keep_their_program_ids(self):
        active = 0
        maximum = 0
        both_started = asyncio.Event()

        async def handler(request):
            nonlocal active, maximum
            if request.url.path.endswith("/server"):
                return info()
            active += 1
            maximum = max(maximum, active)
            if active == 2:
                both_started.set()
            await asyncio.wait_for(both_started.wait(), timeout=2)
            await asyncio.sleep(0.02)
            active -= 1
            return succeeded(request, {"bytes_hex": json.loads(request.content)["arguments"]["program_id"]})

        service = self.service(handler)
        results = await asyncio.gather(*[
            service.call_tool("read_memory", {"program_id": program, "address": "0x1000", "length": 4})
            for program in ["program-a", "program-b"]
        ])
        self.assertEqual(maximum, 2)
        self.assertEqual([result.structuredContent["program_id"] for result in results], ["program-a", "program-b"])

    async def test_closed_program_is_structured_mcp_error(self):
        async def handler(request):
            if request.url.path.endswith("/server"):
                return info()
            return httpx.Response(404, json={"error": {"code": "PROGRAM_CLOSED", "message": "Program closed", "details": {"program_id": "closed"}}})

        result = await self.service(handler).call_tool("get_program_info", {"program_id": "closed"})
        self.assertTrue(result.isError)
        self.assertEqual(result.structuredContent["error"]["code"], "PROGRAM_CLOSED")
        self.assertEqual(json.loads(result.content[0].text), result.structuredContent)

    async def test_http_success_does_not_hide_failed_job(self):
        async def handler(request):
            if request.url.path.endswith("/server"):
                return info()
            return httpx.Response(200, json={
                "request_id": "job-a", "state": "failed", "operation": "start_analysis", "effects": "partial",
                "error": {"code": "TIMEOUT", "message": "Analysis timed out"},
            })

        result = await self.service(handler).call_tool("get_job", {"job_id": "job-a"})
        self.assertTrue(result.isError)
        self.assertEqual(result.structuredContent["data"]["effects"], "partial")
        self.assertEqual(result.structuredContent["data"]["job_id"], "job-a")

    async def test_invalid_json_is_not_a_successful_tool_result(self):
        async def handler(request):
            if request.url.path.endswith("/server"):
                return info()
            return httpx.Response(200, text="not JSON")

        result = await self.service(handler).call_tool("get_program_info", {"program_id": "p"})
        self.assertTrue(result.isError)
        self.assertEqual(result.structuredContent["error"]["code"], "BACKEND_PROTOCOL_ERROR")

    async def test_failed_write_preserves_effects_and_affected_objects(self):
        outcome = {
            "state": "failed", "operation": "patch_bytes", "effects": "partial",
            "affected_programs": {"p": {"revision": "12", "dirty": True}},
            "affected_files": ["/lib/sample.so"],
            "error": {"code": "INTERNAL_ERROR", "message": "Post-write verification failed"},
        }

        async def handler(request):
            if request.url.path.endswith("/server"):
                return info()
            body = json.loads(request.content)
            return httpx.Response(200, json={**outcome, "request_id": body["request_id"], "job_id": body["request_id"]})

        result = await self.service(handler).call_tool("patch_bytes", {
            "program_id": "p", "address": "0x1000", "bytes_hex": "90",
        })
        self.assertTrue(result.isError)
        for key, value in outcome.items():
            self.assertEqual(result.structuredContent[key], value)
        self.assertEqual(result.structuredContent["job_id"], result.structuredContent["request_id"])
        self.assertEqual(json.loads(result.content[0].text), result.structuredContent)

    async def test_wrong_api_version_prevents_submission(self):
        async def handler(request):
            self.assertTrue(request.url.path.endswith("/server"))
            return httpx.Response(200, json={"api_version": 1, "server_id": "old"})

        result = await self.service(handler).call_tool("get_program_info", {"program_id": "p"})
        self.assertEqual(result.structuredContent["error"]["code"], "API_VERSION_MISMATCH")

    async def test_cancellation_reaches_backend_with_original_request_id(self):
        polling = asyncio.Event()
        request_id = None
        cancellations = []

        async def handler(request):
            nonlocal request_id
            if request.url.path.endswith("/server"):
                return info()
            if "/operations/" in request.url.path:
                request_id = json.loads(request.content)["request_id"]
                return httpx.Response(202, json={"request_id": request_id, "state": "running"})
            if request.url.path.endswith("/cancel"):
                cancellations.append(request.url.path)
                return httpx.Response(200, json={"request_id": request_id, "state": "cancelling"})
            polling.set()
            await asyncio.sleep(60)
            self.fail("Polling was not cancelled")

        service = self.service(handler)
        operation = asyncio.create_task(service.call_tool("decompile_function", {"program_id": "p", "function_address": "0x1000"}))
        await asyncio.wait_for(polling.wait(), timeout=2)
        operation.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await operation
        self.assertEqual(cancellations, [f"/api/v2/requests/{request_id}/cancel"])

    async def test_detached_analysis_returns_job_without_polling(self):
        async def handler(request):
            if request.url.path.endswith("/server"):
                return info()
            self.assertIn("/operations/", request.url.path)
            body = json.loads(request.content)
            self.assertEqual(body["wait_ms"], 0)
            return httpx.Response(202, json={"request_id": body["request_id"], "operation": "start_analysis", "state": "queued"})

        result = await self.service(handler).call_tool("start_analysis", {"program_id": "p"})
        self.assertFalse(result.isError)
        self.assertEqual(result.structuredContent["data"]["state"], "queued")
        self.assertEqual(result.structuredContent["data"]["job_id"], result.structuredContent["request_id"])

    async def test_transport_failure_does_not_retry_mutation(self):
        submissions = 0
        cancellations = 0

        async def handler(request):
            nonlocal submissions, cancellations
            if request.url.path.endswith("/server"):
                return info()
            if request.url.path.endswith("/cancel"):
                cancellations += 1
                return httpx.Response(200, json={"state": "cancelling"})
            submissions += 1
            raise httpx.ReadTimeout("response lost", request=request)

        result = await self.service(handler).call_tool("rename_function", {"program_id": "p", "function_address": "0x1000", "new_name": "renamed"})
        self.assertTrue(result.isError)
        self.assertFalse(result.structuredContent["error"]["retryable"])
        self.assertTrue(result.structuredContent["error"]["details"]["outcome_unknown"])
        self.assertEqual((submissions, cancellations), (1, 1))


@unittest.skipIf(os.name == "nt", "Raw stdio smoke uses POSIX pipe readiness")
class StdioTests(unittest.TestCase):
    def test_initialize_list_and_invalid_call(self):
        process = subprocess.Popen(
            [sys.executable, str(ROOT / "bridge_mcp_ghidra.py"), "--ghidra-server", "http://127.0.0.1:1/"],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        buffer = bytearray()

        def send(value):
            process.stdin.write((json.dumps(value) + "\n").encode())
            process.stdin.flush()

        def receive():
            deadline = time.monotonic() + 10
            while b"\n" not in buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    self.fail("MCP stdio response timed out; run outside a sandbox that blocks asyncio wakeups")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    self.fail(f"MCP server closed stdout: {process.stderr.read().decode()}")
                buffer.extend(chunk)
            line, _, remainder = buffer.partition(b"\n")
            buffer[:] = remainder
            return json.loads(line)

        try:
            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "bridge-test", "version": "1"},
            }})
            initialized = receive()
            self.assertEqual(initialized["result"]["serverInfo"]["name"], "ghidra-mcp")
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            listed = receive()
            self.assertEqual(len(listed["result"]["tools"]), len(CATALOG["tools"]))
            send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_memory", "arguments": {"address": "0x1000", "length": 4}}})
            called = receive()
            self.assertTrue(called["result"]["isError"])
            self.assertEqual(called["result"]["structuredContent"]["error"]["code"], "INVALID_ARGUMENT")
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main()
