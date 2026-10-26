import argparse
import json
import logging

import anyio
from jsonschema import Draft202012Validator
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent

from .catalog import load_catalog, mcp_tool
from .client import BackendClient, BackendError


class GhidraMCPServer:
    def __init__(self, backend: BackendClient, catalog: dict | None = None):
        self.backend = backend
        self.catalog = catalog or load_catalog()
        self.definitions = {item["name"]: item for item in self.catalog["tools"]}
        self.validators = {
            name: Draft202012Validator(definition["inputSchema"])
            for name, definition in self.definitions.items()
        }
        self.server = Server("ghidra-mcp", version="2.0.0")
        self.server.list_tools()(self.list_tools)
        self.server.call_tool(validate_input=False)(self.call_tool)

    async def list_tools(self):
        available = None
        try:
            info = await self.backend.server_info()
            available = info.get("operations")
        except BackendError:
            pass
        return [
            mcp_tool(definition, self.catalog["output_schema"])
            for name, definition in self.definitions.items()
            if available is None or name in available
        ]

    async def call_tool(self, name: str, arguments: dict | None) -> CallToolResult:
        arguments = arguments or {}
        definition = self.definitions.get(name)
        if definition is None:
            result = {"error": BackendError("UNKNOWN_TOOL", f"Unknown tool: {name}").as_dict()}
        else:
            errors = sorted(self.validators[name].iter_errors(arguments), key=lambda error: str(error.path))
            if errors:
                error = errors[0]
                result = {"error": BackendError(
                    "INVALID_ARGUMENT", error.message,
                    details={"path": list(error.absolute_path)},
                ).as_dict()}
            else:
                try:
                    result = await self.backend.execute(definition, arguments)
                except Exception:
                    logging.exception("Unhandled backend error for %s", name)
                    result = {"error": BackendError("INTERNAL_ERROR", "The MCP bridge could not process the backend response.").as_dict()}
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, ensure_ascii=False))],
            structuredContent=result,
            isError=isinstance(result.get("error"), dict),
        )

    async def run_stdio(self) -> None:
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream, write_stream,
                self.server.create_initialization_options(NotificationOptions(tools_changed=True)),
            )

    async def run_sse(self, host: str, port: int) -> None:
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route
        import uvicorn

        transport = SseServerTransport("/messages/")

        async def handle_sse(request):
            async with transport.connect_sse(request.scope, request.receive, request._send) as streams:
                await self.server.run(*streams, self.server.create_initialization_options())

        app = Starlette(routes=[Route("/sse", endpoint=handle_sse), Mount("/messages/", app=transport.handle_post_message)])
        server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="info"))
        await server.serve()


async def run(args) -> None:
    backend = BackendClient(args.ghidra_server)
    try:
        service = GhidraMCPServer(backend)
        if args.transport == "stdio":
            await service.run_stdio()
        else:
            await service.run_sse(args.mcp_host, args.mcp_port)
    finally:
        await backend.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP v2 bridge for Ghidra 12.2")
    parser.add_argument("--ghidra-server", default="http://127.0.0.1:8080/")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    parser.add_argument("--mcp-host", default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8081)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    try:
        anyio.run(run, args)
    except KeyboardInterrupt:
        pass
