from __future__ import annotations

import argparse
import asyncio
from datetime import timedelta
import json
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class FixtureChecks:
    def __init__(self, session: ClientSession):
        self.session = session
        self.assertions = 0

    def check(self, condition: bool, message: str) -> None:
        self.assertions += 1
        if not condition:
            raise AssertionError(message)

    async def result(self, name: str, arguments: dict | None = None):
        result = await self.session.call_tool(name, arguments or {})
        self.check(isinstance(result.structuredContent, dict), f"{name}: missing structured content")
        text = [block.text for block in result.content if block.type == "text"]
        self.check(len(text) == 1 and json.loads(text[0]) == result.structuredContent,
                   f"{name}: text and structured content differ")
        return result

    async def call(self, name: str, arguments: dict | None = None) -> dict:
        result = await self.result(name, arguments)
        self.check(not result.isError, f"{name} failed: {result.structuredContent}")
        return result.structuredContent

    async def data(self, name: str, arguments: dict | None = None) -> dict:
        result = await self.call(name, arguments)
        self.check(isinstance(result.get("data"), dict), f"{name}: missing result data")
        return result["data"]

    async def error(self, name: str, arguments: dict, code: str) -> None:
        result = await self.result(name, arguments)
        self.check(result.isError is True, f"{name}: failure was not an MCP error")
        self.check(result.structuredContent.get("error", {}).get("code") == code,
                   f"{name}: expected {code}, got {result.structuredContent}")

    async def run(self) -> dict:
        initialized = await self.session.initialize()
        self.check(initialized.serverInfo.name == "ghidra-mcp", "Unexpected MCP server")
        tools = {tool.name: tool for tool in (await self.session.list_tools()).tools}
        for name in ("get_program_info", "decompile_function", "read_memory", "rename_function", "close_program"):
            self.check("program_id" in tools[name].inputSchema["required"], f"{name} does not require program_id")
        self.check(tools["read_memory"].annotations.readOnlyHint is True, "Read annotation is missing")
        self.check(tools["rename_function"].annotations.readOnlyHint is False, "Write annotation is missing")
        server = await self.data("get_server_info")
        self.check(server["api_version"] == 2, "Backend API version mismatch")
        projects = (await self.data("list_projects"))["items"]
        self.check(len(projects) == 1, "Expected one isolated fixture project")
        project_id = projects[0]["project_id"]
        entries = (await self.data("list_project_files", {
            "project_id": project_id, "recursive": True, "limit": 1000,
        }))["items"]
        files = sorted((entry for entry in entries if entry.get("content_type") == "Program"), key=lambda entry: entry["path"])
        self.check(len(files) == 9 and all("fixture_" in entry["path"] for entry in files),
                   "This test requires the nine generated libraries in an isolated fixture project")
        self.check(len({entry["name"] for entry in files}) == 1, "Fixture libraries should share a basename")
        programs = []
        addresses = []
        texts = []
        snapshots = []
        for entry in files:
            opened = await self.data("open_program", {"project_id": project_id, "project_path": entry["path"]})
            program_id = opened["program_id"]
            programs.append(program_id)
            repeated = await self.data("open_program", {"project_id": project_id, "project_path": entry["path"]})
            self.check(repeated["program_id"] == program_id, "Repeated open duplicated a program")
            before = await self.data("get_program_info", {"program_id": program_id})
            functions = (await self.data("list_functions", {"program_id": program_id, "query": "fixture_entry"}))["items"]
            self.check(len(functions) == 1, f"fixture_entry missing from {entry['path']}")
            address = functions[0]["address"]
            addresses.append(address)
            exports = (await self.data("list_exports", {"program_id": program_id}))["items"]
            self.check(any(item["name"] == "fixture_entry" for item in exports), "Fixture export was not found")
            result = await self.call("decompile_function", {"program_id": program_id, "function_address": address})
            self.check(result["program_id"] == program_id, "Decompilation used another program")
            self.check("fixture_entry" in result["data"]["text"], "Unexpected decompilation")
            texts.append(result["data"]["text"])
            after = await self.data("get_program_info", {"program_id": program_id})
            self.check((before["revision"], before["dirty"]) == (after["revision"], after["dirty"]),
                       "Research reads changed the program")
            snapshots.append(after)
        self.check(len(set(programs)) == 9, "Different files share a program ID")
        self.check(len(set(texts)) == 9, "Different libraries returned identical decompilation")
        registered = (await self.data("list_programs", {"project_id": project_id}))["items"]
        self.check({entry["program_id"] for entry in registered} == set(programs), "Registry does not expose all nine programs")
        concurrent = await asyncio.gather(*[
            self.call("decompile_function", {"program_id": program_id, "function_address": address})
            for program_id, address in zip(programs[:2], addresses[:2])
        ])
        for index, result in enumerate(concurrent):
            self.check(result["program_id"] == programs[index] and result["data"]["text"] == texts[index],
                       "Concurrent decompilation crossed program identity")
        await self.error("get_program_info", {}, "INVALID_ARGUMENT")
        await self.error("decompile_function", {"function_address": addresses[0]}, "INVALID_ARGUMENT")
        await self.error("read_memory", {"address": addresses[0], "length": 1}, "INVALID_ARGUMENT")
        await self.error("get_program_info", {"program_id": "does-not-exist"}, "PROGRAM_NOT_FOUND")
        candidates = [index for index, entry in enumerate(snapshots) if not entry["open_in_tool_ids"]]
        self.check(bool(candidates), "A background-only fixture is required for close/reopen checks")
        index = candidates[-1]
        program_id = programs[index]
        address = addresses[index]
        before = await self.data("get_program_info", {"program_id": program_id})
        renamed = await self.call("rename_function", {
            "program_id": program_id, "function_address": address,
            "new_name": "mcp_e2e_saved_entry", "expected_revision": before["revision"],
        })
        self.check(renamed["changed"] is True and renamed["revision_before"] != renamed["revision_after"],
                   "Rename did not report its revision change")
        await self.error("rename_function", {
            "program_id": program_id, "function_address": address,
            "new_name": "must_not_apply", "expected_revision": before["revision"],
        }, "REVISION_CONFLICT")
        await self.error("close_program", {"program_id": program_id}, "UNSAVED_CHANGES")
        saved = await self.data("save_program", {"program_id": program_id})
        self.check(saved["saved"] is True, "Save did not succeed")
        self.check((await self.data("get_program_info", {"program_id": program_id}))["dirty"] is False,
                   "Saved program is still dirty")
        closed = await self.data("close_program", {"program_id": program_id})
        self.check(closed["closed"] is True, "Background program did not close")
        await self.error("get_program_info", {"program_id": program_id}, "PROGRAM_CLOSED")
        reopened = await self.data("open_program", {"project_id": project_id, "project_path": files[index]["path"]})
        new_id = reopened["program_id"]
        self.check(new_id != program_id, "Reopened program reused a closed identity")
        function = await self.data("get_function", {"program_id": new_id, "address": address, "match": "entry"})
        self.check(function["name"] == "mcp_e2e_saved_entry", "Saved function name was lost after reopening")
        await self.call("rename_function", {"program_id": new_id, "function_address": address, "new_name": "fixture_entry"})
        await self.call("save_program", {"program_id": new_id})
        return {"status": "passed", "assertions": self.assertions, "tools": len(tools), "programs": len(programs),
                "parallel_decompilation": True, "read_state_unchanged": True, "save_reopen": True,
                "transport": "MCP stdio -> Python -> HTTP -> Ghidra", "server_id": server["server_id"]}


async def run(url: str) -> dict:
    repository = Path(__file__).resolve().parents[2]
    parameters = StdioServerParameters(command=sys.executable,
        args=[str(repository / "bridge_mcp_ghidra.py"), "--ghidra-server", url], cwd=repository)
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=90)) as session:
            return await FixtureChecks(session).run()


def main() -> None:
    parser = argparse.ArgumentParser(description="Exercise the MCP stdio bridge against an isolated real Ghidra fixture host")
    parser.add_argument("--ghidra-server", required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = asyncio.run(run(args.ghidra_server))
    report = json.dumps(result, indent=2) + "\n"
    if args.report:
        args.report.write_text(report)
    print(report, end="")


if __name__ == "__main__":
    main()
