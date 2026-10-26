import json
from pathlib import Path

from jsonschema import Draft202012Validator
from mcp.types import Tool, ToolAnnotations


def load_catalog(path: Path | None = None) -> dict:
    source = path or Path(__file__).resolve().parent.parent / "protocol" / "tools.json"
    catalog = json.loads(source.read_text(encoding="utf-8"))
    if catalog["api_version"] != 2:
        raise ValueError("The tool catalog must use API version 2")
    names = set()
    for definition in catalog["tools"]:
        name = definition["name"]
        if name in names:
            raise ValueError(f"Duplicate tool: {name}")
        names.add(name)
        Draft202012Validator.check_schema(definition["inputSchema"])
    Draft202012Validator.check_schema(catalog["output_schema"])
    return catalog


def mcp_tool(definition: dict, output_schema: dict) -> Tool:
    return Tool(
        name=definition["name"],
        description=definition["description"],
        inputSchema=definition["inputSchema"],
        outputSchema=output_schema,
        annotations=ToolAnnotations(**definition["annotations"]),
    )
