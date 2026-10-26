# GhidraMCP 2 for Ghidra 12.2

## Requirements

- Ghidra **12.2** and JDK **25**.
- Python **3.10+**; the locked dependencies are tested with Python **3.14**.

Both the Java extension and Python bridge must be upgraded together. API v2 is incompatible with the old bridge and implicit current-program calls.

## Install the extension

1. Extract `GhidraMCP-12.2-release.zip` into a permanent directory.
2. Start Ghidra 12.2. In its **Project Window**, use **File → Install Extensions → +** to install the included **`GhidraMCP-12.2.zip`**. Remove or disable the previous GhidraMCP extension when upgrading.
3. Restart Ghidra. Fresh profiles load the plugin automatically. If necessary, enable **GhidraMCPPlugin** through **File → Configure** in the **Project Window**, under the Utility package. It is an application plugin, so a CodeBrowser window is not needed to start the server.
4. Open or create a project. The backend listens on `http://127.0.0.1:8080/`. Each running Ghidra process needs a separate port; `GhidraMCP HTTP Server → Server Port` configures it, with a plugin restart required.

## Install and connect the Python bridge

Keep `bridge_mcp_ghidra.py`, `ghidra_mcp/`, `protocol/`, and both requirements files together. Run these commands in the extracted directory:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
```

On Windows, use `python` to create the environment and `.venv\Scripts\python.exe` for subsequent commands.

Register a stdio server in your MCP client using absolute paths:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/absolute/path/to/extracted-release/.venv/bin/python",
      "args": [
        "/absolute/path/to/extracted-release/bridge_mcp_ghidra.py",
        "--ghidra-server", "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Use the Windows environment path for `command` on Windows. Reconnect or restart the MCP client after updating its configuration.

## Verify the connection

Call `get_server_info` through MCP. Expect `api_version: 2`, `ghidra_version: "12.2"`, `plugin_version: "2.0.0"`, and 92 available operations. The HTTP endpoint can also be checked directly:

```bash
curl -fsS http://127.0.0.1:8080/api/v2/server
```

Ask the AI to list project files, open two libraries in the background, and decompile one function in each. Each program has its own `program_id`; program operations always require it. `show_program(program_id, new_tool=true)` opens the same live program in a CodeBrowser. Showing it in another window keeps the same ID and unsaved changes. Closing the windows leaves MCP-owned programs available in the background.

For initial auto-analysis, use `open_program(..., analysis="if_needed")` or `import_program(..., analysis="if_needed")`, then inspect the returned analysis job with `get_job`. The default opening policy is `analysis="none"`. Edits and analysis stay in memory until `save_program` is called; import creates a new project file.

Full access is enabled by default. Use `program_id` for program operations and `tool_id` only for operations on a specific GUI window. Rediscover IDs after a program is closed or Ghidra is restarted.

## Package contents

| File | Purpose |
| --- | --- |
| `GhidraMCP-12.2.zip` | Installable Ghidra extension, including the plugin JAR |
| `bridge_mcp_ghidra.py`, `ghidra_mcp/` | Python MCP bridge |
| `protocol/tools.json` | Schemas and annotations for all 92 tools |
| `requirements.txt`, `requirements.lock` | Pinned Python dependencies |
| `INSTALL.md` | Installation and verification instructions |
| `LICENSE`, `NOTICE` | Apache 2.0 license and attribution |
