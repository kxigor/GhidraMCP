[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# GhidraMCP 2

A [Model Context Protocol](https://modelcontextprotocol.io) bridge for **Ghidra 12.2**. One service in the Ghidra Project Window gives an AI access to background programs and every open CodeBrowser. The AI can open project files, run analysis, inspect several libraries concurrently, edit them, and show the same live programs in the GUI when needed.

Every operation on a program uses an explicit `program_id`. Switching a GUI tab or opening another window does not redirect a request. A separate `tool_id` is used only for GUI operations.

Fork of [GhidraMCP by LaurieWired](https://github.com/LaurieWired/GhidraMCP), distributed under Apache 2.0. See [NOTICE](NOTICE).

## Requirements

- Official **Ghidra 12.2**, with **JDK 25**.
- Python **3.10+**; the locked environment is tested with Python **3.14**.
- Maven 3.9+ to build the extension.

The Python bridge and Java extension must both be version 2. The extension is built against the installed Ghidra distribution; copying JARs into `lib/` is no longer required.

## Build and install

From this repository:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check

python3 scripts/build.py --ghidra-home /absolute/path/to/ghidra_12.2_PUBLIC
```

On Windows, use `.venv\Scripts\python.exe` for the Python commands. `JAVA_HOME` must point to JDK 25. The build also accepts `GHIDRA_INSTALL_DIR` instead of `--ghidra-home` and an optional `--maven-repo` directory.

The resulting extension is **`target/GhidraMCP-12.2.zip`**. For a fresh development installation, `python3 scripts/download_ghidra.py /path/to/downloads` downloads the official distribution and verifies its pinned SHA-256 before extraction.

To prepare a complete release with the extension, Python bridge, tool catalogue, pinned dependencies, and [installation instructions](docs/INSTALL.md), run `python3 scripts/package_release.py`. It creates `target/GhidraMCP-12.2-release.zip` and its `.sha256` file, excluding caches and build intermediates. Install the inner `GhidraMCP-12.2.zip` in Ghidra.

1. In Ghidra's **Project Window**, choose **File → Install Extensions**, select the ZIP, and restart Ghidra. Remove or disable the old GhidraMCP extension when upgrading.
2. A fresh Ghidra profile loads the plugin automatically. If it is disabled in an existing profile, use **File → Configure** in the **Project Window** and enable **GhidraMCPPlugin** in the Utility package. Use the plugin list/filter if needed. This plugin belongs to the Project Window, rather than an individual CodeBrowser.
3. Open or create a project. CodeBrowser windows are optional: MCP can load programs from the project in the background.

The backend listens on loopback port **8080**. The `GhidraMCP HTTP Server` tool options contain `Server Port`; restart the plugin after changing it. Closing a CodeBrowser does not stop the service. Closing Ghidra does.

For isolated test instances, the Ghidra JVM property `-Dghidramcp.port=18080` overrides the saved port option. Each Ghidra process needs a distinct port.

## Connect an MCP client

Point your client's MCP configuration at the virtual environment's Python and the bridge script. Use absolute paths:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/absolute/path/to/GhidraMCP/.venv/bin/python",
      "args": [
        "/absolute/path/to/GhidraMCP/bridge_mcp_ghidra.py",
        "--ghidra-server", "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Keep `bridge_mcp_ghidra.py`, `ghidra_mcp/`, `protocol/`, and the requirements files together. `requirements.txt` installs the exact compatible versions in `requirements.lock`, including MCP and Pydantic.

Stdio is the default transport. Legacy SSE is also available:

```bash
.venv/bin/python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081
```

Check connectivity with `get_server_info`. It reports the Ghidra version, server identity, active project, supported operations, and limits. The tool list follows the connected backend's capabilities; a disconnected backend produces a structured connection error when called.

## Background programs and GUI

A typical workflow uses these MCP calls; the IDs below are placeholders for values returned by the server:

```text
list_projects()
list_project_files(project_id="project-…", path="/")
open_program(project_id="project-…", project_path="/libraries/libexample.so")
list_functions(program_id="program-…", limit=100)
decompile_function(program_id="program-…", function_address="ram:0x1000")
show_program(program_id="program-…", new_tool=true)
```

`open_program` holds the program in the background without opening a window. `show_program` gives a CodeBrowser the **same Program object** and keeps its `program_id`. A program open in several windows appears once in `list_programs`, with its `open_in_tool_ids`. The user can inspect it while the AI continues working through the same MCP connection.

`list_tools` and `get_gui_state(tool_id=…)` inspect windows. `navigate_to` and `set_selection` explicitly change GUI state. Ordinary reads do not switch tabs, move the cursor, or change selection. `close_program` releases MCP ownership; `close_program_in_tool` removes the program from a selected window. A remaining owner keeps it live. Dirty programs require an explicit save or discard before their last owner can be closed.

`close_tool` saves a changed CodeBrowser configuration before closing, using Ghidra's normal tool-template save. This saves window/plugin preferences for future CodeBrowsers; it does **not** save program edits. Set `save_configuration=false` to reject closing a tool with changed configuration instead. A successful response reports `configuration_saved`.

IDs identify live sessions, not filenames. Discover them again after restarting Ghidra or reopening a project. Identical filenames in different folders are unambiguous. Closed or unknown IDs return errors; there is no fallback to the active GUI program.

This release runs in the GUI Ghidra process, with background program loading. It does not require a second headless process or a separate AI connection. GUI project closure uses Ghidra's normal save dialog for open dirty programs and cancels work for that project; wait for operations to finish before switching projects when possible.

Before calling `close_project`, finish active operations, release every background program, and close every project tool, including empty CodeBrowsers. Other tools holding project data also prevent closure with `PROJECT_IN_USE`. MCP does not silently save or close those programs. `open_project` opens the project without restoring previously saved tool windows.

## Analysis and jobs

Ghidra's initial prompt runs **auto-analysis**: it discovers functions, references, types, and other program information. Decompilation is then performed on demand by `decompile_function`.

MCP can run that analysis without the dialog:

- `get_analysis_options` lists available analyzers and typed options.
- `get_analysis_status` reports analysis activity and known outcomes.
- `start_analysis` runs auto-analysis or selected one-shot analyzers, optionally over address ranges.
- `start_analysis_batch` starts analysis across explicitly selected programs.
- `open_program(..., analysis="if_needed")` and `import_program(..., analysis="if_needed")` request initial analysis and return its separate job ID. The default is `analysis="none"`.

`start_analysis`, `start_analysis_batch`, and `import_program` return job handles immediately. Poll `get_job(job_id=…, wait_ms=1000)`; use `list_jobs` or `cancel_job` to inspect and cancel work. Ordinary operations wait for their result. Each call accepts `timeout_ms`, up to 1,800,000 ms; `get_server_info` reports the current limits.

`list_jobs` lists MCP jobs. Analysis started manually in the GUI is visible through `get_analysis_status` for the selected program.

`get_analysis_log(program_id, job_id=…)` reads diagnostics captured for that specific MCP analysis job; omitting `job_id` selects the latest job. Its immutable cursor pages remain valid across later edits and analyses. Each page contains at most 65,536 characters; a retained log is capped at 262,144 characters with explicit truncation flags. Up to 32 logs are retained for at most 15 minutes within job history and are removed when their program closes. Pending, expired, and external GUI history is reported as unavailable instead of returning another job's log.

Analysis and import can have partial effects when interrupted. Job results include `effects`, `affected_programs`, and `affected_files`; a failed job is an MCP error even when its HTTP response succeeded. Cancellation requests cooperative stopping and does not imply that prior analysis changes were undone. Inspect the final state before retrying.

Showing an unanalyzed program suppresses only its initial analysis prompt for the session. It does not mark the program analyzed or save it. The compatibility adapter for this prompt is checked against Ghidra 12.2 and fails explicitly if unsupported.

Three small compatibility adapters use Ghidra internals verified on 12.2: transient analysis-prompt suppression, transaction isolation from concurrent GUI edits, and project-close notifications to native plugins. Unsupported layouts produce `UNSUPPORTED_CAPABILITY`. The extension therefore targets exactly 12.2; changing its version metadata is not a supported upgrade procedure.

## Available operations

The full input schemas and annotations live in [`protocol/tools.json`](protocol/tools.json). The catalogue currently contains 92 tools.

| Area | Capabilities |
| --- | --- |
| Projects and files | List/open/create/close projects, browse files and folders, inspect loaders, import binaries, load/save/release background programs |
| Program inspection | Program identity, architecture, hashes, image base, functions, variables, symbols, namespaces, imports, exports, strings and data |
| Memory and instructions | Read bytes, disassemble bounded ranges from instruction boundaries or their containing instruction, search memory, segment maps, file-offset/address mappings |
| Relationships | Xrefs, callers/callees with callsite addresses, external library mappings, import/thunk/PLT resolution across explicit program scopes |
| Decompiler | Function decompilation, CFG, raw/high P-code, revision-bound variable IDs, chunked large results |
| Editing | Function names/signatures, local names/types, labels, comments, bookmarks, functions, code/data definitions, assembly previews, byte patches |
| Types | Inspect/create/edit structures, unions, enums, typedefs and pointers; apply types and arrays to memory |
| Analysis | Options, status, automatic/one-shot/range analysis, batches, progress, deadlines and cancellation |
| GUI | List windows, inspect state, show/navigate/select programs, close programs in a window or close tools |

Cross-library resolution reports ambiguity or an unresolved target explicitly. `set_import_library` assigns an external symbol to a named dependency; `set_external_library_path` maps that dependency to a project file. Resolving against multiple libraries takes explicit `scope_program_ids`.

## Results and changes

Results are JSON in both MCP `structuredContent` and text content. Program results include `program_id` and a revision. Failures set `isError: true` with an error code and details. Failed operations retain available effect and affected-object metadata. Transport failure after submission includes the request ID and an unknown-outcome marker; the bridge does not retry a write automatically.

Paged lists return `items`, `has_more`, and `next_cursor`. Pass the cursor with the same query; a changed program invalidates it. Large decompiler results return a `result_id` and `next_offset` for `get_result_chunk`; offsets count Unicode code points. Result chunks are bound to the originating program and revision. Retained jobs/results expire after 15 minutes and are also bounded in count.

Edits run in a transaction on the selected program. Where supported, `expected_revision` prevents applying an edit to an unexpectedly changed program. **Saving is explicit:** call `save_program` after edits or analysis. Import necessarily creates a new project file and never silently overwrites an existing file.

Full access is enabled by default. For an inspection-only setup, the optional `Read Only` tool option rejects program changes, analysis, imports, saves, and discards on the Java server; restart the plugin after changing it. Tool annotations describe effects to MCP clients, but server enforcement does not depend on those annotations.

## Migration from version 1

- Install both the new extension and Python bridge, and enable the plugin in the **Project Window**.
- Replace implicit current-program calls with explicit `program_id` from `list_programs` or `open_program`.
- Use `tool_id` only for GUI operations. `select_program` is not part of the protocol.
- Consume JSON results, pagination, structured errors, and asynchronous job handles.
- Use the canonical names in `protocol/tools.json`; legacy aliases and HTTP v1 endpoints are removed.
- Install the locked Python dependencies in a fresh virtual environment. Old `requests`/MCP 1.5.0 installations are not the v2 environment.
- Target Ghidra **12.2/JDK 25** directly when building. Changing extension version text alone does not establish compatibility with another Ghidra version.

## Validation

```bash
.venv/bin/python -m unittest discover -s tests/python -v
python3 scripts/build.py --ghidra-home /absolute/path/to/ghidra_12.2_PUBLIC
```

The Python suite includes actual stdio initialization, schema validation, concurrent requests, cancellation, and error propagation. Maven runs core job lifecycle and result-chunk tests.

The real Ghidra integration suite uses nine generated ELF libraries with the same filename, distinct functions, and a linked cross-library call. On Linux x86-64 with GCC and JDK 25 available on `PATH`, prepare a new fixture directory and run the suite:

```bash
python3 scripts/prepare_test_project.py \
  --ghidra-home /absolute/path/to/ghidra_12.2_PUBLIC \
  --output-dir /tmp/ghidramcp-fixtures

python3 scripts/run_ghidra_tests.py \
  --ghidra-home /absolute/path/to/ghidra_12.2_PUBLIC \
  --project /tmp/ghidramcp-fixtures/projects/FixtureProject.gpr
```

Preparation compiles the fixture binaries, imports and analyzes all nine, and verifies their saved project paths. It refuses to overwrite an existing output directory. Keep the fixture binaries alongside the project: import and analysis tests reuse their source files. Ghidra settings, cache and logs are isolated under the fixture directory.

The runner executes `ResearchSmoke`, `MutationSmoke`, `AnalysisSmoke`, and `ProjectSmoke` by default, each with its own project copy. It prints the retained log directory and writes `results.json`; use `--output-dir` to choose it or `--smoke ResearchSmoke` to select tests. CI prepares this same project, runs all four suites after the extension build, and uploads the logs.

With a desktop display available, the same fixture also supports the GUI lifecycle suite:

```bash
python3 scripts/run_ghidra_tests.py \
  --ghidra-home /absolute/path/to/ghidra_12.2_PUBLIC \
  --project /tmp/ghidramcp-fixtures/projects/FixtureProject.gpr \
  --smoke GuiSmokeRunner
```

For a dedicated running fixture host, `.venv/bin/python tests/python/ghidra_e2e.py --ghidra-server http://127.0.0.1:8080/` checks the full MCP stdio → Python → HTTP → Ghidra chain, including parallel decompilation and save/reopen persistence. It requires the nine fixture libraries and changes a fixture program during the persistence check.

See [`tests/ghidra/`](tests/ghidra/) for the integration checks and the [bridge design](docs/mcp-bridge-v2-design.md) for the protocol and lifecycle model.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
