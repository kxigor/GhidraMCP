[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# GhidraMCP

A [Model Context Protocol](https://modelcontextprotocol.io) server for [Ghidra](https://ghidra-sre.org).
A Ghidra plugin exposes program data and edit operations over a small embedded HTTP server, and a
Python bridge turns them into MCP tools an LLM agent can call to analyze and modify a binary.

> Fork of [GhidraMCP by LaurieWired](https://github.com/LaurieWired/GhidraMCP) (Apache 2.0).
> See [NOTICE](NOTICE) for attribution.

## Features

**Analysis & navigation**
- Decompile and disassemble functions
- List functions, methods, classes, namespaces, imports, exports, segments, strings, data
- Search functions; read current address/function
- Cross-references: to an address, from an address, and to a function

**Renaming & signatures**
- Rename functions, data, and local variables
- Set function prototypes and local variable types

**Data types**
- Structures — create, add/edit/delete fields, rename, delete, inspect layout
- Enums — create, add/remove values
- Unions — create, add fields
- Typedefs — create aliases
- Browse the data type manager and dump any type (`list_data_types`, `get_type`)

**Applying types to memory**
- Apply a data type at an address, create arrays, clear defined data

**Code & symbols**
- Create/delete functions, disassemble (define code) at an address
- Create, rename, and remove labels

**Comments, bookmarks & patching**
- Set comments (plate / pre / eol / post / repeatable)
- Set and list bookmarks
- Assemble a single instruction; patch raw bytes

## Requirements

- Ghidra **12.1.2** (see version note below)
- Python 3.10+ with the `mcp` and `requests` packages

## Install the plugin

1. Build the extension (see below), or use a prebuilt `GhidraMCP-*.zip`.
2. In Ghidra: `File` → `Install Extensions` → `+` → select the zip → restart Ghidra.
3. Enable **GhidraMCP** under `File` → `Configure` → `Developer`.
4. *Optional:* change the HTTP port under `Edit` → `Tool Options` → `GhidraMCP HTTP Server`
   (default `8080`).

> **Version must match.** Ghidra refuses an extension whose `ghidraVersion` differs from your build.
> To target another version, copy that version's jars into `lib/` and update `version` /
> `ghidraVersion` in [`src/main/resources/extension.properties`](src/main/resources/extension.properties).

## Run the MCP bridge

The bridge (`bridge_mcp_ghidra.py`) is a standard MCP server (stdio by default, `--transport sse`
also supported). Point it at the plugin's HTTP server:

```bash
python bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
```

Register it with any MCP client. Tools work while Ghidra is open with the plugin enabled and a
program loaded.

## Build from source

Copy these jars from your Ghidra install into `lib/`, then run `mvn clean package`:

```
Ghidra/Features/Base/lib/Base.jar
Ghidra/Features/Decompiler/lib/Decompiler.jar
Ghidra/Framework/Docking/lib/Docking.jar
Ghidra/Framework/Generic/lib/Generic.jar
Ghidra/Framework/Gui/lib/Gui.jar
Ghidra/Framework/Project/lib/Project.jar
Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar
Ghidra/Framework/Utility/lib/Utility.jar
```

The installable extension is produced at `target/GhidraMCP-*.zip`.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Original project: [GhidraMCP by LaurieWired](https://github.com/LaurieWired/GhidraMCP).
