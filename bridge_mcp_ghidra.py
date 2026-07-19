# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

# Request timeouts (seconds). Most endpoints answer in well under a second, but some
# operations are heavy: anything that runs the decompiler (rename/type on locals, prototypes)
# or builds the SLEIGH assembler (assemble_instruction) can take much longer, especially on
# first use. Heavy tools pass HEAVY_TIMEOUT explicitly.
DEFAULT_TIMEOUT = 10
HEAVY_TIMEOUT = 120

def safe_get(endpoint: str, params: dict = None, timeout: float = DEFAULT_TIMEOUT) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str, timeout: float = DEFAULT_TIMEOUT) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name, timeout=HEAVY_TIMEOUT)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    }, timeout=HEAVY_TIMEOUT)

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}, timeout=HEAVY_TIMEOUT))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype}, timeout=HEAVY_TIMEOUT)

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type}, timeout=HEAVY_TIMEOUT)

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def create_struct(name: str, category: str = None) -> str:
    """
    Create a new (empty) structure data type.

    Args:
        name: Name of the structure to create
        category: Optional data type category path (e.g. "/MyTypes"), defaults to root "/"

    Returns:
        Result message with the created struct's path
    """
    data = {"name": name}
    if category:
        data["category"] = category
    return safe_post("create_struct", data)

@mcp.tool()
def add_struct_field(struct_name: str, field_name: str, field_type: str, offset: int = -1) -> str:
    """
    Add a field to an existing structure.

    Args:
        struct_name: Name of the structure to modify
        field_name: Name of the new field (may be empty for an unnamed field)
        field_type: Data type of the field (e.g. "int", "char *", "uint")
        offset: Byte offset to insert at; -1 (default) appends to the end

    Returns:
        Result message with the structure's new size
    """
    return safe_post("add_struct_field", {
        "struct_name": struct_name,
        "field_name": field_name,
        "field_type": field_type,
        "offset": offset,
    })

@mcp.tool()
def edit_struct_field(struct_name: str, field: str, new_name: str = None, new_type: str = None) -> str:
    """
    Edit an existing structure field's name and/or type. Only provided attributes change.

    Args:
        struct_name: Name of the structure to modify
        field: Field identifier - either its current name or its numeric ordinal
        new_name: Optional new field name
        new_type: Optional new field type (e.g. "uint", "long")

    Returns:
        Result message describing the change
    """
    data = {"struct_name": struct_name, "field": field}
    if new_name is not None:
        data["new_name"] = new_name
    if new_type is not None:
        data["new_type"] = new_type
    return safe_post("edit_struct_field", data)

@mcp.tool()
def delete_struct_field(struct_name: str, field: str) -> str:
    """
    Delete a field from a structure.

    Args:
        struct_name: Name of the structure to modify
        field: Field identifier - either its name or its numeric ordinal

    Returns:
        Result message with the structure's new size
    """
    return safe_post("delete_struct_field", {"struct_name": struct_name, "field": field})

@mcp.tool()
def rename_struct(old_name: str, new_name: str) -> str:
    """
    Rename a structure data type.
    """
    return safe_post("rename_struct", {"old_name": old_name, "new_name": new_name})

@mcp.tool()
def delete_struct(name: str) -> str:
    """
    Delete a structure data type from the program's data type manager.
    """
    return safe_post("delete_struct", {"name": name})

@mcp.tool()
def get_struct(name: str) -> str:
    """
    Get the layout of a structure: for each field its ordinal, offset, length, type and name,
    plus the total size.

    Args:
        name: Name of the structure to inspect

    Returns:
        Human-readable structure layout
    """
    return "\n".join(safe_get("get_struct", {"name": name}))

# ---------------------------------------------------------------------------
# Group B: other data types (enum / union / typedef / browse)
# ---------------------------------------------------------------------------

@mcp.tool()
def create_enum(name: str, size: int = 4, category: str = None) -> str:
    """
    Create a new (empty) enum data type.

    Args:
        name: Name of the enum
        size: Storage size in bytes (1, 2, 4 or 8), default 4
        category: Optional data type category path (e.g. "/MyTypes")
    """
    data = {"name": name, "size": size}
    if category:
        data["category"] = category
    return safe_post("create_enum", data)

@mcp.tool()
def add_enum_value(enum_name: str, value_name: str, value: int) -> str:
    """
    Add a (name = value) member to an existing enum.
    """
    return safe_post("add_enum_value", {
        "enum_name": enum_name, "value_name": value_name, "value": value})

@mcp.tool()
def delete_enum_value(enum_name: str, value_name: str) -> str:
    """
    Remove a member from an enum by its name.
    """
    return safe_post("delete_enum_value", {"enum_name": enum_name, "value_name": value_name})

@mcp.tool()
def create_union(name: str, category: str = None) -> str:
    """
    Create a new (empty) union data type.

    Args:
        name: Name of the union
        category: Optional data type category path
    """
    data = {"name": name}
    if category:
        data["category"] = category
    return safe_post("create_union", data)

@mcp.tool()
def add_union_field(union_name: str, field_name: str, field_type: str) -> str:
    """
    Add a field to an existing union.

    Args:
        union_name: Name of the union to modify
        field_name: Name of the new field (may be empty for unnamed)
        field_type: Data type of the field (e.g. "int", "char *")
    """
    return safe_post("add_union_field", {
        "union_name": union_name, "field_name": field_name, "field_type": field_type})

@mcp.tool()
def create_typedef(name: str, base_type: str, category: str = None) -> str:
    """
    Create a typedef (type alias) for an existing base type.

    Args:
        name: Name of the new typedef
        base_type: The underlying type it aliases (e.g. "uint", "MyStruct *")
        category: Optional data type category path
    """
    data = {"name": name, "base_type": base_type}
    if category:
        data["category"] = category
    return safe_post("create_typedef", data)

@mcp.tool()
def list_data_types(category: str = None, filter: str = None, offset: int = 0, limit: int = 100) -> list:
    """
    List data types in the program's data type manager as "path | kind | size".

    Args:
        category: Optional category path prefix to restrict results (e.g. "/CustomStructs")
        filter: Optional substring to match within the type name
        offset: Pagination offset
        limit: Maximum number of entries to return
    """
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    if filter:
        params["filter"] = filter
    return safe_get("list_data_types", params)

@mcp.tool()
def get_type(name: str) -> str:
    """
    Dump any data type by name: struct/union layout, enum members, typedef target,
    or a summary for primitives.
    """
    return "\n".join(safe_get("get_type", {"name": name}))

# ---------------------------------------------------------------------------
# Group C: apply data types to memory
# ---------------------------------------------------------------------------

@mcp.tool()
def apply_data_type(address: str, type_name: str, clear_existing: bool = True) -> str:
    """
    Apply/define a data type at a memory address (e.g. lay a struct over data).

    Args:
        address: Target address in hex (e.g. "0x124000")
        type_name: Name of the data type to apply
        clear_existing: Clear conflicting existing code/data first (default True)
    """
    return safe_post("apply_data_type", {
        "address": address, "type_name": type_name,
        "clear_existing": "true" if clear_existing else "false"})

@mcp.tool()
def create_array(address: str, type_name: str, count: int) -> str:
    """
    Define an array of `count` elements of `type_name` at an address.
    """
    return safe_post("create_array", {
        "address": address, "type_name": type_name, "count": count})

@mcp.tool()
def clear_data(address: str) -> str:
    """
    Clear the defined data / code unit at an address.
    """
    return safe_post("clear_data", {"address": address})

# ---------------------------------------------------------------------------
# Group D: code & symbols
# ---------------------------------------------------------------------------

@mcp.tool()
def create_function(address: str, name: str = None) -> str:
    """
    Create a function at an address (Ghidra determines the body). Optional name.
    """
    data = {"address": address}
    if name:
        data["name"] = name
    return safe_post("create_function", data)

@mcp.tool()
def delete_function(address: str) -> str:
    """
    Delete the function at or containing an address.
    """
    return safe_post("delete_function", {"address": address})

@mcp.tool()
def define_code(address: str) -> str:
    """
    Disassemble (define code at) undefined bytes starting at an address.
    """
    return safe_post("define_code", {"address": address})

@mcp.tool()
def create_label(address: str, name: str) -> str:
    """
    Create a label (symbol) at an address.
    """
    return safe_post("create_label", {"address": address, "name": name})

@mcp.tool()
def rename_label(address: str, old_name: str, new_name: str) -> str:
    """
    Rename an existing label at an address.
    """
    return safe_post("rename_label", {
        "address": address, "old_name": old_name, "new_name": new_name})

@mcp.tool()
def remove_label(address: str, name: str) -> str:
    """
    Remove a label at an address by name.
    """
    return safe_post("remove_label", {"address": address, "name": name})

# ---------------------------------------------------------------------------
# Group E: comments & bookmarks
# ---------------------------------------------------------------------------

@mcp.tool()
def set_comment(address: str, comment_type: str, text: str) -> str:
    """
    Set a comment at an address.

    Args:
        address: Target address in hex
        comment_type: One of "plate", "pre", "eol", "post", "repeatable"
        text: Comment text (empty string clears it)
    """
    return safe_post("set_comment", {
        "address": address, "comment_type": comment_type, "text": text})

@mcp.tool()
def set_bookmark(address: str, category: str = "", note: str = "", type: str = "Note") -> str:
    """
    Set a bookmark at an address.

    Args:
        address: Target address in hex
        category: Bookmark category (free text)
        note: Bookmark comment
        type: Bookmark type, default "Note"
    """
    return safe_post("set_bookmark", {
        "address": address, "category": category, "note": note, "type": type})

@mcp.tool()
def list_bookmarks(offset: int = 0, limit: int = 100) -> list:
    """
    List all bookmarks as "address | type | category | comment".
    """
    return safe_get("list_bookmarks", {"offset": offset, "limit": limit})

# ---------------------------------------------------------------------------
# Group F: patching
# ---------------------------------------------------------------------------

@mcp.tool()
def assemble_instruction(address: str, instruction: str) -> str:
    """
    Assemble a single instruction and patch it into memory at an address.

    Args:
        address: Target address in hex
        instruction: Assembly text (e.g. "MOV EAX, 0x1")
    """
    return safe_post("assemble_instruction", {"address": address, "instruction": instruction}, timeout=HEAVY_TIMEOUT)

@mcp.tool()
def patch_bytes(address: str, hex_bytes: str) -> str:
    """
    Overwrite raw bytes at an address.

    Args:
        address: Target address in hex
        hex_bytes: Bytes as a hex string (e.g. "90 90" or "9090")
    """
    return safe_post("patch_bytes", {"address": address, "hex_bytes": hex_bytes})

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

