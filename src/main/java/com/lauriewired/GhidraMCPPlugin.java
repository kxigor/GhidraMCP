package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Bookmark;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // Data type (structure) endpoints
        server.createContext("/create_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createStruct(params.get("name"), params.get("category")));
        });

        server.createContext("/add_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), -1);
            sendResponse(exchange, addStructField(
                params.get("struct_name"), params.get("field_name"),
                params.get("field_type"), offset));
        });

        server.createContext("/edit_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, editStructField(
                params.get("struct_name"), params.get("field"),
                params.get("new_name"), params.get("new_type")));
        });

        server.createContext("/delete_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteStructField(params.get("struct_name"), params.get("field")));
        });

        server.createContext("/rename_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameStruct(params.get("old_name"), params.get("new_name")));
        });

        server.createContext("/delete_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteStruct(params.get("name")));
        });

        server.createContext("/get_struct", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, getStruct(qparams.get("name")));
        });

        // Group B: other data types (enum / union / typedef / browse)
        server.createContext("/create_enum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            int size = parseIntOrDefault(params.get("size"), 4);
            sendResponse(exchange, createEnum(params.get("name"), size, params.get("category")));
        });

        server.createContext("/add_enum_value", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            long value = parseLongOrDefault(params.get("value"), 0);
            sendResponse(exchange, addEnumValue(params.get("enum_name"), params.get("value_name"), value));
        });

        server.createContext("/delete_enum_value", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteEnumValue(params.get("enum_name"), params.get("value_name")));
        });

        server.createContext("/create_union", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createUnion(params.get("name"), params.get("category")));
        });

        server.createContext("/add_union_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, addUnionField(
                params.get("union_name"), params.get("field_name"), params.get("field_type")));
        });

        server.createContext("/create_typedef", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createTypedef(
                params.get("name"), params.get("base_type"), params.get("category")));
        });

        server.createContext("/list_data_types", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            int offset = parseIntOrDefault(q.get("offset"), 0);
            int limit = parseIntOrDefault(q.get("limit"), 100);
            sendResponse(exchange, listDataTypes(q.get("category"), q.get("filter"), offset, limit));
        });

        server.createContext("/get_type", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            sendResponse(exchange, getType(q.get("name")));
        });

        // Group C: apply types to memory
        server.createContext("/apply_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean clear = !"false".equalsIgnoreCase(params.getOrDefault("clear_existing", "true"));
            sendResponse(exchange, applyDataType(params.get("address"), params.get("type_name"), clear));
        });

        server.createContext("/create_array", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            int count = parseIntOrDefault(params.get("count"), 1);
            sendResponse(exchange, createArray(params.get("address"), params.get("type_name"), count));
        });

        server.createContext("/clear_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, clearData(params.get("address")));
        });

        // Group D: code & symbols
        server.createContext("/create_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createFunctionAt(params.get("address"), params.get("name")));
        });

        server.createContext("/delete_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, deleteFunctionAt(params.get("address")));
        });

        server.createContext("/define_code", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, defineCode(params.get("address")));
        });

        server.createContext("/create_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, createLabel(params.get("address"), params.get("name")));
        });

        server.createContext("/rename_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, renameLabel(
                params.get("address"), params.get("old_name"), params.get("new_name")));
        });

        server.createContext("/remove_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, removeLabel(params.get("address"), params.get("name")));
        });

        // Group E: comments & bookmarks
        server.createContext("/set_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setComment(
                params.get("address"), params.get("comment_type"), params.get("text")));
        });

        server.createContext("/set_bookmark", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, setBookmark(
                params.get("address"), params.get("category"), params.get("note"), params.get("type")));
        });

        server.createContext("/list_bookmarks", exchange -> {
            Map<String, String> q = parseQueryParams(exchange);
            int offset = parseIntOrDefault(q.get("offset"), 0);
            int limit = parseIntOrDefault(q.get("limit"), 100);
            sendResponse(exchange, listBookmarks(offset, limit));
        });

        // Group F: patching
        server.createContext("/assemble_instruction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, assembleInstruction(params.get("address"), params.get("instruction")));
        });

        server.createContext("/patch_bytes", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, patchBytes(params.get("address"), params.get("hex_bytes")));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    // ----------------------------------------------------------------------------------
    // Structure (data type) create/edit/read
    // ----------------------------------------------------------------------------------

    /**
     * Small functional interface for an operation that runs inside a program transaction
     * on the Swing thread and returns a human-readable result string.
     */
    private interface TxOp {
        String run() throws Exception;
    }

    /**
     * Run a mutating operation on the Swing thread wrapped in a single program transaction.
     * The operation validates its own preconditions and returns a result string (success or a
     * soft-failure message). Exceptions are caught and reported; the transaction is committed
     * only if no exception was thrown.
     */
    private String runInTransaction(String txName, TxOp op) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        final String[] result = new String[]{ "Unknown error" };
        final AtomicBoolean ok = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(txName);
                try {
                    result[0] = op.run();
                    ok.set(true);
                } catch (Exception e) {
                    result[0] = "Error: " + e.getMessage();
                    Msg.error(this, txName + " failed", e);
                } finally {
                    program.endTransaction(tx, ok.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute " + txName.toLowerCase() + " on Swing thread: " + e.getMessage();
        }
        return result[0];
    }

    /**
     * Look up a Structure data type by name in all categories.
     * @return the Structure, or null if not found or not a structure
     */
    private Structure getStructureByName(DataTypeManager dtm, String name) {
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);
        return (dt instanceof Structure) ? (Structure) dt : null;
    }

    /**
     * Resolve a field identifier (numeric ordinal or field name) to a component ordinal.
     * @return the ordinal, or -1 if not found
     */
    private int resolveComponentOrdinal(Structure struct, String field) {
        try {
            int ord = Integer.parseInt(field.trim());
            return (ord >= 0 && ord < struct.getNumComponents()) ? ord : -1;
        } catch (NumberFormatException ignore) {
            // not a number, fall through to name lookup
        }
        for (DataTypeComponent c : struct.getComponents()) {
            String fn = c.getFieldName();
            if (fn != null && fn.equals(field)) {
                return c.getOrdinal();
            }
        }
        return -1;
    }

    /**
     * Create a new empty structure data type.
     */
    private String createStruct(String name, String category) {
        if (name == null || name.isEmpty()) return "Struct name is required";
        return runInTransaction("Create struct", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            if (findDataTypeByNameInAllCategories(dtm, name) != null) {
                return "A data type named '" + name + "' already exists";
            }
            CategoryPath path = (category == null || category.isEmpty())
                ? new CategoryPath("/") : new CategoryPath(category);
            StructureDataType struct = new StructureDataType(path, name, 0, dtm);
            DataType added = dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);
            return "Created struct '" + added.getName() + "' at " + added.getPathName();
        });
    }

    /**
     * Add a field to an existing structure. offset < 0 appends to the end.
     */
    private String addStructField(String structName, String fieldName, String fieldType, int offset) {
        if (structName == null || structName.isEmpty()) return "struct_name is required";
        if (fieldType == null || fieldType.isEmpty()) return "field_type is required";
        return runInTransaction("Add struct field", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            Structure struct = getStructureByName(dtm, structName);
            if (struct == null) return "Struct not found: " + structName;
            DataType ft = resolveDataType(dtm, fieldType);
            if (ft == null) return "Could not resolve field type: " + fieldType;
            int len = ft.getLength() > 0 ? ft.getLength() : 1;
            String fn = (fieldName == null || fieldName.isEmpty()) ? null : fieldName;
            if (offset < 0) {
                struct.add(ft, len, fn, null);
            } else {
                struct.insertAtOffset(offset, ft, len, fn, null);
            }
            return "Added field '" + (fn == null ? "(unnamed)" : fn) + "' of type "
                + ft.getName() + " to " + structName + "; new size = " + struct.getLength();
        });
    }

    /**
     * Edit an existing struct field's name and/or type. Only the provided attributes change.
     */
    private String editStructField(String structName, String field, String newName, String newType) {
        if (structName == null || structName.isEmpty()) return "struct_name is required";
        if (field == null || field.isEmpty()) return "field (name or ordinal) is required";
        return runInTransaction("Edit struct field", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            Structure struct = getStructureByName(dtm, structName);
            if (struct == null) return "Struct not found: " + structName;
            int ordinal = resolveComponentOrdinal(struct, field);
            if (ordinal < 0) return "Field not found: " + field;
            DataTypeComponent comp = struct.getComponent(ordinal);
            DataType ft = (newType == null || newType.isEmpty())
                ? comp.getDataType() : resolveDataType(dtm, newType);
            if (ft == null) return "Could not resolve type: " + newType;
            String fn = (newName == null || newName.isEmpty()) ? comp.getFieldName() : newName;
            int len = ft.getLength() > 0 ? ft.getLength() : comp.getLength();
            struct.replace(ordinal, ft, len, fn, comp.getComment());
            return "Updated field #" + ordinal + " -> name=" + (fn == null ? "(unnamed)" : fn)
                + ", type=" + ft.getName() + "; struct size = " + struct.getLength();
        });
    }

    /**
     * Delete a field from a structure, identified by ordinal or field name.
     */
    private String deleteStructField(String structName, String field) {
        if (structName == null || structName.isEmpty()) return "struct_name is required";
        if (field == null || field.isEmpty()) return "field (name or ordinal) is required";
        return runInTransaction("Delete struct field", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            Structure struct = getStructureByName(dtm, structName);
            if (struct == null) return "Struct not found: " + structName;
            int ordinal = resolveComponentOrdinal(struct, field);
            if (ordinal < 0) return "Field not found: " + field;
            struct.delete(ordinal);
            return "Deleted field #" + ordinal + " from " + structName
                + "; new size = " + struct.getLength();
        });
    }

    /**
     * Rename a structure data type.
     */
    private String renameStruct(String oldName, String newName) {
        if (oldName == null || oldName.isEmpty() || newName == null || newName.isEmpty()) {
            return "old_name and new_name are required";
        }
        return runInTransaction("Rename struct", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            Structure struct = getStructureByName(dtm, oldName);
            if (struct == null) return "Struct not found: " + oldName;
            struct.setName(newName);
            return "Renamed struct '" + oldName + "' to '" + newName + "'";
        });
    }

    /**
     * Delete a structure data type from the data type manager.
     */
    private String deleteStruct(String name) {
        if (name == null || name.isEmpty()) return "name is required";
        return runInTransaction("Delete struct", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            Structure struct = getStructureByName(dtm, name);
            if (struct == null) return "Struct not found: " + name;
            boolean removed = dtm.remove(struct, new ConsoleTaskMonitor());
            return removed ? "Deleted struct '" + name + "'"
                           : "Failed to delete struct '" + name + "'";
        });
    }

    /**
     * Dump a structure's layout (ordinal, offset, length, type, field name).
     */
    private String getStruct(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        Structure struct = getStructureByName(dtm, name);
        if (struct == null) return "Struct not found: " + name;

        StringBuilder sb = new StringBuilder();
        sb.append("Struct: ").append(struct.getName())
          .append(" (").append(struct.getPathName()).append(")")
          .append(", size = ").append(struct.getLength()).append(" bytes\n");
        sb.append("ordinal | offset | length | type | name\n");
        for (DataTypeComponent c : struct.getComponents()) {
            String fn = c.getFieldName();
            sb.append(String.format("%d | %d | %d | %s | %s\n",
                c.getOrdinal(), c.getOffset(), c.getLength(),
                c.getDataType().getName(), fn == null ? "(unnamed)" : fn));
        }
        return sb.toString();
    }

    /**
     * Build a CategoryPath from a string, defaulting to root "/".
     */
    private CategoryPath categoryPath(String category) {
        return (category == null || category.isEmpty())
            ? new CategoryPath("/") : new CategoryPath(category);
    }

    // ----------------------------------------------------------------------------------
    // Group B: enums, unions, typedefs, type browsing
    // ----------------------------------------------------------------------------------

    private String createEnum(String name, int size, String category) {
        if (name == null || name.isEmpty()) return "name is required";
        if (size != 1 && size != 2 && size != 4 && size != 8) return "size must be 1, 2, 4 or 8";
        return runInTransaction("Create enum", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            if (findDataTypeByNameInAllCategories(dtm, name) != null) {
                return "A data type named '" + name + "' already exists";
            }
            EnumDataType e = new EnumDataType(categoryPath(category), name, size, dtm);
            DataType added = dtm.addDataType(e, DataTypeConflictHandler.DEFAULT_HANDLER);
            return "Created enum '" + added.getName() + "' (" + size + " bytes) at " + added.getPathName();
        });
    }

    private String addEnumValue(String enumName, String valueName, long value) {
        if (enumName == null || enumName.isEmpty()) return "enum_name is required";
        if (valueName == null || valueName.isEmpty()) return "value_name is required";
        return runInTransaction("Add enum value", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            DataType dt = findDataTypeByNameInAllCategories(dtm, enumName);
            if (!(dt instanceof Enum)) return "Enum not found: " + enumName;
            ((Enum) dt).add(valueName, value);
            return "Added '" + valueName + "' = " + value + " to enum " + enumName;
        });
    }

    private String deleteEnumValue(String enumName, String valueName) {
        if (enumName == null || enumName.isEmpty()) return "enum_name is required";
        if (valueName == null || valueName.isEmpty()) return "value_name is required";
        return runInTransaction("Delete enum value", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            DataType dt = findDataTypeByNameInAllCategories(dtm, enumName);
            if (!(dt instanceof Enum)) return "Enum not found: " + enumName;
            ((Enum) dt).remove(valueName);
            return "Removed '" + valueName + "' from enum " + enumName;
        });
    }

    private String createUnion(String name, String category) {
        if (name == null || name.isEmpty()) return "name is required";
        return runInTransaction("Create union", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            if (findDataTypeByNameInAllCategories(dtm, name) != null) {
                return "A data type named '" + name + "' already exists";
            }
            UnionDataType u = new UnionDataType(categoryPath(category), name, dtm);
            DataType added = dtm.addDataType(u, DataTypeConflictHandler.DEFAULT_HANDLER);
            return "Created union '" + added.getName() + "' at " + added.getPathName();
        });
    }

    private String addUnionField(String unionName, String fieldName, String fieldType) {
        if (unionName == null || unionName.isEmpty()) return "union_name is required";
        if (fieldType == null || fieldType.isEmpty()) return "field_type is required";
        return runInTransaction("Add union field", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            DataType dt = findDataTypeByNameInAllCategories(dtm, unionName);
            if (!(dt instanceof Union)) return "Union not found: " + unionName;
            Union u = (Union) dt;
            DataType ft = resolveDataType(dtm, fieldType);
            if (ft == null) return "Could not resolve field type: " + fieldType;
            int len = ft.getLength() > 0 ? ft.getLength() : 1;
            String fn = (fieldName == null || fieldName.isEmpty()) ? null : fieldName;
            u.add(ft, len, fn, null);
            return "Added field '" + (fn == null ? "(unnamed)" : fn) + "' of type "
                + ft.getName() + " to union " + unionName + "; size = " + u.getLength();
        });
    }

    private String createTypedef(String name, String baseType, String category) {
        if (name == null || name.isEmpty()) return "name is required";
        if (baseType == null || baseType.isEmpty()) return "base_type is required";
        return runInTransaction("Create typedef", () -> {
            DataTypeManager dtm = getCurrentProgram().getDataTypeManager();
            if (findDataTypeByNameInAllCategories(dtm, name) != null) {
                return "A data type named '" + name + "' already exists";
            }
            DataType base = resolveDataType(dtm, baseType);
            if (base == null) return "Could not resolve base type: " + baseType;
            TypedefDataType td = new TypedefDataType(categoryPath(category), name, base, dtm);
            DataType added = dtm.addDataType(td, DataTypeConflictHandler.DEFAULT_HANDLER);
            return "Created typedef '" + added.getName() + "' -> " + base.getName()
                + " at " + added.getPathName();
        });
    }

    private String listDataTypes(String category, String filter, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DataTypeManager dtm = program.getDataTypeManager();
        List<String> lines = new ArrayList<>();
        Iterator<DataType> it = dtm.getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            String path = dt.getPathName();
            if (category != null && !category.isEmpty() && !path.startsWith(category)) continue;
            if (filter != null && !filter.isEmpty()
                    && !dt.getName().toLowerCase().contains(filter.toLowerCase())) continue;
            int len = dt.getLength();
            lines.add(String.format("%s | %s | %s",
                path, dt.getClass().getSimpleName(), len < 0 ? "?" : String.valueOf(len)));
        }
        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    private String getType(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "name is required";
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dt = findDataTypeByNameInAllCategories(dtm, name);
        if (dt == null) return "Type not found: " + name;

        if (dt instanceof Composite) {
            Composite comp = (Composite) dt;
            StringBuilder sb = new StringBuilder();
            sb.append(dt instanceof Structure ? "Struct: " : "Union: ").append(dt.getName())
              .append(" (").append(dt.getPathName()).append("), size = ")
              .append(dt.getLength()).append(" bytes\n");
            sb.append("ordinal | offset | length | type | name\n");
            for (DataTypeComponent c : comp.getComponents()) {
                String fn = c.getFieldName();
                sb.append(String.format("%d | %d | %d | %s | %s\n",
                    c.getOrdinal(), c.getOffset(), c.getLength(),
                    c.getDataType().getName(), fn == null ? "(unnamed)" : fn));
            }
            return sb.toString();
        }
        if (dt instanceof Enum) {
            Enum e = (Enum) dt;
            StringBuilder sb = new StringBuilder();
            sb.append("Enum: ").append(dt.getName()).append(" (").append(dt.getPathName())
              .append("), size = ").append(dt.getLength()).append(" bytes\n");
            for (String vn : e.getNames()) {
                long v = e.getValue(vn);
                sb.append(String.format("%s = %d (0x%x)\n", vn, v, v));
            }
            return sb.toString();
        }
        if (dt instanceof TypeDef) {
            TypeDef td = (TypeDef) dt;
            return "Typedef: " + dt.getName() + " (" + dt.getPathName() + ") -> "
                + td.getDataType().getName();
        }
        return "Type: " + dt.getName() + " (" + dt.getPathName() + "), size = "
            + dt.getLength() + ", class = " + dt.getClass().getSimpleName();
    }

    // ----------------------------------------------------------------------------------
    // Group C: apply data types to memory
    // ----------------------------------------------------------------------------------

    private String applyDataType(String addressStr, String typeName, boolean clearExisting) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        if (typeName == null || typeName.isEmpty()) return "type_name is required";
        return runInTransaction("Apply data type", () -> {
            Program program = getCurrentProgram();
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = resolveDataType(dtm, typeName);
            if (dt == null) return "Could not resolve type: " + typeName;
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            if (clearExisting) {
                int len = dt.getLength();
                Address end = (len > 1) ? addr.add(len - 1) : addr;
                program.getListing().clearCodeUnits(addr, end, false);
            }
            CreateDataCmd cmd = new CreateDataCmd(addr, dt);
            boolean ok = cmd.applyTo(program);
            return ok ? "Applied " + dt.getName() + " at " + addr
                      : "Failed to apply type: " + cmd.getStatusMsg();
        });
    }

    private String createArray(String addressStr, String typeName, int count) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        if (typeName == null || typeName.isEmpty()) return "type_name is required";
        if (count <= 0) return "count must be > 0";
        return runInTransaction("Create array", () -> {
            Program program = getCurrentProgram();
            DataTypeManager dtm = program.getDataTypeManager();
            DataType elem = resolveDataType(dtm, typeName);
            if (elem == null) return "Could not resolve type: " + typeName;
            int elemLen = elem.getLength() > 0 ? elem.getLength() : 1;
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            ArrayDataType arr = new ArrayDataType(elem, count, elemLen);
            program.getListing().clearCodeUnits(addr, addr.add((long) elemLen * count - 1), false);
            CreateDataCmd cmd = new CreateDataCmd(addr, arr);
            boolean ok = cmd.applyTo(program);
            return ok ? "Applied " + elem.getName() + "[" + count + "] at " + addr
                      : "Failed to create array: " + cmd.getStatusMsg();
        });
    }

    private String clearData(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        return runInTransaction("Clear data", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            Data d = program.getListing().getDefinedDataAt(addr);
            if (d != null) {
                program.getListing().clearCodeUnits(d.getMinAddress(), d.getMaxAddress(), false);
            } else {
                program.getListing().clearCodeUnits(addr, addr, false);
            }
            return "Cleared data at " + addr;
        });
    }

    // ----------------------------------------------------------------------------------
    // Group D: code & symbols
    // ----------------------------------------------------------------------------------

    private String createFunctionAt(String addressStr, String name) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        return runInTransaction("Create function", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            if (program.getFunctionManager().getFunctionAt(addr) != null) {
                return "A function already exists at " + addr;
            }
            String fname = (name == null || name.isEmpty()) ? null : name;
            CreateFunctionCmd cmd = new CreateFunctionCmd(fname, addr, null, SourceType.USER_DEFINED);
            boolean ok = cmd.applyTo(program);
            Function f = program.getFunctionManager().getFunctionAt(addr);
            return (ok && f != null) ? "Created function " + f.getName() + " at " + addr
                                     : "Failed to create function: " + cmd.getStatusMsg();
        });
    }

    private String deleteFunctionAt(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        return runInTransaction("Delete function", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            Function f = getFunctionForAddress(program, addr);
            if (f == null) return "No function at or containing " + addressStr;
            Address entry = f.getEntryPoint();
            boolean ok = program.getFunctionManager().removeFunction(entry);
            return ok ? "Deleted function at " + entry : "Failed to delete function at " + entry;
        });
    }

    private String defineCode(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        return runInTransaction("Disassemble", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
            boolean ok = cmd.applyTo(program);
            return ok ? "Disassembled at " + addr : "Failed to disassemble: " + cmd.getStatusMsg();
        });
    }

    private String createLabel(String addressStr, String name) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        if (name == null || name.isEmpty()) return "name is required";
        return runInTransaction("Create label", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            program.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
            return "Created label '" + name + "' at " + addr;
        });
    }

    private String renameLabel(String addressStr, String oldName, String newName) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        if (oldName == null || oldName.isEmpty() || newName == null || newName.isEmpty()) {
            return "old_name and new_name are required";
        }
        return runInTransaction("Rename label", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            for (Symbol s : program.getSymbolTable().getSymbols(addr)) {
                if (s.getName().equals(oldName)) {
                    s.setName(newName, SourceType.USER_DEFINED);
                    return "Renamed label to '" + newName + "' at " + addr;
                }
            }
            return "Label '" + oldName + "' not found at " + addr;
        });
    }

    private String removeLabel(String addressStr, String name) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        if (name == null || name.isEmpty()) return "name is required";
        return runInTransaction("Remove label", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            for (Symbol s : program.getSymbolTable().getSymbols(addr)) {
                if (s.getName().equals(name)) {
                    boolean ok = s.delete();
                    return ok ? "Removed label '" + name + "' at " + addr
                              : "Failed to remove label '" + name + "'";
                }
            }
            return "Label '" + name + "' not found at " + addr;
        });
    }

    // ----------------------------------------------------------------------------------
    // Group E: comments & bookmarks
    // ----------------------------------------------------------------------------------

    private CommentType commentTypeFromString(String t) {
        if (t == null) return null;
        switch (t.toLowerCase()) {
            case "plate":      return CommentType.PLATE;
            case "pre":        return CommentType.PRE;
            case "eol":        return CommentType.EOL;
            case "post":       return CommentType.POST;
            case "repeatable": return CommentType.REPEATABLE;
            default:           return null;
        }
    }

    private String setComment(String addressStr, String commentType, String text) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        CommentType ct = commentTypeFromString(commentType);
        if (ct == null) return "comment_type must be one of: plate, pre, eol, post, repeatable";
        return runInTransaction("Set comment", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            program.getListing().setComment(addr, ct, text);
            return "Set " + commentType + " comment at " + addr;
        });
    }

    private String setBookmark(String addressStr, String category, String note, String type) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        return runInTransaction("Set bookmark", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            String bt = (type == null || type.isEmpty()) ? "Note" : type;
            program.getBookmarkManager().setBookmark(addr, bt,
                category == null ? "" : category, note == null ? "" : note);
            return "Set bookmark at " + addr;
        });
    }

    private String listBookmarks(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        List<String> lines = new ArrayList<>();
        Iterator<Bookmark> it = program.getBookmarkManager().getBookmarksIterator();
        while (it.hasNext()) {
            Bookmark b = it.next();
            lines.add(String.format("%s | %s | %s | %s",
                b.getAddress(), b.getTypeString(), b.getCategory(), b.getComment()));
        }
        return paginateList(lines, offset, limit);
    }

    // ----------------------------------------------------------------------------------
    // Group F: patching
    // ----------------------------------------------------------------------------------

    private String assembleInstruction(String addressStr, String instruction) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        if (instruction == null || instruction.isEmpty()) return "instruction is required";
        return runInTransaction("Assemble instruction", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            Assembler asm = Assemblers.getAssembler(program);
            asm.assemble(addr, instruction);
            return "Assembled '" + instruction + "' at " + addr;
        });
    }

    private String patchBytes(String addressStr, String hexBytes) {
        if (addressStr == null || addressStr.isEmpty()) return "address is required";
        if (hexBytes == null || hexBytes.isEmpty()) return "hex_bytes is required";
        return runInTransaction("Patch bytes", () -> {
            Program program = getCurrentProgram();
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            String clean = hexBytes.replaceAll("[^0-9a-fA-F]", "");
            if (clean.isEmpty() || clean.length() % 2 != 0) {
                return "hex_bytes must be an even number of hex digits";
            }
            byte[] bytes = new byte[clean.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
            }
            program.getMemory().setBytes(addr, bytes);
            return "Patched " + bytes.length + " byte(s) at " + addr;
        });
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Parse a long from a string (decimal, or 0x-prefixed hex), or return defaultValue.
     */
    private long parseLongOrDefault(String val, long defaultValue) {
        if (val == null) return defaultValue;
        try {
            String v = val.trim();
            if (v.startsWith("0x") || v.startsWith("0X")) {
                return Long.parseLong(v.substring(2), 16);
            }
            if (v.startsWith("-0x") || v.startsWith("-0X")) {
                return -Long.parseLong(v.substring(3), 16);
            }
            return Long.parseLong(v);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
