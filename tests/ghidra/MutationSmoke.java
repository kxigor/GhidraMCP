import com.lauriewired.mcp.ApiException;
import com.lauriewired.mcp.BridgeService;
import com.lauriewired.mcp.Json;
import com.lauriewired.mcp.TransactionGuard;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MutationSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        try (BridgeService bridge = new BridgeService(null, false)) {
            service = bridge;
            service.setProject(state.getProject());
            DomainFile file = getScriptArgs().length == 0 ?
                firstProgram(state.getProject().getProjectData().getRootFolder()) :
                state.getProject().getProjectData().getFile(getScriptArgs()[0]);
            require(file != null, "A fixture program is required");
            Map<String, Object> opened = invoke("open_program", Json.map(
                "project_id", service.registry().projectId(), "project_path", file.getPathname()));
            programId = (String) opened.get("program_id");
            require(programId != null, "open_program must return program_id");
            program = service.registry().entry(programId).program();
            Function entry = findFunction("fixture_entry");
            entryAddress = address(entry.getEntryPoint());
            dataAddress = address(program.getSymbolTable().getGlobalSymbols("fixture_bytes").getFirst().getAddress());

            testFunctionsAndVariables();
            testTypesAndData();
            testLabelsCommentsAndBytes();
            testExternalLibrary();
            testReadOnly();
            testConcurrentTransactionRollback();
            testActiveTransactionRejection();
            testCreateDeleteFunction();
            invoke("close_program", args("discard_changes", true));
            println("MUTATION_SMOKE_OK " + assertions + " assertions");
        }
    }

    private void testFunctionsAndVariables() throws Exception {
        invoke("rename_function", args("function_address", entryAddress, "new_name", "mcp_smoke_entry"));
        require(findFunction("mcp_smoke_entry") != null, "rename_function must update the selected function");
        Address entry = parse(entryAddress);
        TransactionGuard.execute(program, "smoke setup comment", null, monitor, () -> {
            program.getListing().setComment(entry, CommentType.PLATE, "preserve this comment");
            return null;
        });
        String signature = program.getFunctionManager().getFunctionAt(entry).getPrototypeString(false, false);
        expectError("set_function_prototype", args("function_address", entryAddress,
            "prototype", "not a valid prototype("), "INVALID_ARGUMENT");
        require(signature.equals(program.getFunctionManager().getFunctionAt(entry).getPrototypeString(false, false)),
            "Invalid prototype must preserve signature");
        require("preserve this comment".equals(program.getListing().getComment(CommentType.PLATE, entry)),
            "Invalid prototype must not add a plate comment");
        invoke("set_function_prototype", args("function_address", entryAddress,
            "prototype", "int mcp_smoke_entry(int value)"));

        Map<String, Object> variables = invoke("list_variables", args("function_address", entryAddress));
        List<Map<String, Object>> items = items(variables);
        require(!items.isEmpty(), "Fixture parameter must appear in list_variables");
        Map<String, Object> parameter = items.stream().filter(row -> Boolean.TRUE.equals(row.get("parameter")))
            .findFirst().orElseThrow();
        String variableId = (String) parameter.get("variable_id");
        invoke("rename_variable", args("function_address", entryAddress, "variable_id", variableId,
            "new_name", "mcp_value"));
        expectError("rename_variable", args("function_address", entryAddress, "variable_id", variableId,
            "new_name", "stale_should_fail"), "STALE_VARIABLE");
        variables = invoke("list_variables", args("function_address", entryAddress));
        parameter = items(variables).stream().filter(row -> "mcp_value".equals(row.get("name")))
            .findFirst().orElseThrow();
        invoke("set_local_variable_type", args("function_address", entryAddress,
            "variable_id", parameter.get("variable_id"), "type_path", "/uint"));
    }

    private void testTypesAndData() throws Exception {
        invoke("create_struct", args("type_path", "/McpSmoke/State"));
        invoke("add_struct_field", args("type_path", "/McpSmoke/State", "field_name", "value",
            "field_type_path", "/int", "field_offset", 0));
        Structure structure = (Structure) program.getDataTypeManager().getDataType("/McpSmoke/State");
        require(structure.getLength() == 4, "Structure field must use the target integer size");
        expectError("add_struct_field", args("type_path", "/McpSmoke/State", "field_name", "overlap",
            "field_type_path", "/int", "field_offset", 1), "DATA_CONFLICT");
        require(structure.getLength() == 4 && structure.getDefinedComponents().length == 1,
            "Rejected field must not expand or modify the structure");
        Map<String, Object> pointer = invoke("create_pointer", args("base_type_path", "/McpSmoke/State"));
        require(((Number) pointer.get("size")).intValue() == program.getDefaultPointerSize(),
            "Pointer must use the target architecture size by default");
        invoke("create_struct", args("type_path", "/McpSmoke/Holder"));
        invoke("add_struct_field", args("type_path", "/McpSmoke/Holder", "field_name", "state",
            "field_type_path", pointer.get("type_path")));
        require(((Structure) program.getDataTypeManager().getDataType("/McpSmoke/Holder"))
            .getDefinedComponents()[0].getDataType() instanceof ghidra.program.model.data.Pointer,
            "The newly created pointer must be usable as a structure field");
        invoke("edit_struct_field", args("type_path", "/McpSmoke/State", "field_offset", 0,
            "new_name", "renamed_value", "comment", "field comment"));
        require("renamed_value".equals(structure.getComponentAt(0).getFieldName()), "Field rename must apply");
        expectError("edit_struct_field", args("type_path", "/McpSmoke/State", "field_offset", 0,
            "field_ordinal", 0, "new_name", "ambiguous"), "INVALID_ARGUMENT");
        invoke("create_union", args("type_path", "/McpSmoke/Value"));
        invoke("add_union_field", args("type_path", "/McpSmoke/Value", "field_name", "integer",
            "field_type_path", "/int"));
        invoke("create_enum", args("type_path", "/McpSmoke/Flags", "size", 8));
        invoke("add_enum_value", args("type_path", "/McpSmoke/Flags", "value_name", "HighBit",
            "value", "0x8000000000000000"));
        expectError("add_enum_value", args("type_path", "/McpSmoke/Flags", "value_name", "HighBit",
            "value", 1), "NAME_CONFLICT");
        invoke("delete_enum_value", args("type_path", "/McpSmoke/Flags", "value_name", "HighBit"));
        invoke("create_typedef", args("type_path", "/McpSmoke/Handle", "base_type_path", "/int"));

        byte[] before = new byte[4];
        program.getMemory().getBytes(parse(dataAddress), before);
        invoke("apply_data_type", args("address", dataAddress, "type_path", "/McpSmoke/State",
            "clear_existing", true));
        invoke("clear_data", args("address", dataAddress, "length", 4));
        byte[] after = new byte[4];
        program.getMemory().getBytes(parse(dataAddress), after);
        require(Arrays.equals(before, after), "clear_data must preserve bytes");
        invoke("create_array", args("address", dataAddress, "type_path", "/byte", "count", 4));
        require(program.getListing().getDefinedDataAt(parse(dataAddress)).isArray(), "create_array must define an array");
        expectError("apply_data_type", args("address", dataAddress, "type_path", "/int"), "DATA_CONFLICT");
        invoke("delete_struct_field", args("type_path", "/McpSmoke/State", "field_offset", 0));
        invoke("rename_struct", args("type_path", "/McpSmoke/State", "new_name", "RenamedState"));
        invoke("delete_struct", args("type_path", "/McpSmoke/RenamedState"));
        require(program.getDataTypeManager().getDataType("/McpSmoke/RenamedState") == null, "delete_struct must remove the type");
    }

    private void testLabelsCommentsAndBytes() throws Exception {
        invoke("create_label", args("address", entryAddress, "name", "mcp_smoke_label", "namespace", ""));
        invoke("rename_label", args("address", entryAddress, "old_name", "mcp_smoke_label",
            "new_name", "mcp_renamed_label", "namespace", ""));
        invoke("remove_label", args("address", entryAddress, "name", "mcp_renamed_label", "namespace", ""));
        require(program.getSymbolTable().getGlobalSymbol("mcp_renamed_label", parse(entryAddress)) == null,
            "remove_label must remove the exact label");
        invoke("rename_data", args("address", dataAddress, "new_name", "mcp_fixture_bytes"));
        invoke("set_comment", args("address", entryAddress, "comment_type", "eol", "text", "MCP комментарий"));
        require("MCP комментарий".equals(program.getListing().getComment(CommentType.EOL, parse(entryAddress))),
            "Comments must preserve Unicode");
        invoke("set_comment", args("address", entryAddress, "comment_type", "eol", "text", ""));
        require(program.getListing().getComment(CommentType.EOL, parse(entryAddress)) == null, "Empty comment must clear text");
        invoke("set_bookmark", args("address", entryAddress, "type", "Note", "category", "MCP smoke", "note", "checked"));

        byte[] bytes = new byte[4];
        program.getMemory().getBytes(parse(dataAddress), bytes);
        String original = HexFormat.of().formatHex(bytes);
        expectError("patch_bytes", args("address", dataAddress, "bytes_hex", "aabbccdd",
            "expected_bytes_hex", "00000000"), "REVISION_CONFLICT");
        byte[] unchanged = new byte[4];
        program.getMemory().getBytes(parse(dataAddress), unchanged);
        require(Arrays.equals(bytes, unchanged), "Rejected patch must preserve bytes");
        invoke("patch_bytes", args("address", dataAddress, "bytes_hex", "aa bb cc dd",
            "expected_bytes_hex", original));
        invoke("patch_bytes", args("address", dataAddress, "bytes_hex", original,
            "expected_bytes_hex", "aabbccdd"));
        expectError("clear_data", args("address", entryAddress, "length", 1), "DATA_CONFLICT");
        expectError("patch_bytes", args("address", dataAddress, "bytes_hex", "zz12"), "INVALID_ARGUMENT");
    }

    private void testExternalLibrary() throws Exception {
        var imports = program.getExternalManager().getExternalLocations(ghidra.program.model.listing.Library.UNKNOWN);
        require(imports.hasNext(), "Fixture must contain an unassigned external import");
        var location = imports.next();
        String externalAddress = address(location.getExternalSpaceAddress());
        long symbolId = location.getSymbol().getID();
        expectError("set_external_library_path", args("external_library", ghidra.program.model.listing.Library.UNKNOWN,
            "project_id", service.registry().projectId(), "project_path", program.getDomainFile().getPathname()),
            "INVALID_ARGUMENT");
        expectError("set_import_library", args("external_address", entryAddress,
            "external_library", "McpSmokeExternal"), "ADDRESS_INVALID");
        invoke("set_import_library", args("external_address", externalAddress,
            "external_library", "McpSmokeExternal"));
        require("McpSmokeExternal".equals(location.getLibraryName()), "Import must move into the named library");
        require(location.getSymbol().getID() == symbolId && externalAddress.equals(address(location.getExternalSpaceAddress())),
            "Reassigning the import must preserve its symbol identity and references");
        invoke("set_external_library_path", args("external_library", "McpSmokeExternal",
            "project_id", service.registry().projectId(), "project_path", program.getDomainFile().getPathname()));
        require(program.getDomainFile().getPathname().equals(
            program.getExternalManager().getExternalLibraryPath("McpSmokeExternal")), "External library binding must be stored");
        var method = TransactionGuard.execute(program, "create namespaced fixture import", null, monitor, () -> {
            var library = program.getExternalManager().getExternalLibrary("McpSmokeExternal");
            var namespace = program.getSymbolTable().createNameSpace(library, "Nested",
                ghidra.program.model.symbol.SourceType.IMPORTED);
            var clazz = program.getSymbolTable().createClass(namespace, "State",
                ghidra.program.model.symbol.SourceType.IMPORTED);
            return program.getExternalManager().addExtFunction(clazz, "fixture_method", null,
                ghidra.program.model.symbol.SourceType.IMPORTED);
        });
        invoke("set_import_library", args("external_address", address(method.getExternalSpaceAddress()),
            "external_library", "McpSmokeOther"));
        require("McpSmokeOther::Nested::State".equals(method.getParentNameSpace().getName(true)),
            "Moving a C++ import must preserve its namespace qualification");
        require(method.getParentNameSpace().getSymbol().getSymbolType() == ghidra.program.model.symbol.SymbolType.CLASS,
            "Moving a C++ import must preserve its class namespace kind");
    }

    private void testReadOnly() throws Exception {
        try (BridgeService readOnly = new BridgeService(null, true)) {
            readOnly.setProject(state.getProject());
            var entry = readOnly.registry().adopt(program, null);
            Map<String, Object> response = runJob(readOnly, "rename_function", Json.map(
                "program_id", entry.id(), "function_address", entryAddress, "new_name", "must_not_change"));
            require("READ_ONLY".equals(errorCode(response)), "read_only must reject direct backend writes");
            require("mcp_smoke_entry".equals(program.getFunctionManager().getFunctionAt(parse(entryAddress)).getName()),
                "Rejected read_only mutation must preserve name");
        }
    }

    private void testConcurrentTransactionRollback() throws Exception {
        Address first = parse(entryAddress);
        Address second = parse(dataAddress);
        String before = program.getListing().getComment(CommentType.PRE, first);
        CountDownLatch attempted = new CountDownLatch(1);
        CountDownLatch begun = new CountDownLatch(1);
        var executor = Executors.newSingleThreadExecutor();
        try {
            var future = new java.util.concurrent.atomic.AtomicReference<java.util.concurrent.Future<?>>();
            try {
                TransactionGuard.execute(program, "forced rollback", null, TaskMonitor.DUMMY, () -> {
                    program.getListing().setComment(first, CommentType.PRE, "must roll back");
                    future.set(executor.submit(() -> {
                        attempted.countDown();
                        int transaction = program.startTransaction("simulated GUI edit");
                        begun.countDown();
                        try {
                            program.getListing().setComment(second, CommentType.PRE, "GUI edit survives");
                        }
                        finally {
                            program.endTransaction(transaction, true);
                        }
                    }));
                    require(attempted.await(5, TimeUnit.SECONDS), "Concurrent writer must attempt transaction");
                    require(!begun.await(150, TimeUnit.MILLISECONDS), "Concurrent GUI transaction must not join MCP transaction");
                    throw new ApiException("INVALID_ARGUMENT", "Intentional rollback");
                });
                throw new AssertionError("The forced rollback must throw");
            }
            catch (ApiException expected) {
                require(expected.code().equals("INVALID_ARGUMENT"), "Expected forced rollback error");
            }
            future.get().get(5, TimeUnit.SECONDS);
            require(java.util.Objects.equals(before, program.getListing().getComment(CommentType.PRE, first)),
                "Failed MCP transaction must roll back its own edit");
            require("GUI edit survives".equals(program.getListing().getComment(CommentType.PRE, second)),
                "Rollback must preserve the subsequent GUI transaction");
        }
        finally {
            executor.shutdownNow();
        }
    }

    private void testActiveTransactionRejection() throws Exception {
        int transaction = program.startTransaction("active GUI transaction");
        try {
            program.getListing().setComment(parse(entryAddress), CommentType.POST, "active GUI edit");
            expectError("rename_function", args("function_address", entryAddress, "new_name", "must_not_join"), "PROGRAM_BUSY");
        }
        finally {
            program.endTransaction(transaction, true);
        }
        require("active GUI edit".equals(program.getListing().getComment(CommentType.POST, parse(entryAddress))),
            "Rejected MCP transaction must not roll back active GUI changes");
    }

    private void testCreateDeleteFunction() throws Exception {
        invoke("delete_function", args("address", entryAddress));
        require(program.getFunctionManager().getFunctionAt(parse(entryAddress)) == null, "Function must be removed");
        invoke("create_function", args("address", entryAddress, "name", "recreated_fixture"));
        require(program.getFunctionManager().getFunctionAt(parse(entryAddress)) != null, "Function must be recreated");
        var instruction = program.getListing().getInstructionAt(parse(entryAddress));
        int length = instruction.getLength();
        TransactionGuard.execute(program, "clear fixture instruction", null, monitor, () -> {
            program.getListing().clearCodeUnits(instruction.getMinAddress(), instruction.getMaxAddress(), false);
            return null;
        });
        invoke("define_code", args("address", entryAddress, "length", length));
        require(program.getListing().getInstructionAt(parse(entryAddress)) != null,
            "define_code must recreate the cleared instruction");
    }

    private Map<String, Object> invoke(String operation, Map<String, Object> arguments) throws Exception {
        Map<String, Object> response = runJob(service, operation, arguments);
        require("succeeded".equals(response.get("state")), operation + " failed: " + response);
        return map(map(response.get("result")).get("data"));
    }

    private void expectError(String operation, Map<String, Object> arguments, String code) throws Exception {
        Map<String, Object> response = runJob(service, operation, arguments);
        require(code.equals(errorCode(response)), operation + " expected " + code + ": " + response);
    }

    private Map<String, Object> runJob(BridgeService bridge, String operation, Map<String, Object> arguments)
            throws Exception {
        var job = bridge.submit("smoke-" + UUID.randomUUID(), operation, arguments, 120_000);
        for (int attempt = 0; attempt < 130 && !job.terminal(); attempt++) {
            job.await(1000);
        }
        require(job.terminal(), operation + " did not finish");
        return job.snapshot();
    }

    private static String errorCode(Map<String, Object> response) {
        return response.get("error") instanceof Map<?, ?> error ? (String) error.get("code") : "";
    }

    private Map<String, Object> args(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>(Json.map(pairs));
        result.put("program_id", programId);
        return result;
    }

    private Function findFunction(String name) {
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (function.getName().equals(name)) return function;
        }
        throw new AssertionError("Missing fixture function: " + name);
    }

    private static DomainFile firstProgram(DomainFolder folder) {
        for (DomainFile file : folder.getFiles()) {
            if (Program.class.isAssignableFrom(file.getDomainObjectClass())) return file;
        }
        for (DomainFolder child : folder.getFolders()) {
            DomainFile found = firstProgram(child);
            if (found != null) return found;
        }
        return null;
    }

    private Address parse(String address) {
        return com.lauriewired.mcp.Arguments.address(program, address);
    }

    private static String address(Address address) {
        return address.getAddressSpace().getName() + ":0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> items(Map<String, Object> value) {
        return (List<Map<String, Object>>) value.get("items");
    }

    private void require(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    private BridgeService service;
    private Program program;
    private String programId;
    private String entryAddress;
    private String dataAddress;
    private int assertions;
}
