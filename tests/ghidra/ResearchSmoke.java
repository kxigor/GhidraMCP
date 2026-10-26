import com.lauriewired.mcp.ApiException;
import com.lauriewired.mcp.BridgeService;
import com.lauriewired.mcp.Json;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class ResearchSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        List<String> files = new ArrayList<>();
        collect(state.getProject().getProjectData().getRootFolder(), files);
        require(files.size() == 9, "Expected nine fixture programs, got " + files.size());
        try (BridgeService service = new BridgeService(null, false)) {
            service.setProject(state.getProject());
            List<String> programs = new ArrayList<>();
            List<String> addresses = new ArrayList<>();
            HashSet<String> decompiled = new HashSet<>();
            for (String file : files) {
                Map<String, Object> opened = call(service, "open_program", Map.of(
                    "project_id", service.registry().projectId(), "project_path", file));
                String id = (String) opened.get("program_id");
                require(id != null, "open_program omitted program_id");
                programs.add(id);
                Map<String, Object> reopened = call(service, "open_program", Map.of(
                    "project_id", service.registry().projectId(), "project_path", file));
                require(id.equals(reopened.get("program_id")), "Repeated open duplicated a Program");
                List<Map<String, Object>> functions = items(call(service, "list_functions", Map.of(
                    "program_id", id, "query", "fixture_entry")));
                require(functions.size() == 1, "fixture_entry was not found uniquely");
                String address = (String) functions.getFirst().get("address");
                addresses.add(address);
                Map<String, Object> before = call(service, "get_program_info", Map.of("program_id", id));
                Map<String, Object> result = call(service, "decompile_function", Map.of(
                    "program_id", id, "function_address", address));
                String code = (String) result.get("text");
                require(code.contains("fixture_entry"), "Unexpected decompiler result");
                decompiled.add(code);
                require(!items(call(service, "list_exports", Map.of("program_id", id))).isEmpty(), "No fixture exports");
                Map<String, Object> after = call(service, "get_program_info", Map.of("program_id", id));
                require(before.get("revision").equals(after.get("revision")), "Read changed revision");
                require(before.get("dirty").equals(after.get("dirty")), "Read changed dirty flag");
            }
            require(new HashSet<>(programs).size() == 9, "Distinct fixture files share a program ID");
            require(decompiled.size() == 9, "Different libraries produced identical fixture code");
            require(service.registry().entries().size() == 9, "Registry should contain nine programs");

            String providerId = programs.get(0);
            String callerId = programs.get(1);
            List<Map<String, Object>> helperFunctions = items(call(service, "list_functions", Map.of(
                "program_id", providerId, "query", "shared_helper")));
            require(helperFunctions.size() == 1, "Cross-library provider helper missing");
            List<Map<String, Object>> helperImports = items(call(service, "list_imports", Map.of(
                "program_id", callerId, "query", "shared_helper")));
            require(helperImports.size() == 1, "Cross-library caller import missing");
            String library = "libfixture_01.so";
            call(service, "set_import_library", Map.of("program_id", callerId,
                "external_address", helperImports.getFirst().get("external_address"), "external_library", library));
            call(service, "set_external_library_path", Map.of("program_id", callerId,
                "external_library", library, "project_id", service.registry().projectId(), "project_path", files.get(0)));
            Map<String, Object> resolved = call(service, "resolve_import", Map.of("program_id", callerId,
                "external_library", library, "symbol", "shared_helper", "scope_program_ids", List.of(providerId)));
            require(resolved.get("status").equals("resolved"), "Explicit library association was not resolved");
            List<Map<String, Object>> callees = items(call(service, "list_callees", Map.of("program_id", callerId,
                "function_address", addresses.get(1), "scope_program_ids", List.of(providerId))));
            require(!callees.isEmpty(), "Callsite not found in caller fixture");
            Map<String, Object> callTarget = call(service, "resolve_call_target", Map.of("program_id", callerId,
                "callsite_address", callees.getFirst().get("callsite_address"), "scope_program_ids", List.of(providerId)));
            require(callTarget.get("status").equals("resolved"), "PLT/thunk call target was not resolved");
            List<Map<String, Object>> callers = items(call(service, "list_callers", Map.of("program_id", providerId,
                "function_address", helperFunctions.getFirst().get("address"), "scope_program_ids", List.of(callerId))));
            require(callers.stream().anyMatch(row -> callerId.equals(row.get("program_id"))), "Cross-library caller was not found");

            var first = service.submit(UUID.randomUUID().toString(), "decompile_function", Map.of(
                "program_id", programs.get(0), "function_address", addresses.get(0)), 60000);
            var second = service.submit(UUID.randomUUID().toString(), "decompile_function", Map.of(
                "program_id", programs.get(1), "function_address", addresses.get(1)), 60000);
            await(first);
            await(second);
            require(!data(first).get("text").equals(data(second).get("text")), "Parallel requests crossed program identity");

            String id = programs.getFirst();
            String address = addresses.getFirst();
            Map<String, Object> target = Map.of("program_id", id, "function_address", address);
            Map<String, Object> before = call(service, "get_program_info", Map.of("program_id", id));
            Map<String, Object> bytes = call(service, "read_memory", Map.of("program_id", id, "address", address, "length", 4));
            require(((Number) bytes.get("returned_length")).intValue() == 4, "read_memory length mismatch");
            require(!items(call(service, "disassemble_range", Map.of("program_id", id, "address", address, "byte_length", 16))).isEmpty(), "No range instructions");
            List<Map<String, Object>> instructions = items(call(service, "disassemble_function", target));
            require(!instructions.isEmpty(), "No function instructions");
            if (((Number) instructions.getFirst().get("size")).intValue() > 1) {
                String inside = com.lauriewired.mcp.ReadSupport.address(
                    com.lauriewired.mcp.Arguments.address(service.registry().entry(id).program(), address).add(1));
                error(service, "disassemble_range", Map.of("program_id", id, "address", inside,
                    "byte_length", 8, "start_mode", "exact"), "ADDRESS_INVALID");
                Map<String, Object> containing = call(service, "disassemble_range", Map.of("program_id", id,
                    "address", inside, "byte_length", 8, "start_mode", "containing"));
                require(address.equals(containing.get("effective_start")), "Containing instruction start was not reported");
            }
            require(!items(call(service, "get_function_cfg", target)).isEmpty(), "No CFG blocks");
            require(!items(call(service, "get_pcode", target)).isEmpty(), "No raw P-code");
            Map<String, Object> highArgs = new LinkedHashMap<>(target);
            highArgs.put("level", "high");
            require(!items(call(service, "get_pcode", highArgs)).isEmpty(), "No high P-code");
            require(!items(call(service, "list_variables", target)).isEmpty(), "No decompiler variables");
            call(service, "list_callers", target);
            call(service, "list_callees", target);
            call(service, "get_xrefs", Map.of("program_id", id, "address", address, "direction", "to"));
            call(service, "get_comments", Map.of("program_id", id, "address", address));
            call(service, "list_imports", Map.of("program_id", id));
            call(service, "list_symbols", Map.of("program_id", id));
            call(service, "list_namespaces", Map.of("program_id", id));
            call(service, "list_strings", Map.of("program_id", id));
            call(service, "list_data_items", Map.of("program_id", id));
            List<Map<String, Object>> types = items(call(service, "list_data_types", Map.of("program_id", id)));
            require(!types.isEmpty(), "No program types");
            call(service, "get_type", Map.of("program_id", id, "type_path", types.getFirst().get("type_path")));
            require(!items(call(service, "list_memory_regions", Map.of("program_id", id))).isEmpty(), "No memory regions");
            Map<String, Object> assembled = call(service, "assemble_instruction", Map.of(
                "program_id", id, "address", address, "instruction", "NOP"));
            require(assembled.get("bytes_hex").equals("90"), "Unexpected x86 nop encoding");
            error(service, "assemble_instruction", Map.of("program_id", id, "address", address,
                "instruction", "this_is_not_an_instruction"), "INVALID_ARGUMENT");
            call(service, "list_bookmarks", Map.of("program_id", id));
            require(!items(call(service, "search_memory", Map.of("program_id", id, "pattern", bytes.get("bytes_hex"), "limit", 1))).isEmpty(), "Byte pattern not found");
            Map<String, Object> mapping = call(service, "address_to_file_offset", Map.of("program_id", id, "address", address));
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> mappings = (List<Map<String, Object>>) mapping.get("mappings");
            require(!mappings.isEmpty(), "No file provenance for ELF code");
            Map<String, Object> firstMapping = mappings.getFirst();
            Map<String, Object> reverse = call(service, "file_offset_to_address", Map.of(
                "program_id", id, "source_file_id", firstMapping.get("source_file_id"), "file_offset", firstMapping.get("file_offset")));
            require(Json.GSON.toJson(reverse).contains(address), "File-offset roundtrip lost address");
            Map<String, Object> after = call(service, "get_program_info", Map.of("program_id", id));
            require(before.get("revision").equals(after.get("revision")), "Research reads changed program revision");
            require(before.get("dirty").equals(after.get("dirty")), "Research reads changed dirty flag");

            Map<String, Object> page = call(service, "list_functions", Map.of("program_id", id, "limit", 1));
            require(page.get("next_cursor") != null, "Expected function pagination");
            Map<String, Object> nextPage = call(service, "list_functions", Map.of("program_id", id, "limit", 1, "cursor", page.get("next_cursor")));
            require(!items(page).getFirst().get("address").equals(items(nextPage).getFirst().get("address")), "Pagination repeated an item");
            call(service, "rename_function", Map.of("program_id", id, "function_address", address, "new_name", "fixture_renamed"));
            error(service, "list_functions", Map.of("program_id", id, "limit", 1, "cursor", page.get("next_cursor")), "CURSOR_STALE");
            error(service, "get_program_info", Map.of("program_id", "missing"), "PROGRAM_NOT_FOUND");
            error(service, "read_memory", Map.of("program_id", id, "address", "ram:0xffffffffffffffff", "length", 1), "MEMORY_UNAVAILABLE");
            Map<String, Object> partial = call(service, "read_memory", Map.of("program_id", id,
                "address", "ram:0xffffffffffffffff", "length", 1, "allow_partial", true));
            require(((Number) partial.get("returned_length")).intValue() == 0, "Unmapped memory should be a gap");
            call(service, "close_program", Map.of("program_id", id, "discard_changes", true));
            error(service, "get_program_info", Map.of("program_id", id), "PROGRAM_CLOSED");

            try (BridgeService readOnly = new BridgeService(null, true)) {
                readOnly.setProject(state.getProject());
                var owned = readOnly.registry().adopt(service.registry().entry(programs.get(1)).program(), null);
                error(readOnly, "rename_function", Map.of("program_id", owned.id(),
                    "function_address", addresses.get(1), "new_name", "forbidden"), "READ_ONLY");
            }
            String report = Json.GSON.toJson(Map.of("status", "passed", "programs", programs.size(),
                "distinct_decompilations", decompiled.size(), "reads_preserved_state", true,
                "cross_library_calls", true));
            if (getScriptArgs().length > 0) Files.writeString(Path.of(getScriptArgs()[0]), report);
            println("RESEARCH_SMOKE_OK " + report);
        }
    }

    private void collect(DomainFolder folder, List<String> paths) throws Exception {
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program")) paths.add(file.getPathname());
        }
        for (DomainFolder child : folder.getFolders()) collect(child, paths);
        paths.sort(String::compareTo);
    }

    private void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private void await(com.lauriewired.mcp.JobService.Job job) throws Exception {
        while (!job.terminal()) {
            monitor.checkCancelled();
            job.await(1000);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> data(com.lauriewired.mcp.JobService.Job job) {
        Map<String, Object> snapshot = job.snapshot();
        require(snapshot.get("state").equals("succeeded"), "Operation failed: " + Json.GSON.toJson(snapshot));
        return (Map<String, Object>) ((Map<String, Object>) snapshot.get("result")).get("data");
    }

    private Map<String, Object> call(BridgeService service, String operation, Map<String, Object> args) throws Exception {
        var job = service.submit(UUID.randomUUID().toString(), operation, args, 60000);
        await(job);
        return data(job);
    }

    private void error(BridgeService service, String operation, Map<String, Object> args, String code) throws Exception {
        var job = service.submit(UUID.randomUUID().toString(), operation, args, 60000);
        await(job);
        Map<String, Object> snapshot = job.snapshot();
        require(snapshot.get("error") instanceof Map<?, ?> && ((Map<?, ?>) snapshot.get("error")).get("code").equals(code),
            "Expected " + code + ": " + Json.GSON.toJson(snapshot));
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> items(Map<String, Object> result) {
        return (List<Map<String, Object>>) result.get("items");
    }
}
