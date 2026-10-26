package com.lauriewired.mcp;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class ReferenceOperations {
    private ReferenceOperations() {}

    public static void register(Map<String, OperationDefinition> operations) {
        operations.put("get_xrefs", OperationDefinition.read("get_xrefs", ReferenceOperations::xrefs));
        operations.put("list_callers", OperationDefinition.read("list_callers", ReferenceOperations::callers));
        operations.put("list_callees", OperationDefinition.read("list_callees", ReferenceOperations::callees));
        operations.put("resolve_call_target", OperationDefinition.read("resolve_call_target", ReferenceOperations::resolveCall));
        operations.put("resolve_import", OperationDefinition.read("resolve_import", ReferenceOperations::resolveImport));
    }

    private static Object xrefs(OperationContext context, Map<String, Object> args) throws Exception {
        Address address = Arguments.address(context.program(), args, "address");
        String direction = Arguments.string(args, "direction");
        List<String> kinds = Arguments.strings(args, "kinds");
        List<Reference> references = new ArrayList<>();
        if (direction.equals("to")) {
            for (var reference : context.program().getReferenceManager().getReferencesTo(address)) {
                references.add(reference);
            }
        }
        else if (direction.equals("from")) {
            references.addAll(List.of(context.program().getReferenceManager().getReferencesFrom(address)));
        }
        else {
            throw new ApiException("INVALID_ARGUMENT", "direction must be to or from");
        }
        references.sort(Comparator.comparing(Reference::getFromAddress).thenComparing(Reference::getToAddress)
            .thenComparing(reference -> reference.getReferenceType().getName()).thenComparingInt(Reference::getOperandIndex));
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Reference reference : references) {
            context.monitor().checkCancelled();
            if (!kinds.isEmpty() && !kinds.stream().anyMatch(kind -> matchesKind(reference, kind))) {
                continue;
            }
            Function function = context.program().getFunctionManager().getFunctionContaining(reference.getFromAddress());
            rows.add(ReadSupport.map("program_id", context.programId(),
                "from_address", ReadSupport.address(reference.getFromAddress()),
                "to_address", ReadSupport.address(reference.getToAddress()),
                "type", reference.getReferenceType().getName(), "operand_index", reference.getOperandIndex(),
                "source", reference.getSource().toString(), "primary", reference.isPrimary(),
                "function_address", function == null ? null : ReadSupport.address(function.getEntryPoint()),
                "function_name", function == null ? null : function.getName(true)));
        }
        return Pages.page(context, args, rows, "get_xrefs");
    }

    private static boolean matchesKind(Reference reference, String kind) {
        var type = reference.getReferenceType();
        return type.getName().equalsIgnoreCase(kind) || switch (kind.toLowerCase(java.util.Locale.ROOT)) {
            case "all" -> true;
            case "call" -> type.isCall();
            case "jump" -> type.isJump();
            case "data" -> type.isData();
            case "read" -> type.isRead();
            case "write" -> type.isWrite();
            case "flow" -> type.isFlow();
            default -> false;
        };
    }

    private static Object resolveImport(OperationContext context, Map<String, Object> args) throws Exception {
        return importTarget(context, context.entry(), Arguments.string(args, "external_library"),
            Arguments.string(args, "symbol"), scope(context, args));
    }

    private static Object resolveCall(OperationContext context, Map<String, Object> args) throws Exception {
        Address address = Arguments.address(context.program(), args, "callsite_address");
        Instruction instruction = context.program().getListing().getInstructionAt(address);
        if (instruction == null || !instruction.getFlowType().isCall()) {
            throw new ApiException("INVALID_ARGUMENT", "callsite_address must identify a call instruction");
        }
        return call(context, context.entry(), instruction, scope(context, args),
            Arguments.integer(args, "max_depth", 16, 1, 64));
    }

    private static Object callees(OperationContext context, Map<String, Object> args) throws Exception {
        Function function = ReadSupport.function(context, args);
        List<ProgramRegistry.Entry> scope = scope(context, args);
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Instruction instruction : context.program().getListing().getInstructions(function.getBody(), true)) {
            context.monitor().checkCancelled();
            if (instruction.getFlowType().isCall()) {
                rows.add(call(context, context.entry(), instruction, scope, 16));
            }
        }
        var page = Pages.page(context, args, rows, "list_callees");
        page.put("analysis_scope", "static_references");
        return page;
    }

    private static Object callers(OperationContext context, Map<String, Object> args) throws Exception {
        Function target = ReadSupport.function(context, args);
        List<ProgramRegistry.Entry> scope = scope(context, args);
        List<Map<String, Object>> rows = new ArrayList<>();
        for (ProgramRegistry.Entry source : scope) {
            for (Instruction instruction : source.program().getListing().getInstructions(true)) {
                context.monitor().checkCancelled();
                if (!instruction.getFlowType().isCall()) {
                    continue;
                }
                Map<String, Object> call = call(context, source, instruction, scope, 16);
                boolean found = false;
                for (Map<String, Object> candidate : targets(call)) {
                    if (context.programId().equals(candidate.get("program_id")) &&
                            (ReadSupport.address(target.getEntryPoint()).equals(candidate.get("address")) ||
                             ReadSupport.address(target.getEntryPoint()).equals(candidate.get("function_address")))) {
                        found = true;
                        break;
                    }
                }
                if (found) {
                    call.put("relationship", call.get("status").equals("resolved") ? "confirmed" : "candidate");
                    rows.add(call);
                }
            }
        }
        rows.sort(Comparator.<Map<String, Object>, String>comparing(row -> (String) row.get("program_id"))
            .thenComparing(row -> (String) row.get("callsite_address"), ReadSupport::compareAddresses));
        var page = Pages.page(context, args, rows, "list_callers");
        page.put("analysis_scope", "static_references");
        return page;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> targets(Map<String, Object> resolution) {
        return (List<Map<String, Object>>) resolution.get("targets");
    }

    private static List<ProgramRegistry.Entry> scope(OperationContext context, Map<String, Object> args) {
        Set<String> ids = new LinkedHashSet<>();
        ids.add(context.programId());
        ids.addAll(Arguments.strings(args, "scope_program_ids"));
        List<ProgramRegistry.Entry> entries = new ArrayList<>();
        for (String id : ids) {
            entries.add(context.registry().entry(id));
        }
        entries.sort(Comparator.comparing(ProgramRegistry.Entry::id));
        return entries;
    }

    private static Map<String, Object> call(OperationContext context, ProgramRegistry.Entry source,
            Instruction instruction, List<ProgramRegistry.Entry> scope, int maxDepth) throws Exception {
        Function caller = source.program().getFunctionManager().getFunctionContaining(instruction.getAddress());
        Set<Address> destinations = new LinkedHashSet<>();
        for (Reference reference : source.program().getReferenceManager().getReferencesFrom(instruction.getAddress())) {
            if (reference.getReferenceType().isCall()) {
                destinations.add(reference.getToAddress());
            }
        }
        for (Address flow : instruction.getFlows()) {
            destinations.add(flow);
        }
        List<Map<String, Object>> paths = new ArrayList<>();
        List<Map<String, Object>> targets = new ArrayList<>();
        String status = destinations.isEmpty() ? "unresolved" : "resolved";
        for (Address destination : destinations) {
            Map<String, Object> path = follow(context, source, destination, scope, maxDepth);
            paths.add(path);
            targets.addAll(targets(path));
            if (!path.get("status").equals("resolved")) {
                status = (String) path.get("status");
            }
        }
        if (destinations.size() > 1 && status.equals("resolved")) {
            status = "ambiguous";
        }
        return ReadSupport.map("program_id", source.id(), "callsite_address", ReadSupport.address(instruction.getAddress()),
            "function_address", caller == null ? null : ReadSupport.address(caller.getEntryPoint()),
            "function_name", caller == null ? null : caller.getName(true),
            "flow_type", instruction.getFlowType().getName(), "status", status,
            "paths", paths, "targets", targets, "analysis_scope", "static_references");
    }

    private static Map<String, Object> follow(OperationContext context, ProgramRegistry.Entry source,
            Address destination, List<ProgramRegistry.Entry> scope, int maxDepth) throws Exception {
        List<Map<String, Object>> chain = new ArrayList<>();
        Set<Address> visited = new HashSet<>();
        Address current = destination;
        for (int depth = 0; depth < maxDepth; depth++) {
            context.monitor().checkCancelled();
            if (!visited.add(current)) {
                return ReadSupport.map("status", "cycle", "chain", chain, "targets", List.of());
            }
            Function function = source.program().getFunctionManager().getFunctionAt(current);
            chain.add(ReadSupport.map("program_id", source.id(), "address", ReadSupport.address(current),
                "kind", current.isExternalAddress() ? "external" : function != null && function.isThunk() ? "thunk" : "direct",
                "function_name", function == null ? null : function.getName(true)));
            if (current.isExternalAddress()) {
                ExternalLocation location = null;
                for (var symbol : source.program().getSymbolTable().getSymbols(current)) {
                    location = source.program().getExternalManager().getExternalLocation(symbol);
                    if (location != null) {
                        break;
                    }
                }
                if (location == null) {
                    return ReadSupport.map("status", "unresolved", "chain", chain, "targets", List.of());
                }
                String name = location.getOriginalImportedName() == null ? location.getLabel() : location.getOriginalImportedName();
                var resolution = importTarget(context, source, location.getLibraryName(), name, scope);
                resolution.put("chain", chain);
                return resolution;
            }
            if (function != null && function.isThunk()) {
                Function thunk = function.getThunkedFunction(false);
                if (thunk == null) {
                    return ReadSupport.map("status", "unresolved", "chain", chain, "targets", List.of());
                }
                current = thunk.getEntryPoint();
                continue;
            }
            Function containing = function != null ? function : source.program().getFunctionManager().getFunctionContaining(current);
            return ReadSupport.map("status", "resolved", "chain", chain, "targets", List.of(ReadSupport.map(
                "program_id", source.id(), "address", ReadSupport.address(current),
                "function_address", containing == null ? null : ReadSupport.address(containing.getEntryPoint()),
                "function_name", containing == null ? null : containing.getName(true),
                "evidence", "direct_reference")));
        }
        return ReadSupport.map("status", "depth_limit", "chain", chain, "targets", List.of());
    }

    private static Map<String, Object> importTarget(OperationContext context, ProgramRegistry.Entry source,
            String library, String name, List<ProgramRegistry.Entry> scope) throws Exception {
        String linkedPath = source.program().getExternalManager().getExternalLibraryPath(library);
        List<Map<String, Object>> candidates = new ArrayList<>();
        List<Map<String, Object>> proven = new ArrayList<>();
        for (ProgramRegistry.Entry target : scope) {
            if (target.id().equals(source.id())) {
                continue;
            }
            boolean linked = linkedPath != null && linkedPath.equals(target.program().getDomainFile().getPathname());
            var symbols = target.program().getSymbolTable().getSymbols(name);
            while (symbols.hasNext()) {
                context.monitor().checkCancelled();
                var symbol = symbols.next();
                if (symbol.isExternal() || !symbol.isExternalEntryPoint()) {
                    continue;
                }
                Function function = target.program().getFunctionManager().getFunctionAt(symbol.getAddress());
                var candidate = ReadSupport.map("program_id", target.id(), "address", ReadSupport.address(symbol.getAddress()),
                    "function_address", function == null ? null : ReadSupport.address(function.getEntryPoint()),
                    "name", symbol.getName(true), "project_path", target.program().getDomainFile().getPathname(),
                    "evidence", linked ? "external_library_path_and_export" : "symbol_name_only");
                candidates.add(candidate);
                if (linked) {
                    proven.add(candidate);
                }
            }
        }
        String status = proven.size() == 1 ? "resolved" : proven.size() > 1 || candidates.size() > 1 ? "ambiguous" : "unresolved";
        return ReadSupport.map("external_library", library, "symbol", name, "linked_project_path", linkedPath,
            "status", status, "targets", proven.isEmpty() ? candidates : proven, "candidates", candidates,
            "analysis_scope", "static_references");
    }
}
