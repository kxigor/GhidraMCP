package com.lauriewired.mcp;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class DecompilerOperations {
    private DecompilerOperations() {}

    public static void register(Map<String, OperationDefinition> operations) {
        operations.put("decompile_function", OperationDefinition.read("decompile_function", DecompilerOperations::decompile));
        operations.put("list_variables", OperationDefinition.read("list_variables", DecompilerOperations::variables));
        operations.put("get_function_cfg", OperationDefinition.read("get_function_cfg", DecompilerOperations::cfg));
        operations.put("get_pcode", OperationDefinition.read("get_pcode", DecompilerOperations::pcode));
    }

    private static Object decompile(OperationContext context, Map<String, Object> args) throws Exception {
        Function function = ReadSupport.function(context, args);
        DecompInterface decompiler = open(context);
        try {
            DecompileResults result = perform(context, args, function, decompiler);
            var data = context.storeText(result.getDecompiledFunction().getC());
            data.put("function_address", ReadSupport.address(function.getEntryPoint()));
            data.put("function_name", function.getName(true));
            String message = result.getErrorMessage();
            data.put("warnings", message == null || message.isBlank() ? List.of() : List.of(message));
            return data;
        }
        finally {
            decompiler.dispose();
        }
    }

    private static Object variables(OperationContext context, Map<String, Object> args) throws Exception {
        if (!Arguments.string(args, "source", "decompiler").equals("decompiler")) {
            throw new ApiException("INVALID_ARGUMENT", "source must be decompiler");
        }
        Function function = ReadSupport.function(context, args);
        return Pages.page(context, args, VariableSupport.describe(context, function), "list_variables");
    }

    private static Object cfg(OperationContext context, Map<String, Object> args) throws Exception {
        Function function = ReadSupport.function(context, args);
        BasicBlockModel model = new BasicBlockModel(context.program());
        List<Map<String, Object>> rows = new ArrayList<>();
        var blocks = model.getCodeBlocksContaining(function.getBody(), context.monitor());
        while (blocks.hasNext()) {
            context.monitor().checkCancelled();
            var block = blocks.next();
            String blockId = ReadSupport.address(block.getFirstStartAddress());
            List<Map<String, Object>> edges = new ArrayList<>();
            var destinations = block.getDestinations(context.monitor());
            while (destinations.hasNext()) {
                var destination = destinations.next();
                edges.add(ReadSupport.map("source_block", blockId,
                    "target_block", ReadSupport.address(destination.getDestinationAddress()),
                    "callsite_address", ReadSupport.address(destination.getReferent()),
                    "target_address", ReadSupport.address(destination.getReference()),
                    "flow_type", destination.getFlowType().getName(),
                    "within_function", function.getBody().contains(destination.getDestinationAddress())));
            }
            if (edges.isEmpty() && block.getFlowType().isComputed()) {
                edges.add(ReadSupport.map("source_block", blockId, "target_block", null,
                    "target_address", null, "flow_type", block.getFlowType().getName(), "status", "unresolved"));
            }
            rows.add(ReadSupport.map("block_id", blockId, "name", block.getName(),
                "ranges", ReadSupport.ranges(block.intersect(function.getBody())),
                "flow_type", block.getFlowType().getName(), "edges", edges));
        }
        var result = Pages.page(context, args, rows, "get_function_cfg");
        result.put("function_address", ReadSupport.address(function.getEntryPoint()));
        result.put("model", "basic_blocks");
        return result;
    }

    private static Object pcode(OperationContext context, Map<String, Object> args) throws Exception {
        Function function = ReadSupport.function(context, args);
        String level = Arguments.string(args, "level", "raw");
        List<Map<String, Object>> rows = new ArrayList<>();
        if (level.equals("raw")) {
            BasicBlockModel blocks = new BasicBlockModel(context.program());
            for (var instruction : context.program().getListing().getInstructions(function.getBody(), true)) {
                context.monitor().checkCancelled();
                var block = blocks.getFirstCodeBlockContaining(instruction.getAddress(), context.monitor());
                for (PcodeOp operation : instruction.getPcode()) {
                    var row = operation(operation);
                    row.put("block_id", block == null ? null : ReadSupport.address(block.getFirstStartAddress()));
                    rows.add(row);
                }
            }
        }
        else if (level.equals("high")) {
            DecompInterface decompiler = open(context);
            try {
                var result = perform(context, args, function, decompiler);
                if (result.getHighFunction() == null) {
                    throw new ApiException("INTERNAL_ERROR", "Decompiler did not produce a high function");
                }
                var operations = result.getHighFunction().getPcodeOps();
                while (operations.hasNext()) {
                    context.monitor().checkCancelled();
                    rows.add(operation(operations.next()));
                }
            }
            finally {
                decompiler.dispose();
            }
        }
        else {
            throw new ApiException("INVALID_ARGUMENT", "level must be raw or high");
        }
        var result = Pages.page(context, args, rows, "get_pcode");
        result.put("function_address", ReadSupport.address(function.getEntryPoint()));
        result.put("level", level);
        return result;
    }

    private static Map<String, Object> operation(PcodeOp operation) {
        List<Map<String, Object>> inputs = new ArrayList<>();
        for (Varnode input : operation.getInputs()) {
            inputs.add(varnode(input));
        }
        return ReadSupport.map("instruction_address", ReadSupport.address(operation.getSeqnum().getTarget()),
            "sequence", operation.getSeqnum().getTime(), "opcode", operation.getMnemonic(),
            "inputs", inputs, "output", varnode(operation.getOutput()),
            "block_id", operation.getParent() == null ? null : "high:" + operation.getParent().getIndex());
    }

    private static Map<String, Object> varnode(Varnode node) {
        if (node == null) {
            return null;
        }
        return ReadSupport.map("space", node.getAddress().getAddressSpace().getName(),
            "offset", ReadSupport.hex(node.getOffset()), "size", node.getSize(),
            "kind", node.isConstant() ? "constant" : node.isUnique() ? "temporary" : node.isRegister() ? "register" : "address");
    }

    private static DecompInterface open(OperationContext context) {
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(context.program());
        decompiler.setOptions(options);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(context.program())) {
            String message = decompiler.getLastMessage();
            decompiler.dispose();
            throw new ApiException("INTERNAL_ERROR", "Cannot open program in decompiler: " + message);
        }
        return decompiler;
    }

    private static DecompileResults perform(OperationContext context, Map<String, Object> args,
            Function function, DecompInterface decompiler) throws Exception {
        int timeout = Arguments.integer(args, "timeout_ms", 60000, 1, 1800000);
        context.monitor().checkCancelled();
        DecompileResults result = decompiler.decompileFunction(function, (timeout + 999) / 1000, context.monitor());
        context.monitor().checkCancelled();
        if (result.isTimedOut()) {
            throw new ApiException("TIMEOUT", "Decompiler time limit exceeded");
        }
        if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
            throw new ApiException("INTERNAL_ERROR", "Decompilation failed: " + result.getErrorMessage());
        }
        return result;
    }
}
