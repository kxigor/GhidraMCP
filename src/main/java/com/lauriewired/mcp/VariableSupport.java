package com.lauriewired.mcp;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class VariableSupport {
    private VariableSupport() {}

    public static List<Map<String, Object>> describe(OperationContext context, Function function)
            throws Exception {
        return withSymbols(context, function, (symbols, fingerprint) -> {
            List<Map<String, Object>> result = new ArrayList<>();
            for (HighSymbol symbol : symbols) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("variable_id", variableId(context, function, symbol, fingerprint));
                row.put("name", symbol.getName());
                row.put("type_path", symbol.getDataType().getPathName());
                row.put("size", symbol.getSize());
                row.put("storage", symbol.getStorage().toString());
                row.put("first_use", address(symbol.getPCAddress()));
                row.put("parameter", symbol.isParameter());
                row.put("parameter_index", symbol.isParameter() ? symbol.getCategoryIndex() : null);
                row.put("revision", context.revision());
                result.add(row);
            }
            result.sort(Comparator.comparing(row -> (String) row.get("variable_id")));
            return result;
        });
    }

    public static Map<String, Object> update(OperationContext context, Function function,
            String variableId, String newName, DataType newType) throws Exception {
        return withSymbols(context, function, (symbols, fingerprint) -> {
            List<HighSymbol> matches = new ArrayList<>();
            for (HighSymbol symbol : symbols) {
                if (variableId(context, function, symbol, fingerprint).equals(variableId)) {
                    matches.add(symbol);
                }
            }
            if (matches.size() != 1) {
                throw new ApiException("STALE_VARIABLE",
                    "Variable identity is stale or does not belong to this function. List its variables again.");
            }
            HighSymbol symbol = matches.getFirst();
            String oldName = symbol.getName();
            String oldType = symbol.getDataType().getPathName();
            boolean changed = newName != null && !newName.equals(oldName) ||
                newType != null && !newType.isEquivalent(symbol.getDataType());
            if (changed) {
                context.monitor().checkCancelled();
                HighFunctionDBUtil.updateDBVariable(symbol, newName, newType, SourceType.USER_DEFINED);
            }
            return Map.of(
                "function_address", address(function.getEntryPoint()),
                "previous_variable_id", variableId,
                "name", newName == null ? oldName : newName,
                "type_path", newType == null ? oldType : newType.getPathName(),
                "changed", changed);
        });
    }

    private static <T> T withSymbols(OperationContext context, Function function,
            SymbolAction<T> action) throws Exception {
        context.monitor().checkCancelled();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(context.program());
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setOptions(options);
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(context.program())) {
                throw new ApiException("DECOMPILATION_FAILED", decompiler.getLastMessage());
            }
            DecompileResults result = decompiler.decompileFunction(function, 1_800, context.monitor());
            context.monitor().checkCancelled();
            if (!result.decompileCompleted() || result.getHighFunction() == null ||
                    result.getDecompiledFunction() == null) {
                throw new ApiException(result.isTimedOut() ? "TIMEOUT" : "DECOMPILATION_FAILED",
                    result.getErrorMessage());
            }
            List<HighSymbol> symbols = new ArrayList<>();
            result.getHighFunction().getLocalSymbolMap().getSymbols().forEachRemaining(symbols::add);
            String fingerprint = digest(result.getDecompiledFunction().getC());
            return action.apply(symbols, fingerprint);
        }
        finally {
            decompiler.dispose();
        }
    }

    private static String variableId(OperationContext context, Function function,
            HighSymbol symbol, String fingerprint) throws Exception {
        String description = String.join("\n", "decompile-v1", context.programId(),
            context.revision(), address(function.getEntryPoint()), fingerprint,
            Long.toUnsignedString(symbol.getId()), symbol.getStorage().toString(),
            address(symbol.getPCAddress()), symbol.getName(), symbol.getDataType().getPathName(),
            Integer.toString(symbol.getCategoryIndex()), Boolean.toString(symbol.isParameter()));
        return "var-" + digest(description);
    }

    private static String digest(String text) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(text.getBytes(StandardCharsets.UTF_8)));
    }

    private static String address(Address address) {
        return address == null ? "" : address.getAddressSpace().getName() + ":0x" +
            Long.toUnsignedString(address.getOffset(), 16);
    }

    @FunctionalInterface
    private interface SymbolAction<T> {
        T apply(List<HighSymbol> symbols, String fingerprint) throws Exception;
    }
}
