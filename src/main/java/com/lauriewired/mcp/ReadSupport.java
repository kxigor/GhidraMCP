package com.lauriewired.mcp;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class ReadSupport {
    private ReadSupport() {}

    public static Map<String, Object> map(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            result.put((String) pairs[i], pairs[i + 1]);
        }
        return result;
    }

    public static String address(Address address) {
        return address == null ? null : address.getAddressSpace().getName() + ":0x" +
            Long.toUnsignedString(address.getOffset(), 16);
    }

    public static String hex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    public static int compareAddresses(String first, String second) {
        if (first == null) return second == null ? 0 : -1;
        if (second == null) return 1;
        int a = first.lastIndexOf(":0x");
        int b = second.lastIndexOf(":0x");
        if (a < 0 || b < 0) return first.compareTo(second);
        int space = first.substring(0, a).compareTo(second.substring(0, b));
        if (space != 0) return space;
        return Long.compareUnsigned(Long.parseUnsignedLong(first.substring(a + 3), 16),
            Long.parseUnsignedLong(second.substring(b + 3), 16));
    }

    public static String bytes(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    public static Address lastAddress(Address start, long length) {
        try {
            return start.addNoWrap(length - 1);
        }
        catch (ghidra.program.model.address.AddressOverflowException e) {
            throw new ApiException("ADDRESS_INVALID", "Range exceeds its address space",
                map("address", address(start), "length", length));
        }
    }

    public static byte[] parseBytes(String input, String name) {
        try {
            String clean = input.replaceAll("\\s", "");
            if (clean.isEmpty()) {
                throw new IllegalArgumentException();
            }
            return HexFormat.of().parseHex(clean);
        }
        catch (IllegalArgumentException e) {
            throw new ApiException("INVALID_ARGUMENT", name + " must contain hexadecimal byte pairs");
        }
    }

    public static boolean matches(String value, String query) {
        return query == null || query.isEmpty() || value != null &&
            value.toLowerCase(Locale.ROOT).contains(query.toLowerCase(Locale.ROOT));
    }

    public static Function function(Program program, Address address, boolean exact) {
        Function function = exact ? program.getFunctionManager().getFunctionAt(address) :
            program.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            throw new ApiException("FUNCTION_NOT_FOUND", "No function at the requested address",
                map("address", address(address), "match", exact ? "entry" : "containing"));
        }
        return function;
    }

    public static Function function(OperationContext context, Map<String, Object> args) {
        return function(context.program(), Arguments.address(context.program(), args, "function_address"), true);
    }

    public static List<Map<String, Object>> ranges(AddressSetView body) {
        List<Map<String, Object>> ranges = new ArrayList<>();
        for (var range : body.getAddressRanges()) {
            Address next = range.getMaxAddress().next();
            ranges.add(map("start", address(range.getMinAddress()), "end", address(next),
                "length", range.getLength(), "last_address", address(range.getMaxAddress())));
        }
        return ranges;
    }

    public static Map<String, Object> functionInfo(Function function) {
        return map("name", function.getName(), "qualified_name", function.getName(true),
            "address", address(function.getEntryPoint()), "namespace", function.getParentNamespace().getName(true),
            "signature", function.getPrototypeString(false, false), "calling_convention", function.getCallingConventionName(),
            "thunk", function.isThunk(), "external", function.isExternal(),
            "size", function.getBody().getNumAddresses(), "ranges", ranges(function.getBody()),
            "no_return", function.hasNoReturn(), "varargs", function.hasVarArgs());
    }

    public static Map<String, Object> instruction(Instruction instruction, String source) throws Exception {
        List<String> operands = new ArrayList<>();
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            operands.add(instruction.getDefaultOperandRepresentation(i));
        }
        List<String> flows = new ArrayList<>();
        for (Address flow : instruction.getFlows()) {
            flows.add(address(flow));
        }
        return map("address", address(instruction.getAddress()), "size", instruction.getLength(),
            "bytes_hex", bytes(instruction.getBytes()), "mnemonic", instruction.getMnemonicString(),
            "operands", operands, "text", instruction.toString(), "flow_type", instruction.getFlowType().getName(),
            "flows", flows, "fallthrough", address(instruction.getFallThrough()), "source", source);
    }
}
