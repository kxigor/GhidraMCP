package com.lauriewired.mcp;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class Arguments {
    private Arguments() {}

    public static String string(Map<String, Object> args, String key) {
        String value = optionalString(args, key);
        if (value == null || value.isBlank()) {
            throw new ApiException("INVALID_ARGUMENT", "Required nonempty string: " + key);
        }
        return value;
    }

    public static String string(Map<String, Object> args, String key, String fallback) {
        String value = optionalString(args, key);
        return value == null ? fallback : value;
    }

    public static String optionalString(Map<String, Object> args, String key) {
        Object value = args.get(key);
        if (value == null) return null;
        if (!(value instanceof String text)) {
            throw new ApiException("INVALID_ARGUMENT", key + " must be a string");
        }
        return text;
    }

    public static boolean bool(Map<String, Object> args, String key, boolean fallback) {
        Object value = args.get(key);
        if (value == null) return fallback;
        if (value instanceof Boolean flag) return flag;
        throw new ApiException("INVALID_ARGUMENT", key + " must be a boolean");
    }

    public static int integer(Map<String, Object> args, String key, int fallback, int min, int max) {
        Object value = args.get(key);
        if (value == null) return fallback;
        if (!(value instanceof Number number) || !Double.isFinite(number.doubleValue()) ||
                number.doubleValue() != Math.rint(number.doubleValue()) ||
                number.doubleValue() < min || number.doubleValue() > max) {
            throw new ApiException("INVALID_ARGUMENT", key + " must be an integer in [" + min + ", " + max + "]");
        }
        return number.intValue();
    }

    public static long longValue(Map<String, Object> args, String key, long fallback) {
        Object value = args.get(key);
        if (value == null) return fallback;
        try {
            if (value instanceof String text) return Long.decode(text);
            if (value instanceof Number number && number.doubleValue() == Math.rint(number.doubleValue())) {
                return number.longValue();
            }
        }
        catch (NumberFormatException ignored) {}
        throw new ApiException("INVALID_ARGUMENT", key + " must be an integer or hexadecimal string");
    }

    public static Address address(Program program, Map<String, Object> args, String key) {
        return address(program, string(args, key));
    }

    public static Address address(Program program, String value) {
        try {
            String normalized = value.replace(":0x", ":");
            if (normalized.startsWith("0x")) normalized = normalized.substring(2);
            Address result = program.getAddressFactory().getAddress(normalized);
            if (result != null) return result;
        }
        catch (RuntimeException ignored) {}
        throw new ApiException("ADDRESS_INVALID", "Invalid address: " + value);
    }

    public static List<String> strings(Map<String, Object> args, String key) {
        Object value = args.get(key);
        if (value == null) return List.of();
        if (!(value instanceof List<?> list)) throw new ApiException("INVALID_ARGUMENT", key + " must be an array");
        List<String> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof String text) || text.isBlank()) {
                throw new ApiException("INVALID_ARGUMENT", key + " must contain nonempty strings");
            }
            result.add(text);
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(Map<String, Object> args, String key) {
        Object value = args.get(key);
        if (value == null) return Map.of();
        if (!(value instanceof Map<?, ?> map)) throw new ApiException("INVALID_ARGUMENT", key + " must be an object");
        return (Map<String, Object>) map;
    }
}
