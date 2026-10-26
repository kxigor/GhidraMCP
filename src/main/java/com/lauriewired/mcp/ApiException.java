package com.lauriewired.mcp;

import java.util.Map;

public final class ApiException extends RuntimeException {
    public ApiException(String code, String message) {
        this(code, message, Map.of());
    }

    public ApiException(String code, String message, Map<String, Object> details) {
        super(message == null ? code : message);
        this.code = code;
        this.details = details;
    }

    public String code() { return code; }
    public Map<String, Object> details() { return details; }

    public Map<String, Object> toMap() {
        return Map.of("code", code, "message", getMessage(), "details", details,
            "retryable", code.equals("PROGRAM_BUSY") || code.equals("QUEUE_FULL"));
    }

    private final String code;
    private final Map<String, Object> details;
}
