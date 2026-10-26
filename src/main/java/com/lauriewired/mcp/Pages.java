package com.lauriewired.mcp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class Pages {
    private Pages() {}

    public static Map<String, Object> page(OperationContext context, Map<String, Object> args,
            List<?> items, String operation) {
        int limit = Arguments.integer(args, "limit", 100, 1, 1000);
        String fingerprint = fingerprint(context, args, operation);
        int offset = offset(args, fingerprint);
        if (offset > items.size()) {
            throw new ApiException("INVALID_ARGUMENT", "Cursor offset exceeds the result set");
        }
        int end = Math.min(items.size(), offset + limit);
        boolean more = end < items.size();
        return ReadSupport.map("items", List.copyOf(items.subList(offset, end)),
            "has_more", more, "next_cursor", more ? encode(fingerprint, end) : null);
    }

    public static Window window(OperationContext context, Map<String, Object> args, String operation) {
        String fingerprint = fingerprint(context, args, operation);
        return new Window(fingerprint, offset(args, fingerprint), Arguments.integer(args, "limit", 100, 1, 1000));
    }

    private static String fingerprint(OperationContext context, Map<String, Object> args, String operation) {
        Map<String, Object> query = new TreeMap<>(args);
        query.remove("cursor");
        query.remove("limit");
        query.remove("timeout_ms");
        String identity = operation + "\n" + context.programId() + "\n" +
            new TreeMap<>(context.programRevisions()) + "\n" + query;
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(identity.getBytes(StandardCharsets.UTF_8)));
        }
        catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static int offset(Map<String, Object> args, String fingerprint) {
        String cursor = Arguments.optionalString(args, "cursor");
        if (cursor == null) {
            return 0;
        }
        try {
            String decoded = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
            String[] parts = decoded.split(":", -1);
            if (parts.length != 2) {
                throw new IllegalArgumentException();
            }
            if (!parts[0].equals(fingerprint)) {
                throw new ApiException("CURSOR_STALE", "Cursor belongs to a different query or program revision");
            }
            int value = Integer.parseInt(parts[1]);
            if (value < 0) {
                throw new IllegalArgumentException();
            }
            return value;
        }
        catch (IllegalArgumentException e) {
            throw new ApiException("INVALID_ARGUMENT", "Invalid pagination cursor");
        }
    }

    private static String encode(String fingerprint, int offset) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            (fingerprint + ":" + offset).getBytes(StandardCharsets.UTF_8));
    }

    public static final class Window {
        private Window(String fingerprint, int offset, int limit) {
            this.fingerprint = fingerprint;
            this.offset = offset;
            this.limit = limit;
        }

        public boolean add(Object item) {
            if (seen++ >= offset) items.add(item);
            return items.size() > limit;
        }

        public Map<String, Object> result() {
            if (seen < offset) throw new ApiException("INVALID_ARGUMENT", "Cursor offset exceeds result set");
            boolean more = items.size() > limit;
            return ReadSupport.map("items", List.copyOf(items.subList(0, Math.min(items.size(), limit))),
                "has_more", more, "next_cursor", more ? encode(fingerprint, offset + limit) : null);
        }

        private final String fingerprint;
        private final int offset;
        private final int limit;
        private final java.util.ArrayList<Object> items = new java.util.ArrayList<>();
        private int seen;
    }
}
