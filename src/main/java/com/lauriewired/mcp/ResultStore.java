package com.lauriewired.mcp;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.nio.charset.StandardCharsets;

public final class ResultStore {
    public synchronized Map<String, Object> store(String programId, String revision, String text) {
        if (text.codePointCount(0, text.length()) <= CHUNK_SIZE) {
            return Json.map("text", text, "total_length", text.codePointCount(0, text.length()),
                "next_offset", null, "result_id", null, "truncated", false);
        }
        if (text.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) throw new ApiException("INVALID_ARGUMENT", "Decompiler result exceeds 8 MiB");
        cleanup();
        String id = "result-" + UUID.randomUUID();
        results.put(id, new Result(programId, revision, text, System.currentTimeMillis()));
        while (results.size() > MAX_RESULTS) results.remove(results.keySet().iterator().next());
        return chunk(id, programId, revision, 0, CHUNK_SIZE);
    }

    public synchronized Map<String, Object> chunk(String id, String programId, String revision, int offset, int length) {
        cleanup();
        Result result = results.get(id);
        if (result == null) throw new ApiException("RESULT_EXPIRED", "Result no longer retained");
        if (!result.programId.equals(programId)) throw new ApiException("INVALID_ARGUMENT", "Result belongs to another program");
        if (!result.revision.equals(revision)) throw new ApiException("RESULT_STALE", "Program changed after this result");
        int total = result.text.codePointCount(0, result.text.length());
        if (offset < 0 || offset > total || length < 1 || length > CHUNK_SIZE) {
            throw new ApiException("INVALID_ARGUMENT", "Invalid text chunk range");
        }
        int end = Math.min(total, offset + length);
        String text = result.text.substring(result.text.offsetByCodePoints(0, offset), result.text.offsetByCodePoints(0, end));
        return Json.map("result_id", id, "text", text, "offset", offset, "total_length", total,
            "next_offset", end < total ? end : null, "truncated", end < total);
    }

    private void cleanup() { results.values().removeIf(r -> System.currentTimeMillis() - r.created > RETENTION_MS); }

    private record Result(String programId, String revision, String text, long created) {}

    public static final int CHUNK_SIZE = 65536;
    public static final int MAX_BYTES = 8 * 1024 * 1024;
    public static final int MAX_RESULTS = 32;
    public static final long RETENTION_MS = 15 * 60 * 1000;
    private final Map<String, Result> results = new LinkedHashMap<>();
}
