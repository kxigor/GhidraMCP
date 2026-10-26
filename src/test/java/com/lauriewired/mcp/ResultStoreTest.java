package com.lauriewired.mcp;

import static org.junit.Assert.*;

import java.util.Map;
import org.junit.Test;

public class ResultStoreTest {
    @Test
    public void chunksUseCodePointOffsetsWithoutSplittingSupplementaryCharacters() {
        ResultStore store = new ResultStore();
        String text = "a".repeat(ResultStore.CHUNK_SIZE - 1) + "\ud83d\udd12" + "tail";
        Map<String, Object> first = store.store("program", "1", text);
        assertEquals(ResultStore.CHUNK_SIZE, first.get("next_offset"));
        assertTrue(((String) first.get("text")).endsWith("\ud83d\udd12"));
        Map<String, Object> rest = store.chunk((String) first.get("result_id"), "program", "1", ResultStore.CHUNK_SIZE, 8);
        assertEquals("tail", rest.get("text"));
        assertNull(rest.get("next_offset"));
        assertEquals(false, rest.get("truncated"));
    }

    @Test
    public void retainedResultsRejectAnotherProgramAndChangedRevision() {
        ResultStore store = new ResultStore();
        String id = (String) store.store("program", "1", "x".repeat(ResultStore.CHUNK_SIZE + 1)).get("result_id");
        ApiException wrongProgram = assertThrows(ApiException.class, () -> store.chunk(id, "other", "1", 0, 1));
        ApiException stale = assertThrows(ApiException.class, () -> store.chunk(id, "program", "2", 0, 1));
        assertEquals("INVALID_ARGUMENT", wrongProgram.code());
        assertEquals("RESULT_STALE", stale.code());
    }
}
