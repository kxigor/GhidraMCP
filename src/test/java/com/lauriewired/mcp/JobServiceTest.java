package com.lauriewired.mcp;

import static org.junit.Assert.*;

import java.util.Map;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

public class JobServiceTest {
    @Test
    public void replayDoesNotExecuteMutationTwiceAndRejectsDifferentArguments() throws Exception {
        AtomicInteger executions = new AtomicInteger();
        try (JobService service = new JobService("server", job -> {
            executions.incrementAndGet();
            return Map.of("changed", true);
        })) {
            JobService.Job first = service.submit("request", "rename_function", Map.of("new_name", "first"), 10000);
            first.await(2000);
            assertEquals("succeeded", first.snapshot().get("state"));
            assertSame(first, service.submit("request", "rename_function", Map.of("new_name", "first"), 10000));
            ApiException conflict = assertThrows(ApiException.class,
                () -> service.submit("request", "rename_function", Map.of("new_name", "second"), 10000));
            assertEquals("REQUEST_ID_CONFLICT", conflict.code());
            assertEquals(1, executions.get());
        }
    }

    @Test
    public void cancellationArrivingBeforeSubmissionPreventsExecution() throws Exception {
        AtomicInteger executions = new AtomicInteger();
        try (JobService service = new JobService("server", job -> executions.incrementAndGet())) {
            service.cancel("request");
            JobService.Job job = service.submit("request", "patch_bytes", Map.of(), 10000);
            job.await(2000);
            assertEquals("cancelled", job.snapshot().get("state"));
            assertEquals(0, executions.get());
        }
    }

    @Test
    public void deadlinePreservesPartialEffectsAndFailureDetails() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        try (JobService service = new JobService("server", job -> {
            job.effects("partial");
            job.affectedFile("/lib/imported.so");
            started.countDown();
            while (!job.monitor().isCancelled()) Thread.sleep(1);
            throw new ApiException("IMPORT_INTERRUPTED", "Import interrupted", Map.of("created", true));
        })) {
            JobService.Job job = service.submit("request", "import_program", Map.of(), 100);
            assertTrue(started.await(2, TimeUnit.SECONDS));
            job.await(2000);
            Map<String, Object> result = job.snapshot();
            assertEquals("timed_out", result.get("state"));
            assertEquals("partial", result.get("effects"));
            assertEquals(java.util.List.of("/lib/imported.so"), result.get("affected_files"));
            Map<?, ?> error = (Map<?, ?>) result.get("error");
            assertEquals("TIMEOUT", error.get("code"));
            assertEquals(Map.of("created", true), error.get("details"));
        }
    }

    @Test
    public void shutdownReleasesResourcesOnlyAfterWorkerReturns() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch drained = new CountDownLatch(1);
        JobService service = new JobService("server", job -> {
            started.countDown();
            release.await();
            job.monitor().checkCancelled();
            return null;
        });
        try {
            service.submit("request", "read_memory", Map.of(), 10000);
            assertTrue(started.await(2, TimeUnit.SECONDS));
            service.close(drained::countDown);
            assertFalse(drained.await(50, TimeUnit.MILLISECONDS));
            release.countDown();
            assertTrue(drained.await(2, TimeUnit.SECONDS));
        }
        finally {
            release.countDown();
            service.close();
        }
    }

    @Test
    public void jobPagesKeepTheirSnapshotAndRejectChangedFilters() throws Exception {
        try (JobService service = new JobService("server", job -> Map.of("large_result", "payload"))) {
            for (String id : List.of("first", "second", "third")) {
                service.submit(id, "decompile_function", Map.of("program_id", "program"), 10000).await(2000);
            }
            Map<String, Object> first = service.list(Map.of("program_id", "program", "limit", 2));
            List<?> firstRows = (List<?>) first.get("items");
            assertEquals(2, firstRows.size());
            assertFalse(((Map<?, ?>) firstRows.getFirst()).containsKey("result"));
            String cursor = (String) first.get("next_cursor");
            service.submit("new", "decompile_function", Map.of("program_id", "program"), 10000).await(2000);
            Map<String, Object> second = service.list(Map.of("program_id", "program", "limit", 2, "cursor", cursor));
            List<?> secondRows = (List<?>) second.get("items");
            assertEquals(1, secondRows.size());
            assertNotEquals("new", ((Map<?, ?>) secondRows.getFirst()).get("job_id"));
            assertEquals(false, second.get("has_more"));
            assertEquals(first.get("snapshot_time_ms"), second.get("snapshot_time_ms"));
            ApiException changed = assertThrows(ApiException.class,
                () -> service.list(Map.of("program_id", "other", "cursor", cursor)));
            assertEquals("CURSOR_STALE", changed.code());
        }
    }

    @Test
    public void jobPageRetentionEvictsTheOldestSnapshot() throws Exception {
        try (JobService service = new JobService("server", job -> null)) {
            service.submit("first", "read_memory", Map.of(), 10000).await(2000);
            service.submit("second", "read_memory", Map.of(), 10000).await(2000);
            String oldest = (String) service.list(Map.of("limit", 1)).get("next_cursor");
            for (int i = 0; i < 32; i++) service.list(Map.of("limit", 1));
            ApiException stale = assertThrows(ApiException.class, () -> service.list(Map.of("cursor", oldest)));
            assertEquals("CURSOR_STALE", stale.code());
        }
    }
}
