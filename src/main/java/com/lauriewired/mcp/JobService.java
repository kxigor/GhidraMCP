package com.lauriewired.mcp;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Comparator;
import java.util.UUID;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public final class JobService implements AutoCloseable {
    @FunctionalInterface
    public interface Runner { Object run(Job job) throws Exception; }

    public JobService(String serverId, Runner runner) {
        this.serverId = serverId;
        this.runner = runner;
        timer.scheduleAtFixedRate(this::expire, 30, 30, TimeUnit.SECONDS);
    }

    public synchronized Job submit(String id, String operation, Map<String, Object> arguments, int timeoutMs) {
        if (closing) throw new ApiException("BACKEND_UNAVAILABLE", "Server is shutting down");
        if (id.length() > 128 || !id.matches("[A-Za-z0-9_.:-]+")) {
            throw new ApiException("INVALID_ARGUMENT", "Invalid request_id");
        }
        Job existing = jobs.get(id);
        if (existing != null) {
            if (!existing.operation.equals(operation) || !existing.arguments.equals(arguments)) {
                throw new ApiException("REQUEST_ID_CONFLICT", "Request ID already has different arguments");
            }
            return existing;
        }
        expire();
        if (jobs.size() >= MAX_JOBS) throw new ApiException("QUEUE_FULL", "Request history is full; retry after expiration");
        Job job = new Job(id, operation, new LinkedHashMap<>(arguments), timeoutMs);
        jobs.put(id, job);
        if (cancelledBeforeSubmit.containsKey(id)) {
            job.cancel(false);
            return job;
        }
        ThreadPoolExecutor executor = operation.equals("start_analysis_batch") ? coordinators :
            operation.equals("get_job") ? waiters : OBSERVER_OPERATIONS.contains(operation) ? observers : workers;
        try { executor.execute(() -> run(job)); }
        catch (RejectedExecutionException error) {
            jobs.remove(id);
            throw new ApiException("QUEUE_FULL", "Backend execution queue is full");
        }
        timer.schedule(() -> job.cancel(true), timeoutMs, TimeUnit.MILLISECONDS);
        return job;
    }

    private void run(Job job) {
        synchronized (job) {
            if (job.terminal()) return;
            job.state = "running";
        }
        try {
            job.monitor.checkCancelled();
            Object result = runner.run(job);
            synchronized (job) { job.result = result; job.state = "succeeded"; }
        }
        catch (Throwable error) {
            if (error instanceof VirtualMachineError) throw (Error) error;
            ApiException api;
            if (error instanceof CancelledException || error instanceof InterruptedException || job.monitor.isCancelled()) {
                api = new ApiException(job.timedOut ? "TIMEOUT" : "CANCELLED", job.timedOut ? "Operation deadline exceeded" : "Operation cancelled");
            }
            else if (error instanceof ApiException failure) api = failure;
            else api = new ApiException("INTERNAL_ERROR", error.getClass().getSimpleName() + ": " + error.getMessage());
            synchronized (job) {
                job.error = api.toMap();
                if (error instanceof ApiException original && api != original) {
                    job.error = new ApiException(api.code(), api.getMessage(), original.details()).toMap();
                }
                job.state = api.code().equals("TIMEOUT") ? "timed_out" : api.code().equals("CANCELLED") ? "cancelled" : "failed";
            }
        }
        finally { job.completed.countDown(); finishShutdown(); }
    }

    public Job get(String id) {
        Job job = jobs.get(id);
        if (job == null) throw new ApiException("REQUEST_NOT_FOUND", "Request not found or expired: " + id);
        return job;
    }

    public Map<String, Object> cancel(String id) {
        Job job = jobs.get(id);
        if (job == null) {
            if (cancelledBeforeSubmit.size() >= 2048) throw new ApiException("QUEUE_FULL", "Cancellation history is full");
            cancelledBeforeSubmit.put(id, System.currentTimeMillis());
            return Json.map("request_id", id, "job_id", id, "state", "cancelling");
        }
        job.cancel(false);
        return job.snapshot();
    }

    public synchronized Map<String, Object> list(Map<String, Object> arguments) {
        String programId = Arguments.optionalString(arguments, "program_id");
        String state = Arguments.optionalString(arguments, "status");
        if (state != null && !List.of("queued", "running", "cancelling", "succeeded", "failed", "cancelled", "timed_out").contains(state)) {
            throw new ApiException("INVALID_ARGUMENT", "Unknown job status");
        }
        int limit = Arguments.integer(arguments, "limit", 100, 1, 1000);
        String cursor = Arguments.optionalString(arguments, "cursor");
        String query = Json.GSON.toJson(Json.map("program_id", programId, "status", state));
        JobListing listing;
        String id;
        int offset = 0;
        listings.values().removeIf(value -> value.created() < System.currentTimeMillis() - RETENTION_MS);
        if (cursor == null) {
            List<Map<String, Object>> rows = jobs.values().stream()
                .filter(job -> !job.operation.equals("list_jobs"))
                .sorted(Comparator.comparingLong((Job job) -> job.created).thenComparing(Job::id))
                .map(Job::summary)
                .filter(row -> (programId == null || programId.equals(row.get("program_id"))) &&
                    (state == null || state.equals(row.get("state")))).toList();
            listing = new JobListing(query, System.currentTimeMillis(), rows);
            id = UUID.randomUUID().toString();
        }
        else {
            String[] parts = cursor.split(":", -1);
            if (parts.length != 2) throw new ApiException("INVALID_ARGUMENT", "Invalid job cursor");
            id = parts[0];
            listing = listings.get(id);
            if (listing == null || !listing.query().equals(query)) throw new ApiException("CURSOR_STALE", "Job listing expired or filters changed");
            try { offset = Integer.parseInt(parts[1]); }
            catch (NumberFormatException error) { throw new ApiException("INVALID_ARGUMENT", "Invalid job cursor offset"); }
            if (offset < 0 || offset > listing.items().size()) throw new ApiException("INVALID_ARGUMENT", "Invalid job cursor offset");
        }
        int end = Math.min(listing.items().size(), offset + limit);
        boolean more = end < listing.items().size();
        if (more && cursor == null) {
            while (listings.size() >= 32) listings.remove(listings.keySet().iterator().next());
            listings.put(id, listing);
        }
        return Json.map("items", listing.items().subList(offset, end), "has_more", more,
            "next_cursor", more ? id + ":" + end : null, "snapshot_time_ms", listing.created());
    }

    private void expire() {
        long before = System.currentTimeMillis() - RETENTION_MS;
        jobs.values().removeIf(job -> job.created < before && job.terminal());
        cancelledBeforeSubmit.values().removeIf(created -> created < before);
    }

    public void cancelProject(String projectId, List<String> programIds) {
        for (Job job : jobs.values()) {
            if (List.of("open_project", "close_project", "create_project").contains(job.operation)) continue;
            if ((projectId != null && projectId.equals(job.arguments.get("project_id"))) ||
                    programIds.contains(job.arguments.get("program_id"))) job.cancel(false);
        }
    }

    @Override public void close() { close(() -> {}); }

    public void close(Runnable whenDrained) {
        afterDrain = whenDrained;
        closing = true;
        jobs.values().forEach(job -> job.cancel(false));
        workers.shutdown();
        coordinators.shutdown();
        observers.shutdown();
        waiters.shutdown();
        timer.shutdownNow();
        finishShutdown();
    }

    private synchronized void finishShutdown() {
        if (closing && afterDrain != null && jobs.values().stream().allMatch(Job::terminal)) {
            Runnable callback = afterDrain;
            afterDrain = null;
            callback.run();
        }
    }

    public final class Job {
        private Job(String id, String operation, Map<String, Object> arguments, int timeoutMs) {
            this.id = id; this.operation = operation; this.arguments = arguments; this.timeoutMs = timeoutMs;
        }

        public String id() { return id; }
        public String operation() { return operation; }
        public Map<String, Object> arguments() { return arguments; }
        public TaskMonitorAdapter monitor() { return monitor; }
        public int timeoutMs() { return timeoutMs; }

        public synchronized void effects(String effects) { this.effects = effects; }
        public synchronized void affected(ProgramRegistry.Entry entry) {
            if (!entry.program().isClosed()) {
                affectedPrograms.put(entry.id(), Json.map("revision", entry.revision(), "dirty", entry.program().isChanged()));
            }
        }
        public synchronized void affectedFile(String path) { affectedFiles.add(path); }

        public synchronized boolean terminal() {
            return state.equals("succeeded") || state.equals("failed") || state.equals("cancelled") || state.equals("timed_out");
        }

        public void await(int waitMs) throws InterruptedException { completed.await(waitMs, TimeUnit.MILLISECONDS); }

        private synchronized void cancel(boolean timeout) {
            if (terminal()) return;
            timedOut |= timeout;
            monitor.cancel();
            if (state.equals("queued")) {
                state = timedOut ? "timed_out" : "cancelled";
                error = new ApiException(timedOut ? "TIMEOUT" : "CANCELLED", "Operation cancelled before execution").toMap();
                completed.countDown();
            }
            else state = "cancelling";
        }

        public synchronized Map<String, Object> snapshot() {
            return Json.map("request_id", id, "job_id", id, "server_id", serverId, "operation", operation,
                "state", state, "program_id", arguments.get("program_id"), "progress", monitor.getProgress(),
                "maximum", monitor.getMaximum(), "message", monitor.getMessage(), "result", result, "error", error,
                "effects",effects,"affected_programs",new LinkedHashMap<>(affectedPrograms),"affected_files",List.copyOf(affectedFiles));
        }

        private synchronized Map<String, Object> summary() {
            Map<String, Object> result = snapshot();
            result.remove("result");
            result.put("created_ms", created);
            if (error != null) result.put("error", Json.map("code", error.get("code"), "message", error.get("message")));
            return result;
        }

        private final String id;
        private final String operation;
        private final Map<String, Object> arguments;
        private final int timeoutMs;
        private final long created = System.currentTimeMillis();
        private final TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
        private final CountDownLatch completed = new CountDownLatch(1);
        private volatile String state = "queued";
        private volatile boolean timedOut;
        private Object result;
        private Map<String, Object> error;
        private String effects = "none";
        private final Map<String,Object> affectedPrograms = new LinkedHashMap<>();
        private final List<String> affectedFiles = new ArrayList<>();
    }

    private record JobListing(String query, long created, List<Map<String, Object>> items) {}

    public static final long RETENTION_MS = 15 * 60 * 1000;
    public static final int MAX_JOBS = 2048;
    private static final Set<String> OBSERVER_OPERATIONS = Set.of("get_server_info", "get_program_info",
        "get_analysis_status", "get_analysis_log", "list_jobs", "cancel_job", "list_projects", "get_project_info",
        "list_programs", "close_program", "list_tools", "get_gui_state", "show_program", "navigate_to",
        "set_selection", "close_program_in_tool", "close_tool");
    private final String serverId;
    private final Runner runner;
    private volatile boolean closing;
    private Runnable afterDrain;
    private final Map<String, Job> jobs = new ConcurrentHashMap<>();
    private final Map<String, Long> cancelledBeforeSubmit = new ConcurrentHashMap<>();
    private final Map<String, JobListing> listings = new LinkedHashMap<>();
    private final ThreadPoolExecutor workers = new ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(128), runnable -> { Thread t = new Thread(runnable, "GhidraMCP-worker"); t.setDaemon(true); return t; });
    private final ThreadPoolExecutor coordinators = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(16), runnable -> { Thread t = new Thread(runnable, "GhidraMCP-batch"); t.setDaemon(true); return t; });
    private final ThreadPoolExecutor observers = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(64), runnable -> { Thread t = new Thread(runnable, "GhidraMCP-observer"); t.setDaemon(true); return t; });
    private final ThreadPoolExecutor waiters = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(16), runnable -> { Thread t = new Thread(runnable, "GhidraMCP-waiter"); t.setDaemon(true); return t; });
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread t = new Thread(runnable, "GhidraMCP-deadlines"); t.setDaemon(true); return t;
    });
}
