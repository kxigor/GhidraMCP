package com.lauriewired.mcp;

import com.google.gson.reflect.TypeToken;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.framework.Application;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.Project;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;

public final class BridgeService implements AutoCloseable {
    public BridgeService(FrontEndTool frontEnd, boolean readOnly) {
        this.frontEnd = frontEnd;
        this.readOnly = readOnly;
        this.jobs = new JobService(serverId, this::execute);
        ResearchOperations.register(operations);
        MutationOperations.register(operations);
        projectService = new ProjectService(this, frontEnd);
        projectService.register(operations);
        analysisService = new AnalysisService(this);
        analysisService.register(operations);
        new GuiService(this).register(operations);
        registerSystem();
    }

    public void start(int port) throws IOException {
        http = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 128);
        http.setExecutor(httpWorkers);
        http.createContext("/api/v2", this::handle);
        http.createContext("/", exchange -> send(exchange, 410, Json.map("error",
            new ApiException("API_VERSION_MISMATCH", "Use the MCP v2 bridge and explicit program_id").toMap())));
        http.start();
    }

    public void setProject(Project project) {
        if (registry.project() != project) {
            jobs.cancelProject(registry.projectId(), registry.entries().stream().map(ProgramRegistry.Entry::id).toList());
            registry.setProject(project);
        }
    }
    public ProgramRegistry registry() { return registry; }
    public ResultStore results() { return results; }
    public JobService jobs() { return jobs; }
    public boolean readOnly() { return readOnly; }
    public FrontEndTool frontEnd() { return frontEnd; }
    public AnalysisService analysis() { return analysisService; }
    public int port() { return http == null ? 0 : http.getAddress().getPort(); }

    public JobService.Job submit(String id, String operation, Map<String, Object> args, int timeoutMs) {
        if (!operations.containsKey(operation)) throw new ApiException("UNSUPPORTED_CAPABILITY", "Unknown operation: " + operation);
        JobService.Job job = jobs.submit(id, operation, args, timeoutMs);
        if (operation.equals("start_analysis") && args.get("program_id") instanceof String programId) analysisService.track(programId, id);
        return job;
    }

    private Object execute(JobService.Job job) throws Exception {
        OperationDefinition definition = operations.get(job.operation());
        Map<String, Object> args = job.arguments();
        if (definition.requiresWritableServer() && readOnly) throw new ApiException("READ_ONLY", "Server is read-only");
        if (readOnly && Arguments.bool(args, "discard_changes", false)) throw new ApiException("READ_ONLY", "Discard is disabled");
        registry.refresh();
        List<ProgramRegistry.Lease> leases = new ArrayList<>();
        List<Lock> locks = new ArrayList<>();
        ProgramRegistry.Entry entry = null;
        boolean completed = false;
        Map<String, String> revisions = new LinkedHashMap<>();
        ProgramRegistry.ProjectLease projectLease = List.of("open_project","close_project","create_project",
            "get_server_info","get_job","cancel_job","list_jobs").contains(job.operation()) ? null : registry.acquireProject();
        try {
            if (definition.programRequired()) {
                String programId = Arguments.string(args, "program_id");
                List<String> ids = new ArrayList<>(Arguments.strings(args, "scope_program_ids"));
                ids.add(programId);
                for (String id : ids.stream().distinct().sorted().toList()) {
                    ProgramRegistry.Lease lease = registry.acquire(id, definition.mutatesProgram() && id.equals(programId));
                    leases.add(lease);
                    ProgramRegistry.Entry selected = lease.entry();
                    if (id.equals(programId)) entry = selected;
                    Lock lock = definition.mutatesProgram() && id.equals(programId) ?
                        selected.lock().writeLock() : selected.lock().readLock();
                    if (definition.effect() != OperationDefinition.Effect.LIVE_READ && definition.effect() != OperationDefinition.Effect.UI) {
                        while (!lock.tryLock(100, TimeUnit.MILLISECONDS)) job.monitor().checkCancelled();
                        locks.add(lock);
                    }
                    revisions.put(id, selected.revision());
                }
            }
            OperationContext context = new OperationContext(registry, entry, job.monitor(), this, revisions);
            context.setJob(job);
            Object data;
            if (definition.effect() == OperationDefinition.Effect.WRITE) {
                data = TransactionGuard.execute(context.program(), job.operation(), Arguments.optionalString(args, "expected_revision"),
                    job.monitor(), () -> definition.handler().execute(context, args));
            }
            else data = definition.handler().execute(context, args);
            if (definition.requiresWritableServer()) {
                job.effects("committed");
                completed = true;
            }
            if (projectLease != null) projectLease.check();
            if (definition.effect() == OperationDefinition.Effect.READ) {
                job.monitor().checkCancelled();
                for (ProgramRegistry.Lease lease : leases) {
                    if (!revisions.get(lease.entry().id()).equals(lease.entry().revision())) {
                        throw new ApiException("PROGRAM_CHANGED", "Program changed during read", Map.of("program_id", lease.entry().id()));
                    }
                }
            }
            Map<String, Object> envelope = Json.map("request_id", job.id(), "server_id", serverId, "data", data,
                "truncated", data instanceof Map<?, ?> map && Boolean.TRUE.equals(map.get("truncated")), "warnings", List.of());
            if (entry != null) {
                envelope.put("program_id", entry.id());
                envelope.put("revision", entry.revision());
                if (definition.mutatesProgram()) {
                    envelope.put("revision_before", revisions.get(entry.id()));
                    envelope.put("revision_after", entry.revision());
                    envelope.put("changed", !revisions.get(entry.id()).equals(entry.revision()));
                }
            }
            if (revisions.size() > 1) envelope.put("program_revisions", revisions);
            if (definition.effect() == OperationDefinition.Effect.LIVE_READ) envelope.put("consistency", "live");
            return envelope;
        }
        finally {
            if (entry != null && definition.mutatesProgram()) {
                job.affected(entry);
                if (!completed && definition.effect() != OperationDefinition.Effect.WRITE &&
                        !entry.program().isClosed() && !entry.revision().equals(revisions.get(entry.id()))) job.effects("partial");
            }
            for (int i = locks.size() - 1; i >= 0; i--) locks.get(i).unlock();
            for (int i = leases.size() - 1; i >= 0; i--) leases.get(i).close();
            if (projectLease != null) projectLease.close();
        }
    }

    private void registerSystem() {
        operations.put("get_server_info", new OperationDefinition("get_server_info", OperationDefinition.Effect.READ, false, false, (c,a) -> serverInfo()));
        operations.put("get_job", new OperationDefinition("get_job", OperationDefinition.Effect.READ, false, false, (c,a) -> {
            var job = jobs.get(Arguments.string(a, "job_id"));
            job.await(Arguments.integer(a, "wait_ms", 0, 0, 10000));
            Map<String, Object> state = job.snapshot();
            if (state.get("error") instanceof Map<?, ?> error) {
                throw new ApiException((String) error.get("code"), (String) error.get("message"), state);
            }
            return state;
        }));
        operations.put("list_jobs", new OperationDefinition("list_jobs", OperationDefinition.Effect.READ, false, false,
            (c,a) -> jobs.list(a)));
        operations.put("cancel_job", new OperationDefinition("cancel_job", OperationDefinition.Effect.SESSION, false, false,
            (c,a) -> jobs.cancel(Arguments.string(a,"job_id"))));
        operations.put("get_result_chunk", OperationDefinition.read("get_result_chunk", (c,a) -> results.chunk(
            Arguments.string(a,"result_id"), c.programId(), c.revision(), Arguments.integer(a,"offset",0,0,Integer.MAX_VALUE),
            Arguments.integer(a,"length",ResultStore.CHUNK_SIZE,1,ResultStore.CHUNK_SIZE))));
    }

    public Map<String, Object> serverInfo() {
        return Json.map("api_version", 2, "server_id", serverId, "ghidra_version", Application.getApplicationVersion(),
            "plugin_version", "2.0.0", "read_only", readOnly, "project_id", registry.projectId(),
            "operations", operations.keySet().stream().sorted().toList(),
            "capabilities", Json.map("background_programs", true, "gui", frontEnd != null, "analysis", true),
            "limits", Json.map("max_memory_read",65536,"max_page_size",1000,"max_timeout_ms",1800000,
                "result_retention_ms",ResultStore.RETENTION_MS,"job_retention_ms",JobService.RETENTION_MS,
                "max_retained_jobs",JobService.MAX_JOBS,"max_retained_results",ResultStore.MAX_RESULTS,
                "max_result_bytes",ResultStore.MAX_BYTES,"max_text_chunk_code_points",ResultStore.CHUNK_SIZE));
    }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath().substring("/api/v2".length());
            String method = exchange.getRequestMethod();
            if (path.equals("/server") && method.equals("GET")) { send(exchange, 200, serverInfo()); return; }
            JobService.Job job;
            int waitMs = 0;
            if (path.startsWith("/operations/") && method.equals("POST")) {
                byte[] bytes = exchange.getRequestBody().readNBytes(1024 * 1024 + 1);
                if (bytes.length > 1024 * 1024) throw new ApiException("INVALID_ARGUMENT", "Request body exceeds 1 MiB");
                Map<String, Object> body;
                try { body = Json.GSON.fromJson(new String(bytes, StandardCharsets.UTF_8), new TypeToken<Map<String,Object>>() {}.getType()); }
                catch (RuntimeException error) { throw new ApiException("INVALID_ARGUMENT", "Invalid JSON object"); }
                if (body == null) throw new ApiException("INVALID_ARGUMENT", "JSON object required");
                String operation = path.substring("/operations/".length());
                int timeout = Arguments.integer(body,"timeout_ms",60000,1,1800000);
                waitMs = Arguments.integer(body,"wait_ms",1000,0,10000);
                job = submit(Arguments.string(body,"request_id"), operation, Arguments.object(body,"arguments"), timeout);
            }
            else if (path.startsWith("/requests/")) {
                String id = path.substring("/requests/".length());
                if (id.endsWith("/cancel") && method.equals("POST")) {
                    send(exchange,200,jobs.cancel(id.substring(0,id.length()-7))); return;
                }
                if (!method.equals("GET")) throw new ApiException("INVALID_ARGUMENT","GET required");
                job = jobs.get(id);
                String query = exchange.getRequestURI().getQuery();
                if (query != null && query.startsWith("wait_ms=")) {
                    try { waitMs = Math.min(10000, Math.max(0,Integer.parseInt(query.substring(8)))); }
                    catch (NumberFormatException e) { throw new ApiException("INVALID_ARGUMENT","Invalid wait_ms"); }
                }
            }
            else throw new ApiException("UNSUPPORTED_CAPABILITY", "Unknown API route");
            job.await(waitMs);
            send(exchange,job.terminal()?200:202,job.snapshot());
        }
        catch (ApiException error) { send(exchange,status(error.code()),Json.map("server_id",serverId,"error",error.toMap())); }
        catch (Exception error) { send(exchange,500,Json.map("error",new ApiException("INTERNAL_ERROR",error.toString()).toMap())); }
        finally { exchange.close(); }
    }

    private static int status(String code) {
        return switch (code) {
            case "READ_ONLY" -> 403;
            case "REQUEST_NOT_FOUND", "PROGRAM_NOT_FOUND", "PROJECT_NOT_FOUND", "FILE_NOT_FOUND" -> 404;
            case "QUEUE_FULL" -> 429;
            case "PROGRAM_BUSY", "REVISION_CONFLICT", "UNSAVED_CHANGES", "REQUEST_ID_CONFLICT" -> 409;
            case "INTERNAL_ERROR" -> 500;
            default -> 400;
        };
    }

    private static void send(HttpExchange exchange, int status, Object body) throws IOException {
        byte[] bytes = Json.GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type","application/json; charset=utf-8");
        exchange.sendResponseHeaders(status,bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }

    @Override public void close() {
        if (http != null) http.stop(1);
        jobs.close(registry::close);
        httpWorkers.shutdown();
    }

    private final String serverId = "server-" + UUID.randomUUID();
    private final FrontEndTool frontEnd;
    private final boolean readOnly;
    private final ProgramRegistry registry = new ProgramRegistry();
    private final ResultStore results = new ResultStore();
    private final Map<String,OperationDefinition> operations = new LinkedHashMap<>();
    private final JobService jobs;
    private final ProjectService projectService;
    private final AnalysisService analysisService;
    private final ExecutorService httpWorkers = Executors.newFixedThreadPool(8, runnable -> {
        Thread t = new Thread(runnable,"GhidraMCP-http"); t.setDaemon(true); return t;
    });
    private HttpServer http;
}
