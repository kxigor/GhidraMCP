import com.lauriewired.mcp.BridgeService;
import com.lauriewired.mcp.JobService;
import com.lauriewired.mcp.Json;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class AnalysisSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        try (BridgeService bridge = new BridgeService(null, false)) {
            service = bridge;
            service.setProject(state.getProject());
            List<DomainFile> fixtures = new ArrayList<>();
            collect(state.getProject().getProjectData().getRootFolder(), fixtures);
            require(fixtures.size() >= 8, "At least eight fixture programs are required");
            String original = id(open(fixtures.getFirst().getPathname(), "none"));
            require(Boolean.FALSE.equals(invoke("get_analysis_log", Json.map("program_id", original)).get("available_history")),
                "Preexisting GUI/import analysis must not fabricate MCP log history");
            source = service.registry().entry(original).program().getExecutablePath();
            require(new File(source).isFile(), "Fixture source binary must remain available");
            close(original, false);

            testOpenSchedulingAndSave();
            testImportScheduling();
            testOneShotAndOptions();
            testLiveStatusAndCancellation();
            testAnalysisLogs(fixtures.getFirst());
            testBatchCoordinators(fixtures);
            for (var entry : service.registry().entries()) close(entry.id(), true);
            println("ANALYSIS_SMOKE_OK " + assertions + " assertions");
        }
    }

    private void testOpenSchedulingAndSave() throws Exception {
        String path = "/McpAnalysis/OpenFirst";
        String programId = id(importProgram(path, "none"));
        require(!GhidraProgramUtilities.isAnalyzed(program(programId)), "Import without analysis must remain unanalyzed");
        close(programId, false);
        Map<String, Object> first = open(path, "if_needed");
        programId = id(first);
        String jobId = (String) map(first.get("analysis")).get("job_id");
        require(jobId != null, "First open must schedule analysis");
        Map<String, Object> repeated = open(path, "if_needed");
        require(programId.equals(id(repeated)), "Repeated open must reuse program identity");
        require(jobId.equals(map(repeated.get("analysis")).get("job_id")), "Repeated open must reuse the analysis job");
        succeeded(service.jobs().get(jobId));
        require(rows(invoke("list_jobs", Json.map("program_id", programId, "limit", 1000)).get("items")).stream()
            .filter(row -> "start_analysis".equals(row.get("operation"))).count() == 1,
            "if_needed must schedule only one analysis");
        require(GhidraProgramUtilities.isAnalyzed(program(programId)), "Full analysis must mark the program analyzed");
        require(program(programId).isChanged(), "Analysis must leave unsaved changes");
        expectError("close_program", Json.map("program_id", programId), "UNSAVED_CHANGES");
        close(programId, true);
        programId = id(open(path, "none"));
        require(!GhidraProgramUtilities.isAnalyzed(program(programId)), "Discarding analysis must restore the saved unanalyzed file");
        invoke("start_analysis", Json.map("program_id", programId));
        invoke("save_program", Json.map("program_id", programId));
        require(!program(programId).isChanged(), "Explicit save must clear dirty state");
        close(programId, false);
        Map<String, Object> saved = open(path, "if_needed");
        require("not_needed".equals(map(saved.get("analysis")).get("state")), "Saved analysis must not run again on reopen");
        require(map(saved.get("analysis")).get("job_id") == null, "Reopened analyzed file must not create a job");
        close(id(saved), false);
    }

    private void testImportScheduling() throws Exception {
        String path = "/McpAnalysis/ImportFirst";
        Map<String, Object> imported = importProgram(path, "if_needed");
        String programId = id(imported);
        String jobId = (String) map(imported.get("analysis")).get("job_id");
        require(jobId != null, "Import if_needed must schedule analysis");
        succeeded(service.jobs().get(jobId));
        require(program(programId).isChanged(), "Import analysis must not autosave");
        close(programId, true);
        programId = id(open(path, "none"));
        require(!GhidraProgramUtilities.isAnalyzed(program(programId)), "Import must save the binary before optional analysis");
        close(programId, false);
    }

    private void testOneShotAndOptions() throws Exception {
        String path = "/McpAnalysis/Options";
        analysisProgramId = id(importProgram(path, "none"));
        Program program = program(analysisProgramId);
        long revision = program.getModificationNumber();
        Map<String, Object> options = invoke("get_analysis_options", Json.map("program_id", analysisProgramId));
        require(revision == program.getModificationNumber(), "Listing analysis options must not modify the program");
        List<Map<String, Object>> analyzers = rows(options.get("analyzers"));
        Map<String, Object> oneShot = analyzers.stream().filter(row -> Boolean.TRUE.equals(row.get("supports_one_shot")))
            .findFirst().orElseThrow();
        invoke("start_analysis", Json.map("program_id", analysisProgramId, "mode", "one_shot",
            "analyzers", List.of(oneShot.get("analyzer_id"))));
        require(!GhidraProgramUtilities.isAnalyzed(program), "One-shot must not mark full analysis complete");
        Map<String, Object> needed = map(open(path, "if_needed").get("analysis"));
        require(needed.get("job_id") != null && !"not_needed".equals(needed.get("state")),
            "One-shot completion must not suppress full first-open analysis");
        succeeded(service.jobs().get((String) needed.get("job_id")));
        invoke("start_analysis", Json.map("program_id", analysisProgramId, "mode", "one_shot",
            "analyzers", List.of(oneShot.get("analyzer_id"))));
        require("not_needed".equals(map(open(path, "if_needed").get("analysis")).get("state")),
            "One-shot after completed full analysis must preserve the analyzed state");

        options = invoke("get_analysis_options", Json.map("program_id", analysisProgramId));
        List<Map<String, Object>> fields = rows(options.get("options"));
        var integer = fields.stream().filter(row -> row.get("value") instanceof Integer).findFirst().orElseThrow();
        var bool = fields.stream().filter(row -> row.get("value") instanceof Boolean).findFirst().orElseThrow();
        String integerName = (String) integer.get("name");
        Object before = program.getOptions(Program.ANALYSIS_PROPERTIES).getObject(integerName, null);
        expectError("start_analysis", Json.map("program_id", analysisProgramId,
            "options", Map.of(integerName, new BigDecimal("1.5"))), "INVALID_ARGUMENT");
        expectError("start_analysis", Json.map("program_id", analysisProgramId,
            "options", Map.of(integerName, new BigDecimal("2147483648"))), "INVALID_ARGUMENT");
        require(before.equals(program.getOptions(Program.ANALYSIS_PROPERTIES).getObject(integerName, null)),
            "Invalid numeric options must not truncate or modify values");
        Map<String, Object> invalid = new LinkedHashMap<>();
        invalid.put((String) bool.get("name"), !((Boolean) bool.get("value")));
        invalid.put("MCP nonexistent option", true);
        revision = program.getModificationNumber();
        expectError("start_analysis", Json.map("program_id", analysisProgramId, "options", invalid,
            "analyzers", List.of(oneShot.get("analyzer_id"))), "INVALID_ARGUMENT");
        require(revision == program.getModificationNumber(), "Invalid option maps must not partially apply analyzer switches");
        Map<String, Object> validOptions = new LinkedHashMap<>();
        validOptions.put(integerName, before);
        validOptions.put((String) bool.get("name"), bool.get("value"));
        for (Map<String, Object> field : fields) {
            if (field.get("choices") instanceof List<?> choices && !choices.isEmpty()) {
                require(choices.contains(field.get("value")), "Enum options must advertise canonical round-trippable choices");
                validOptions.put((String) field.get("name"), field.get("value"));
            }
        }
        Map<String, Object> completed = invoke("start_analysis", Json.map("program_id", analysisProgramId,
            "options", validOptions));
        require(before.equals(map(completed.get("effective_options")).get(integerName)), "Explicit numeric options must be applied exactly");
        require(Boolean.FALSE.equals(completed.get("saved")), "Analysis result must identify unsaved changes");
        Map<String, Object> status = invoke("get_analysis_status", Json.map("program_id", analysisProgramId));
        require(Boolean.TRUE.equals(status.get("history_known")), "Explicit analysis must appear in tracked history");
        require("succeeded".equals(map(status.get("last_job")).get("state")), "Tracked analysis status must report completion");
    }

    private void testLiveStatusAndCancellation() throws Exception {
        Program program = program(analysisProgramId);
        AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
        ControlledAnalyzer gui = new ControlledAnalyzer("MCP simulated GUI analysis");
        var executor = Executors.newSingleThreadExecutor();
        try {
            var running = executor.submit(() -> {
                try {
                    manager.scheduleWorker(new AnalysisWorker() {
                        @Override public String getWorkerName() { return "Simulated GUI analysis"; }
                        @Override public boolean analysisWorkerCallback(Program p, Object ignored, TaskMonitor taskMonitor) {
                            manager.scheduleOneTimeAnalysis(gui, p.getMemory());
                            manager.startAnalysis(taskMonitor);
                            return true;
                        }
                    }, null, true, TaskMonitor.DUMMY);
                }
                catch (Exception error) { throw new RuntimeException(error); }
            });
            require(gui.started.await(15, TimeUnit.SECONDS), "Simulated GUI analysis must start");
            Map<String, Object> status = invoke("get_analysis_status", Json.map("program_id", analysisProgramId));
            require(Boolean.TRUE.equals(status.get("running")), "Live status must remain available during GUI analysis");
            require("gui".equals(status.get("origin")) && Boolean.FALSE.equals(status.get("cancellable")),
                "External GUI analysis must be explicitly non-cancellable through MCP");
            Map<String, Object> prepared = map(open(program.getDomainFile().getPathname(), "if_needed").get("analysis"));
            require("gui".equals(prepared.get("origin")) && "running".equals(prepared.get("state")),
                "if_needed must report active GUI analysis even after an earlier successful MCP run");
            gui.release.countDown();
            running.get(15, TimeUnit.SECONDS);
        }
        finally {
            gui.release.countDown();
            executor.shutdownNow();
        }

        ControlledAnalyzer cancellable = new ControlledAnalyzer("MCP cancellable analysis");
        manager.scheduleOneTimeAnalysis(cancellable, program.getMemory());
        JobService.Job job = submit("start_analysis", Json.map("program_id", analysisProgramId));
        try {
            require(cancellable.started.await(15, TimeUnit.SECONDS), "Controlled MCP analyzer must start");
            Map<String, Object> status = invoke("get_analysis_status", Json.map("program_id", analysisProgramId));
            require(job.id().equals(status.get("last_job_id")), "Live status must identify the running MCP job");
            require(Boolean.TRUE.equals(status.get("running")), "MCP analysis must report running while ordinary reads are locked");
            Map<String, Object> pending = invoke("get_analysis_log", Json.map("program_id", analysisProgramId, "job_id", job.id()));
            require(Boolean.FALSE.equals(pending.get("available_history")) && "pending".equals(pending.get("reason")),
                "An unfinished job must not return a previous job's diagnostic log");
            service.jobs().cancel(job.id());
            Map<String, Object> cancelled = await(job);
            require("cancelled".equals(cancelled.get("state")), "Cancellation must stop analysis");
            require("partial".equals(cancelled.get("effects")), "Cancelled analysis must disclose partial effects");
            require(map(cancelled.get("affected_programs")).containsKey(analysisProgramId),
                "Cancelled analysis must identify the affected program revision");
            require("MCP cancellable analysis".equals(program.getListing().getComment(CommentType.POST, program.getMinAddress())),
                "Committed analysis work must remain visible after cancellation");
            Map<String, Object> log = invoke("get_analysis_log", Json.map("program_id", analysisProgramId));
            require(Boolean.TRUE.equals(log.get("available_history")), "Cancelled analysis must retain its log");
        }
        finally { cancellable.release.countDown(); }
    }

    private void testAnalysisLogs(DomainFile otherFile) throws Exception {
        String firstText = "MCP first log\n" + "A😀Б".repeat(4000);
        JobService.Job first = loggingJob(firstText);
        Map<String, Object> page = invoke("get_analysis_log", Json.map("program_id", analysisProgramId,
            "job_id", first.id(), "limit", 1));
        require(Boolean.TRUE.equals(page.get("available_history")) && first.id().equals(page.get("job_id")),
            "Diagnostics must be retained under their exact analysis job");
        require(rows(page.get("items")).size() == 1 && Boolean.TRUE.equals(page.get("has_more")),
            "Log pagination must honor item limits and report continuation");
        String firstCursor = (String) page.get("next_cursor");
        JobService.Job second = loggingJob("MCP second log");
        StringBuilder restored = new StringBuilder((String) page.get("log"));
        while (Boolean.TRUE.equals(page.get("has_more"))) {
            page = invoke("get_analysis_log", Json.map("program_id", analysisProgramId, "job_id", first.id(),
                "cursor", page.get("next_cursor"), "limit", 1));
            restored.append(page.get("log"));
        }
        require(restored.toString().contains(firstText) && !restored.toString().contains("MCP second log"),
            "Historical pagination must preserve Unicode and remain stable after later program changes");
        Map<String, Object> latest = invoke("get_analysis_log", Json.map("program_id", analysisProgramId));
        require(second.id().equals(latest.get("job_id")) && ((String) latest.get("log")).contains("MCP second log") &&
            !((String) latest.get("log")).contains("MCP first log"), "Default log lookup must select the latest job only");
        expectError("get_analysis_log", Json.map("program_id", analysisProgramId, "job_id", second.id(),
            "cursor", firstCursor), "CURSOR_STALE");
        String other = id(open(otherFile.getPathname(), "none"));
        expectError("get_analysis_log", Json.map("program_id", other, "job_id", first.id()), "INVALID_ARGUMENT");
        JobService.Job unrelated = submit("get_program_info", Json.map("program_id", analysisProgramId));
        succeeded(unrelated);
        expectError("get_analysis_log", Json.map("program_id", analysisProgramId, "job_id", unrelated.id()), "INVALID_ARGUMENT");
        JobService.Job large = loggingJob("Z".repeat(300_000));
        Map<String, Object> bounded = invoke("get_analysis_log", Json.map("program_id", analysisProgramId,
            "job_id", large.id(), "limit", 1000));
        String text = (String) bounded.get("log");
        require(text.codePointCount(0, text.length()) <= 65536 && Boolean.TRUE.equals(bounded.get("has_more")),
            "Even a large item limit must obey the bounded log page size");
        require(Boolean.TRUE.equals(bounded.get("storage_truncated")) && Boolean.TRUE.equals(bounded.get("truncated")),
            "The retained log cap must be explicit");
        Map<String, Object> completed = map(map(large.snapshot().get("result")).get("data"));
        require(((String) completed.get("analysis_log")).length() <= 65536 &&
            Boolean.TRUE.equals(completed.get("analysis_log_truncated")), "Analysis job results must bound their inline diagnostic preview");
    }

    private JobService.Job loggingJob(String text) throws Exception {
        Program program = program(analysisProgramId);
        AutoAnalysisManager.getAnalysisManager(program).scheduleOneTimeAnalysis(new LoggingAnalyzer(text), program.getMemory());
        JobService.Job job = submit("start_analysis", Json.map("program_id", analysisProgramId,
            "analyzers", List.of("ghidra.app.plugin.core.analysis.ApplyDataArchiveAnalyzer")));
        succeeded(job);
        return job;
    }

    private void testBatchCoordinators(List<DomainFile> fixtures) throws Exception {
        List<String> ids = new ArrayList<>();
        for (DomainFile file : fixtures.subList(0, 8)) ids.add(id(open(file.getPathname(), "none")));
        List<JobService.Job> batches = new ArrayList<>();
        for (int i = 0; i < 8; i += 2) {
            batches.add(submit("start_analysis_batch", Json.map("program_ids", List.of(ids.get(i), ids.get(i), ids.get(i + 1)))));
        }
        for (JobService.Job batch : batches) {
            Map<String, Object> result = succeeded(batch);
            require(rows(result.get("jobs")).size() == 2, "Batch must deduplicate program IDs and let child workers finish");
        }
        ControlledAnalyzer first = new ControlledAnalyzer("MCP cancelled batch first");
        ControlledAnalyzer second = new ControlledAnalyzer("MCP cancelled batch second");
        AutoAnalysisManager.getAnalysisManager(program(ids.get(0))).scheduleOneTimeAnalysis(first, program(ids.get(0)).getMemory());
        AutoAnalysisManager.getAnalysisManager(program(ids.get(1))).scheduleOneTimeAnalysis(second, program(ids.get(1)).getMemory());
        JobService.Job batch = submit("start_analysis_batch", Json.map("program_ids", ids.subList(0, 2)));
        try {
            require(first.started.await(15, TimeUnit.SECONDS) && second.started.await(15, TimeUnit.SECONDS),
                "Both batch children must begin before cancellation");
            service.jobs().cancel(batch.id());
            Map<String, Object> cancelled = await(batch);
            require("cancelled".equals(cancelled.get("state")) && "partial".equals(cancelled.get("effects")),
                "Cancelled batch must disclose child partial effects");
            Map<String, Object> details = map(map(cancelled.get("error")).get("details"));
            List<Map<String, Object>> children = rows(details.get("jobs"));
            require(children.size() == 2, "Cancelled batch must return child job identities and states");
            require(map(cancelled.get("affected_programs")).keySet().containsAll(ids.subList(0, 2)),
                "Cancelled batch must identify affected programs");
            for (Map<String, Object> child : children) {
                require("cancelled".equals(await(service.jobs().get((String) child.get("job_id"))).get("state")),
                    "Cancelling a batch must cancel each child");
            }
        }
        finally {
            first.release.countDown();
            second.release.countDown();
        }
        testObserverSaturation(ids.subList(0, 4));
    }

    private void testObserverSaturation(List<String> ids) throws Exception {
        List<ControlledAnalyzer> analyzers = new ArrayList<>();
        List<JobService.Job> jobs = new ArrayList<>();
        try {
            for (String id : ids) {
                ControlledAnalyzer analyzer = new ControlledAnalyzer("MCP saturated " + id);
                analyzers.add(analyzer);
                AutoAnalysisManager.getAnalysisManager(program(id)).scheduleOneTimeAnalysis(analyzer, program(id).getMemory());
                jobs.add(submit("start_analysis", Json.map("program_id", id,
                    "analyzers", List.of("ghidra.app.plugin.core.analysis.ApplyDataArchiveAnalyzer"))));
            }
            for (ControlledAnalyzer analyzer : analyzers) {
                require(analyzer.started.await(15, TimeUnit.SECONDS), "Each analysis worker must reach the blocking analyzer");
            }
            for (String operation : List.of("get_analysis_status", "get_analysis_log", "get_program_info")) {
                JobService.Job observation = submit(operation, Json.map("program_id", ids.getFirst()));
                observation.await(2000);
                require(observation.terminal(), operation + " must not starve behind long-running analysis workers");
                succeeded(observation);
            }
            for (JobService.Job job : jobs) {
                JobService.Job cancellation = submit("cancel_job", Json.map("job_id", job.id()));
                cancellation.await(2000);
                require(cancellation.terminal(), "cancel_job must remain available while analysis workers are occupied");
                succeeded(cancellation);
            }
            for (JobService.Job job : jobs) {
                require("cancelled".equals(await(job).get("state")), "Control requests must cancel saturated workers");
            }
        }
        finally {
            analyzers.forEach(analyzer -> analyzer.release.countDown());
            jobs.forEach(job -> service.jobs().cancel(job.id()));
        }
    }

    private Map<String, Object> importProgram(String path, String policy) throws Exception {
        return invoke("import_program", Json.map("project_id", service.registry().projectId(), "source_path", source,
            "destination_path", path, "analysis", policy));
    }

    private Map<String, Object> open(String path, String policy) throws Exception {
        return invoke("open_program", Json.map("project_id", service.registry().projectId(),
            "project_path", path, "analysis", policy));
    }

    private void close(String programId, boolean discard) throws Exception {
        invoke("close_program", Json.map("program_id", programId, "discard_changes", discard));
    }

    private Program program(String programId) { return service.registry().entry(programId).program(); }

    private JobService.Job submit(String operation, Map<String, Object> args) {
        return service.submit("analysis-smoke-" + UUID.randomUUID(), operation, args, 120_000);
    }

    private Map<String, Object> invoke(String operation, Map<String, Object> args) throws Exception {
        return succeeded(submit(operation, args));
    }

    private Map<String, Object> succeeded(JobService.Job job) throws Exception {
        Map<String, Object> result = await(job);
        require("succeeded".equals(result.get("state")), job.operation() + " failed: " + result);
        return map(map(result.get("result")).get("data"));
    }

    private Map<String, Object> await(JobService.Job job) throws Exception {
        for (int i = 0; i < 130 && !job.terminal(); i++) job.await(1000);
        require(job.terminal(), "Job did not finish: " + job.operation());
        return job.snapshot();
    }

    private void expectError(String operation, Map<String, Object> args, String code) throws Exception {
        Map<String, Object> result = await(submit(operation, args));
        require(result.get("error") instanceof Map<?, ?> error && code.equals(error.get("code")),
            "Expected " + code + " from " + operation + ": " + result);
    }

    private static void collect(DomainFolder folder, List<DomainFile> files) {
        for (DomainFile file : folder.getFiles()) if (Program.class.isAssignableFrom(file.getDomainObjectClass())) files.add(file);
        for (DomainFolder child : folder.getFolders()) collect(child, files);
    }

    private static String id(Map<String, Object> value) { return (String) value.get("program_id"); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) { return (Map<String, Object>) value; }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> rows(Object value) { return (List<Map<String, Object>>) value; }

    private void require(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    private static final class ControlledAnalyzer extends AbstractAnalyzer {
        private ControlledAnalyzer(String name) {
            super(name, "Deterministic live status and cancellation fixture", AnalyzerType.BYTE_ANALYZER);
            setPriority(AnalysisPriority.FORMAT_ANALYSIS.before());
        }

        @Override
        public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
                throws CancelledException {
            log.appendMsg(getName());
            program.getListing().setComment(program.getMinAddress(), CommentType.POST, getName());
            started.countDown();
            try {
                while (!release.await(100, TimeUnit.MILLISECONDS)) monitor.checkCancelled();
            }
            catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new CancelledException();
            }
            monitor.checkCancelled();
            return true;
        }

        private final CountDownLatch started = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
    }

    private static final class LoggingAnalyzer extends AbstractAnalyzer {
        private LoggingAnalyzer(String text) {
            super("MCP deterministic diagnostics", "Analysis log ownership and pagination fixture", AnalyzerType.BYTE_ANALYZER);
            setPriority(AnalysisPriority.FORMAT_ANALYSIS.before());
            this.text = text;
        }

        @Override
        public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
            log.appendMsg(text);
            return true;
        }

        private final String text;
    }

    private BridgeService service;
    private String source;
    private String analysisProgramId;
    private int assertions;
}
