import com.lauriewired.mcp.BridgeService;
import com.lauriewired.mcp.GuiExecutor;
import com.lauriewired.mcp.Json;
import com.lauriewired.mcp.JobService;
import ghidra.GhidraApplicationLayout;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProjectManager;
import java.io.File;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.swing.Timer;

public final class GuiSmokeRunner {
    public static void main(String[] args) throws Exception {
        GhidraApplicationConfiguration configuration = new GhidraApplicationConfiguration();
        configuration.setShowSplashScreen(false);
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])), configuration);
        int status = 1;
        Project project = null;
        FrontEndTool frontEnd = null;
        try {
            SmokeProjectManager manager = new SmokeProjectManager();
            project = manager.openProject(new ProjectLocator(args[1], args[2]), true, false);
            Project selected = project;
            int port;
            try (ServerSocket socket = new ServerSocket(0)) { port = socket.getLocalPort(); }
            System.setProperty("ghidramcp.port", Integer.toString(port));
            frontEnd = GuiExecutor.call(() -> {
                FrontEndTool tool = new FrontEndTool(manager);
                tool.setActiveProject(selected);
                tool.setVisible(true);
                return tool;
            });
            var field = com.lauriewired.GhidraMCPPlugin.class.getDeclaredField("sharedService");
            field.setAccessible(true);
            BridgeService service = (BridgeService) field.get(null);
            require(service != null && service.port() == port, "Frontend plugin did not start HTTP service");
            run(service);
            if (args.length > 3) {
                Path ready = Path.of(args[3]);
                Files.writeString(ready, Json.GSON.toJson(Map.of("port", port, "gui_smoke", "passed")));
                Path stop = Path.of(args[4]);
                long deadline = System.nanoTime() + 300_000_000_000L;
                while (!Files.exists(stop) && System.nanoTime() < deadline) Thread.sleep(100);
                require(Files.exists(stop), "Timed out waiting for MCP client smoke");
            }
            System.out.println("GUI_SMOKE_OK");
            status = 0;
        }
        catch (Throwable failure) { failure.printStackTrace(); }
        finally {
            FrontEndTool tool = frontEnd;
            Project selected = tool == null ? project : tool.getProject();
            GuiExecutor.call(() -> {
                if (selected != null) {
                    var dispose = ghidra.framework.plugintool.PluginTool.class.getDeclaredMethod("dispose");
                    dispose.setAccessible(true);
                    for (var running : selected.getToolManager().getRunningTools()) dispose.invoke(running);
                }
                if (tool != null) tool.dispose();
                return null;
            });
            if (selected != null) selected.close();
        }
        System.exit(status);
    }

    private static void run(BridgeService service) throws Exception {
        require(items(call(service, "list_tools", Map.of())).isEmpty(), "Expected no initial CodeBrowsers");
        List<String> ids = new ArrayList<>();
        List<String> addresses = new ArrayList<>();
        for (int i = 1; i <= 9; i++) {
            var opened = call(service, "open_program", Map.of("project_id", service.registry().projectId(),
                "project_path", "/binaries/fixture_%02d/libfixture.so".formatted(i), "analysis", "none"));
            String id = (String) opened.get("program_id");
            ids.add(id);
            var functions = items(call(service, "list_functions", Map.of("program_id", id, "query", "fixture_entry")));
            addresses.add((String) functions.getFirst().get("address"));
            require(!items(call(service, "list_exports", Map.of("program_id", id))).isEmpty(), "No exports");
            require(call(service, "decompile_function", Map.of("program_id", id,
                "function_address", addresses.getLast())).get("text").toString().contains("fixture_entry"), "Wrong decompile");
        }
        require(items(call(service, "list_tools", Map.of())).isEmpty(), "Background opening created CodeBrowsers");
        System.out.println("GUI_SMOKE_BACKGROUND_OK");
        String first = ids.get(0), second = ids.get(1);
        String toolA = (String) call(service, "show_program", Map.of("program_id", first, "new_tool", true)).get("tool_id");
        String toolB = (String) call(service, "show_program", Map.of("program_id", first, "new_tool", true)).get("tool_id");
        require(!toolA.equals(toolB), "new_tool did not create a separate CodeBrowser");
        require(service.registry().entries().size() == 9, "GUI duplicated program identity");
        var program = service.registry().entry(first).program();
        require(GuiExecutor.call(() -> service.registry().tool(toolA).getService(ProgramManager.class).getCurrentProgram()) == program,
            "GUI and background use different Program objects");
        call(service, "show_program", Map.of("program_id", second, "tool_id", toolA));
        Timer timer = GuiExecutor.call(() -> {
            var manager = service.registry().tool(toolA).getService(ProgramManager.class);
            var other = service.registry().entry(second).program();
            Timer switching = new Timer(15, event -> manager.setCurrentProgram(manager.getCurrentProgram() == program ? other : program));
            switching.start();
            return switching;
        });
        try {
            var a = service.submit(UUID.randomUUID().toString(), "decompile_function",
                Map.of("program_id", first, "function_address", addresses.get(0)), 60000);
            var b = service.submit(UUID.randomUUID().toString(), "decompile_function",
                Map.of("program_id", second, "function_address", addresses.get(1)), 60000);
            require(!data(a).get("text").equals(data(b).get("text")), "Concurrent window switching crossed programs");
        }
        finally { GuiExecutor.call(() -> { timer.stop(); return null; }); }
        var before = call(service, "get_gui_state", Map.of("tool_id", toolA));
        var metadata = call(service, "get_program_info", Map.of("program_id", first));
        call(service, "decompile_function", Map.of("program_id", first, "function_address", addresses.getFirst()));
        call(service, "read_memory", Map.of("program_id", first, "address", addresses.getFirst(), "length", 4));
        require(before.equals(call(service, "get_gui_state", Map.of("tool_id", toolA))), "Reading moved GUI state");
        var after = call(service, "get_program_info", Map.of("program_id", first));
        require(metadata.get("revision").equals(after.get("revision")), "GUI read changed revision");
        call(service, "rename_function", Map.of("program_id", first, "function_address", addresses.getFirst(), "new_name", "gui_visible_rename"));
        require(program.getFunctionManager().getFunctionAt(com.lauriewired.mcp.Arguments.address(program, addresses.getFirst()))
            .getName().equals("gui_visible_rename"), "Unsaved rename not shared with GUI");
        var renamed = call(service, "get_program_info", Map.of("program_id", first));
        GuiExecutor.call(() -> { service.registry().tool(toolA).setConfigChanged(true); return null; });
        var closedTool = call(service, "close_tool", Map.of("tool_id", toolA));
        require(Boolean.TRUE.equals(closedTool.get("configuration_saved")), "close_tool did not save changed configuration");
        require(service.port() > 0 && service.registry().entry(first).program() == program, "Closing first window stopped service");
        call(service, "close_tool", Map.of("tool_id", toolB));
        var closedInfo = call(service, "get_program_info", Map.of("program_id", first));
        require(Boolean.TRUE.equals(closedInfo.get("dirty")), "Window closure implicitly saved program");
        require(renamed.get("revision").equals(closedInfo.get("revision")), "Window closure changed program revision");
        require(items(call(service, "list_tools", Map.of())).isEmpty(), "CodeBrowsers remain open");
        require(call(service, "decompile_function", Map.of("program_id", first,
            "function_address", addresses.getFirst())).get("text").toString().contains("gui_visible_rename"), "Background program lost changes");
        System.out.println("GUI_SMOKE_WINDOWS_OK");
        String source = program.getExecutablePath();
        for (String id : ids) call(service, "close_program", Map.of("program_id", id, "discard_changes", true));
        require(service.registry().entries().isEmpty(), "Background consumers leaked");
        lifecycle(service, source);
    }

    private static void lifecycle(BridgeService service, String source) throws Exception {
        String directory = service.registry().project().getProjectLocator().getLocation();
        String originalName = service.registry().project().getName();
        call(service, "close_project", Map.of("project_id", service.registry().projectId()));
        require(items(call(service, "list_projects", Map.of())).isEmpty(), "Project did not close");
        String name = "McpLifecycle-" + UUID.randomUUID();
        String projectId = (String) call(service, "create_project", Map.of("directory", directory, "name", name)).get("project_id");
        var imported = call(service, "import_program", Map.of("project_id", projectId,
            "source_path", source, "destination_path", "/fresh/libfixture.so", "analysis", "none"));
        String id = (String) imported.get("program_id");
        var before = call(service, "get_program_info", Map.of("program_id", id));
        require(Boolean.FALSE.equals(before.get("ghidra_analyzed")), "Fresh import unexpectedly analyzed");
        String tool = (String) call(service, "show_program", Map.of("program_id", id)).get("tool_id");
        var shown = call(service, "get_program_info", Map.of("program_id", id));
        require(before.get("revision").equals(shown.get("revision")), "Showing unanalyzed program changed revision");
        require(Boolean.FALSE.equals(shown.get("ghidra_analyzed")), "Showing program fabricated analyzed flag");
        call(service, "start_analysis", Map.of("program_id", id));
        var functions = items(call(service, "list_functions", Map.of("program_id", id, "query", "fixture_entry")));
        require(functions.size() == 1, "Fresh analysis did not find function");
        String address = (String) functions.getFirst().get("address");
        call(service, "rename_function", Map.of("program_id", id, "function_address", address, "new_name", "persisted_gui_function"));
        call(service, "close_tool", Map.of("tool_id", tool));
        var dirty = call(service, "get_program_info", Map.of("program_id", id));
        require(Boolean.TRUE.equals(dirty.get("dirty")), "Tool save saved program data");
        call(service, "save_program", Map.of("program_id", id, "expected_revision", dirty.get("revision")));
        call(service, "close_program", Map.of("program_id", id));
        call(service, "close_project", Map.of("project_id", projectId));
        projectId = (String) call(service, "open_project", Map.of("directory", directory, "name", name)).get("project_id");
        String reopened = (String) call(service, "open_program", Map.of("project_id", projectId,
            "project_path", "/fresh/libfixture.so")).get("program_id");
        require(!reopened.equals(id), "Reopening recycled a closed program ID");
        require(call(service, "decompile_function", Map.of("program_id", reopened,
            "function_address", address)).get("text").toString().contains("persisted_gui_function"), "Saved rename lost across project reopen");
        call(service, "close_program", Map.of("program_id", reopened));
        call(service, "close_project", Map.of("project_id", projectId));
        call(service, "open_project", Map.of("directory", directory, "name", originalName));
        System.out.println("GUI_SMOKE_PROJECT_LIFECYCLE_OK");
    }

    private static Map<String, Object> call(BridgeService service, String operation, Map<String, Object> args) throws Exception {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (true) {
            var job = service.submit(UUID.randomUUID().toString(), operation, args, 60000);
            while (!job.terminal()) job.await(1000);
            var result = job.snapshot();
            if (result.get("error") instanceof Map<?, ?> error && "PROGRAM_BUSY".equals(error.get("code")) &&
                    "none".equals(result.get("effects")) && System.nanoTime() < deadline) {
                Thread.sleep(25);
                continue;
            }
            return data(job);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> data(JobService.Job job) throws Exception {
        while (!job.terminal()) job.await(1000);
        var snapshot = job.snapshot();
        require("succeeded".equals(snapshot.get("state")), Json.GSON.toJson(snapshot));
        return (Map<String, Object>) ((Map<String, Object>) snapshot.get("result")).get("data");
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> items(Map<String, Object> data) {
        return (List<Map<String, Object>>) data.get("items");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static final class SmokeProjectManager extends DefaultProjectManager {}
}
