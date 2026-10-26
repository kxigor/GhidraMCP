import com.lauriewired.mcp.BridgeService;
import com.lauriewired.mcp.Json;
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;

public class McpServerFixture extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("Expected ready JSON path and stop file path");
        Path ready = Path.of(args[0]);
        Path stop = Path.of(args[1]);
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(
            args.length > 2 ? Long.parseLong(args[2]) : 600);
        try (BridgeService service = new BridgeService(null, false)) {
            service.setProject(state.getProject());
            service.start(0);
            Files.createDirectories(ready.toAbsolutePath().getParent());
            Path pending = ready.resolveSibling(ready.getFileName() + ".tmp");
            Files.writeString(pending, Json.GSON.toJson(Map.of("port", service.port(),
                "url", "http://127.0.0.1:" + service.port(), "project_id", service.registry().projectId())));
            Files.move(pending, ready, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            println("MCP_SERVER_FIXTURE_READY " + ready);
            while (!Files.exists(stop) && System.nanoTime() < deadline) {
                monitor.checkCancelled();
                Thread.sleep(250);
            }
            if (!Files.exists(stop)) throw new AssertionError("MCP server fixture timed out waiting for stop file");
        }
    }
}
