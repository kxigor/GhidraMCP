package com.lauriewired;

import com.lauriewired.mcp.BridgeService;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.UtilityPluginPackage;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import java.io.IOException;
import java.util.List;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = UtilityPluginPackage.NAME,
    category = "Analysis",
    shortDescription = "Ghidra MCP process service",
    description = "One MCP backend for background programs and every CodeBrowser in this Ghidra process."
)
public class GhidraMCPPlugin extends Plugin implements ApplicationLevelOnlyPlugin, ProjectListener {
    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        if (!(tool instanceof FrontEndTool frontEndTool)) {
            throw new IllegalArgumentException("GhidraMCP must be installed in the Project Window");
        }
        frontEnd = frontEndTool;
        Options options = tool.getOptions(OPTION_CATEGORY);
        options.registerOption(PORT_OPTION, 8080, null, "Loopback HTTP port. Restart the plugin after changing this value.");
        options.registerOption(READ_ONLY_OPTION, false, null, "Reject MCP changes, analysis, import and saving. Restart the plugin after changing this value.");
    }

    @Override
    protected void init() {
        super.init();
        Options options = tool.getOptions(OPTION_CATEGORY);
        int port = Integer.parseInt(System.getProperty("ghidramcp.port", Integer.toString(options.getInt(PORT_OPTION, 8080))));
        if (port < 1 || port > 65535) throw new IllegalArgumentException("MCP HTTP port must be between 1 and 65535");
        synchronized (GhidraMCPPlugin.class) {
            if (sharedService != null) throw new IllegalStateException("A Ghidra MCP service is already running");
            BridgeService created = new BridgeService(frontEnd, options.getBoolean(READ_ONLY_OPTION, false));
            try {
                created.setProject(frontEnd.getProject());
                created.start(port);
                service = created;
                sharedService = created;
                frontEnd.addProjectListener(this);
                Msg.info(this, "GhidraMCP API v2 listening on loopback port " + created.port());
            }
            catch (IOException | RuntimeException error) {
                created.close();
                throw new IllegalStateException("Cannot start the Ghidra MCP service", error);
            }
        }
    }

    @Override
    public void projectOpened(Project project) {
        if (service != null) service.setProject(project);
    }

    @Override
    public void projectClosed(Project project) {
        if (service != null && service.registry().project() == project) service.setProject(null);
    }

    @Override
    protected boolean canClose() {
        if (service == null) return true;
        if (service.registry().activeOperations() > 0) {
            Msg.showWarn(this, tool.getToolFrame(), "MCP operations are running",
                "Wait for the MCP operations to finish or cancel them before closing Ghidra.");
            return false;
        }
        List<String> pending = service.registry().entries().stream()
            .filter(entry -> entry.owned() && (entry.program().isChanged() || entry.mutations().get() > 0))
            .map(entry -> entry.program().getName()).toList();
        if (pending.isEmpty()) return true;
        Msg.showWarn(this, tool.getToolFrame(), "MCP programs need attention",
            "Save or explicitly close the following MCP programs before closing Ghidra: " + String.join(", ", pending));
        return false;
    }

    @Override
    public DomainFile[] getData() {
        if (service == null) return new DomainFile[0];
        return service.registry().entries().stream().filter(entry -> entry.owned())
            .map(entry -> entry.program().getDomainFile()).filter(java.util.Objects::nonNull).distinct().toArray(DomainFile[]::new);
    }

    @Override
    protected void dispose() {
        frontEnd.removeProjectListener(this);
        synchronized (GhidraMCPPlugin.class) {
            if (service != null) {
                service.close();
                if (sharedService == service) sharedService = null;
                service = null;
            }
        }
        super.dispose();
    }

    private static final String OPTION_CATEGORY = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION = "Server Port";
    private static final String READ_ONLY_OPTION = "Read Only";
    private static BridgeService sharedService;
    private final FrontEndTool frontEnd;
    private BridgeService service;
}
