package com.lauriewired.mcp;

import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public final class GuiService {
    public GuiService(BridgeService service) {
        this.service = service;
        this.registry = service.registry();
    }

    public void register(Map<String, OperationDefinition> operations) {
        operations.put("list_tools", new OperationDefinition("list_tools", OperationDefinition.Effect.READ,
            false, false, (c, a) -> listTools()));
        operations.put("get_gui_state", new OperationDefinition("get_gui_state", OperationDefinition.Effect.READ,
            false, false, (c, a) -> GuiExecutor.call(() -> state(tool(a)))));
        operations.put("show_program", ui("show_program", true, this::showProgram));
        operations.put("navigate_to", ui("navigate_to", true, this::navigate));
        operations.put("set_selection", ui("set_selection", true, this::select));
        operations.put("close_program_in_tool", ui("close_program_in_tool", true, this::closeProgram));
        operations.put("close_tool", ui("close_tool", false, this::closeTool));
    }

    private static OperationDefinition ui(String name, boolean programRequired, OperationDefinition.Handler handler) {
        return new OperationDefinition(name, OperationDefinition.Effect.UI, programRequired, false, handler);
    }

    private void requireGui() {
        if (service.frontEnd() == null) throw new ApiException("GUI_UNAVAILABLE", "This server has no GUI host");
    }

    private PluginTool tool(Map<String, Object> arguments) {
        requireGui();
        return registry.tool(Arguments.string(arguments, "tool_id"));
    }

    private Object listTools() {
        requireGui();
        return GuiExecutor.call(() -> {
            List<Map<String, Object>> items = new ArrayList<>();
            for (var entry : registry.tools().entrySet()) items.add(state(entry.getKey()));
            items.sort(Comparator.comparing(item -> item.get("tool_id").toString()));
            return Json.map("items", items, "has_more", false, "next_cursor", null);
        });
    }

    private Map<String, Object> state(PluginTool tool) {
        ProgramManager manager = manager(tool);
        Program current = manager.getCurrentProgram();
        ProgramRegistry.Entry entry = registered(current);
        CodeViewerService viewer = tool.getService(CodeViewerService.class);
        var location = viewer == null ? null : viewer.getCurrentLocation();
        Address address = location != null && location.getProgram() == current ? location.getAddress() : null;
        var function = address == null || current == null ? null : current.getFunctionManager().getFunctionContaining(address);
        List<String> ids = new ArrayList<>();
        for (Program program : manager.getAllOpenPrograms()) {
            ProgramRegistry.Entry open = registered(program);
            if (open != null) ids.add(open.id());
        }
        ids.sort(String::compareTo);
        return Json.map("tool_id", registry.toolId(tool), "name", tool.getName(),
            "program_id", entry == null ? null : entry.id(), "open_program_ids", ids,
            "address", address == null ? null : ProgramRegistry.address(address),
            "function_address", function == null ? null : ProgramRegistry.address(function.getEntryPoint()),
            "selection", viewer == null ? List.of() : ranges(viewer.getCurrentSelection()));
    }

    private ProgramRegistry.Entry registered(Program program) {
        if (program == null) return null;
        return registry.entries().stream().filter(entry -> entry.program() == program).findFirst().orElse(null);
    }

    private Object showProgram(OperationContext context, Map<String, Object> arguments) {
        requireGui();
        String requested = Arguments.optionalString(arguments, "tool_id");
        boolean newTool = Arguments.bool(arguments, "new_tool", false);
        if (requested != null && newTool) throw new ApiException("INVALID_ARGUMENT", "tool_id and new_tool=true are mutually exclusive");
        Address address = arguments.containsKey("address") ? Arguments.address(context.program(), arguments, "address") : null;
        return GuiExecutor.call(() -> {
            context.monitor().checkCancelled();
            suppressAnalysisPrompt(context.program());
            PluginTool target = requested == null ? null : registry.tool(requested);
            if (target == null && !newTool) {
                target = registry.tools().entrySet().stream()
                    .filter(item -> contains(manager(item.getKey()), context.program()))
                    .sorted(Map.Entry.comparingByValue()).map(Map.Entry::getKey).findFirst().orElse(null);
            }
            if (target == null) {
                target = service.frontEnd().getToolServices().launchTool("CodeBrowser", List.of());
                if (target == null) throw new ApiException("GUI_UNAVAILABLE", "The CodeBrowser tool template could not be launched");
            }
            manager(target).openProgram(context.program(), ProgramManager.OPEN_CURRENT);
            manager(target).setCurrentProgram(context.program());
            if (address != null) goTo(target, context.program(), address);
            target.setVisible(true);
            registry.refresh();
            return state(target);
        });
    }

    private Object navigate(OperationContext context, Map<String, Object> arguments) {
        Address address = Arguments.address(context.program(), arguments, "address");
        return GuiExecutor.call(() -> {
            PluginTool target = tool(arguments);
            requireOpen(target, context.program());
            suppressAnalysisPrompt(context.program());
            manager(target).setCurrentProgram(context.program());
            goTo(target, context.program(), address);
            return state(target);
        });
    }

    private Object select(OperationContext context, Map<String, Object> arguments) {
        AddressSet selection = selection(context.program(), arguments.get("ranges"));
        return GuiExecutor.call(() -> {
            PluginTool target = tool(arguments);
            requireOpen(target, context.program());
            suppressAnalysisPrompt(context.program());
            manager(target).setCurrentProgram(context.program());
            target.firePluginEvent(new ProgramSelectionPluginEvent("GhidraMCP",
                new ProgramSelection(selection), context.program()));
            return state(target);
        });
    }

    private Object closeProgram(OperationContext context, Map<String, Object> arguments) {
        boolean discard = Arguments.bool(arguments, "discard_changes", false);
        return GuiExecutor.call(() -> {
            PluginTool target = tool(arguments);
            requireOpen(target, context.program());
            validateClose(target, context.entry(), discard);
            if (!manager(target).closeProgram(context.program(), true)) {
                throw new ApiException("PROGRAM_BUSY", "Ghidra could not close the program in this tool");
            }
            registry.refresh();
            return Json.map("tool_id", Arguments.string(arguments, "tool_id"),
                "program_id", context.programId(), "closed_in_tool", true,
                "still_open", registered(context.program()) != null);
        });
    }

    private Object closeTool(OperationContext context, Map<String, Object> arguments) {
        boolean saveConfiguration = Arguments.bool(arguments, "save_configuration", true);
        return GuiExecutor.call(() -> {
            PluginTool target = tool(arguments);
            if (target.isExecutingCommand()) throw new ApiException("PROGRAM_BUSY", "The tool has running tasks");
            // GhidraTool.shouldSave() can prompt and also returns true for clean auto-saving tools.
            if (!saveConfiguration && target.hasConfigChanged()) {
                throw new ApiException("UNSAVED_CHANGES", "Retry with save_configuration=true to preserve this tool's configuration");
            }
            Program[] programs = manager(target).getAllOpenPrograms();
            for (Program program : programs) validateClose(target, registered(program), false);
            for (Program program : programs) {
                if (!manager(target).closeProgram(program, true)) {
                    throw new ApiException("PROGRAM_BUSY", "Ghidra could not close all programs in this tool");
                }
            }
            boolean configurationSaved = target.hasConfigChanged();
            if (configurationSaved) {
                if (!saveConfiguration) {
                    throw new ApiException("UNSAVED_CHANGES", "Closing programs changed the tool configuration; retry with save_configuration=true");
                }
                target.saveTool();
                if (target.hasConfigChanged()) throw new ApiException("GUI_SAVE_FAILED", "Ghidra could not save this tool's configuration");
            }
            target.close();
            registry.refresh();
            boolean stillOpen = registry.tools().containsKey(target);
            if (stillOpen) throw new ApiException("PROGRAM_BUSY", "A tool plugin prevented closing this CodeBrowser");
            return Json.map("tool_id", Arguments.string(arguments, "tool_id"), "closed", true,
                "configuration_saved", configurationSaved);
        });
    }

    private void validateClose(PluginTool tool, ProgramRegistry.Entry entry, boolean discard) {
        if (entry == null) throw new ApiException("PROGRAM_CHANGED", "The set of open programs changed");
        if (tool.isExecutingCommand() || entry.mutations().get() > 0) {
            throw new ApiException("PROGRAM_BUSY", "Wait for running commands before closing this program");
        }
        if (discard && service.readOnly()) throw new ApiException("READ_ONLY", "Discarding changes is disabled");
        boolean otherOwner = entry.owned() || entry.toolIds().stream().anyMatch(id -> !id.equals(registry.toolId(tool)));
        if (!otherOwner && entry.program().isChanged() && !discard) {
            throw new ApiException("UNSAVED_CHANGES", "Save the program or explicitly discard its changes");
        }
    }

    private static ProgramManager manager(PluginTool tool) {
        ProgramManager manager = tool.getService(ProgramManager.class);
        if (manager == null) throw new ApiException("GUI_UNAVAILABLE", "This tool has no ProgramManager");
        return manager;
    }

    private static boolean contains(ProgramManager manager, Program program) {
        for (Program open : manager.getAllOpenPrograms()) if (open == program) return true;
        return false;
    }

    private static void requireOpen(PluginTool tool, Program program) {
        if (!contains(manager(tool), program)) {
            throw new ApiException("PROGRAM_NOT_OPEN_IN_TOOL", "Use show_program before navigating this program in the selected tool");
        }
    }

    private static void goTo(PluginTool tool, Program program, Address address) {
        GoToService goTo = tool.getService(GoToService.class);
        if (goTo == null || !goTo.goTo(address, program)) {
            throw new ApiException("ADDRESS_INVALID", "The selected tool cannot navigate to this address");
        }
    }

    @SuppressWarnings("unchecked")
    private static AddressSet selection(Program program, Object value) {
        if (!(value instanceof List<?> ranges)) throw new ApiException("INVALID_ARGUMENT", "ranges must be an array");
        AddressSet result = new AddressSet();
        for (Object item : ranges) {
            if (!(item instanceof Map<?, ?> range)) throw new ApiException("INVALID_ARGUMENT", "Each selection range must be an object");
            Map<String, Object> values = (Map<String, Object>) range;
            Address start = Arguments.address(program, values, "start");
            Address end = Arguments.address(program, values, "end");
            if (!start.getAddressSpace().equals(end.getAddressSpace()) || start.compareTo(end) >= 0) {
                throw new ApiException("INVALID_ARGUMENT", "Selection ranges must be nonempty [start, end) in one address space");
            }
            result.add(start, end.subtract(1));
        }
        return result;
    }

    private static List<Map<String, Object>> ranges(AddressSetView selection) {
        List<Map<String, Object>> result = new ArrayList<>();
        if (selection == null) return result;
        for (var range : selection.getAddressRanges()) {
            Address end = range.getMaxAddress().next();
            result.add(Json.map("start", ProgramRegistry.address(range.getMinAddress()),
                "end", end == null ? null : ProgramRegistry.address(end),
                "end_inclusive", end == null ? ProgramRegistry.address(range.getMaxAddress()) : null));
        }
        return result;
    }

    public static void suppressAnalysisPrompt(Program program) {
        if (!javax.swing.SwingUtilities.isEventDispatchThread()) {
            throw new ApiException("INTERNAL_ERROR", "Analysis prompt control must run on the GUI thread");
        }
        if (!"12.2".equals(Application.getApplicationVersion())) {
            throw new ApiException("UNSUPPORTED_CAPABILITY", "Analysis prompt control is verified only for Ghidra 12.2");
        }
        try {
            // Ghidra exposes no public transient prompt control; this field does not alter Program metadata.
            Field asked = AutoAnalysisManager.class.getDeclaredField("alreadyAskedThisSession");
            if (asked.getType() != boolean.class || !asked.trySetAccessible()) {
                throw new ReflectiveOperationException("Unsupported analysis prompt field");
            }
            asked.setBoolean(AutoAnalysisManager.getAnalysisManager(program), true);
        }
        catch (ReflectiveOperationException | RuntimeException error) {
            throw new ApiException("UNSUPPORTED_CAPABILITY", "Cannot suppress the initial analysis dialog without modifying the program");
        }
    }

    private final BridgeService service;
    private final ProgramRegistry registry;
}
