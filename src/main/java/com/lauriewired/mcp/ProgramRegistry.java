package com.lauriewired.mcp;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import java.awt.GraphicsEnvironment;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public final class ProgramRegistry implements AutoCloseable {
    public synchronized void setProject(Project next) {
        if (project == next) return;
        close();
        project = next;
        projectId = next == null ? null : "project-" + UUID.randomUUID();
    }

    public synchronized Project project() { return project; }
    public synchronized String projectId() { return projectId; }
    public synchronized int activeOperations() { return activeOperations; }

    public synchronized ProjectLease acquireProject() {
        if (changingProject) throw new ApiException("PROJECT_IN_USE", "Project is changing");
        if (project == null) return null;
        activeOperations++;
        return new ProjectLease(project, projectId);
    }

    public synchronized void beginProjectChange() {
        if (changingProject || activeOperations > 0) throw new ApiException("PROJECT_IN_USE", "Project has active operations");
        changingProject = true;
    }

    public synchronized void endProjectChange() { changingProject = false; }

    public Project requireProject(Map<String, Object> args) {
        String id = Arguments.string(args, "project_id");
        synchronized (this) {
            if (project == null || !id.equals(projectId)) {
                throw new ApiException("PROJECT_NOT_FOUND", "Project session is not open: " + id);
            }
            return project;
        }
    }

    public void refresh() {
        Project selected = project();
        if (selected == null || GraphicsEnvironment.isHeadless()) return;
        Map<PluginTool, List<Program>> snapshot = GuiExecutor.call(() -> {
            Map<PluginTool, List<Program>> result = new IdentityHashMap<>();
            for (PluginTool tool : selected.getToolManager().getRunningTools()) {
                ProgramManager pm = tool.getService(ProgramManager.class);
                if (pm != null) result.put(tool, List.of(pm.getAllOpenPrograms()));
            }
            return result;
        });
        synchronized (this) {
            if (selected != project) return;
            tools.keySet().retainAll(snapshot.keySet());
            for (Entry entry : byId.values()) entry.toolIds.clear();
            for (var tool : snapshot.entrySet()) {
                String toolId = tools.computeIfAbsent(tool.getKey(), ignored -> "tool-" + UUID.randomUUID());
                for (Program program : tool.getValue()) {
                    if (!program.isClosed()) register(program).toolIds.add(toolId);
                }
            }
            for (Entry entry : new ArrayList<>(byId.values())) {
                if (entry.program.isClosed() || !entry.owned && entry.toolIds.isEmpty()) retire(entry);
            }
        }
    }

    public synchronized Entry adopt(Program program, Object existingConsumer) {
        Entry entry = register(program);
        if (!entry.owned) {
            if (!program.addConsumer(entry.owner)) throw new ApiException("PROGRAM_CLOSED", "Program closed during open");
            entry.owned = true;
        }
        if (existingConsumer != null) program.release(existingConsumer);
        return entry;
    }

    public synchronized Entry adopt(Program program, Object existingConsumer, String expectedProjectId) {
        if (project == null || !projectId.equals(expectedProjectId)) {
            if (existingConsumer != null && !program.isClosed()) program.release(existingConsumer);
            throw new ApiException("PROJECT_NOT_FOUND", "Project changed while the program was loading");
        }
        return adopt(program, existingConsumer);
    }

    public synchronized void own(Entry entry) {
        if (byId.get(entry.id) != entry) throw new ApiException("PROGRAM_CLOSED", "Program session is no longer open");
        if (!entry.owned) {
            if (!entry.program.addConsumer(entry.owner)) throw new ApiException("PROGRAM_CLOSED", "Program closed during request");
            entry.owned = true;
        }
    }

    private Entry register(Program program) {
        Entry entry = byProgram.get(program);
        if (entry == null) {
            entry = new Entry("program-" + UUID.randomUUID(), program);
            byProgram.put(program, entry);
            byId.put(entry.id, entry);
        }
        return entry;
    }

    public synchronized Entry entry(String id) {
        Entry entry = byId.get(id);
        if (entry == null || entry.program.isClosed()) {
            throw new ApiException(closedIds.contains(id) || entry != null ? "PROGRAM_CLOSED" : "PROGRAM_NOT_FOUND",
                "Program is not open: " + id, Map.of("program_id", id));
        }
        return entry;
    }

    public synchronized List<Entry> entries() {
        return byId.values().stream().filter(e -> !e.program.isClosed()).sorted(Comparator.comparing(Entry::id)).toList();
    }

    public synchronized Lease acquire(String id) {
        return acquire(id, false);
    }

    public synchronized Lease acquire(String id, boolean mutation) {
        Entry entry = entry(id);
        Object consumer = new Object();
        if (!entry.program.addConsumer(consumer)) throw new ApiException("PROGRAM_CLOSED", "Program closed during request");
        if (mutation) {
            own(entry);
            entry.mutations.incrementAndGet();
        }
        return new Lease(entry, consumer, mutation);
    }

    public synchronized Map<String, Object> releaseOwnership(String id, boolean discard, boolean readOnly) {
        Entry entry = entry(id);
        if (entry.mutations.get() > 0) throw new ApiException("PROGRAM_BUSY", "Program has a pending mutation");
        if (discard && readOnly) throw new ApiException("READ_ONLY", "Discarding changes is disabled");
        if (entry.toolIds.isEmpty() && entry.program.isChanged() && !discard) {
            throw new ApiException("UNSAVED_CHANGES", "Save the program or explicitly discard changes");
        }
        if (entry.owned) {
            entry.owned = false;
            entry.program.release(entry.owner);
        }
        boolean closed = entry.toolIds.isEmpty();
        List<String> remaining = List.copyOf(entry.toolIds);
        if (closed) retire(entry);
        return Json.map("closed", closed, "mcp_owned", false, "open_in_tool_ids", remaining);
    }

    private void retire(Entry entry) {
        byId.remove(entry.id);
        byProgram.remove(entry.program);
        closedIds.add(entry.id);
        while (closedIds.size() > 4096) closedIds.remove(closedIds.iterator().next());
    }

    public synchronized PluginTool tool(String id) {
        return tools.entrySet().stream().filter(e -> e.getValue().equals(id)).map(Map.Entry::getKey).findFirst()
            .orElseThrow(() -> new ApiException("GUI_UNAVAILABLE", "CodeBrowser is not open: " + id));
    }

    public synchronized String toolId(PluginTool tool) {
        return tools.computeIfAbsent(tool, ignored -> "tool-" + UUID.randomUUID());
    }

    public synchronized Map<PluginTool, String> tools() { return new IdentityHashMap<>(tools); }

    public synchronized Map<String, Object> info(Entry entry) {
        Program p = entry.program;
        var file = p.getDomainFile();
        return Json.map("program_id", entry.id, "project_id", projectId, "name", p.getName(),
            "project_path", file == null ? null : file.getPathname(), "language_id", p.getLanguageID().toString(),
            "compiler_spec_id", p.getCompilerSpec().getCompilerSpecID().toString(),
            "architecture", p.getLanguage().getProcessor().toString(),
            "endian", p.getLanguage().isBigEndian() ? "big" : "little", "pointer_size", p.getDefaultPointerSize(),
            "image_base", address(p.getImageBase()), "executable_path", p.getExecutablePath(),
            "executable_format", p.getExecutableFormat(), "md5", p.getExecutableMD5(), "sha256", p.getExecutableSHA256(),
            "dirty", p.isChanged(), "read_only", !p.canSave(), "revision", entry.revision(),
            "mcp_owned", entry.owned, "open_in_tool_ids", List.copyOf(entry.toolIds),
            "ghidra_analyzed", GhidraProgramUtilities.isAnalyzed(p));
    }

    public static String revision(Program program) { return Long.toUnsignedString(program.getModificationNumber()); }

    public static String address(ghidra.program.model.address.Address address) {
        return address.getAddressSpace().getName() + ":0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    @Override
    public synchronized void close() {
        for (Entry entry : new ArrayList<>(byId.values())) {
            if (entry.owned && !entry.program.isClosed()) entry.program.release(entry.owner);
            retire(entry);
        }
        tools.clear();
        project = null;
        projectId = null;
    }

    public static final class Entry {
        private Entry(String id, Program program) { this.id = id; this.program = program; }
        public String id() { return id; }
        public Program program() { return program; }
        public String revision() { return ProgramRegistry.revision(program); }
        public ReentrantReadWriteLock lock() { return lock; }
        public AtomicInteger mutations() { return mutations; }
        public boolean owned() { return owned; }
        public Set<String> toolIds() { return Set.copyOf(toolIds); }

        private final String id;
        private final Program program;
        private final Object owner = new Object();
        private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
        private final AtomicInteger mutations = new AtomicInteger();
        private final Set<String> toolIds = new java.util.concurrent.ConcurrentSkipListSet<>();
        private volatile boolean owned;
    }

    public static final class Lease implements AutoCloseable {
        private Lease(Entry entry, Object consumer, boolean mutation) { this.entry = entry; this.consumer = consumer; this.mutation = mutation; }
        public Entry entry() { return entry; }
        @Override public void close() {
            if (mutation) entry.mutations.decrementAndGet();
            entry.program.release(consumer);
        }

        private final Entry entry;
        private final Object consumer;
        private final boolean mutation;
    }

    public final class ProjectLease implements AutoCloseable {
        private ProjectLease(Project project, String id) { this.project = project; this.id = id; }
        public void check() {
            synchronized (ProgramRegistry.this) {
                if (ProgramRegistry.this.project != project || !id.equals(projectId)) {
                    throw new ApiException("PROJECT_NOT_FOUND", "Project changed during the operation");
                }
            }
        }
        @Override public void close() { synchronized (ProgramRegistry.this) { activeOperations--; } }

        private final Project project;
        private final String id;
    }

    private Project project;
    private String projectId;
    private int activeOperations;
    private boolean changingProject;
    private final Map<String, Entry> byId = new LinkedHashMap<>();
    private final Map<Program, Entry> byProgram = new IdentityHashMap<>();
    private final Map<PluginTool, String> tools = new IdentityHashMap<>();
    private final Set<String> closedIds = new LinkedHashSet<>();
}
