package com.lauriewired.mcp;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.Map;

public final class OperationContext {
    public OperationContext(ProgramRegistry registry, ProgramRegistry.Entry entry,
            TaskMonitor monitor, BridgeService service) {
        this(registry, entry, monitor, service, entry == null ? Map.of() : Map.of(entry.id(), entry.revision()));
    }

    public OperationContext(ProgramRegistry registry, ProgramRegistry.Entry entry,
            TaskMonitor monitor, BridgeService service, Map<String,String> revisions) {
        this.registry = registry;
        this.entry = entry;
        this.monitor = monitor;
        this.service = service;
        this.revision = entry == null ? null : entry.revision();
        this.programRevisions = Map.copyOf(revisions);
    }

    public Program program() { return entry.program(); }
    public String programId() { return entry.id(); }
    public String revision() { return revision; }
    public ProgramRegistry registry() { return registry; }
    public ProgramRegistry.Entry entry() { return entry; }
    public TaskMonitor monitor() { return monitor; }
    public BridgeService service() { return service; }
    public Map<String,String> programRevisions() { return programRevisions; }
    public JobService.Job job() { return job; }
    public void setJob(JobService.Job job) { this.job = job; }

    public Map<String, Object> storeText(String text) {
        return service.results().store(programId(), revision, text);
    }

    private final ProgramRegistry registry;
    private final ProgramRegistry.Entry entry;
    private final TaskMonitor monitor;
    private final BridgeService service;
    private final String revision;
    private final Map<String,String> programRevisions;
    private JobService.Job job;
}
