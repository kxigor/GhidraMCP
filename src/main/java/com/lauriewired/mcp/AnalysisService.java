package com.lauriewired.mcp;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.app.services.Analyzer;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class AnalysisService {
    public AnalysisService(BridgeService service) { this.service=service; }

    public void register(Map<String,OperationDefinition> operations) {
        operations.put("get_analysis_options",OperationDefinition.read("get_analysis_options",this::options));
        operations.put("get_analysis_status",OperationDefinition.liveRead("get_analysis_status",(c,a)->status(c.entry())));
        operations.put("get_analysis_log",OperationDefinition.liveRead("get_analysis_log",this::log));
        operations.put("start_analysis",new OperationDefinition("start_analysis",OperationDefinition.Effect.ANALYSIS,true,true,this::analyze));
        operations.put("start_analysis_batch",new OperationDefinition("start_analysis_batch",OperationDefinition.Effect.ANALYSIS,false,true,this::batch));
    }

    public synchronized Map<String,Object> prepare(ProgramRegistry.Entry entry,String policy) {
        pruneHistory();
        if(policy.equals("none")) return Json.map("state","not_requested","job_id",null);
        if(!policy.equals("if_needed")) throw new ApiException("INVALID_ARGUMENT","analysis must be none or if_needed");
        if(AutoAnalysisManager.hasAutoAnalysisManager(entry.program())&&AutoAnalysisManager.getAnalysisManager(entry.program()).isAnalyzing()) {
            String active=lastJobs.get(entry.id());
            if(active!=null) try {
                var job=service.jobs().get(active);
                if(!job.terminal()) return Json.map("state",job.snapshot().get("state"),"job_id",active,"history_known",true);
            }
            catch(ApiException ignored) {}
            return Json.map("state","running","origin","gui","cancellable",false,"job_id",null,"history_known",false);
        }
        String previous=lastJobs.get(entry.id());
        if(previous!=null) {
            try {
                var job=service.jobs().get(previous);
                if(!job.terminal()) return Json.map("state",job.snapshot().get("state"),"job_id",previous,"history_known",true);
                if("succeeded".equals(job.snapshot().get("state"))&&
                        (GhidraProgramUtilities.isAnalyzed(entry.program())||
                        Arguments.string(job.arguments(),"mode","auto").equals("auto")&&
                        !job.arguments().containsKey("ranges"))) {
                    return Json.map("state","not_needed","reason","completed","job_id",previous,"history_known",true);
                }
            }
            catch(ApiException ignored) {}
        }
        if(previous==null&&GhidraProgramUtilities.isAnalyzed(entry.program())) {
            return Json.map("state","not_needed","reason","marked_analyzed","job_id",null,"history_known",false);
        }
        if(service.readOnly()) return Json.map("state","blocked_read_only","reason","READ_ONLY","job_id",null);
        String id="analysis-"+UUID.randomUUID();
        lastJobs.put(entry.id(),id);
        service.submit(id,"start_analysis",Map.of("program_id",entry.id()),300000);
        return Json.map("state","queued","job_id",id,"history_known",true);
    }

    public Map<String,Object> status(ProgramRegistry.Entry entry) {
        pruneHistory();
        String id=lastJobs.get(entry.id());
        JobService.Job job=retainedJob(id);
        boolean running=AutoAnalysisManager.hasAutoAnalysisManager(entry.program())&&AutoAnalysisManager.getAnalysisManager(entry.program()).isAnalyzing();
        boolean owned=job!=null&&!job.terminal();
        Map<String,Object> state=Json.map("ghidra_analyzed",GhidraProgramUtilities.isAnalyzed(entry.program()),
            "running",running,"origin",owned?"mcp":running?"gui":null,"cancellable",owned,
            "history_known",job!=null,"last_job_id",job==null?null:id);
        if(job!=null) state.put("last_job",job.snapshot());
        return state;
    }

    public void track(String programId, String jobId) {
        pruneHistory();
        lastJobs.put(programId, jobId);
    }

    private Object log(OperationContext context,Map<String,Object> args) {
        pruneHistory();
        int limit=Arguments.integer(args,"limit",100,1,1000);
        String selected=Arguments.optionalString(args,"job_id");
        if(selected==null) selected=lastJobs.get(context.programId());
        if(selected==null) return unavailableLog(args,null,"no_recorded_job",null);
        JobService.Job job=service.jobs().get(selected);
        if(!job.operation().equals("start_analysis")||!context.programId().equals(job.arguments().get("program_id"))) {
            throw new ApiException("INVALID_ARGUMENT","job_id must identify an analysis job for this program");
        }
        AnalysisLog record;
        synchronized(logs) { record=logs.get(selected); }
        if(record==null) return unavailableLog(args,selected,job.terminal()?"not_retained":"pending",job.snapshot().get("state"));
        int offset=logOffset(args,record);
        int total=record.text().codePointCount(0,record.text().length());
        if(offset>total) throw new ApiException("INVALID_ARGUMENT","Cursor offset exceeds the retained log");
        List<Map<String,Object>> items=new ArrayList<>();
        StringBuilder page=new StringBuilder();
        int end=offset;
        int budget=LOG_PAGE_CHARACTERS;
        for(int item=0;item<limit&&end<total&&budget>0;item++) {
            int length=Math.min(Math.min(LOG_CHUNK_CHARACTERS,budget),total-end);
            String text=record.text().substring(record.text().offsetByCodePoints(0,end),record.text().offsetByCodePoints(0,end+length));
            items.add(Json.map("offset",end,"text",text));
            page.append(text);
            end+=length;
            budget-=length;
        }
        boolean more=end<total;
        return Json.map("available_history",true,"job_id",selected,"log",page.toString(),"items",items,
            "offset",offset,"total_length",total,"has_more",more,"next_cursor",more?logCursor(record,end):null,
            "truncated",more||record.storageTruncated()||record.sourceTruncated(),
            "storage_truncated",record.storageTruncated(),"source_truncated",record.sourceTruncated(),
            "timings",record.timings(),"timings_truncated",record.timingsTruncated());
    }

    private static Map<String,Object> unavailableLog(Map<String,Object> args,String job,String reason,Object state) {
        if(args.containsKey("cursor")) throw new ApiException("CURSOR_STALE","The requested log is no longer retained");
        return Json.map("available_history",false,"job_id",job,"reason",reason,"job_state",state,
            "log","","items",List.of(),"has_more",false,"next_cursor",null,"truncated",false);
    }

    private static int logOffset(Map<String,Object> args,AnalysisLog record) {
        String cursor=Arguments.optionalString(args,"cursor");
        if(cursor==null) return 0;
        try {
            String[] fields=new String(Base64.getUrlDecoder().decode(cursor),StandardCharsets.UTF_8).split(":",-1);
            if(fields.length!=2) throw new IllegalArgumentException();
            if(!fields[0].equals(record.token())) throw new ApiException("CURSOR_STALE","Cursor belongs to a different analysis log");
            int offset=Integer.parseInt(fields[1]);
            if(offset<0) throw new IllegalArgumentException();
            return offset;
        }
        catch(IllegalArgumentException error) { throw new ApiException("INVALID_ARGUMENT","Invalid analysis log cursor"); }
    }

    private static String logCursor(AnalysisLog record,int offset) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString((record.token()+":"+offset).getBytes(StandardCharsets.UTF_8));
    }

    private JobService.Job retainedJob(String id) {
        if(id==null) return null;
        try { return service.jobs().get(id); }
        catch(ApiException ignored) { return null; }
    }

    private void pruneHistory() {
        long before=System.currentTimeMillis()-JobService.RETENTION_MS;
        synchronized(logs) {
            logs.entrySet().removeIf(entry->entry.getValue().created()<before||retainedJob(entry.getKey())==null);
        }
        lastJobs.entrySet().removeIf(entry->retainedJob(entry.getValue())==null);
    }

    private void observeClose(OperationContext context) {
        String id=context.programId();
        if(observedPrograms.putIfAbsent(id,Boolean.TRUE)==null) {
            context.program().addCloseListener(ignored->{
                lastJobs.remove(id);
                observedPrograms.remove(id);
                synchronized(logs) { logs.values().removeIf(record->record.programId().equals(id)); }
            });
        }
    }

    private void retainLog(OperationContext context,LogCapture capture) {
        if(context.job()==null||!capture.started()) return;
        pruneHistory();
        AnalysisLog record=new AnalysisLog(context.programId(),UUID.randomUUID().toString(),capture.text(),
            capture.timings(),capture.storageTruncated(),capture.sourceTruncated(),capture.timingsTruncated(),System.currentTimeMillis());
        synchronized(logs) {
            logs.put(context.job().id(),record);
            while(logs.size()>MAX_LOG_RECORDS) logs.remove(logs.keySet().iterator().next());
        }
    }

    private List<Analyzer> analyzers(Program program) {
        // Analyzer constructors share Ghidra's non-thread-safe file cache with manager initialization.
        synchronized(AutoAnalysisManager.class) {
            return ClassSearcher.getInstances(Analyzer.class).stream().filter(a->a.canAnalyze(program))
                .sorted(java.util.Comparator.comparing(Analyzer::getName)).toList();
        }
    }

    private Object options(OperationContext context,Map<String,Object> args) throws Exception {
        Program program=context.program();
        ToolOptions defaults=new ToolOptions("MCP analysis defaults");
        List<Map<String,Object>> available=new ArrayList<>();
        for(Analyzer analyzer:analyzers(program)) {
            context.monitor().checkCancelled();
            defaults.setBoolean(analyzer.getName(),analyzer.getDefaultEnablement(program));
            analyzer.registerOptions(defaults.getOptions(analyzer.getName()),program);
            available.add(Json.map("analyzer_id",analyzer.getClass().getName(),"name",analyzer.getName(),
                "description",analyzer.getDescription(),"supports_one_shot",analyzer.supportsOneTimeAnalysis(),
                "default_enabled",analyzer.getDefaultEnablement(program)));
        }
        Options stored=program.getOptions(Program.ANALYSIS_PROPERTIES);
        List<Map<String,Object>> fields=new ArrayList<>();
        for(String name:defaults.getOptionNames()) {
            Object defaultValue=defaults.getObject(name,null);
            fields.add(Json.map("name",name,"type",defaults.getType(name).toString(),"default",safe(defaults.getObject(name,null)),
                "value",safe(stored.getObject(name,defaultValue)),"choices",defaultValue instanceof Enum<?> enumeration?
                    java.util.Arrays.stream(enumeration.getDeclaringClass().getEnumConstants()).map(value->((Enum<?>)value).name()).toList():List.of()));
        }
        return Json.map("analyzers",available,"options",fields);
    }

    private Object analyze(OperationContext context,Map<String,Object> args) throws Exception {
        Program program=context.program();
        String mode=Arguments.string(args,"mode","auto");
        if(!mode.equals("auto")&&!mode.equals("one_shot")) throw new ApiException("INVALID_ARGUMENT","Unknown analysis mode");
        List<String> requested=Arguments.strings(args,"analyzers");
        if(mode.equals("one_shot")&&requested.isEmpty()) throw new ApiException("INVALID_ARGUMENT","one_shot requires analyzers");
        List<Analyzer> all=analyzers(program);
        List<Analyzer> selected=new ArrayList<>();
        for(String id:requested) {
            Analyzer analyzer=all.stream().filter(a->a.getClass().getName().equals(id)||a.getName().equals(id)).findFirst()
                .orElseThrow(()->new ApiException("INVALID_ARGUMENT","Analyzer not applicable: "+id));
            if(mode.equals("one_shot")&&!analyzer.supportsOneTimeAnalysis()) throw new ApiException("INVALID_ARGUMENT","Analyzer does not support one-shot: "+id);
            selected.add(analyzer);
        }
        AddressSet ranges=ranges(program,args);
        AutoAnalysisManager manager=AutoAnalysisManager.getAnalysisManager(program);
        if(manager.isAnalyzing()) throw new ApiException("PROGRAM_BUSY","Analysis already running");
        Options storedOptions=program.getOptions(Program.ANALYSIS_PROPERTIES);
        Map<String,Object> requestedOptions=new LinkedHashMap<>();
        for(var option:Arguments.object(args,"options").entrySet()) {
            if(!storedOptions.getOptionNames().contains(option.getKey())) throw new ApiException("INVALID_ARGUMENT","Unknown analysis option: "+option.getKey());
            requestedOptions.put(option.getKey(),coerce(option.getValue(),storedOptions.getObject(option.getKey(),null)));
        }
        Map<String,Object> effective=new LinkedHashMap<>();
        LogCapture capture=new LogCapture();
        AutoAnalysisManagerListener listener=(finished,cancelled)->capture.capture(finished);
        observeClose(context);
        try {
            manager.scheduleWorker(new AnalysisWorker() {
                @Override public String getWorkerName() { return "MCP analysis"; }
                @Override public boolean analysisWorkerCallback(Program p,Object ignored,TaskMonitor monitor) throws Exception {
                    capture.begin(manager);
                    manager.addListener(listener);
                    try {
                        manager.initializeOptions();
                        Options options=p.getOptions(Program.ANALYSIS_PROPERTIES);
                        if(mode.equals("auto")&&!selected.isEmpty()) {
                            for(Analyzer analyzer:all) options.setBoolean(analyzer.getName(),selected.contains(analyzer));
                        }
                        for(var option:requestedOptions.entrySet()) options.putObject(option.getKey(),option.getValue());
                        manager.initializeOptions(options);
                        for(String name:options.getOptionNames()) effective.put(name,safe(options.getObject(name,null)));
                        if(mode.equals("one_shot")) {
                            for(Analyzer analyzer:selected) manager.scheduleOneTimeAnalysis(analyzer,ranges==null?p.getMemory():ranges);
                        }
                        else manager.reAnalyzeAll(ranges);
                        manager.startAnalysis(monitor);
                        monitor.checkCancelled();
                        if(mode.equals("auto")&&ranges==null) GhidraProgramUtilities.markProgramAnalyzed(p);
                        return true;
                    }
                    finally {
                        capture.capture(manager);
                        manager.removeListener(listener);
                    }
                }
            },null,true,context.monitor());
            context.monitor().checkCancelled();
            String fullLog=capture.text();
            String preview=bounded(fullLog,LOG_PAGE_CHARACTERS);
            boolean truncated=preview.length()!=fullLog.length()||capture.storageTruncated()||capture.sourceTruncated();
            return Json.map("completed",true,"mode",mode,"effective_options",effective,
                "analysis_log",preview,"analysis_log_job_id",context.job()==null?null:context.job().id(),
                "analysis_log_truncated",truncated,"truncated",truncated,
                "timings",capture.timings(),"timings_truncated",capture.timingsTruncated(),"saved",false);
        }
        catch(InvocationTargetException error) {
            if(error.getCause() instanceof Exception cause) throw cause;
            throw error;
        }
        finally { retainLog(context,capture); }
    }

    private Object batch(OperationContext context,Map<String,Object> args) throws Exception {
        List<String> ids=Arguments.strings(args,"program_ids");
        if(ids.isEmpty()||ids.size()>100) throw new ApiException("INVALID_ARGUMENT","program_ids must contain 1 to 100 programs");
        List<JobService.Job> children=new ArrayList<>();
        Map<String,Object> perProgram=Arguments.object(args,"options_by_program");
        for(String id:ids) context.registry().entry(id);
        for(var options:perProgram.entrySet()) {
            if(!ids.contains(options.getKey())) throw new ApiException("INVALID_ARGUMENT","options_by_program contains an unselected program");
            if(!(options.getValue() instanceof Map<?,?>)) throw new ApiException("INVALID_ARGUMENT","Each options_by_program value must be an object");
        }
        try {
            for(String id:ids.stream().distinct().toList()) {
                Map<String,Object> child=Json.map("program_id",id);
                if(perProgram.containsKey(id)) child.put("options",perProgram.get(id));
                String request="analysis-"+UUID.randomUUID();
                lastJobs.put(id,request);
                children.add(service.submit(request,"start_analysis",child,Arguments.integer(args,"timeout_ms",300000,1,1800000)));
            }
            for(var child:children) while(!child.terminal()) { context.monitor().checkCancelled(); child.await(100); }
            List<Map<String,Object>> results=children.stream().map(JobService.Job::snapshot).toList();
            if(results.stream().anyMatch(r->!r.get("state").equals("succeeded"))) {
                throw new ApiException("ANALYSIS_FAILED","Some programs could not be analyzed",Map.of("jobs",results,"effects","partial"));
            }
            return Json.map("jobs",results,"effects","committed");
        }
        catch(Exception error) {
            children.forEach(child->service.jobs().cancel(child.id()));
            List<Map<String,Object>> results=children.stream().map(JobService.Job::snapshot).toList();
            String effects=results.stream().anyMatch(row->!"none".equals(row.get("effects"))||
                "cancelling".equals(row.get("state")))?"partial":"none";
            if(context.job()!=null) {
                context.job().effects(effects);
                for(JobService.Job child:children) {
                    try { context.job().affected(context.registry().entry((String)child.arguments().get("program_id"))); }
                    catch(ApiException ignored) {}
                }
            }
            Map<String,Object> details=error instanceof ApiException api?new LinkedHashMap<>(api.details()):new LinkedHashMap<>();
            details.put("jobs",results);
            details.put("effects",effects);
            if(error instanceof ApiException api) throw new ApiException(api.code(),api.getMessage(),details);
            if(error instanceof CancelledException||error instanceof InterruptedException) {
                throw new ApiException("CANCELLED","Batch analysis cancelled",details);
            }
            throw new ApiException("ANALYSIS_FAILED",error.getMessage(),details);
        }
    }

    @SuppressWarnings("unchecked")
    private static AddressSet ranges(Program program,Map<String,Object> args) {
        Object value=args.get("ranges");
        if(value==null) return null;
        if(!(value instanceof List<?> list)||list.isEmpty()) throw new ApiException("INVALID_ARGUMENT","ranges must be nonempty");
        AddressSet result=new AddressSet();
        for(Object item:list) {
            if(!(item instanceof Map<?,?>)) throw new ApiException("INVALID_ARGUMENT","Range must be an object");
            Map<String,Object> range=(Map<String,Object>)item;
            var start=Arguments.address(program,range,"start");
            var end=Arguments.address(program,range,"end");
            if(!start.getAddressSpace().equals(end.getAddressSpace())||start.compareTo(end)>=0) throw new ApiException("INVALID_ARGUMENT","Invalid half-open range");
            result.add(start,end.previous());
        }
        return result;
    }

    private static Object safe(Object value) {
        if(value instanceof Enum<?> enumeration) return enumeration.name();
        return value==null||value instanceof String||value instanceof Number||value instanceof Boolean?value:value.toString();
    }

    private static Object coerce(Object value,Object previous) {
        if(value instanceof Number number) {
            try {
                if(previous instanceof Integer) return new BigDecimal(number.toString()).intValueExact();
                if(previous instanceof Long) return new BigDecimal(number.toString()).longValueExact();
                if(previous instanceof Float&&Float.isFinite(number.floatValue())) return number.floatValue();
                if(previous instanceof Double&&Double.isFinite(number.doubleValue())) return number.doubleValue();
            }
            catch(ArithmeticException|NumberFormatException error) {
                throw new ApiException("INVALID_ARGUMENT","Analysis option requires an exact integer within its supported range");
            }
            if(previous instanceof Float||previous instanceof Double) throw new ApiException("INVALID_ARGUMENT","Analysis option requires a finite number within its supported range");
        }
        if(previous instanceof Enum<?> enumeration&&value instanceof String text) {
            for(Object option:enumeration.getDeclaringClass().getEnumConstants()) if(((Enum<?>)option).name().equals(text)) return option;
        }
        if(previous==null||previous.getClass().isInstance(value)) return value;
        throw new ApiException("INVALID_ARGUMENT","Analysis option has the wrong type");
    }

    private static String bounded(String text,int length) {
        int total=text.codePointCount(0,text.length());
        return total<=length?text:text.substring(0,text.offsetByCodePoints(0,length));
    }

    private record AnalysisLog(String programId,String token,String text,String timings,
            boolean storageTruncated,boolean sourceTruncated,boolean timingsTruncated,long created) {}

    private static final class LogCapture {
        private synchronized void begin(AutoAnalysisManager manager) {
            baseline=manager.getMessageLog().toString();
            started=true;
        }

        private synchronized void capture(AutoAnalysisManager manager) {
            if(!started) return;
            String current=manager.getMessageLog().toString();
            String addition=current.startsWith(baseline)?current.substring(baseline.length()):current;
            baseline=current;
            int remaining=MAX_LOG_CHARACTERS-text.codePointCount(0,text.length());
            String retained=bounded(addition,remaining);
            text.append(retained);
            storageTruncated|=retained.length()!=addition.length();
            sourceTruncated|=current.startsWith("There were too many messages to display.\n");
            String fullTimings=manager.getTaskTimesString();
            timings=bounded(fullTimings,MAX_TIMING_CHARACTERS);
            timingsTruncated|=timings.length()!=fullTimings.length();
        }

        private synchronized boolean started() { return started; }
        private synchronized String text() { return text.toString(); }
        private synchronized String timings() { return timings; }
        private synchronized boolean storageTruncated() { return storageTruncated; }
        private synchronized boolean sourceTruncated() { return sourceTruncated; }
        private synchronized boolean timingsTruncated() { return timingsTruncated; }

        private final StringBuilder text=new StringBuilder();
        private String baseline="";
        private String timings="";
        private boolean started;
        private boolean storageTruncated;
        private boolean sourceTruncated;
        private boolean timingsTruncated;
    }

    private static final int LOG_CHUNK_CHARACTERS=4096;
    private static final int LOG_PAGE_CHARACTERS=65536;
    private static final int MAX_LOG_CHARACTERS=262144;
    private static final int MAX_TIMING_CHARACTERS=16384;
    private static final int MAX_LOG_RECORDS=32;
    private final BridgeService service;
    private final Map<String,String> lastJobs=new ConcurrentHashMap<>();
    private final Map<String,AnalysisLog> logs=new LinkedHashMap<>();
    private final Map<String,Boolean> observedPrograms=new ConcurrentHashMap<>();
}
