package com.lauriewired.mcp;

import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.Option;
import ghidra.framework.store.LockException;
import ghidra.app.util.importer.CsHintLoadSpecChooser;
import ghidra.app.util.importer.LcsHintLoadSpecChooser;
import ghidra.app.util.importer.LoadSpecChooser;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderService;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.VersionException;
import ghidra.app.util.HexLong;
import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

public final class ProjectService {
    public ProjectService(BridgeService service, FrontEndTool frontEnd) {
        this.service = service; this.frontEnd = frontEnd;
    }

    public void register(Map<String, OperationDefinition> operations) {
        add(operations,"list_projects",OperationDefinition.Effect.READ,false,(c,a) ->
            Json.map("items",service.registry().project()==null?List.of():List.of(projectInfo()),"has_more",false,"next_cursor",null));
        add(operations,"get_project_info",OperationDefinition.Effect.READ,false,(c,a) -> { c.registry().requireProject(a); return projectInfo(); });
        add(operations,"list_project_files",OperationDefinition.Effect.READ,false,this::listFiles);
        add(operations,"list_programs",OperationDefinition.Effect.READ,false,(c,a) -> {
            if (a.get("project_id")!=null) c.registry().requireProject(a);
            List<Map<String,Object>> items = c.registry().entries().stream().map(c.registry()::info).toList();
            return page(c,a,items,"list_programs");
        });
        operations.put("get_program_info",OperationDefinition.liveRead("get_program_info",(c,a)->c.registry().info(c.entry())));
        add(operations,"open_program",OperationDefinition.Effect.SESSION,false,this::openProgram);
        add(operations,"close_program",OperationDefinition.Effect.SESSION,false,(c,a)->c.registry().releaseOwnership(
            Arguments.string(a,"program_id"),Arguments.bool(a,"discard_changes",false),service.readOnly()));
        operations.put("save_program",new OperationDefinition("save_program",OperationDefinition.Effect.SAVE,true,false,(c,a)-> {
            TransactionGuard.save(c.program(),Arguments.optionalString(a,"expected_revision"),c.monitor());
            return Json.map("saved",true,"saved_revision",c.entry().revision(),"project_path",c.program().getDomainFile().getPathname());
        }));
        add(operations,"create_project_folder",OperationDefinition.Effect.PROJECT_WRITE,false,(c,a)-> {
            Project project=c.registry().requireProject(a);
            DomainFolder folder=folder(project,Arguments.string(a,"path"),true);
            return Json.map("project_id",c.registry().projectId(),"path",folder.getPathname());
        });
        add(operations,"create_project",OperationDefinition.Effect.PROJECT_WRITE,false,(c,a)->openProject(c,a,true));
        add(operations,"open_project",OperationDefinition.Effect.SESSION,false,(c,a)->openProject(c,a,false));
        add(operations,"close_project",OperationDefinition.Effect.SESSION,false,(c,a)-> {
            Project project=c.registry().requireProject(a);
            c.registry().beginProjectChange();
            try {
                if(!c.registry().entries().isEmpty()) throw new ApiException("PROJECT_IN_USE","Close all programs before closing the project");
                if(!c.registry().tools().isEmpty()) throw new ApiException("PROJECT_IN_USE","Close all CodeBrowser tools before closing the project");
                if(!project.getOpenData().isEmpty() || project.getToolManager().getRunningTools().length != 0) {
                    throw new ApiException("PROJECT_IN_USE","Other Ghidra tools still hold project data; close them before closing the project");
                }
                ProjectLifecycle.close(frontEnd,project); service.setProject(null);
                return Json.map("closed",true,"project_id",a.get("project_id"));
            }
            finally { c.registry().endProjectChange(); }
        });
        add(operations,"get_import_options",OperationDefinition.Effect.READ,false,this::importOptions);
        add(operations,"import_program",OperationDefinition.Effect.PROJECT_WRITE,true,this::importProgram);
    }

    private static void add(Map<String,OperationDefinition> operations,String name,OperationDefinition.Effect effect,
            boolean async,OperationDefinition.Handler handler) {
        operations.put(name,new OperationDefinition(name,effect,false,async,handler));
    }

    private Map<String,Object> projectInfo() {
        Project project=service.registry().project();
        if(project==null) throw new ApiException("PROJECT_NOT_FOUND","No project open");
        return Json.map("project_id",service.registry().projectId(),"name",project.getName(),
            "location",project.getProjectLocator().getLocation(),"read_only",service.readOnly(),
            "open_program_count",service.registry().entries().size());
    }

    private Object openProject(OperationContext context,Map<String,Object> args,boolean create) {
        if(frontEnd==null) throw new ApiException("GUI_UNAVAILABLE","Opening a project requires the application host");
        ProjectLocator locator=new ProjectLocator(Arguments.string(args,"directory"),Arguments.string(args,"name"));
        Project active=service.registry().project();
        if(active!=null) {
            if(!create&&active.getProjectLocator().equals(locator)) return projectInfo();
            throw new ApiException("PROJECT_ALREADY_OPEN","Close the current project first");
        }
        if(create&&(locator.getProjectDir().exists()||locator.getMarkerFile().exists())) {
            throw new ApiException("INVALID_ARGUMENT","Project already exists");
        }
        service.registry().beginProjectChange();
        Project opened=null;
        try {
            Project project=create?frontEnd.getProjectManager().createProject(locator,null,true):
                frontEnd.getProjectManager().openProject(locator,false,false);
            if(project==null) throw new ApiException("PROJECT_IN_USE","Ghidra could not establish the active project");
            opened=project;
            if(create&&context.job()!=null) {
                context.job().affectedFile(locator.getMarkerFile().getAbsolutePath());
                context.job().effects("partial");
            }
            GuiExecutor.call(()-> {
                if(project.getToolManager().getActiveWorkspace()==null) project.getToolManager().createWorkspace(null);
                frontEnd.setActiveProject(project);
                return null;
            });
            service.setProject(project);
            return projectInfo();
        }
        catch(Exception e) {
            if(opened!=null) {
                try { ProjectLifecycle.close(frontEnd,opened); }
                catch(RuntimeException cleanup) { e.addSuppressed(cleanup); }
                service.setProject(null);
            }
            if(e instanceof ApiException api) throw api;
            throw new ApiException(e instanceof LockException?"PROJECT_LOCKED":"INVALID_ARGUMENT",e.getMessage());
        }
        finally { service.registry().endProjectChange(); }
    }

    private Object listFiles(OperationContext context,Map<String,Object> args) throws Exception {
        Project project=context.registry().requireProject(args);
        DomainFolder folder=folder(project,Arguments.string(args,"path","/"),false);
        List<Map<String,Object>> items=new ArrayList<>();
        collect(folder,Arguments.bool(args,"recursive",false),Arguments.string(args,"query","").toLowerCase(Locale.ROOT),items,context);
        items.sort(Comparator.comparing(m->(String)m.get("path")));
        return page(context,args,items,"list_project_files");
    }

    private void collect(DomainFolder folder,boolean recursive,String query,List<Map<String,Object>> items,OperationContext context) throws Exception {
        context.monitor().checkCancelled();
        for(DomainFolder child:folder.getFolders()) {
            if(child.getName().toLowerCase(Locale.ROOT).contains(query)) items.add(Json.map("kind","folder","path",child.getPathname(),"name",child.getName()));
            if(recursive) collect(child,true,query,items,context);
        }
        for(DomainFile file:folder.getFiles()) {
            if(!file.getName().toLowerCase(Locale.ROOT).contains(query)) continue;
            String programId=context.registry().entries().stream().filter(e->file.equals(e.program().getDomainFile())).map(ProgramRegistry.Entry::id).findFirst().orElse(null);
            items.add(Json.map("kind","file","path",file.getPathname(),"name",file.getName(),"content_type",file.getContentType(),
                "program_id",programId,"version",file.getVersion(),"read_only",file.isReadOnly()));
        }
    }

    private Object openProgram(OperationContext context,Map<String,Object> args) throws Exception {
        Project project=context.registry().requireProject(args);
        String policy=Arguments.string(args,"analysis","none");
        if(!policy.equals("none")&&!policy.equals("if_needed")) throw new ApiException("INVALID_ARGUMENT","analysis must be none or if_needed");
        boolean upgrade=Arguments.bool(args,"allow_upgrade",false);
        if(upgrade&&service.readOnly()) throw new ApiException("READ_ONLY","Program upgrade is disabled");
        DomainFile file=project.getProjectData().getFile(Arguments.string(args,"project_path"));
        if(file==null) throw new ApiException("FILE_NOT_FOUND","Project file does not exist");
        if(!Program.class.isAssignableFrom(file.getDomainObjectClass())) throw new ApiException("INVALID_ARGUMENT","Project file is not a program");
        Object consumer=new Object();
        Program program;
        try { program=(Program)file.getDomainObject(consumer,upgrade,false,context.monitor()); }
        catch(VersionException e) { throw new ApiException("UPGRADE_REQUIRED",e.getMessage()); }
        ProgramRegistry.Entry entry=context.registry().adopt(program,consumer,Arguments.string(args,"project_id"));
        Map<String,Object> result=context.registry().info(entry);
        result.put("analysis",service.analysis().prepare(entry,policy));
        return result;
    }

    private Object importOptions(OperationContext context,Map<String,Object> args) throws Exception {
        File source=source(args);
        List<Map<String,Object>> loaders=new ArrayList<>();
        try(var provider=new FileByteProvider(source,null,java.nio.file.AccessMode.READ)) {
            Class<? extends Loader> requested=loaderClass(args);
            var supported=LoaderService.getSupportedLoadSpecs(provider,
                loader->requested==null||loader.getClass().equals(requested),context.monitor());
            boolean selected=args.containsKey("language_id")||args.containsKey("compiler_spec_id");
            LoadSpec chosen=selected?chooseLoadSpec(supported,args):null;
            for(var entry:supported.entrySet()) {
                if(chosen!=null&&entry.getKey()!=chosen.getLoader()) continue;
                List<Map<String,Object>> specs=new ArrayList<>();
                for(var spec:chosen==null?entry.getValue():List.of(chosen)) {
                    context.monitor().checkCancelled();
                    var pair=spec.getLanguageCompilerSpec();
                    var defaults=spec.getLoader().getDefaultOptions(provider,spec,null,false,false);
                    List<Map<String,Object>> options=new ArrayList<>();
                    if(defaults!=null) for(Option option:defaults) options.add(optionInfo(option));
                    specs.add(Json.map("language_id",pair==null?null:pair.languageID.toString(),
                        "compiler_spec_id",pair==null?null:pair.compilerSpecID.toString(),"preferred",spec.isPreferred(),
                        "options",options,"options_available",defaults!=null));
                }
                loaders.add(Json.map("loader",entry.getKey().getClass().getName(),"name",entry.getKey().getName(),"load_specs",specs));
            }
        }
        return Json.map("source_path",source.getAbsolutePath(),"loaders",loaders);
    }

    private Object importProgram(OperationContext context,Map<String,Object> args) throws Exception {
        Project project=context.registry().requireProject(args);
        String policy=Arguments.string(args,"analysis","none");
        if(!policy.equals("none")&&!policy.equals("if_needed")) throw new ApiException("INVALID_ARGUMENT","analysis must be none or if_needed");
        File source=source(args);
        String path=Arguments.string(args,"destination_path");
        if(!path.startsWith("/")||path.endsWith("/")||path.contains("..")) throw new ApiException("INVALID_ARGUMENT","destination_path must be a full project file path");
        if(project.getProjectData().getFile(path)!=null) throw new ApiException("INVALID_ARGUMENT","Destination already exists");
        int slash=path.lastIndexOf('/');
        String folderPath=path.substring(0,slash); if(folderPath.isEmpty()) folderPath="/";
        MessageLog log=new MessageLog();
        try(var provider=new FileByteProvider(source,null,java.nio.file.AccessMode.READ)) {
            Class<? extends Loader> requested=loaderClass(args);
            var supported=LoaderService.getSupportedLoadSpecs(provider,
                loader->requested==null||loader.getClass().equals(requested),context.monitor());
            LoadSpec spec=chooseLoadSpec(supported,args);
            Map<String,String> options=validatedOptions(provider,spec,Arguments.object(args,"options"));
            context.monitor().checkCancelled();
            var builder=ProgramLoader.builder().source(provider).project(project).projectFolderPath(folderPath)
                .name(path.substring(slash+1)).monitor(context.monitor()).log(log).loaders(spec.getLoader().getClass());
            var pair=spec.getLanguageCompilerSpec();
            if(pair!=null) builder.language(pair.languageID).compiler(pair.compilerSpecID);
            options.forEach(builder::addLoaderArg);
            folder(project,folderPath,true);
            try(var loaded=builder.load()) {
                context.monitor().checkCancelled();
                context.registry().requireProject(args);
                loaded.save(context.monitor());
                if (context.job()!=null) { context.job().affectedFile(path); context.job().effects("partial"); }
                Object consumer=new Object();
                Program program=loaded.getPrimaryDomainObject(consumer);
                ProgramRegistry.Entry entry=context.registry().adopt(program,consumer,Arguments.string(args,"project_id"));
                if (context.job()!=null) context.job().affected(entry);
                Map<String,Object> result=context.registry().info(entry);
                result.put("import_log",log.toString());
                result.put("loader",spec.getLoader().getClass().getName());
                result.put("applied_options",options);
                result.put("analysis",service.analysis().prepare(entry,policy));
                return result;
            }
        }
    }

    private static Class<? extends Loader> loaderClass(Map<String,Object> args) {
        String name=Arguments.optionalString(args,"loader");
        if(name==null) return null;
        var matches=LoaderService.getAllLoaders().stream().filter(loader->loader.getClass().getName().equals(name)||
            loader.getClass().getSimpleName().equals(name)).toList();
        if(matches.size()!=1) throw new ApiException("INVALID_ARGUMENT","Unknown or ambiguous import loader",Map.of("loader",name));
        return matches.getFirst().getClass();
    }

    private static LoadSpec chooseLoadSpec(ghidra.app.util.opinion.LoaderMap supported,Map<String,Object> args) {
        String language=Arguments.optionalString(args,"language_id");
        String compiler=Arguments.optionalString(args,"compiler_spec_id");
        try {
            LoadSpecChooser chooser=language!=null?
                new LcsHintLoadSpecChooser(new LanguageID(language),compiler==null?null:new CompilerSpecID(compiler)):
                compiler!=null?new CsHintLoadSpecChooser(compiler):LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED;
            LoadSpec spec=chooser.choose(supported);
            if(spec==null) throw new ApiException("INVALID_ARGUMENT","No matching import specification; raw binaries require language_id");
            var pair=spec.getLanguageCompilerSpec();
            if(pair!=null) DefaultLanguageService.getLanguageService().getLanguage(pair.languageID).getCompilerSpecByID(pair.compilerSpecID);
            return spec;
        }
        catch(LanguageNotFoundException|ghidra.program.model.lang.CompilerSpecNotFoundException error) {
            throw new ApiException("INVALID_ARGUMENT","Unknown language or compiler specification",Map.of("reason",error.getMessage()));
        }
    }

    private static Map<String,Object> optionInfo(Option option) {
        Class<?> type=option.getValueClass();
        Object value=option.getValue();
        String kind=type==Boolean.class?"boolean":type==Integer.class||type==Long.class||type==Short.class||type==Byte.class?
            "integer":type==Double.class||type==Float.class?"number":"string";
        Object safe=value==null||value instanceof String||value instanceof Boolean||value instanceof Integer||
            value instanceof Long||value instanceof Short||value instanceof Byte||value instanceof Double||value instanceof Float?
            value:value.toString();
        return Json.map("arg",option.getArg(),"name",option.getName(),"group",option.getGroup(),
            "description",option.getDescription(),"java_type",type.getName(),"value_type",kind,
            "format",HexLong.class.isAssignableFrom(type)?"hexadecimal":Address.class.isAssignableFrom(type)?"address":null,
            "default",safe,"configurable",option.getArg()!=null,"hidden",option.isHidden());
    }

    private static Map<String,String> validatedOptions(ByteProvider provider,LoadSpec spec,Map<String,Object> values) {
        List<Option> defaults=spec.getLoader().getDefaultOptions(provider,spec,null,false,false);
        if(defaults==null) throw new ApiException("INVALID_ARGUMENT","Selected loader does not provide import options");
        AddressFactory addresses=null;
        var pair=spec.getLanguageCompilerSpec();
        try {
            if(pair!=null) addresses=DefaultLanguageService.getLanguageService().getLanguage(pair.languageID).getAddressFactory();
        }
        catch(LanguageNotFoundException error) {
            throw new ApiException("INVALID_ARGUMENT","Unknown import language");
        }
        Map<String,Option> byArgument=new LinkedHashMap<>();
        for(Option option:defaults) {
            if(option.getArg()!=null) byArgument.put(option.getArg().toLowerCase(Locale.ROOT),option);
            // Raw Binary's importer supplies address zero when its GUI-only default is null.
            if(spec.getLoader() instanceof BinaryLoader&&option.getName().equals(BinaryLoader.OPTION_NAME_BASE_ADDR)&&
                    option.getValue()==null&&addresses!=null) option.setValue(addresses.getDefaultAddressSpace().getAddress(0));
        }
        Map<String,String> applied=new LinkedHashMap<>();
        for(var entry:values.entrySet()) {
            Option option=byArgument.get(entry.getKey().toLowerCase(Locale.ROOT));
            if(option==null) throw new ApiException("INVALID_ARGUMENT","Unknown loader option",
                Json.map("option",entry.getKey(),"loader",spec.getLoader().getClass().getName(),"accepted_arguments",byArgument.keySet()));
            if(applied.containsKey(option.getArg())) throw new ApiException("INVALID_ARGUMENT","Duplicate loader option",Map.of("option",entry.getKey()));
            String text=optionArgument(option,entry.getValue());
            boolean parsed;
            try { parsed=option.parseAndSetValueByType(text,addresses); }
            catch(RuntimeException error) { parsed=false; }
            if(!parsed) throw new ApiException("INVALID_ARGUMENT","Invalid loader option value",
                Json.map("option",option.getArg(),"value",entry.getValue(),"java_type",option.getValueClass().getName()));
            applied.put(option.getArg(),text);
        }
        String error=spec.getLoader().validateOptions(provider,spec,defaults,null);
        if(error!=null) throw new ApiException("INVALID_ARGUMENT","Invalid import options",Map.of("reason",error));
        return applied;
    }

    private static String optionArgument(Option option,Object value) {
        if(value instanceof String text) return text;
        if(value instanceof Boolean&&option.getValueClass()==Boolean.class) return value.toString();
        Class<?> type=option.getValueClass();
        if(value instanceof Number&&(Number.class.isAssignableFrom(type)||type==HexLong.class)) {
            try {
                var number=new java.math.BigDecimal(value.toString());
                if(type==HexLong.class) return "0x"+Long.toHexString(number.toBigIntegerExact().longValueExact());
                if(type==Double.class||type==Float.class) return number.toPlainString();
                return number.toBigIntegerExact().toString();
            }
            catch(NumberFormatException|ArithmeticException error) {
                throw new ApiException("INVALID_ARGUMENT","Invalid numeric loader option",Map.of("option",option.getArg()));
            }
        }
        throw new ApiException("INVALID_ARGUMENT","Loader option requires a compatible scalar value",
            Map.of("option",option.getArg(),"java_type",type.getName()));
    }

    private static File source(Map<String,Object> args) {
        File file=new File(Arguments.string(args,"source_path"));
        if(!file.isFile()) throw new ApiException("FILE_NOT_FOUND","Source file does not exist");
        return file;
    }

    private static DomainFolder folder(Project project,String path,boolean create) throws Exception {
        if(!path.startsWith("/")||path.contains("..")) throw new ApiException("INVALID_ARGUMENT","Expected absolute project path");
        DomainFolder folder=project.getProjectData().getRootFolder();
        for(String component:path.split("/")) {
            if(component.isEmpty()) continue;
            DomainFolder child=folder.getFolder(component);
            if(child==null) {
                if(!create) throw new ApiException("FILE_NOT_FOUND","Project folder does not exist");
                child=folder.createFolder(component);
            }
            folder=child;
        }
        return folder;
    }

    private static Map<String,Object> page(OperationContext context,Map<String,Object> args,
            List<Map<String,Object>> items,String operation) {
        int limit=Arguments.integer(args,"limit",100,1,1000);
        int offset=0;
        String cursor=Arguments.optionalString(args,"cursor");
        Map<String,Object> query=new TreeMap<>(args);
        query.remove("cursor"); query.remove("limit"); query.remove("timeout_ms");
        String identity=Json.GSON.toJson(Json.map("operation",operation,"project_id",context.registry().projectId(),
            "query",query,"items",items));
        String fingerprint;
        try {
            fingerprint=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(identity.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        }
        catch(java.security.NoSuchAlgorithmException error) { throw new IllegalStateException(error); }
        if(cursor!=null) {
            String[] parts=cursor.split(":");
            if(parts.length!=2||!parts[0].equals(fingerprint)) throw new ApiException("CURSOR_STALE","List changed since previous page");
            try { offset=Integer.parseInt(parts[1]); }
            catch(NumberFormatException e) { throw new ApiException("INVALID_ARGUMENT","Invalid cursor"); }
            if(offset<0||offset>items.size()) throw new ApiException("INVALID_ARGUMENT","Invalid cursor offset");
        }
        int end=Math.min(items.size(),offset+limit);
        return Json.map("items",items.subList(offset,end),"has_more",end<items.size(),"next_cursor",end<items.size()?fingerprint+":"+end:null);
    }

    private final BridgeService service;
    private final FrontEndTool frontEnd;
}
