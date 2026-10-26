import com.lauriewired.mcp.BridgeService;
import com.lauriewired.mcp.Json;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class ProjectSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        Path raw=Files.createTempFile("ghidramcp-project-smoke-",".bin");
        byte[] content=new byte[32];
        for(int index=0;index<content.length;index++) content[index]=(byte)index;
        Files.write(raw,content);
        try(BridgeService bridge=new BridgeService(null,false)) {
            service=bridge;
            service.setProject(state.getProject());
            projectId=service.registry().projectId();
            DomainFile original=firstProgram(state.getProject().getProjectData().getRootFolder());
            Map<String,Object> opened=call("open_program",Json.map("project_id",projectId,"project_path",original.getPathname()));
            String source=(String)opened.get("executable_path");
            String language=(String)opened.get("language_id");
            String compiler=(String)opened.get("compiler_spec_id");
            String elfLoader="ghidra.app.util.opinion.ElfLoader";
            String binaryLoader="ghidra.app.util.opinion.BinaryLoader";

            Map<String,Object> discovery=call("get_import_options",Map.of("source_path",source));
            require(((List<?>)discovery.get("loaders")).size()>=2,"Expected format and Raw Binary loaders");
            Map<String,Object> filtered=call("get_import_options",Map.of("source_path",source,"loader",elfLoader,
                "language_id",language,"compiler_spec_id",compiler));
            List<Map<String,Object>> loaders=rows(filtered,"loaders");
            require(loaders.size()==1&&loaders.getFirst().get("loader").equals(elfLoader),"Loader filter failed");
            List<Map<String,Object>> specs=rows(loaders.getFirst(),"load_specs");
            require(specs.size()==1&&specs.getFirst().get("language_id").equals(language),"Language filter failed");
            List<Map<String,Object>> options=rows(specs.getFirst(),"options");
            require(!options.isEmpty(),"Loader options missing");
            for(var option:options) {
                require(option.containsKey("arg")&&option.containsKey("java_type")&&option.containsKey("description"),"Option metadata incomplete");
                Object value=option.get("default");
                require(value==null||value instanceof String||value instanceof Number||value instanceof Boolean,"Default leaked an arbitrary Java object");
            }
            Map<String,Object> bool=options.stream().filter(option->"boolean".equals(option.get("value_type"))&&option.get("arg")!=null)
                .findFirst().orElseThrow();
            String boolArg=(String)bool.get("arg");
            invalid(source,"/RejectedUnknown/Library",Map.of("options",Map.of("-loader-unknown-option",true)));
            invalid(source,"/RejectedBool/Library",Map.of("loader",elfLoader,"options",Map.of(boolArg,"not-a-boolean")));
            invalid(source,"/RejectedObject/Library",Map.of("loader",elfLoader,"options",Map.of(boolArg,Map.of("nested",true))));
            invalid(source,"/RejectedDuplicate/Library",Map.of("loader",elfLoader,"options",Map.of(boolArg,true,boolArg.toUpperCase(java.util.Locale.ROOT),false)));
            invalid(source,"/RejectedLoader/Library",Map.of("loader","NoSuchLoader"));
            invalid(source,"/RejectedLanguage/Library",Map.of("loader",elfLoader,"language_id","NoSuchLanguage"));
            invalid(source,"/RejectedCompiler/Library",Map.of("loader",elfLoader,"language_id",language,"compiler_spec_id","NoSuchCompiler"));

            Map<String,Object> imported=call("import_program",arguments(source,"/McpProject/Elf",Map.of("loader",elfLoader,
                "options",Map.of(boolArg,false))));
            require(imported.get("project_path").equals("/McpProject/Elf"),"ELF saved to wrong project path");
            require(((Map<?,?>)imported.get("applied_options")).get(boolArg).equals("false"),"Validated option was not applied");
            require(state.getProject().getProjectData().getFile("/McpProject/Elf")!=null,"ELF import was not saved");

            Map<String,Object> rawOptions=call("get_import_options",Map.of("source_path",raw.toString(),"loader",binaryLoader,
                "language_id",language,"compiler_spec_id",compiler));
            List<Map<String,Object>> rawSpec=rows(rows(rawOptions,"loaders").getFirst(),"load_specs");
            require(rows(rawSpec.getFirst(),"options").stream().anyMatch(option->"hexadecimal".equals(option.get("format"))),"Hexadecimal option metadata missing");
            invalid(raw.toString(),"/RejectedRawLanguage/Library",Map.of("loader",binaryLoader));
            invalid(raw.toString(),"/RejectedFraction/Library",Map.of("loader",binaryLoader,"language_id",language,
                "options",Map.of("-loader-length",1.5)));
            invalid(raw.toString(),"/RejectedRawRange/Library",Map.of("loader",binaryLoader,"language_id",language,
                "options",Map.of("-loader-fileOffset","0x1000")));
            Map<String,Object> rawDefault=call("import_program",arguments(raw.toString(),"/McpProject/RawDefault",
                Map.of("loader",binaryLoader,"language_id",language,"compiler_spec_id",compiler)));
            var defaultMemory=service.registry().entry((String)rawDefault.get("program_id")).program().getMemory();
            require(defaultMemory.getMinAddress().getOffset()==0&&defaultMemory.getSize()==content.length,"Raw default mapping changed");
            Map<String,Object> rawCustom=call("import_program",arguments(raw.toString(),"/McpProject/RawCustom",
                Map.of("loader",binaryLoader,"language_id",language,"compiler_spec_id",compiler,"options",
                    Map.of("-loader-baseAddr","0x1000","-loader-fileOffset",4,"-loader-length",8,"-loader-blockName","MCP_RAW"))));
            var memory=service.registry().entry((String)rawCustom.get("program_id")).program().getMemory();
            var block=memory.getBlock("MCP_RAW");
            require(block!=null&&block.getStart().getOffset()==0x1000&&block.getSize()==8,"Raw options did not affect the loaded block");
            byte[] actual=new byte[8];
            memory.getBytes(block.getStart(),actual);
            require(java.util.Arrays.equals(actual,java.util.Arrays.copyOfRange(content,4,12)),"Raw numeric offsets were not interpreted correctly");

            Map<String,Object> page=call("list_project_files",Map.of("project_id",projectId,"recursive",true,"limit",1));
            require(page.get("next_cursor")!=null,"Expected project pagination");
            Map<String,Object> next=call("list_project_files",Map.of("project_id",projectId,"recursive",true,"limit",1,"cursor",page.get("next_cursor")));
            require(!rows(page,"items").equals(rows(next,"items")),"Project cursor repeated an item");
            error("list_project_files",Map.of("project_id",projectId,"recursive",true,"query","","limit",1,"cursor",page.get("next_cursor")),"CURSOR_STALE");
            call("create_project_folder",Map.of("project_id",projectId,"path","/McpCursorChange"));
            error("list_project_files",Map.of("project_id",projectId,"recursive",true,"limit",1,"cursor",page.get("next_cursor")),"CURSOR_STALE");
            println("PROJECT_SMOKE_OK "+assertions+" assertions");
        }
        finally { Files.deleteIfExists(raw); }
    }

    private Map<String,Object> arguments(String source,String destination,Map<String,Object> extra) {
        var result=Json.map("project_id",projectId,"source_path",source,"destination_path",destination);
        result.putAll(extra);
        return result;
    }

    private void invalid(String source,String destination,Map<String,Object> extra) throws Exception {
        error("import_program",arguments(source,destination,extra),"INVALID_ARGUMENT");
        String parent=destination.substring(0,destination.lastIndexOf('/'));
        require(state.getProject().getProjectData().getFolder(parent)==null,"Invalid import created project folders: "+parent);
    }

    private DomainFile firstProgram(DomainFolder folder) throws Exception {
        for(var file:folder.getFiles()) if(file.getContentType().equals("Program")) return file;
        for(var child:folder.getFolders()) {
            var found=firstProgram(child);
            if(found!=null) return found;
        }
        return null;
    }

    private Map<String,Object> outcome(String operation,Map<String,Object> args) throws Exception {
        var job=service.submit(UUID.randomUUID().toString(),operation,args,60000);
        while(!job.terminal()) { monitor.checkCancelled(); job.await(1000); }
        return job.snapshot();
    }

    @SuppressWarnings("unchecked")
    private Map<String,Object> call(String operation,Map<String,Object> args) throws Exception {
        var result=outcome(operation,args);
        require(result.get("state").equals("succeeded"),operation+": "+Json.GSON.toJson(result));
        return (Map<String,Object>)((Map<String,Object>)result.get("result")).get("data");
    }

    private void error(String operation,Map<String,Object> args,String code) throws Exception {
        var result=outcome(operation,args);
        require(result.get("error") instanceof Map<?,?>&&code.equals(((Map<?,?>)result.get("error")).get("code")),
            operation+" expected "+code+": "+Json.GSON.toJson(result));
        require(result.get("effects").equals("none"),"Rejected operation reported side effects");
    }

    @SuppressWarnings("unchecked")
    private List<Map<String,Object>> rows(Map<String,Object> value,String key) { return (List<Map<String,Object>>)value.get(key); }

    private void require(boolean condition,String message) {
        assertions++;
        if(!condition) throw new AssertionError(message);
    }

    private BridgeService service;
    private String projectId;
    private int assertions;
}
