package com.lauriewired.mcp;

import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyException;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public final class MemoryOperations {
    private MemoryOperations() {}

    public static void register(Map<String, OperationDefinition> operations) {
        operations.put("read_memory", OperationDefinition.read("read_memory", MemoryOperations::read));
        operations.put("disassemble_range", OperationDefinition.read("disassemble_range", MemoryOperations::range));
        operations.put("disassemble_function", OperationDefinition.read("disassemble_function", MemoryOperations::function));
        operations.put("list_memory_regions", OperationDefinition.read("list_memory_regions", MemoryOperations::regions));
        operations.put("search_memory", OperationDefinition.read("search_memory", MemoryOperations::search));
        operations.put("address_to_file_offset", OperationDefinition.read("address_to_file_offset", MemoryOperations::toFileOffset));
        operations.put("file_offset_to_address", OperationDefinition.read("file_offset_to_address", MemoryOperations::toAddress));
        operations.put("assemble_instruction", OperationDefinition.read("assemble_instruction", MemoryOperations::assemble));
    }

    private static Object read(OperationContext context, Map<String, Object> args) throws Exception {
        Address start = Arguments.address(context.program(), args, "address");
        int length = Arguments.integer(args, "length", -1, 1, 65536);
        if (length < 1) throw new ApiException("INVALID_ARGUMENT", "length is required");
        ReadSupport.lastAddress(start, length);
        boolean partial = Arguments.bool(args, "allow_partial", false);
        List<Map<String, Object>> chunks = new ArrayList<>();
        List<Map<String, Object>> gaps = new ArrayList<>();
        ByteArrayOutputStream current = new ByteArrayOutputStream();
        Address chunkStart = start;
        Address gapStart = null;
        int gapLength = 0;
        int returned = 0;
        for (int index = 0; index < length; index++) {
            context.monitor().checkCancelled();
            Address address = start.add(index);
            try {
                byte value = context.program().getMemory().getByte(address);
                if (gapStart != null) {
                    gaps.add(ReadSupport.map("address", ReadSupport.address(gapStart), "length", gapLength));
                    gapStart = null;
                    gapLength = 0;
                    chunkStart = address;
                }
                current.write(value);
                returned++;
            }
            catch (MemoryAccessException e) {
                if (!partial) {
                    throw new ApiException("MEMORY_UNAVAILABLE", "Requested range contains unavailable memory",
                        ReadSupport.map("address", ReadSupport.address(address), "requested_length", length));
                }
                if (current.size() > 0) {
                    chunks.add(ReadSupport.map("address", ReadSupport.address(chunkStart),
                        "bytes_hex", ReadSupport.bytes(current.toByteArray()), "length", current.size()));
                    current.reset();
                }
                if (gapStart == null) {
                    gapStart = address;
                }
                gapLength++;
            }
        }
        if (current.size() > 0) {
            chunks.add(ReadSupport.map("address", ReadSupport.address(chunkStart),
                "bytes_hex", ReadSupport.bytes(current.toByteArray()), "length", current.size()));
        }
        if (gapStart != null) {
            gaps.add(ReadSupport.map("address", ReadSupport.address(gapStart), "length", gapLength));
        }
        return ReadSupport.map("address", ReadSupport.address(start), "requested_length", length,
            "returned_length", returned, "bytes_hex", gaps.isEmpty() ? chunks.getFirst().get("bytes_hex") : null,
            "chunks", chunks, "gaps", gaps);
    }

    private static Object range(OperationContext context, Map<String, Object> args) throws Exception {
        Program program = context.program();
        Address requested = Arguments.address(program, args, "address");
        int length = Arguments.integer(args, "byte_length", 256, 1, 65536);
        Address last = ReadSupport.lastAddress(requested, length);
        String mode = Arguments.string(args, "start_mode", "exact");
        if (!List.of("exact", "containing").contains(mode)) {
            throw new ApiException("INVALID_ARGUMENT", "start_mode must be exact or containing");
        }
        boolean pseudo = Arguments.bool(args, "decode_undefined", false);
        Instruction containing = program.getListing().getInstructionContaining(requested);
        Address start = requested;
        if (containing != null && !containing.getAddress().equals(requested)) {
            if (mode.equals("exact")) {
                throw new ApiException("ADDRESS_INVALID", "Requested address is inside an instruction",
                    Map.of("instruction_address", ReadSupport.address(containing.getAddress())));
            }
            start = containing.getAddress();
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        List<Map<String, Object>> gaps = new ArrayList<>();
        PseudoDisassembler decoder = pseudo ? new PseudoDisassembler(program) : null;
        Address current = start;
        Address gapStart = null;
        long gapLength = 0;
        while (current != null && current.compareTo(last) <= 0) {
            context.monitor().checkCancelled();
            Instruction instruction = program.getListing().getInstructionAt(current);
            String source = "defined";
            if (instruction == null && decoder != null) {
                try {
                    instruction = decoder.disassemble(current);
                    source = "pseudo";
                }
                catch (ghidra.program.model.lang.InsufficientBytesException |
                       ghidra.program.model.lang.UnknownInstructionException |
                       ghidra.program.model.lang.UnknownContextException e) {
                    instruction = null;
                }
            }
            if (instruction == null) {
                if (gapStart == null) {
                    gapStart = current;
                }
                gapLength++;
                current = current.next();
                continue;
            }
            if (gapStart != null) {
                gaps.add(ReadSupport.map("address", ReadSupport.address(gapStart), "length", gapLength));
                gapStart = null;
                gapLength = 0;
            }
            rows.add(ReadSupport.instruction(instruction, source));
            current = instruction.getMaxAddress().next();
        }
        if (gapStart != null) {
            gaps.add(ReadSupport.map("address", ReadSupport.address(gapStart), "length", gapLength));
        }
        var page = Pages.page(context, args, rows, "disassemble_range");
        page.put("requested_address", ReadSupport.address(requested));
        page.put("effective_start", ReadSupport.address(start));
        page.put("end", ReadSupport.address(last.next()));
        page.put("gaps", gaps);
        return page;
    }

    private static Object function(OperationContext context, Map<String, Object> args) throws Exception {
        var function = ReadSupport.function(context, args);
        List<Map<String, Object>> rows = new ArrayList<>();
        for (var instruction : context.program().getListing().getInstructions(function.getBody(), true)) {
            context.monitor().checkCancelled();
            rows.add(ReadSupport.instruction(instruction, "defined"));
        }
        var page = Pages.page(context, args, rows, "disassemble_function");
        page.put("function_address", ReadSupport.address(function.getEntryPoint()));
        return page;
    }

    private static Object regions(OperationContext context, Map<String, Object> args) throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        var blocks = context.program().getMemory().getBlocks();
        Arrays.sort(blocks, Comparator.comparing(block -> block.getStart()));
        for (var block : blocks) {
            context.monitor().checkCancelled();
            List<Map<String, Object>> sources = new ArrayList<>();
            for (var info : block.getSourceInfos()) {
                var source = ReadSupport.map("start", ReadSupport.address(info.getMinAddress()),
                    "length", info.getLength(), "description", info.getDescription(), "mapped", info.getMappedRange().isPresent());
                if (info.getFileBytes().isPresent()) {
                    FileBytes file = info.getFileBytes().get();
                    source.putAll(sourceFile(context.program(), file));
                    source.put("file_offset", info.getFileBytesOffset() < 0 ? null :
                        ReadSupport.hex(file.getFileOffset() + info.getFileBytesOffset()));
                }
                sources.add(source);
            }
            rows.add(ReadSupport.map("name", block.getName(), "start", ReadSupport.address(block.getStart()),
                "end", ReadSupport.address(block.getEnd().next()), "length", block.getSize(),
                "read", block.isRead(), "write", block.isWrite(), "execute", block.isExecute(),
                "initialized", block.isInitialized(), "overlay", block.isOverlay(),
                "type", block.getType().toString(), "sources", sources));
        }
        return Pages.page(context, args, rows, "list_memory_regions");
    }

    private static Object toFileOffset(OperationContext context, Map<String, Object> args) {
        Address address = Arguments.address(context.program(), args, "address");
        var block = context.program().getMemory().getBlock(address);
        if (block == null) {
            throw new ApiException("MEMORY_UNAVAILABLE", "Address has no memory block");
        }
        List<Map<String, Object>> mappings = new ArrayList<>();
        boolean unknown = false;
        for (var info : block.getSourceInfos()) {
            if (!info.contains(address)) {
                continue;
            }
            long offset = info.getFileBytesOffset(address);
            if (info.getFileBytes().isPresent() && offset >= 0) {
                FileBytes file = info.getFileBytes().get();
                var row = sourceFile(context.program(), file);
                row.put("file_offset", ReadSupport.hex(file.getFileOffset() + offset));
                row.put("file_bytes_offset", ReadSupport.hex(offset));
                mappings.add(row);
            }
            else if (info.getMappedRange().isPresent() || info.getFileBytes().isPresent()) {
                unknown = true;
            }
        }
        return ReadSupport.map("address", ReadSupport.address(address), "status",
            mappings.isEmpty() ? unknown ? "unknown" : "unbacked" : "mapped", "mappings", mappings);
    }

    private static Object toAddress(OperationContext context, Map<String, Object> args) {
        String id = Arguments.string(args, "source_file_id");
        FileBytes file = null;
        for (FileBytes candidate : context.program().getMemory().getAllFileBytes()) {
            if (sourceFile(context.program(), candidate).get("source_file_id").equals(id)) {
                file = candidate;
                break;
            }
        }
        if (file == null) {
            throw new ApiException("FILE_NOT_FOUND", "Unknown source_file_id");
        }
        String offsetText = Arguments.string(args, "file_offset");
        long offset;
        try {
            offset = offsetText.startsWith("0x") ? Long.parseUnsignedLong(offsetText.substring(2), 16) : Long.parseLong(offsetText);
        }
        catch (NumberFormatException e) {
            throw new ApiException("INVALID_ARGUMENT", "Invalid file_offset");
        }
        if (offset < 0 || offset < file.getFileOffset() || offset - file.getFileOffset() >= file.getSize()) {
            throw new ApiException("INVALID_ARGUMENT", "file_offset is outside the stored source file range");
        }
        long relative = offset - file.getFileOffset();
        List<Map<String, Object>> mappings = new ArrayList<>();
        for (Address address : context.program().getMemory().locateAddressesForFileBytesOffset(file, relative)) {
            mappings.add(ReadSupport.map("address", ReadSupport.address(address)));
        }
        mappings.sort(Comparator.comparing(row -> (String) row.get("address"), ReadSupport::compareAddresses));
        boolean unknown = false;
        for (var block : context.program().getMemory().getBlocks()) {
            for (var info : block.getSourceInfos()) {
                if (info.getFileBytes().isPresent() && info.getFileBytes().get().equals(file) && info.getFileBytesOffset() < 0) {
                    unknown = true;
                }
            }
        }
        return ReadSupport.map("source_file_id", id, "file_offset", ReadSupport.hex(offset),
            "status", mappings.isEmpty() ? unknown ? "unknown" : "unmapped" : "mapped", "mappings", mappings);
    }

    private static Map<String, Object> sourceFile(Program program, FileBytes file) {
        int index = program.getMemory().getAllFileBytes().indexOf(file);
        return ReadSupport.map("source_file_id", "filebytes:" + ProgramRegistry.revision(program) + ":" + index,
            "source_filename", file.getFilename(),
            "stored_file_offset", ReadSupport.hex(file.getFileOffset()), "stored_length", file.getSize());
    }

    private static Object search(OperationContext context, Map<String, Object> args) throws Exception {
        byte[] pattern = ReadSupport.parseBytes(Arguments.string(args, "pattern"), "pattern");
        if (pattern.length > 4096) {
            throw new ApiException("INVALID_ARGUMENT", "pattern exceeds 4096 bytes");
        }
        String maskText = Arguments.optionalString(args, "mask");
        byte[] mask = maskText == null ? null : ReadSupport.parseBytes(maskText, "mask");
        if (mask != null && mask.length != pattern.length) {
            throw new ApiException("INVALID_ARGUMENT", "mask and pattern lengths differ");
        }
        Address start = args.get("start") == null ? context.program().getMinAddress() :
            Arguments.address(context.program(), args, "start");
        Address end = args.get("end") == null ? context.program().getMaxAddress() :
            Arguments.address(context.program(), args, "end").previous();
        if (start == null || end == null || start.compareTo(end) > 0) {
            throw new ApiException("INVALID_ARGUMENT", "Invalid search range");
        }
        Pages.Window page = Pages.window(context, args, "search_memory");
        Address current = start;
        while (current != null && current.compareTo(end) <= 0) {
            context.monitor().checkCancelled();
            Address match = context.program().getMemory().findBytes(current, end, pattern, mask, true, context.monitor());
            if (match == null) {
                break;
            }
            if (ReadSupport.lastAddress(match, pattern.length).compareTo(end) > 0) break;
            if (page.add(ReadSupport.map("address", ReadSupport.address(match), "length", pattern.length))) break;
            current = match.next();
        }
        return page.result();
    }

    private static Object assemble(OperationContext context, Map<String, Object> args) throws Exception {
        Address address = Arguments.address(context.program(), args, "address");
        context.monitor().checkCancelled();
        var assembler = Assemblers.getAssembler(context.program());
        byte[] bytes;
        try {
            bytes = assembler.assembleLine(address, Arguments.string(args, "instruction"));
        }
        catch (AssemblyException error) {
            throw new ApiException("INVALID_ARGUMENT", "Instruction does not match the language's assembly syntax or context",
                Map.of("assembly_error", error.getMessage()));
        }
        context.monitor().checkCancelled();
        return ReadSupport.map("address", ReadSupport.address(address), "bytes_hex", ReadSupport.bytes(bytes), "length", bytes.length);
    }
}
