package com.lauriewired.mcp;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public final class MutationOperations {
    private MutationOperations() {}

    public static void register(Map<String, OperationDefinition> operations) {
        add(operations, "rename_function", MutationOperations::renameFunction);
        add(operations, "set_function_prototype", MutationOperations::setFunctionPrototype);
        add(operations, "rename_variable", MutationOperations::renameVariable);
        add(operations, "set_local_variable_type", MutationOperations::setVariableType);
        add(operations, "create_function", MutationOperations::createFunction);
        add(operations, "delete_function", MutationOperations::deleteFunction);
        add(operations, "define_code", MutationOperations::defineCode);
        add(operations, "create_label", MutationOperations::createLabel);
        add(operations, "rename_label", MutationOperations::renameLabel);
        add(operations, "remove_label", MutationOperations::removeLabel);
        add(operations, "rename_data", MutationOperations::renameData);
        add(operations, "set_comment", MutationOperations::setComment);
        add(operations, "set_bookmark", MutationOperations::setBookmark);
        add(operations, "patch_bytes", MutationOperations::patchBytes);
        add(operations, "create_struct", (context, args) -> createType(context, args, "struct"));
        add(operations, "create_union", (context, args) -> createType(context, args, "union"));
        add(operations, "create_enum", (context, args) -> createType(context, args, "enum"));
        add(operations, "create_typedef", (context, args) -> createType(context, args, "typedef"));
        add(operations, "create_pointer", MutationOperations::createPointer);
        add(operations, "add_struct_field", MutationOperations::addStructField);
        add(operations, "edit_struct_field", MutationOperations::editStructField);
        add(operations, "delete_struct_field", MutationOperations::deleteStructField);
        add(operations, "rename_struct", MutationOperations::renameStruct);
        add(operations, "delete_struct", MutationOperations::deleteStruct);
        add(operations, "add_union_field", MutationOperations::addUnionField);
        add(operations, "add_enum_value", MutationOperations::addEnumValue);
        add(operations, "delete_enum_value", MutationOperations::deleteEnumValue);
        add(operations, "apply_data_type", MutationOperations::applyDataType);
        add(operations, "create_array", MutationOperations::createArray);
        add(operations, "clear_data", MutationOperations::clearData);
        add(operations, "set_import_library", MutationOperations::setImportLibrary);
        add(operations, "set_external_library_path", MutationOperations::setExternalLibraryPath);
    }

    private static void add(Map<String, OperationDefinition> operations, String name, Handler handler) {
        operations.put(name, OperationDefinition.write(name, (context, args) -> {
            try {
                context.monitor().checkCancelled();
                return handler.execute(context, args);
            }
            catch (ApiException | CancelledException exception) {
                throw exception;
            }
            catch (DuplicateNameException exception) {
                throw new ApiException("NAME_CONFLICT", exception.getMessage());
            }
            catch (InvalidInputException | InvalidNameException | ParseException |
                    IllegalArgumentException | IndexOutOfBoundsException exception) {
                throw new ApiException("INVALID_ARGUMENT", exception.getMessage());
            }
            catch (MemoryAccessException exception) {
                throw new ApiException("MEMORY_UNAVAILABLE", exception.getMessage());
            }
            catch (CodeUnitInsertionException exception) {
                throw new ApiException("DATA_CONFLICT", exception.getMessage());
            }
            catch (UnsupportedOperationException exception) {
                throw new ApiException("UNSUPPORTED_CAPABILITY", exception.getMessage());
            }
        }));
    }

    private static Object renameFunction(OperationContext context, Map<String, Object> args)
            throws Exception {
        Function function = function(context, args, "function_address");
        String name = Arguments.string(args, "new_name");
        String previous = function.getName();
        if (!previous.equals(name)) {
            function.setName(name, SourceType.USER_DEFINED);
        }
        return Map.of("function_address", address(function.getEntryPoint()),
            "previous_name", previous, "name", function.getName(), "changed", !previous.equals(name));
    }

    private static Object setFunctionPrototype(OperationContext context, Map<String, Object> args)
            throws Exception {
        Function function = function(context, args, "function_address");
        String prototype = Arguments.string(args, "prototype");
        var parser = new FunctionSignatureParser(context.program().getDataTypeManager(), null);
        var signature = parser.parse(function.getSignature(), prototype);
        var command = new ApplyFunctionSignatureCmd(function.getEntryPoint(), signature,
            SourceType.USER_DEFINED);
        if (!command.applyTo(context.program(), context.monitor())) {
            throw new ApiException("INVALID_ARGUMENT", "Cannot apply prototype: " + command.getStatusMsg());
        }
        return Map.of("function_address", address(function.getEntryPoint()),
            "prototype", function.getPrototypeString(false, false));
    }

    private static Object renameVariable(OperationContext context, Map<String, Object> args)
            throws Exception {
        return VariableSupport.update(context, function(context, args, "function_address"),
            Arguments.string(args, "variable_id"), Arguments.string(args, "new_name"), null);
    }

    private static Object setVariableType(OperationContext context, Map<String, Object> args)
            throws Exception {
        DataType type = dataType(context.program(), Arguments.string(args, "type_path"));
        fixedLength(type);
        return VariableSupport.update(context, function(context, args, "function_address"),
            Arguments.string(args, "variable_id"), null, type);
    }

    private static Object createFunction(OperationContext context, Map<String, Object> args)
            throws Exception {
        Program program = context.program();
        Address entry = Arguments.address(program, args, "address");
        requireMemory(program, entry, entry);
        if (program.getFunctionManager().getFunctionAt(entry) != null) {
            throw new ApiException("ALREADY_EXISTS", "A function already exists at " + address(entry));
        }
        String name = Arguments.optionalString(args, "name");
        var command = new CreateFunctionCmd(name, entry, null, SourceType.USER_DEFINED);
        if (!command.applyTo(program, context.monitor())) {
            throw new ApiException("INVALID_ARGUMENT", "Cannot create function: " + command.getStatusMsg());
        }
        Function function = program.getFunctionManager().getFunctionAt(entry);
        if (function == null) {
            throw new ApiException("INVALID_ARGUMENT", "Ghidra did not create a function at the requested address.");
        }
        return Map.of("function_address", address(entry), "name", function.getName());
    }

    private static Object deleteFunction(OperationContext context, Map<String, Object> args)
            throws Exception {
        Function function = function(context, args, "address");
        Address entry = function.getEntryPoint();
        if (!context.program().getFunctionManager().removeFunction(entry)) {
            throw new ApiException("INVALID_ARGUMENT", "Cannot delete function at " + address(entry));
        }
        return Map.of("function_address", address(entry), "deleted", true);
    }

    private static Object defineCode(OperationContext context, Map<String, Object> args)
            throws Exception {
        Address start = Arguments.address(context.program(), args, "address");
        int length = Arguments.integer(args, "length", 1, 1, 1_048_576);
        Address end = rangeEnd(start, length);
        requireMemory(context.program(), start, end);
        var command = new DisassembleCommand(start, new AddressSet(start, end), true);
        command.enableCodeAnalysis(false);
        if (!command.applyTo(context.program(), context.monitor())) {
            throw new ApiException("INVALID_ARGUMENT", "Cannot define code: " + command.getStatusMsg());
        }
        return Map.of("address", address(start), "requested_length", length,
            "defined_bytes", command.getDisassembledAddressSet().getNumAddresses());
    }

    private static Object createLabel(OperationContext context, Map<String, Object> args)
            throws Exception {
        Program program = context.program();
        Address target = Arguments.address(program, args, "address");
        requireMemory(program, target, target);
        Namespace namespace = namespace(program, Arguments.string(args, "namespace", ""));
        String name = Arguments.string(args, "name");
        Symbol existing = program.getSymbolTable().getSymbol(name, target, namespace);
        if (existing != null && existing.getSymbolType() != SymbolType.LABEL) {
            throw new ApiException("NAME_CONFLICT", "The requested name belongs to a non-label symbol.");
        }
        Symbol symbol = existing == null ? program.getSymbolTable().createLabel(target, name,
            namespace, SourceType.USER_DEFINED) : existing;
        return symbolResult(symbol, existing == null);
    }

    private static Object renameLabel(OperationContext context, Map<String, Object> args)
            throws Exception {
        Symbol symbol = label(context.program(), args, "old_name");
        String name = Arguments.string(args, "new_name");
        boolean changed = !symbol.getName().equals(name);
        if (changed) {
            symbol.setName(name, SourceType.USER_DEFINED);
        }
        return symbolResult(symbol, changed);
    }

    private static Object removeLabel(OperationContext context, Map<String, Object> args)
            throws Exception {
        Symbol symbol = label(context.program(), args, "name");
        Map<String, Object> result = symbolResult(symbol, true);
        if (!symbol.delete()) {
            throw new ApiException("INVALID_ARGUMENT", "Ghidra could not remove the label.");
        }
        return result;
    }

    private static Object renameData(OperationContext context, Map<String, Object> args)
            throws Exception {
        Program program = context.program();
        Address target = Arguments.address(program, args, "address");
        Data data = program.getListing().getDefinedDataAt(target);
        Symbol symbol = program.getSymbolTable().getPrimarySymbol(target);
        if (data == null || symbol == null || symbol.getSymbolType() != SymbolType.LABEL) {
            throw new ApiException("SYMBOL_NOT_FOUND", "No primary data label exists at this address.");
        }
        String name = Arguments.string(args, "new_name");
        boolean changed = !symbol.getName().equals(name);
        if (changed) {
            symbol.setName(name, SourceType.USER_DEFINED);
        }
        return symbolResult(symbol, changed);
    }

    private static Object setComment(OperationContext context, Map<String, Object> args)
            throws Exception {
        Address target = Arguments.address(context.program(), args, "address");
        requireMemory(context.program(), target, target);
        String kind = Arguments.string(args, "comment_type").toUpperCase(Locale.ROOT);
        CommentType type;
        try {
            type = CommentType.valueOf(kind);
        }
        catch (IllegalArgumentException exception) {
            throw new ApiException("INVALID_ARGUMENT", "comment_type must be plate, pre, eol, post, or repeatable.");
        }
        if (!(args.get("text") instanceof String text)) {
            throw new ApiException("INVALID_ARGUMENT", "text must be a string; an empty string deletes the comment.");
        }
        String desired = text.isEmpty() ? null : text;
        String previous = context.program().getListing().getComment(type, target);
        if (!Objects.equals(previous, desired)) {
            context.program().getListing().setComment(target, type, desired);
        }
        return Map.of("address", address(target), "comment_type", kind.toLowerCase(Locale.ROOT),
            "text", text, "changed", !Objects.equals(previous, desired));
    }

    private static Object setBookmark(OperationContext context, Map<String, Object> args)
            throws Exception {
        Address target = Arguments.address(context.program(), args, "address");
        requireMemory(context.program(), target, target);
        String type = Arguments.string(args, "type", "Note");
        String category = text(args, "category", "");
        String note = text(args, "note", "");
        var bookmark = context.program().getBookmarkManager().setBookmark(target, type, category, note);
        return Map.of("address", address(target), "type", bookmark.getTypeString(),
            "category", Objects.toString(bookmark.getCategory(), ""),
            "note", Objects.toString(bookmark.getComment(), ""));
    }

    private static Object patchBytes(OperationContext context, Map<String, Object> args)
            throws Exception {
        Address target = Arguments.address(context.program(), args, "address");
        byte[] bytes = bytes(Arguments.string(args, "bytes_hex"));
        if (bytes.length == 0 || bytes.length > 65_536) {
            throw new ApiException("INVALID_ARGUMENT", "A patch must contain between 1 and 65536 bytes.");
        }
        requireMemory(context.program(), target, rangeEnd(target, bytes.length));
        byte[] previous = new byte[bytes.length];
        if (context.program().getMemory().getBytes(target, previous) != bytes.length) {
            throw new ApiException("MEMORY_UNAVAILABLE", "Cannot read the complete patch range.");
        }
        String expected = Arguments.optionalString(args, "expected_bytes_hex");
        if (expected != null && !Arrays.equals(previous, bytes(expected))) {
            throw new ApiException("REVISION_CONFLICT", "The bytes do not match expected_bytes_hex.");
        }
        context.monitor().checkCancelled();
        if (!Arrays.equals(previous, bytes)) {
            context.program().getMemory().setBytes(target, bytes);
        }
        return Map.of("address", address(target), "length", bytes.length,
            "previous_bytes_hex", HexFormat.of().formatHex(previous),
            "bytes_hex", HexFormat.of().formatHex(bytes), "changed", !Arrays.equals(previous, bytes));
    }

    private static Object createType(OperationContext context, Map<String, Object> args, String kind)
            throws Exception {
        DataTypeManager manager = context.program().getDataTypeManager();
        String path = typePath(Arguments.string(args, "type_path"));
        if (manager.getDataType(path) != null || BuiltInDataTypeManager.getDataTypeManager().getDataType(path) != null) {
            throw new ApiException("ALREADY_EXISTS", "A type already exists at " + path);
        }
        int slash = path.lastIndexOf('/');
        CategoryPath category = new CategoryPath(slash == 0 ? "/" : path.substring(0, slash));
        String name = path.substring(slash + 1);
        DataType type = switch (kind) {
            case "struct" -> new StructureDataType(category, name, 0, manager);
            case "union" -> new UnionDataType(category, name, manager);
            case "enum" -> new EnumDataType(category, name,
                Arguments.integer(args, "size", 4, 1, 8), manager);
            case "typedef" -> new TypedefDataType(category, name,
                dataType(context.program(), Arguments.string(args, "base_type_path")), manager);
            default -> throw new IllegalArgumentException("Unknown type kind");
        };
        return typeResult(manager.addDataType(type, DataTypeConflictHandler.DEFAULT_HANDLER));
    }

    private static Object addStructField(OperationContext context, Map<String, Object> args)
            throws Exception {
        Structure structure = structure(context.program(), args);
        DataType type = dataType(context.program(), Arguments.string(args, "field_type_path"));
        int size = fixedLength(type);
        int offset = Arguments.integer(args, "field_offset", -1, -1, 1_048_576);
        String name = Arguments.optionalString(args, "field_name");
        String comment = Arguments.optionalString(args, "comment");
        DataTypeComponent component;
        if (offset == -1) {
            component = structure.add(type, size, name, comment);
        }
        else {
            if (structure.isPackingEnabled()) {
                throw new ApiException("INVALID_ARGUMENT", "An explicit field_offset requires a non-packed structure.");
            }
            long required = (long) offset + size;
            if (required > 1_048_576) {
                throw new ApiException("INVALID_ARGUMENT", "The structure exceeds the 1 MiB operation limit.");
            }
            for (DataTypeComponent current : structure.getDefinedComponents()) {
                if (current.getOffset() < required && current.getEndOffset() >= offset) {
                    throw new ApiException("DATA_CONFLICT", "The field overlaps an existing structure component.");
                }
            }
            if (required > structure.getLength()) {
                structure.growStructure((int) required - structure.getLength());
            }
            component = structure.replaceAtOffset(offset, type, size, name, comment);
        }
        return componentResult(structure, component);
    }

    private static Object createPointer(OperationContext context, Map<String, Object> args) {
        Program program = context.program();
        DataType base = dataType(program, Arguments.string(args, "base_type_path"));
        int size = Arguments.integer(args, "size", -1, 1, PointerDataType.MAX_POINTER_SIZE_BYTES);
        DataType pointer = new PointerDataType(base, size, program.getDataTypeManager());
        pointer = program.getDataTypeManager().addDataType(pointer, DataTypeConflictHandler.DEFAULT_HANDLER);
        return Map.of("type_path", pointer.getPathName(), "base_type_path", base.getPathName(),
            "size", pointer.getLength());
    }

    private static Object editStructField(OperationContext context, Map<String, Object> args)
            throws Exception {
        Structure structure = structure(context.program(), args);
        DataTypeComponent component = component(structure, args);
        if (!args.containsKey("new_name") && !args.containsKey("field_type_path") && !args.containsKey("comment")) {
            throw new ApiException("INVALID_ARGUMENT", "Specify new_name, field_type_path, or comment.");
        }
        String name = args.containsKey("new_name") ? text(args, "new_name", "") : component.getFieldName();
        String comment = args.containsKey("comment") ? text(args, "comment", "") : component.getComment();
        if (args.containsKey("field_type_path")) {
            if (component.isBitFieldComponent()) {
                throw new ApiException("UNSUPPORTED_CAPABILITY", "Changing a bitfield's type requires explicit bitfield parameters.");
            }
            DataType type = dataType(context.program(), Arguments.string(args, "field_type_path"));
            component = structure.replace(component.getOrdinal(), type, fixedLength(type), name, comment);
        }
        else {
            component.setFieldName(name == null || name.isEmpty() ? null : name);
            component.setComment(comment == null || comment.isEmpty() ? null : comment);
        }
        return componentResult(structure, component);
    }

    private static Object deleteStructField(OperationContext context, Map<String, Object> args)
            throws Exception {
        Structure structure = structure(context.program(), args);
        DataTypeComponent component = component(structure, args);
        int offset = component.getOffset();
        int ordinal = component.getOrdinal();
        structure.delete(ordinal);
        return Map.of("type_path", structure.getPathName(), "field_offset", offset,
            "field_ordinal", ordinal, "size", structure.getLength(), "deleted", true);
    }

    private static Object renameStruct(OperationContext context, Map<String, Object> args)
            throws Exception {
        Structure structure = structure(context.program(), args);
        String name = Arguments.string(args, "new_name");
        structure.setName(name);
        return typeResult(structure);
    }

    private static Object deleteStruct(OperationContext context, Map<String, Object> args)
            throws Exception {
        Structure structure = structure(context.program(), args);
        String path = structure.getPathName();
        context.monitor().checkCancelled();
        if (!context.program().getDataTypeManager().remove(structure)) {
            throw new ApiException("INVALID_ARGUMENT", "Ghidra could not remove the structure.");
        }
        return Map.of("type_path", path, "deleted", true);
    }

    private static Object addUnionField(OperationContext context, Map<String, Object> args)
            throws Exception {
        DataType target = dataType(context.program(), Arguments.string(args, "type_path"));
        if (!(target instanceof Union union)) {
            throw new ApiException("INVALID_ARGUMENT", "type_path does not refer to a union.");
        }
        requireProgramType(context.program(), union);
        DataType type = dataType(context.program(), Arguments.string(args, "field_type_path"));
        var component = union.add(type, fixedLength(type), Arguments.optionalString(args, "field_name"),
            Arguments.optionalString(args, "comment"));
        return Map.of("type_path", union.getPathName(), "field_ordinal", component.getOrdinal(),
            "field_type_path", component.getDataType().getPathName(), "size", union.getLength());
    }

    private static Object addEnumValue(OperationContext context, Map<String, Object> args)
            throws Exception {
        var enumeration = enumeration(context.program(), args);
        String name = Arguments.string(args, "value_name");
        long value = integer64(args.get("value"));
        if (Arrays.asList(enumeration.getNames()).contains(name)) {
            if (enumeration.getValue(name) != value) {
                throw new ApiException("NAME_CONFLICT", "An enum value with this name already exists.");
            }
            return Map.of("type_path", enumeration.getPathName(), "value_name", name,
                "value", Long.toString(value), "changed", false);
        }
        enumeration.add(name, value);
        return Map.of("type_path", enumeration.getPathName(), "value_name", name,
            "value", Long.toString(value), "changed", true);
    }

    private static Object deleteEnumValue(OperationContext context, Map<String, Object> args)
            throws Exception {
        var enumeration = enumeration(context.program(), args);
        String name = Arguments.string(args, "value_name");
        if (!Arrays.asList(enumeration.getNames()).contains(name)) {
            throw new ApiException("SYMBOL_NOT_FOUND", "The enum value does not exist.");
        }
        enumeration.remove(name);
        return Map.of("type_path", enumeration.getPathName(), "value_name", name, "deleted", true);
    }

    private static Object applyDataType(OperationContext context, Map<String, Object> args)
            throws Exception {
        DataType type = dataType(context.program(), Arguments.string(args, "type_path"));
        return defineData(context, args, type);
    }

    private static Object createArray(OperationContext context, Map<String, Object> args)
            throws Exception {
        DataType element = dataType(context.program(), Arguments.string(args, "type_path"));
        int count = Arguments.integer(args, "count", 0, 1, 1_048_576);
        int length = fixedLength(element);
        if ((long) count * length > 1_048_576) {
            throw new ApiException("INVALID_ARGUMENT", "The array exceeds the 1 MiB operation limit.");
        }
        return defineData(context, args, new ArrayDataType(element, count, length,
            context.program().getDataTypeManager()));
    }

    private static Object defineData(OperationContext context, Map<String, Object> args, DataType type)
            throws Exception {
        Program program = context.program();
        Address start = Arguments.address(program, args, "address");
        int length = fixedLength(type);
        if (length > 1_048_576) {
            throw new ApiException("INVALID_ARGUMENT", "The data exceeds the 1 MiB operation limit.");
        }
        Address end = rangeEnd(start, length);
        requireMemory(program, start, end);
        boolean clear = Arguments.bool(args, "clear_existing", false);
        var existing = program.getListing().getCodeUnits(new AddressSet(start, end), true);
        while (existing.hasNext()) {
            var unit = existing.next();
            if (unit instanceof Instruction || unit instanceof Data data && data.isDefined()) {
                if (!clear) {
                    throw new ApiException("DATA_CONFLICT", "Existing code/data requires clear_existing=true.");
                }
                if (unit.getMinAddress().compareTo(start) < 0 || unit.getMaxAddress().compareTo(end) > 0) {
                    throw new ApiException("DATA_CONFLICT", "The operation would partially overwrite an existing code unit.");
                }
            }
        }
        var containing = program.getListing().getCodeUnitContaining(start);
        if (containing != null && containing.getMinAddress().compareTo(start) < 0 &&
                (!(containing instanceof Data data) || data.isDefined())) {
            throw new ApiException("DATA_CONFLICT", "address lies inside an existing code unit.");
        }
        context.monitor().checkCancelled();
        if (clear) {
            program.getListing().clearCodeUnits(start, end, false);
        }
        Data data = program.getListing().createData(start, type);
        return Map.of("address", address(start), "length", data.getLength(),
            "type_path", data.getDataType().getPathName());
    }

    private static Object clearData(OperationContext context, Map<String, Object> args)
            throws Exception {
        Program program = context.program();
        Address start = Arguments.address(program, args, "address");
        int length = Arguments.integer(args, "length", 1, 1, 1_048_576);
        Address end = rangeEnd(start, length);
        requireMemory(program, start, end);
        List<Data> toClear = new ArrayList<>();
        var units = program.getListing().getCodeUnits(new AddressSet(start, end), true);
        while (units.hasNext()) {
            var unit = units.next();
            if (unit instanceof Instruction) {
                throw new ApiException("DATA_CONFLICT", "clear_data does not remove instructions.");
            }
            if (unit instanceof Data data && data.isDefined()) {
                if (data.getMinAddress().compareTo(start) < 0 || data.getMaxAddress().compareTo(end) > 0) {
                    throw new ApiException("DATA_CONFLICT", "The range only partially covers a defined data item.");
                }
                toClear.add(data);
            }
        }
        var containing = program.getListing().getCodeUnitContaining(start);
        if (containing != null && containing.getMinAddress().compareTo(start) < 0 &&
                (!(containing instanceof Data data) || data.isDefined())) {
            throw new ApiException("DATA_CONFLICT", "address lies inside an existing code unit.");
        }
        for (Data data : toClear) {
            context.monitor().checkCancelled();
            program.getListing().clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), false);
        }
        return Map.of("address", address(start), "length", length,
            "cleared_items", toClear.size(), "changed", !toClear.isEmpty());
    }

    private static Object setImportLibrary(OperationContext context, Map<String, Object> args)
            throws Exception {
        Program program = context.program();
        Address externalAddress = Arguments.address(program, args, "external_address");
        if (!externalAddress.isExternalAddress()) {
            throw new ApiException("ADDRESS_INVALID", "external_address must identify an EXTERNAL space symbol.");
        }
        var manager = program.getExternalManager();
        Symbol symbol = program.getSymbolTable().getPrimarySymbol(externalAddress);
        var location = symbol == null ? null : manager.getExternalLocation(symbol);
        if (location == null) {
            throw new ApiException("SYMBOL_NOT_FOUND", "No import exists at external_address.");
        }
        String library = externalLibrary(args);
        String previous = location.getLibraryName();
        boolean changed = !previous.equals(library);
        if (changed) {
            Namespace target = manager.addExternalLibraryName(library, SourceType.USER_DEFINED);
            List<Namespace> hierarchy = new ArrayList<>();
            for (Namespace parent = location.getParentNameSpace(); parent != null && !(parent instanceof Library);
                    parent = parent.getParentNamespace()) {
                hierarchy.add(parent);
            }
            for (Namespace original : hierarchy.reversed()) {
                SymbolType kind = original.getSymbol().getSymbolType();
                if (kind != SymbolType.NAMESPACE && kind != SymbolType.CLASS) {
                    throw new ApiException("UNSUPPORTED_CAPABILITY", "The import belongs to an unsupported namespace kind.");
                }
                Namespace existing = program.getSymbolTable().getNamespace(original.getName(), target);
                if (existing != null && existing.getSymbol().getSymbolType() != kind) {
                    throw new ApiException("NAME_CONFLICT", "The target library contains a different namespace kind at " + original.getName());
                }
                target = existing != null ? existing : kind == SymbolType.CLASS ?
                    program.getSymbolTable().createClass(target, original.getName(), SourceType.USER_DEFINED) :
                    program.getSymbolTable().createNameSpace(target, original.getName(), SourceType.USER_DEFINED);
            }
            location.setName(target, location.getLabel(), SourceType.USER_DEFINED);
        }
        if (!library.equals(location.getLibraryName())) {
            throw new ApiException("MUTATION_FAILED", "Ghidra did not associate the import with the requested library.");
        }
        return Map.of("external_address", address(externalAddress), "name", location.getLabel(),
            "previous_external_library", previous, "external_library", library,
            "namespace", location.getParentNameSpace().getName(true), "changed", changed);
    }

    private static Object setExternalLibraryPath(OperationContext context, Map<String, Object> args)
            throws Exception {
        String library = externalLibrary(args);
        String projectId = Arguments.string(args, "project_id");
        if (!projectId.equals(context.registry().projectId()) || context.registry().project() == null) {
            throw new ApiException("PROJECT_NOT_FOUND", "project_id does not identify the active project.");
        }
        String path = Arguments.string(args, "project_path");
        if (!path.startsWith("/")) {
            throw new ApiException("INVALID_ARGUMENT", "project_path must be an absolute project path.");
        }
        DomainFile file = context.registry().project().getProjectData().getFile(path);
        if (file == null || !Program.class.isAssignableFrom(file.getDomainObjectClass())) {
            throw new ApiException("FILE_NOT_FOUND", "The target is not a program file in the project.");
        }
        if (!context.program().getExternalManager().contains(library)) {
            throw new ApiException("SYMBOL_NOT_FOUND", "The external library is not present in this program.");
        }
        context.program().getExternalManager().setExternalPath(library, path, true);
        if (!path.equals(context.program().getExternalManager().getExternalLibraryPath(library))) {
            throw new ApiException("MUTATION_FAILED", "Ghidra did not store the requested external library path.");
        }
        return Map.of("external_library", library, "project_id", projectId, "project_path", path);
    }

    private static String externalLibrary(Map<String, Object> args) {
        String library = Arguments.string(args, "external_library");
        if (Library.UNKNOWN.equals(library)) {
            throw new ApiException("INVALID_ARGUMENT",
                "The reserved <EXTERNAL> namespace cannot identify a dependency. Assign the import to a named library first.");
        }
        return library;
    }

    public static DataType dataType(Program program, String path) {
        path = typePath(path);
        DataType type = program.getDataTypeManager().getDataType(path);
        if (type == null) {
            type = BuiltInDataTypeManager.getDataTypeManager().getDataType(path);
            if (type != null) {
                type = type.clone(program.getDataTypeManager());
            }
        }
        if (type == null) {
            throw new ApiException("TYPE_NOT_FOUND", "No data type exists at " + path);
        }
        return type;
    }

    private static String typePath(String path) {
        if (!path.startsWith("/") || path.endsWith("/") || path.contains("//") ||
                Arrays.stream(path.split("/")).anyMatch(part -> part.equals(".") || part.equals(".."))) {
            throw new ApiException("INVALID_ARGUMENT", "A full type_path such as /Crypto/State is required.");
        }
        return path;
    }

    private static void requireProgramType(Program program, DataType type) {
        if (type.getDataTypeManager() != program.getDataTypeManager()) {
            throw new ApiException("READ_ONLY", "A built-in or external type cannot be modified in place.");
        }
    }

    private static Structure structure(Program program, Map<String, Object> args) {
        DataType type = dataType(program, Arguments.string(args, "type_path"));
        if (!(type instanceof Structure structure)) {
            throw new ApiException("INVALID_ARGUMENT", "type_path does not refer to a structure.");
        }
        requireProgramType(program, structure);
        return structure;
    }

    private static ghidra.program.model.data.Enum enumeration(Program program, Map<String, Object> args) {
        DataType type = dataType(program, Arguments.string(args, "type_path"));
        if (!(type instanceof ghidra.program.model.data.Enum enumeration)) {
            throw new ApiException("INVALID_ARGUMENT", "type_path does not refer to an enum.");
        }
        requireProgramType(program, enumeration);
        return enumeration;
    }

    private static DataTypeComponent component(Structure structure, Map<String, Object> args) {
        boolean offsetSelected = args.containsKey("field_offset");
        boolean ordinalSelected = args.containsKey("field_ordinal");
        if (offsetSelected == ordinalSelected) {
            throw new ApiException("INVALID_ARGUMENT", "Specify exactly one of field_offset and field_ordinal.");
        }
        if (ordinalSelected) {
            int ordinal = Arguments.integer(args, "field_ordinal", -1, 0,
                Math.max(0, structure.getNumComponents() - 1));
            DataTypeComponent component = structure.getComponent(ordinal);
            if (component == null || Undefined.isUndefined(component.getDataType())) {
                throw new ApiException("FIELD_NOT_FOUND", "No defined component has this ordinal.");
            }
            return component;
        }
        int offset = Arguments.integer(args, "field_offset", -1, 0, 1_048_576);
        List<DataTypeComponent> matches = new ArrayList<>();
        for (DataTypeComponent component : structure.getDefinedComponents()) {
            if (component.getOffset() == offset) {
                matches.add(component);
            }
        }
        if (matches.isEmpty()) {
            throw new ApiException("FIELD_NOT_FOUND", "No defined field starts at field_offset.");
        }
        if (matches.size() != 1) {
            throw new ApiException("AMBIGUOUS_SYMBOL", "Several fields share this offset; use field_ordinal.");
        }
        return matches.getFirst();
    }

    private static Function function(OperationContext context, Map<String, Object> args, String key) {
        Address address = Arguments.address(context.program(), args, key);
        Function function = context.program().getFunctionManager().getFunctionAt(address);
        if (function == null) {
            throw new ApiException("FUNCTION_NOT_FOUND", key + " must be the exact entry address of a function.");
        }
        return function;
    }

    private static Namespace namespace(Program program, String path) {
        Namespace current = program.getGlobalNamespace();
        if (path.isEmpty() || path.equals("Global") || path.equals("::")) {
            return current;
        }
        String normalized = path.startsWith("::") ? path.substring(2) : path;
        for (String part : normalized.split("::", -1)) {
            if (part.isEmpty()) {
                throw new ApiException("INVALID_ARGUMENT", "Invalid namespace path.");
            }
            current = program.getSymbolTable().getNamespace(part, current);
            if (current == null) {
                throw new ApiException("SYMBOL_NOT_FOUND", "Namespace does not exist: " + path);
            }
        }
        return current;
    }

    private static Symbol label(Program program, Map<String, Object> args, String key) {
        Address target = Arguments.address(program, args, "address");
        Namespace namespace = namespace(program, Arguments.string(args, "namespace", ""));
        Symbol symbol = program.getSymbolTable().getSymbol(Arguments.string(args, key), target, namespace);
        if (symbol == null || symbol.getSymbolType() != SymbolType.LABEL) {
            throw new ApiException("SYMBOL_NOT_FOUND", "No matching label exists at the exact address and namespace.");
        }
        return symbol;
    }

    private static int fixedLength(DataType type) {
        if (type.getLength() <= 0) {
            throw new ApiException("INVALID_ARGUMENT", "A nonempty fixed-length data type is required.");
        }
        return type.getLength();
    }

    private static Address rangeEnd(Address start, long length) throws Exception {
        try {
            return start.addNoWrap(length - 1);
        }
        catch (Exception exception) {
            throw new ApiException("ADDRESS_INVALID", "The address range overflows its address space.");
        }
    }

    private static void requireMemory(Program program, Address start, Address end) {
        if (!start.isMemoryAddress() || !program.getMemory().contains(start, end)) {
            throw new ApiException("MEMORY_UNAVAILABLE", "The range is not completely backed by program memory.");
        }
    }

    private static byte[] bytes(String value) {
        String clean = value.replaceAll("\\s+", "");
        if (!clean.matches("(?:[0-9a-fA-F]{2})+")) {
            throw new ApiException("INVALID_ARGUMENT", "Hex bytes must contain complete byte pairs separated only by whitespace.");
        }
        return HexFormat.of().parseHex(clean);
    }

    private static String text(Map<String, Object> args, String key, String defaultValue) {
        Object value = args.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (!(value instanceof String text)) {
            throw new ApiException("INVALID_ARGUMENT", key + " must be a string.");
        }
        return text;
    }

    private static long integer64(Object raw) {
        try {
            BigInteger value;
            if (raw instanceof Number number) {
                value = new BigDecimal(number.toString()).toBigIntegerExact();
            }
            else if (raw instanceof String string) {
                boolean negative = string.startsWith("-");
                String digits = negative ? string.substring(1) : string;
                value = digits.startsWith("0x") || digits.startsWith("0X") ?
                    new BigInteger(digits.substring(2), 16) : new BigInteger(digits);
                if (negative) {
                    value = value.negate();
                }
            }
            else {
                throw new IllegalArgumentException();
            }
            if (value.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) < 0 || value.bitLength() > 64) {
                throw new IllegalArgumentException();
            }
            return value.longValue();
        }
        catch (IllegalArgumentException | ArithmeticException exception) {
            throw new ApiException("INVALID_ARGUMENT", "value must be an exact signed or unsigned 64-bit integer.");
        }
    }

    private static String address(Address address) {
        return address.getAddressSpace().getName() + ":0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    private static Map<String, Object> typeResult(DataType type) {
        return Map.of("type_path", type.getPathName(), "size", type.getLength());
    }

    private static Map<String, Object> componentResult(Structure structure, DataTypeComponent component) {
        return Map.of("type_path", structure.getPathName(), "field_offset", component.getOffset(),
            "field_ordinal", component.getOrdinal(), "field_name", component.getFieldName() == null ? "" : component.getFieldName(),
            "field_type_path", component.getDataType().getPathName(), "field_length", component.getLength(),
            "size", structure.getLength());
    }

    private static Map<String, Object> symbolResult(Symbol symbol, boolean changed) {
        return Map.of("address", address(symbol.getAddress()), "name", symbol.getName(),
            "namespace", symbol.getParentNamespace().getName(true), "changed", changed);
    }

    @FunctionalInterface
    private interface Handler {
        Object execute(OperationContext context, Map<String, Object> arguments) throws Exception;
    }
}
