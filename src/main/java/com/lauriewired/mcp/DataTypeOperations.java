package com.lauriewired.mcp;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public final class DataTypeOperations {
    private DataTypeOperations() {}

    public static void register(Map<String, OperationDefinition> operations) {
        operations.put("list_data_types", OperationDefinition.read("list_data_types", DataTypeOperations::list));
        operations.put("get_type", OperationDefinition.read("get_type", DataTypeOperations::get));
    }

    private static Object list(OperationContext context, Map<String, Object> args) throws Exception {
        String category = Arguments.optionalString(args, "category");
        String query = Arguments.optionalString(args, "query");
        List<Map<String, Object>> rows = new ArrayList<>();
        var iterator = context.program().getDataTypeManager().getAllDataTypes();
        while (iterator.hasNext()) {
            context.monitor().checkCancelled();
            DataType type = iterator.next();
            if ((category == null || type.getCategoryPath().getPath().equals(category)) &&
                    ReadSupport.matches(type.getPathName(), query)) {
                rows.add(summary(type));
            }
        }
        rows.sort(Comparator.comparing(row -> (String) row.get("type_path")));
        return Pages.page(context, args, rows, "list_data_types");
    }

    private static Object get(OperationContext context, Map<String, Object> args) {
        String path = Arguments.string(args, "type_path");
        DataType type = context.program().getDataTypeManager().getDataType(path);
        if (type == null) {
            throw new ApiException("TYPE_NOT_FOUND", "No data type at the requested path", Map.of("type_path", path));
        }
        var result = summary(type);
        result.put("description", type.getDescription());
        if (type instanceof Composite composite) {
            List<Map<String, Object>> fields = new ArrayList<>();
            for (var field : composite.getComponents()) {
                var row = ReadSupport.map("ordinal", field.getOrdinal(), "offset", field.getOffset(),
                    "length", field.getLength(), "name", field.getFieldName(),
                    "type_path", field.getDataType().getPathName(), "comment", field.getComment(),
                    "bitfield", field.isBitFieldComponent());
                if (field.getDataType() instanceof BitFieldDataType bits) {
                    row.put("bit_offset", bits.getBitOffset());
                    row.put("bit_size", bits.getBitSize());
                }
                fields.add(row);
            }
            result.put("fields", fields);
            result.put("packing_enabled", composite.isPackingEnabled());
        }
        if (type instanceof Enum enumeration) {
            List<Map<String, Object>> values = new ArrayList<>();
            for (String name : enumeration.getNames()) {
                values.add(ReadSupport.map("name", name, "value", Long.toString(enumeration.getValue(name)),
                    "value_hex", ReadSupport.hex(enumeration.getValue(name)), "comment", enumeration.getComment(name)));
            }
            result.put("values", values);
        }
        if (type instanceof TypeDef typedef) {
            result.put("base_type_path", typedef.getBaseDataType().getPathName());
        }
        if (type instanceof Pointer pointer) {
            result.put("referenced_type_path", pointer.getDataType() == null ? null : pointer.getDataType().getPathName());
        }
        if (type instanceof Array array) {
            result.put("element_type_path", array.getDataType().getPathName());
            result.put("count", array.getNumElements());
        }
        return result;
    }

    private static Map<String, Object> summary(DataType type) {
        return ReadSupport.map("type_path", type.getPathName(), "name", type.getName(),
            "category", type.getCategoryPath().getPath(), "length", type.getLength(),
            "alignment", type.getAlignment(), "kind", type.getClass().getSimpleName());
    }
}
