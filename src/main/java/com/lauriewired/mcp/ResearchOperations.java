package com.lauriewired.mcp;

import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public final class ResearchOperations {
    private ResearchOperations() {}

    public static void register(Map<String, OperationDefinition> operations) {
        operations.put("list_functions", OperationDefinition.read("list_functions", ResearchOperations::functions));
        operations.put("get_function", OperationDefinition.read("get_function", ResearchOperations::function));
        operations.put("list_symbols", OperationDefinition.read("list_symbols", ResearchOperations::symbols));
        operations.put("list_namespaces", OperationDefinition.read("list_namespaces", ResearchOperations::namespaces));
        operations.put("list_imports", OperationDefinition.read("list_imports", ResearchOperations::imports));
        operations.put("list_exports", OperationDefinition.read("list_exports", ResearchOperations::exports));
        operations.put("list_strings", OperationDefinition.read("list_strings", ResearchOperations::strings));
        operations.put("list_data_items", OperationDefinition.read("list_data_items", ResearchOperations::data));
        operations.put("get_comments", OperationDefinition.read("get_comments", ResearchOperations::comments));
        operations.put("list_bookmarks", OperationDefinition.read("list_bookmarks", ResearchOperations::bookmarks));
        MemoryOperations.register(operations);
        ReferenceOperations.register(operations);
        DecompilerOperations.register(operations);
        DataTypeOperations.register(operations);
    }

    private static Object functions(OperationContext context, Map<String, Object> args) throws Exception {
        String query = Arguments.optionalString(args, "query");
        String namespace = Arguments.optionalString(args, "namespace");
        Pages.Window page = Pages.window(context, args, "list_functions");
        for (var function : context.program().getFunctionManager().getFunctions(true)) {
            context.monitor().checkCancelled();
            if (ReadSupport.matches(function.getName(true), query) &&
                    (namespace == null || function.getParentNamespace().getName(true).equals(namespace))) {
                if (page.add(ReadSupport.functionInfo(function))) break;
            }
        }
        return page.result();
    }

    private static Object function(OperationContext context, Map<String, Object> args) {
        String match = Arguments.string(args, "match", "containing");
        if (!match.equals("entry") && !match.equals("containing")) {
            throw new ApiException("INVALID_ARGUMENT", "match must be entry or containing");
        }
        return ReadSupport.functionInfo(ReadSupport.function(context.program(),
            Arguments.address(context.program(), args, "address"), match.equals("entry")));
    }

    private static Object symbols(OperationContext context, Map<String, Object> args) throws Exception {
        String query = Arguments.optionalString(args, "query");
        String kind = Arguments.optionalString(args, "kind");
        String namespace = Arguments.optionalString(args, "namespace");
        List<Map<String, Object>> rows = new ArrayList<>();
        for (var symbol : context.program().getSymbolTable().getAllSymbols(true)) {
            context.monitor().checkCancelled();
            if (ReadSupport.matches(symbol.getName(true), query) &&
                    (kind == null || symbol.getSymbolType().toString().equalsIgnoreCase(kind)) &&
                    (namespace == null || symbol.getParentNamespace().getName(true).equals(namespace))) {
                rows.add(symbolInfo(context.program(), symbol));
            }
        }
        rows.sort(Comparator.<Map<String, Object>, String>comparing(row -> (String) row.get("address"), ReadSupport::compareAddresses)
            .thenComparing(row -> row.get("qualified_name") + "\n" + row.get("symbol_id")));
        return Pages.page(context, args, rows, "list_symbols");
    }

    private static Object namespaces(OperationContext context, Map<String, Object> args) throws Exception {
        String query = Arguments.optionalString(args, "query");
        String kind = Arguments.string(args, "kind", "all");
        if (!List.of("all", "class", "namespace").contains(kind)) {
            throw new ApiException("INVALID_ARGUMENT", "kind must be all, class or namespace");
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (var symbol : context.program().getSymbolTable().getAllSymbols(true)) {
            context.monitor().checkCancelled();
            boolean isClass = symbol.getSymbolType() == SymbolType.CLASS;
            boolean isNamespace = symbol.getSymbolType() == SymbolType.NAMESPACE;
            if ((isClass || isNamespace) && ReadSupport.matches(symbol.getName(true), query) &&
                    (kind.equals("all") || kind.equals(isClass ? "class" : "namespace"))) {
                rows.add(ReadSupport.map("name", symbol.getName(), "path", symbol.getName(true),
                    "kind", isClass ? "class" : "namespace"));
            }
        }
        rows.sort(Comparator.comparing(row -> (String) row.get("path")));
        return Pages.page(context, args, rows, "list_namespaces");
    }

    private static Object imports(OperationContext context, Map<String, Object> args) throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (var symbol : context.program().getSymbolTable().getExternalSymbols()) {
            context.monitor().checkCancelled();
            if (ReadSupport.matches(symbol.getName(true), Arguments.optionalString(args, "query"))) {
                rows.add(symbolInfo(context.program(), symbol));
            }
        }
        rows.sort(Comparator.comparing(row -> row.get("qualified_name") + "\n" + row.get("address")));
        var page = Pages.page(context, args, rows, "list_imports");
        List<Map<String, Object>> libraries = new ArrayList<>();
        String[] libraryNames = context.program().getExternalManager().getExternalLibraryNames();
        java.util.Arrays.sort(libraryNames);
        for (String library : libraryNames) {
            libraries.add(ReadSupport.map("name", library,
                "project_path", context.program().getExternalManager().getExternalLibraryPath(library)));
        }
        page.put("external_libraries", libraries);
        return page;
    }

    private static Object exports(OperationContext context, Map<String, Object> args) throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (var symbol : context.program().getSymbolTable().getAllSymbols(true)) {
            context.monitor().checkCancelled();
            if (symbol.isExternalEntryPoint() && ReadSupport.matches(symbol.getName(true), Arguments.optionalString(args, "query"))) {
                rows.add(symbolInfo(context.program(), symbol));
            }
        }
        rows.sort(Comparator.<Map<String, Object>, String>comparing(row -> (String) row.get("address"), ReadSupport::compareAddresses)
            .thenComparing(row -> (String) row.get("qualified_name")));
        return Pages.page(context, args, rows, "list_exports");
    }

    private static Map<String, Object> symbolInfo(Program program, Symbol symbol) {
        var result = ReadSupport.map("symbol_id", Long.toUnsignedString(symbol.getID()),
            "name", symbol.getName(), "qualified_name", symbol.getName(true),
            "address", ReadSupport.address(symbol.getAddress()), "kind", symbol.getSymbolType().toString(),
            "namespace", symbol.getParentNamespace().getName(true), "primary", symbol.isPrimary(),
            "source", symbol.getSource().toString(), "external", symbol.isExternal());
        if (symbol.isExternal()) {
            var location = program.getExternalManager().getExternalLocation(symbol);
            if (location != null) {
                result.put("external_library", location.getLibraryName());
                result.put("external_address", ReadSupport.address(location.getExternalSpaceAddress()));
                result.put("original_address", ReadSupport.address(location.getAddress()));
                result.put("original_name", location.getOriginalImportedName());
            }
        }
        return result;
    }

    private static Object strings(OperationContext context, Map<String, Object> args) throws Exception {
        Pages.Window page = Pages.window(context, args, "list_strings");
        String query = Arguments.optionalString(args, "query");
        String encoding = Arguments.optionalString(args, "encoding");
        for (var data : context.program().getListing().getDefinedData(true)) {
            context.monitor().checkCancelled();
            if (!StringDataInstance.isString(data)) {
                continue;
            }
            var value = StringDataInstance.getStringDataInstance(data);
            if (ReadSupport.matches(value.getStringValue(), query) &&
                    (encoding == null || value.getCharsetName().equalsIgnoreCase(encoding))) {
                if (page.add(ReadSupport.map("address", ReadSupport.address(data.getAddress()),
                    "length", data.getLength(), "encoding", value.getCharsetName(),
                    "value", value.getStringValue(), "type_path", data.getDataType().getPathName()))) break;
            }
        }
        return page.result();
    }

    private static Object data(OperationContext context, Map<String, Object> args) throws Exception {
        Pages.Window page = Pages.window(context, args, "list_data_items");
        String query = Arguments.optionalString(args, "query");
        for (var data : context.program().getListing().getDefinedData(true)) {
            context.monitor().checkCancelled();
            String value = data.getDefaultValueRepresentation();
            if (ReadSupport.matches(data.getLabel(), query) || ReadSupport.matches(value, query)) {
                boolean truncated = value != null && value.length() > 4096;
                if (page.add(ReadSupport.map("address", ReadSupport.address(data.getAddress()),
                    "name", data.getLabel(), "length", data.getLength(),
                    "type_path", data.getDataType().getPathName(), "value", truncated ? value.substring(0, 4096) : value,
                    "value_truncated", truncated))) break;
            }
        }
        return page.result();
    }

    private static Object comments(OperationContext context, Map<String, Object> args) {
        var address = Arguments.address(context.program(), args, "address");
        String selected = Arguments.optionalString(args, "comment_type");
        List<Map<String, Object>> rows = new ArrayList<>();
        boolean valid = selected == null;
        for (CommentType type : CommentType.values()) {
            if (selected == null || type.name().equalsIgnoreCase(selected)) {
                valid = true;
                String text = context.program().getListing().getComment(type, address);
                if (text != null) {
                    rows.add(ReadSupport.map("comment_type", type.name().toLowerCase(java.util.Locale.ROOT), "text", text));
                }
            }
        }
        if (!valid) {
            throw new ApiException("INVALID_ARGUMENT", "Unknown comment_type");
        }
        return ReadSupport.map("address", ReadSupport.address(address), "comments", rows);
    }

    private static Object bookmarks(OperationContext context, Map<String, Object> args) throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        String type = Arguments.optionalString(args, "type");
        String category = Arguments.optionalString(args, "category");
        var iterator = context.program().getBookmarkManager().getBookmarksIterator();
        while (iterator.hasNext()) {
            context.monitor().checkCancelled();
            var bookmark = iterator.next();
            if ((type == null || type.equals(bookmark.getTypeString())) &&
                    (category == null || category.equals(bookmark.getCategory()))) {
                rows.add(ReadSupport.map("address", ReadSupport.address(bookmark.getAddress()),
                    "type", bookmark.getTypeString(), "category", bookmark.getCategory(), "note", bookmark.getComment()));
            }
        }
        rows.sort(Comparator.<Map<String, Object>, String>comparing(row -> (String) row.get("address"), ReadSupport::compareAddresses)
            .thenComparing(row -> row.get("type") + "\n" + row.get("category")));
        return Pages.page(context, args, rows, "list_bookmarks");
    }
}
