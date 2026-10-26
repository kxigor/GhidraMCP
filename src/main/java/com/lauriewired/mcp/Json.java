package com.lauriewired.mcp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Json {
    private Json() {}

    public static Map<String, Object> map(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }

    public static final Gson GSON = new GsonBuilder().serializeNulls().disableHtmlEscaping()
        .setObjectToNumberStrategy(ToNumberPolicy.BIG_DECIMAL).create();
}
