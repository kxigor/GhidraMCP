package com.lauriewired.mcp;

import java.util.Map;

public record OperationDefinition(String name, Effect effect, boolean programRequired,
        boolean asynchronous, Handler handler) {
    @FunctionalInterface
    public interface Handler {
        Object execute(OperationContext context, Map<String, Object> arguments) throws Exception;
    }

    public enum Effect { READ, LIVE_READ, WRITE, SESSION, UI, ANALYSIS, PROJECT_WRITE, SAVE }

    public static OperationDefinition read(String name, Handler handler) {
        return new OperationDefinition(name, Effect.READ, true, false, handler);
    }

    public static OperationDefinition write(String name, Handler handler) {
        return new OperationDefinition(name, Effect.WRITE, true, false, handler);
    }

    public static OperationDefinition liveRead(String name, Handler handler) {
        return new OperationDefinition(name, Effect.LIVE_READ, true, false, handler);
    }

    public boolean mutatesProgram() {
        return effect == Effect.WRITE || effect == Effect.ANALYSIS || effect == Effect.SAVE;
    }

    public boolean requiresWritableServer() {
        return mutatesProgram() || effect == Effect.PROJECT_WRITE;
    }
}
