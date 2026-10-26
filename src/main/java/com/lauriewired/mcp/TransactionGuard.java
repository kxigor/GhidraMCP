package com.lauriewired.mcp;

import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Field;
import java.util.Map;

public final class TransactionGuard {
    @FunctionalInterface
    public interface Work<T> { T run() throws Exception; }

    private TransactionGuard() {}

    public static <T> T execute(Program program, String name, String expectedRevision,
            TaskMonitor monitor, Work<T> work) throws Exception {
        Object manager = manager(program);
        // Ghidra nests transactions across threads. Its own manager monitor must cover the whole write.
        synchronized (manager) {
            monitor.checkCancelled();
            if (program.getCurrentTransactionInfo() != null || program.isLocked()) {
                throw new ApiException("PROGRAM_BUSY", "Program has an active transaction or lock");
            }
            if (!program.canSave()) throw new ApiException("READ_ONLY", "Program is not writable");
            String actual = ProgramRegistry.revision(program);
            if (expectedRevision != null && !expectedRevision.equals(actual)) {
                throw new ApiException("REVISION_CONFLICT", "Program changed before mutation",
                    Map.of("expected_revision", expectedRevision, "actual_revision", actual));
            }
            int transaction = program.startTransaction("MCP: " + name);
            boolean commit = false;
            try {
                T result = work.run();
                monitor.checkCancelled();
                commit = true;
                return result;
            }
            finally {
                program.endTransaction(transaction, commit);
            }
        }
    }

    public static void save(Program program, String expectedRevision, TaskMonitor monitor) throws Exception {
        synchronized (manager(program)) {
            monitor.checkCancelled();
            if (program.getCurrentTransactionInfo() != null || program.isLocked()) {
                throw new ApiException("PROGRAM_BUSY", "Program has an active transaction or lock");
            }
            if (!program.canSave()) throw new ApiException("READ_ONLY", "Program is not writable");
            String actual = ProgramRegistry.revision(program);
            if (expectedRevision != null && !expectedRevision.equals(actual)) {
                throw new ApiException("REVISION_CONFLICT", "Program changed before save",
                    Map.of("expected_revision", expectedRevision, "actual_revision", actual));
            }
            program.save("Saved by MCP", monitor);
        }
    }

    private static Object manager(Program program) {
        try {
            if (!(program instanceof DomainObjectAdapterDB)) {
                throw new ReflectiveOperationException("Unsupported Program implementation");
            }
            Field field = DomainObjectAdapterDB.class.getDeclaredField("transactionMgr");
            if (!field.trySetAccessible()) throw new ReflectiveOperationException("Transaction manager inaccessible");
            Object manager = field.get(program);
            if (manager == null || !manager.getClass().getName().equals("ghidra.framework.data.DomainObjectTransactionManager")) {
                throw new ReflectiveOperationException("Unsupported synchronized transaction manager");
            }
            return manager;
        }
        catch (ReflectiveOperationException | SecurityException error) {
            throw new ApiException("UNSUPPORTED_CAPABILITY", "Cannot isolate transactions on this Ghidra runtime",
                Map.of("reason", error.toString()));
        }
    }
}
