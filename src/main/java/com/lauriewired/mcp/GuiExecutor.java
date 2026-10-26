package com.lauriewired.mcp;

import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import javax.swing.SwingUtilities;

public final class GuiExecutor {
    private GuiExecutor() {}

    public static <T> T call(Callable<T> action) {
        try {
            if (SwingUtilities.isEventDispatchThread()) return action.call();
            FutureTask<T> task = new FutureTask<>(action);
            SwingUtilities.invokeAndWait(task);
            return task.get();
        }
        catch (Exception error) {
            Throwable cause = error;
            while (cause.getCause() != null) cause = cause.getCause();
            if (cause instanceof ApiException api) throw api;
            throw new ApiException("INTERNAL_ERROR", "GUI operation failed: " + cause);
        }
    }
}
