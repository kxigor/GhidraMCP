package com.lauriewired.mcp;

import ghidra.framework.Application;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import java.util.ArrayList;
import java.util.List;

public final class ProjectLifecycle {
    private ProjectLifecycle() {}

    public static void close(FrontEndTool frontEnd, Project project) {
        if (frontEnd == null) {
            project.close();
            return;
        }
        GuiExecutor.call(() -> {
            List<ProjectListener> listeners = listeners(frontEnd);
            project.close();
            // setActiveProject(null) omits this notification in 12.2; recovery and other plugins need it.
            for (ProjectListener listener : listeners) listener.projectClosed(project);
            frontEnd.setActiveProject(null);
            return null;
        });
    }

    private static List<ProjectListener> listeners(FrontEndTool frontEnd) {
        if (!"12.2".equals(Application.getApplicationVersion())) {
            throw new ApiException("UNSUPPORTED_CAPABILITY", "Project lifecycle adapter is verified only for Ghidra 12.2");
        }
        try {
            var method = FrontEndTool.class.getDeclaredMethod("getListeners");
            if (!method.trySetAccessible() || !(method.invoke(frontEnd) instanceof Iterable<?> registered)) {
                throw new ReflectiveOperationException("Project listeners inaccessible");
            }
            List<ProjectListener> listeners = new ArrayList<>();
            for (Object listener : registered) {
                if (!(listener instanceof ProjectListener projectListener)) {
                    throw new ReflectiveOperationException("Unsupported project listener");
                }
                listeners.add(projectListener);
            }
            return listeners;
        }
        catch (ReflectiveOperationException error) {
            throw new ApiException("UNSUPPORTED_CAPABILITY", "Cannot notify Ghidra plugins when closing this project");
        }
    }
}
