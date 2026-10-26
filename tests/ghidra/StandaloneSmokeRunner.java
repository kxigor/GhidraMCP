import ghidra.GhidraApplicationLayout;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.PrintWriter;
import java.util.Arrays;

public final class StandaloneSmokeRunner {
    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            throw new IllegalArgumentException("Expected installation, project directory, project name and script class");
        }
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        GhidraProject project = GhidraProject.openProject(args[1], args[2], true);
        try {
            GhidraScript script = (GhidraScript) Class.forName(args[3]).getConstructor().newInstance();
            script.setScriptArgs(Arrays.copyOfRange(args, 4, args.length));
            script.execute(new GhidraState(null, project.getProject(), null, null, null, null),
                TaskMonitor.DUMMY, new PrintWriter(System.out, true));
        }
        finally {
            project.close();
        }
        System.exit(0);
    }
}
