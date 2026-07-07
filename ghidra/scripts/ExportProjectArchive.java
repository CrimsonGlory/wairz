// Ghidra headless script: pack the current program's DomainFile into a
// standalone .gzf archive.
//
// This is the reverse of a plain -import: it lets a LIVE persistent GZF
// process-mode project (see gzf_project_paths / _run_gzf_process_mode in
// app/services/ghidra_service.py) — with any renames, retyping, or comments
// applied by prior script runs — be packaged back out as a downloadable
// archive, mirroring Ghidra's own GUI "File > Archive Current Project"
// action (DomainFile.packFile is the same API that action calls).
//
// Usage with analyzeHeadless (see export_ghidra_archive in
// app/ai/tools/ghidra_research.py):
//   analyzeHeadless <proj_base> gzf_project \
//     -process * -noanalysis \
//     -scriptPath <scripts_path> \
//     -postScript ExportProjectArchive.java <output_gzf_path>
//
// @category Wairz
// @author Wairz AI

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import java.io.File;

public class ExportProjectArchive extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: Output path argument required");
            println("Usage: -postScript ExportProjectArchive.java <output_gzf_path>");
            return;
        }

        String outputPath = args[0];

        if (currentProgram == null) {
            println("ERROR: No current program bound to this script run");
            return;
        }

        DomainFile domainFile = currentProgram.getDomainFile();
        if (domainFile == null) {
            println("ERROR: Current program has no associated DomainFile");
            return;
        }

        println("===EXPORT_START===");
        println("// Program: " + currentProgram.getName());
        println("// Domain file: " + domainFile.getPathname());

        File outputFile = new File(outputPath);
        domainFile.packFile(outputFile, monitor);

        println("// Packed to: " + outputFile.getAbsolutePath());
        println("===EXPORT_END===");
    }
}
