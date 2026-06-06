// Ghidra headless setup script for raw MIPS16E binaries.
//
// Run as the FIRST -postScript before AnalyzeBinary.java:
//   analyzeHeadless ... \
//     -postScript Mips16eSetup.java \
//     -postScript AnalyzeBinary.java \
//     -processor MIPS:LE:32:default -loader BinaryLoader -loader-baseAddr 0x80100000
//
// Problem this solves:
//   Ghidra's auto-analysis starts in MIPS32 mode.  MIPS16E opcodes use the
//   EXTEND prefix (bits[15:11] = 0x1E) which look like invalid MIPS32 words.
//   Ghidra fails to form instructions and creates 0 function entries.
//
// What this script does:
//   1. Sets the ISA_MODE context register to 1 (MIPS16e) across all loaded memory.
//   2. Clears any incorrect MIPS32 code units from the failed auto-analysis.
//   3. Re-disassembles from the binary entry address following flow.
//   4. Sweeps any unreached blocks linearly (catches indirect-only functions).
//   5. Calls analyzeChanges() to trigger Ghidra's function-boundary analyzers.
//   6. Falls back to creating a function manually at the entry point if needed.
//
// After this script completes, AnalyzeBinary.java finds the function list via
// currentProgram.getFunctionManager().getFunctions(true) as normal.
//
// @category Wairz
// @author Wairz AI

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;

import java.math.BigInteger;

public class Mips16eSetup extends GhidraScript {

    @Override
    public void run() throws Exception {

        // 1. Verify the MIPS ISA_MODE register exists.
        //    This register selects the instruction set: 0=MIPS32, 1=MIPS16e, 2=microMIPS.
        //    If absent the language is not MIPS or doesn't support ISA switching — bail out.
        Register isaModeReg = currentProgram.getLanguage().getRegister("ISA_MODE");
        if (isaModeReg == null) {
            println("Mips16eSetup: WARNING — ISA_MODE register not found for language "
                + currentProgram.getLanguage().getLanguageID()
                + "; skipping MIPS16e setup");
            return;
        }

        // 2. Build an address set covering all initialized memory blocks.
        //    BinaryLoader does not set execute-permission bits, so we use isInitialized()
        //    rather than isExecute() to catch all loaded bytes.
        AddressSet allBlocks = new AddressSet();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.isInitialized()) {
                allBlocks.add(block.getStart(), block.getEnd());
            }
        }
        if (allBlocks.isEmpty()) {
            println("Mips16eSetup: no initialized memory blocks found");
            return;
        }
        Address entryAddr = allBlocks.getMinAddress();

        // 3. Set ISA_MODE = 1 (MIPS16e) across the entire loaded image.
        //    clearContext=false in step 4 ensures this value is not wiped when we
        //    clear the MIPS32 code units.
        currentProgram.getProgramContext().setValue(
            isaModeReg,
            allBlocks.getMinAddress(),
            allBlocks.getMaxAddress(),
            BigInteger.ONE
        );
        println("Mips16eSetup: ISA_MODE=1 set over "
            + allBlocks.getNumAddresses() + " addresses"
            + " [" + allBlocks.getMinAddress() + " – " + allBlocks.getMaxAddress() + "]");

        // 4. Clear any MIPS32 code units Ghidra's initial auto-analysis may have formed.
        //    clearContext=false preserves the ISA_MODE=1 we just wrote.
        currentProgram.getListing().clearCodeUnits(
            allBlocks.getMinAddress(), allBlocks.getMaxAddress(), false
        );

        // 5. Re-disassemble from the entry address, following all flow edges.
        //    The program context now carries ISA_MODE=1 so Ghidra decodes MIPS16e opcodes.
        DisassembleCommand flowCmd = new DisassembleCommand(entryAddr, null, true);
        flowCmd.applyTo(currentProgram, monitor);
        println("Mips16eSetup: flow disassembly applied from " + entryAddr);

        // 6. Trigger Ghidra's function-boundary and calling-convention analyzers on
        //    the newly created instructions.  analyzeChanges() is faster than analyzeAll()
        //    because it only processes the queued changes from step 5.
        analyzeChanges(currentProgram);

        // 7. Sweep any blocks not reached by flow disassembly (indirect-only call targets,
        //    data-interleaved code, etc.).  followFlow=false avoids re-traversing already-
        //    disassembled ranges.
        AddressSet coveredBodies = new AddressSet();
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) {
            coveredBodies.add(fi.next().getBody());
        }
        AddressSet unreached = allBlocks.subtract(coveredBodies);
        if (!unreached.isEmpty()) {
            println("Mips16eSetup: sweeping " + unreached.getNumAddresses()
                + " unreached addresses");
            DisassembleCommand sweepCmd = new DisassembleCommand(unreached, null, false);
            sweepCmd.applyTo(currentProgram, monitor);
            analyzeChanges(currentProgram);
        }

        // 8. Count discovered functions.  If still zero (no symbols, no obvious entry-
        //    point heuristics fired), create a function manually at the entry address so
        //    AnalyzeBinary.java has at least one entry to decompile.
        int funcCount = 0;
        fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) { fi.next(); funcCount++; }

        if (funcCount == 0) {
            println("Mips16eSetup: no functions after analyzeChanges"
                + " — creating function manually at " + entryAddr);
            Function f = createFunction(entryAddr, null);
            if (f != null) funcCount = 1;
        }

        println("Mips16eSetup: complete — " + funcCount + " function(s) ready for AnalyzeBinary");
    }
}
