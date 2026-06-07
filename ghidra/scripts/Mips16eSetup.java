// Ghidra headless PRE-SCRIPT for raw MIPS16E binaries.
//
// Run as -preScript so ISA_MODE is set BEFORE Ghidra's auto-analysis pass:
//   analyzeHeadless ... \
//     -preScript Mips16eSetup.java \
//     -postScript AnalyzeBinary.java \
//     -processor MIPS:LE:32:default -loader BinaryLoader -loader-baseAddr 0x80100000
//
// Why -preScript and not -postScript:
//   Ghidra's auto-analysis runs in MIPS32 mode if ISA_MODE is not set first.
//   MIPS16E opcodes look like invalid MIPS32 words; Ghidra fails to form
//   instructions and creates 0 function entries.  Setting the context register
//   here means Ghidra's own analyzers (Function Start Search, MIPS16e analyzer)
//   run in MIPS16E mode from the outset.
//
// What this script does:
//   1. Sets ISAModeSwitch (or ISA_MODE as fallback) = 1 across all loaded memory.
//   2. Clears any MIPS32 code units the importer may have created.
//   3. Seeds an initial DisassembleCommand at the start of the first memory block
//      so Ghidra's analyzers have a flow-entry to start from.
//   Ghidra's auto-analysis then runs with MIPS16E mode already established.
//
// @category Wairz
// @author Wairz AI

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryBlock;

import java.math.BigInteger;

public class Mips16eSetup extends GhidraScript {

    @Override
    public void run() throws Exception {

        // 1. Find the ISA context register.
        //    Ghidra's MIPS SLEIGH spec calls it "ISAModeSwitch" in most variants;
        //    older Ghidra versions or alternate MIPS specs may use "ISA_MODE".
        Register isaModeReg = currentProgram.getLanguage().getRegister("ISAModeSwitch");
        if (isaModeReg == null) {
            isaModeReg = currentProgram.getLanguage().getRegister("ISA_MODE");
        }
        if (isaModeReg == null) {
            println("Mips16eSetup: WARNING — neither ISAModeSwitch nor ISA_MODE found "
                + "for language " + currentProgram.getLanguage().getLanguageID()
                + "; MIPS16E mode cannot be set.  Analysis will proceed in MIPS32 mode.");
            return;
        }
        println("Mips16eSetup: using register '" + isaModeReg.getName() + "' for ISA mode");

        // 2. Collect all initialized memory blocks.
        //    BinaryLoader does not set execute-permission bits, so we use
        //    isInitialized() rather than isExecute() to cover all loaded bytes.
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
        println("Mips16eSetup: memory range "
            + entryAddr + " – " + allBlocks.getMaxAddress()
            + " (" + allBlocks.getNumAddresses() + " bytes)");

        // 3. Set ISAModeSwitch = 1 (MIPS16e) across all loaded memory.
        //    clearContext=false in step 4 preserves this value.
        currentProgram.getProgramContext().setValue(
            isaModeReg,
            allBlocks.getMinAddress(),
            allBlocks.getMaxAddress(),
            BigInteger.ONE
        );
        println("Mips16eSetup: " + isaModeReg.getName() + "=1 set across all memory");

        // 4. Clear any MIPS32 code units the importer may have created during load.
        //    clearContext=false preserves the ISAModeSwitch=1 we just wrote.
        currentProgram.getListing().clearCodeUnits(
            allBlocks.getMinAddress(), allBlocks.getMaxAddress(), false
        );

        // 5. Seed an initial flow-disassembly at the first byte of loaded memory.
        //    This gives Ghidra's auto-analyzers a code-flow entry point.
        //    followFlow=true lets disassembly follow call/branch targets.
        //    The program context now carries ISAModeSwitch=1 so opcodes are
        //    decoded as MIPS16E.
        DisassembleCommand seedCmd = new DisassembleCommand(entryAddr, null, true);
        boolean ok = seedCmd.applyTo(currentProgram, monitor);
        println("Mips16eSetup: seed DisassembleCommand from " + entryAddr
            + (ok ? " succeeded" : " returned false (auto-analysis may still recover)"));

        println("Mips16eSetup: pre-script complete — Ghidra auto-analysis will now run "
            + "in MIPS16E mode");
    }
}
