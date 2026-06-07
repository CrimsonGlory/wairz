// Ghidra headless PRE-SCRIPT for raw MIPS16E binaries.
//
// Run as -preScript so ISA_MODE is set BEFORE Ghidra's auto-analysis pass:
//   analyzeHeadless ... \
//     -preScript Mips16eSetup.java [<code_offset_hex>] \
//     -postScript AnalyzeBinary.java \
//     -processor MIPS:LE:32:default -loader BinaryLoader -loader-baseAddr 0x80100000
//
// Optional argument:
//   code_offset_hex  Hex (or decimal) byte offset from the load base to the
//                    first MIPS16E instruction.  Bytes before this offset are
//                    marked as raw data (not code) so Ghidra doesn't try to
//                    disassemble the firmware header.
//                    Example: "0x30" for RTL8761BU (48-byte Realtechk header).
//                    Default: 0 (seed from the load base directly).
//
// Why -preScript and not -postScript:
//   Ghidra's auto-analysis runs in MIPS32 mode if ISAModeSwitch is not set
//   first.  MIPS16E opcodes look like invalid MIPS32 words; Ghidra fails to
//   form instructions and creates 0 function entries.  Setting the context
//   register here means Ghidra's own analyzers run in MIPS16E mode.
//
// What this script does:
//   1. Sets ISAModeSwitch (or ISA_MODE as fallback) = 1 across all loaded memory.
//   2. If code_offset > 0, marks [base, base+code_offset) as raw byte-array data.
//   3. Clears any MIPS32 code units the importer created in the code region.
//   4. Seeds a DisassembleCommand from base+code_offset.
//   5. Creates a function at base+code_offset as a fallback if disassembly
//      produces no functions.
//   Ghidra's auto-analysis then runs with MIPS16E mode already established.
//
// @category Wairz
// @author Wairz AI

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;

import java.math.BigInteger;

public class Mips16eSetup extends GhidraScript {

    @Override
    public void run() throws Exception {

        // --- Parse optional code_offset argument ----------------------------
        long codeOffset = 0;
        String[] args = getScriptArgs();
        if (args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            try {
                // Long.decode handles "0x30", "48", "0X30" etc.
                codeOffset = Long.decode(args[0]);
                println("Mips16eSetup: code_offset=" + args[0] + " (" + codeOffset + " bytes)");
            } catch (NumberFormatException e) {
                println("Mips16eSetup: WARNING — invalid code_offset '" + args[0]
                    + "'; defaulting to 0");
            }
        }

        // --- Find the ISA context register ----------------------------------
        // Ghidra's MIPS SLEIGH spec names it "ISAModeSwitch" in most variants;
        // older or alternate specs may use "ISA_MODE".
        Register isaModeReg = currentProgram.getLanguage().getRegister("ISAModeSwitch");
        if (isaModeReg == null) {
            isaModeReg = currentProgram.getLanguage().getRegister("ISA_MODE");
        }
        if (isaModeReg == null) {
            println("Mips16eSetup: WARNING — neither ISAModeSwitch nor ISA_MODE found "
                + "for language " + currentProgram.getLanguage().getLanguageID()
                + "; MIPS16E mode cannot be set.");
            return;
        }
        println("Mips16eSetup: using register '" + isaModeReg.getName() + "' for ISA mode");

        // --- Collect all initialized memory blocks --------------------------
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
        Address baseAddr = allBlocks.getMinAddress();
        Address seedAddr = (codeOffset > 0) ? baseAddr.add(codeOffset) : baseAddr;
        println("Mips16eSetup: memory " + baseAddr + " – " + allBlocks.getMaxAddress()
            + ", seed at " + seedAddr);

        // --- Mark firmware header as data (not code) ------------------------
        if (codeOffset > 0) {
            Address headerEnd = baseAddr.add(codeOffset - 1);
            try {
                // Clear anything the importer put there first
                currentProgram.getListing().clearCodeUnits(baseAddr, headerEnd, false);
                // Mark as a flat byte array so the listing shows it as data
                createData(baseAddr, new ArrayDataType(ByteDataType.dataType, (int) codeOffset, 1));
                println("Mips16eSetup: header [" + baseAddr + ", " + headerEnd + "] marked as data");
            } catch (Exception e) {
                println("Mips16eSetup: WARNING — could not mark header as data: " + e.getMessage());
            }
        }

        // --- Set ISAModeSwitch = 1 across all loaded memory -----------------
        // clearContext=false in the next step preserves this value.
        AddressSet codeRegion = new AddressSet(seedAddr, allBlocks.getMaxAddress());
        currentProgram.getProgramContext().setValue(
            isaModeReg, seedAddr, allBlocks.getMaxAddress(), BigInteger.ONE
        );
        println("Mips16eSetup: " + isaModeReg.getName() + "=1 set [" + seedAddr
            + ", " + allBlocks.getMaxAddress() + "]");

        // --- Clear any MIPS32 code units in the code region -----------------
        currentProgram.getListing().clearCodeUnits(seedAddr, allBlocks.getMaxAddress(), false);

        // --- Seed initial flow-disassembly at the first code byte -----------
        DisassembleCommand seedCmd = new DisassembleCommand(seedAddr, null, true);
        boolean ok = seedCmd.applyTo(currentProgram, monitor);
        println("Mips16eSetup: DisassembleCommand from " + seedAddr
            + (ok ? " succeeded" : " returned false (auto-analysis may still recover)"));

        // --- Fallback: create a function at the entry if none found ---------
        int funcCount = 0;
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) { fi.next(); funcCount++; }

        if (funcCount == 0) {
            println("Mips16eSetup: no functions after seed disassembly — creating entry function");
            Function f = createFunction(seedAddr, null);
            if (f != null) {
                println("Mips16eSetup: created function '" + f.getName() + "' at " + seedAddr);
            }
        } else {
            println("Mips16eSetup: " + funcCount + " function(s) found after seed disassembly");
        }

        println("Mips16eSetup: pre-script complete — Ghidra auto-analysis will now "
            + "run in MIPS16E mode");
    }
}
