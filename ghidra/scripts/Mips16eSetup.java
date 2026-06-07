// Ghidra headless PRE+POST SCRIPT for raw MIPS16E binaries.
//
// Invoked TWICE by wairz — first as -preScript, then as -postScript:
//   analyzeHeadless ... \
//     -preScript  Mips16eSetup.java [<code_offset_hex>] \
//     -postScript Mips16eSetup.java [<code_offset_hex>] \
//     -postScript AnalyzeBinary.java \
//     -processor MIPS:LE:32:default -loader BinaryLoader -loader-baseAddr 0x80100000
//
// Why both pre AND post?
//   Pre-script: Seeds MIPS16E mode BEFORE Ghidra's auto-analysis so the
//     auto-analyzers see MIPS16E from the start and don't create MIPS32 garbage.
//   Post-script: Some MIPS analyzers ("MIPS UnAlligned Instruction Fix",
//     "Disassemble Entry Points") run during auto-analysis and re-disassemble
//     the code region in MIPS32 mode, overwriting the correct MIPS16E code.
//     The post pass clears that garbage, re-establishes MIPS16E context, and
//     re-disassembles.  AnalyzeBinary.java then runs last and captures the
//     corrected state.
//
// Optional argument:
//   code_offset_hex  Hex (or decimal) byte offset from the load base to the
//                    first MIPS16E instruction.  Bytes before this offset are
//                    marked as raw data (not code) so Ghidra doesn't try to
//                    disassemble the firmware header.
//                    Example: "0x30" for RTL8761BU (48-byte Realtechk header).
//                    Default: 0 (seed from the load base directly).
//
// Three-pronged ISA mode strategy (Ghidra 12.1.2):
//   1. setRegisterValue(start, end, RegisterValue(ISAModeSwitch, 1))
//      Persists ISAModeSwitch=1 in the program database so future sessions
//      and subsequent analyses see MIPS16E throughout the code region.
//      MUST be called AFTER clearCodeUnits or it throws ContextChangeException.
//   2. setDefaultDisassemblyContext(RegisterValue(ISAModeSwitch, 1))
//      Sets the program-wide default context so newly discovered code paths
//      (e.g. via branch targets) inherit MIPS16E mode.
//   3. Disassembler.disassemble(seedAddr, codeRange, RegisterValue(ISAModeSwitch, 1), true)
//      Passes ISAModeSwitch=1 directly to the disassembler at the seed address,
//      bypassing ProgramContext reads entirely.  This is the only approach that
//      is guaranteed to affect what the disassembler actually uses.
//
// @category Wairz
// @author Wairz AI

import ghidra.program.disassemble.Disassembler;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
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
        Address maxAddr  = allBlocks.getMaxAddress();
        Address seedAddr = (codeOffset > 0) ? baseAddr.add(codeOffset) : baseAddr;
        println("Mips16eSetup: memory " + baseAddr + " – " + maxAddr
            + ", seed at " + seedAddr);

        // --- Mark firmware header as data (not code) ------------------------
        if (codeOffset > 0) {
            Address headerEnd = baseAddr.add(codeOffset - 1);
            try {
                currentProgram.getListing().clearCodeUnits(baseAddr, headerEnd, false);
                createData(baseAddr,
                    new ArrayDataType(ByteDataType.dataType, (int) codeOffset, 1));
                println("Mips16eSetup: header [" + baseAddr + ", " + headerEnd
                    + "] marked as data");
            } catch (Exception e) {
                println("Mips16eSetup: WARNING — could not mark header as data: "
                    + e.getMessage());
            }
        }

        // --- Clear any existing code units in the code region ---------------
        // MUST happen before setRegisterValue; if code units exist in the range,
        // setRegisterValue throws ContextChangeException and the write is lost.
        currentProgram.getListing().clearCodeUnits(seedAddr, maxAddr, false);
        println("Mips16eSetup: cleared code units [" + seedAddr + ", " + maxAddr + "]");

        // --- Establish MIPS16E context — three independent mechanisms -------
        RegisterValue isaModeOn = new RegisterValue(isaModeReg, BigInteger.ONE);

        // 1. Persist across the full code range so subsequent analyses (and
        //    future headless runs on the same project) see MIPS16E.
        try {
            currentProgram.getProgramContext().setRegisterValue(
                seedAddr, maxAddr, isaModeOn);
            println("Mips16eSetup: setRegisterValue ISAModeSwitch=1 ["
                + seedAddr + ", " + maxAddr + "]");
        } catch (Exception e) {
            println("Mips16eSetup: WARNING — setRegisterValue: " + e.getMessage());
        }

        // 2. Set program-wide default disassembly context so any code newly
        //    discovered via branch targets also gets MIPS16E mode.
        try {
            currentProgram.getProgramContext().setDefaultDisassemblyContext(isaModeOn);
            println("Mips16eSetup: setDefaultDisassemblyContext ISAModeSwitch=1");
        } catch (Exception e) {
            println("Mips16eSetup: WARNING — setDefaultDisassemblyContext: "
                + e.getMessage());
        }

        // 3. Disassemble with explicit seed context — this bypasses ProgramContext
        //    reads entirely and passes ISAModeSwitch=1 directly to the disassembler
        //    at the seed address.  followFlow=true propagates context through branches.
        Disassembler dis = Disassembler.getDisassembler(currentProgram, monitor, null);
        AddressSet codeRange = new AddressSet(seedAddr, maxAddr);
        AddressSet disResult = dis.disassemble(seedAddr, codeRange, isaModeOn, true);
        println("Mips16eSetup: Disassembler covered " + disResult.getNumAddressRanges()
            + " range(s), " + disResult.getNumAddresses() + " byte(s)");

        // --- Fallback: create a function at the entry if none found ---------
        int funcCount = 0;
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) { fi.next(); funcCount++; }

        if (funcCount == 0) {
            println("Mips16eSetup: no functions after disassembly — creating entry function");
            Function f = createFunction(seedAddr, null);
            if (f != null) {
                println("Mips16eSetup: created function '" + f.getName()
                    + "' at " + seedAddr);
            }
        } else {
            println("Mips16eSetup: " + funcCount + " function(s) found");
        }

        // Run pending analysis tasks so cross-references, stack frames, and
        // call targets resolve on the MIPS16E code (especially useful when
        // running as post-script after Ghidra's own auto-analysis pass).
        analyzeChanges(currentProgram);

        println("Mips16eSetup: script complete");
    }
}
