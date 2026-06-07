// Ghidra headless PRE+POST SCRIPT for raw MIPS16E binaries.
//
// Invoked TWICE by wairz — first as -preScript, then as -postScript:
//   analyzeHeadless ... \
//     -preScript  Mips16eSetup.java [<code_offset_hex>] \
//     -postScript Mips16eSetup.java [<code_offset_hex>] \
//     -postScript AnalyzeBinary.java \
//     -processor MIPS:LE:32:default -loader BinaryLoader -loader-baseAddr 0x80000000
//
// Why both pre AND post?
//   Pre-script: Seeds ISA_MODE=1 and disassembles BEFORE Ghidra's auto-analysis
//     so the auto-analyzers see MIPS16E from the start.
//   Post-script: "MIPS UnAlligned Instruction Fix" and "Disassemble Entry Points"
//     run during auto-analysis and re-disassemble the code region in MIPS32 mode.
//     The post pass clears the garbage, re-establishes ISA_MODE=1, and
//     re-disassembles.  AnalyzeBinary.java then runs last and captures the
//     corrected MIPS16E state.
//
// Optional argument:
//   code_offset_hex  Byte offset from the load base to the first MIPS16E
//                    instruction (hex or decimal).
//                    Example: "0x30" skips the 48-byte RTL8761BU Realtechk header.
//                    Default: 0 (start from load base).
//
// MIPS context register map (from mips.sinc):
//   define context contextreg
//     ISA_MODE = (1,1)   ← bit 1; =1 means decode as alternate ISA (MIPS16E here)
//
//   ISAModeSwitch is a REGULAR register (offset 0x3F00) used for RUNTIME mode
//   switching via setISAMode().  It is NOT a context register and must not be
//   used for disassembly context operations.  Using it caused:
//     "Register ISAModeSwitch does not share common base register contextreg"
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
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryBlock;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class Mips16eSetup extends GhidraScript {

    @Override
    public void run() throws Exception {

        // --- Parse optional code_offset argument ----------------------------
        long codeOffset = 0;
        String[] args = getScriptArgs();
        if (args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            try {
                codeOffset = Long.decode(args[0]);
                println("Mips16eSetup: code_offset=" + args[0] + " (" + codeOffset + " bytes)");
            } catch (NumberFormatException e) {
                println("Mips16eSetup: WARNING — invalid code_offset '" + args[0]
                    + "'; defaulting to 0");
            }
        }

        // --- Find ISA_MODE — the disassembly context register ---------------
        // ISA_MODE is bit 1 of contextreg (defined in mips.sinc as ISA_MODE=(1,1)).
        // When ISA_MODE=1, Ghidra decodes instructions as the alternate ISA (MIPS16E).
        // ISAModeSwitch is a regular register for runtime mode switching — NOT this.
        Register isaModeReg = currentProgram.getLanguage().getRegister("ISA_MODE");
        if (isaModeReg == null) {
            // Fallback: try ProgramContext (covers language variants that expose it there)
            isaModeReg = currentProgram.getProgramContext().getRegister("ISA_MODE");
        }
        if (isaModeReg == null) {
            println("Mips16eSetup: FATAL — ISA_MODE context register not found for language "
                + currentProgram.getLanguage().getLanguageID());
            println("Mips16eSetup: NOTE: ISAModeSwitch exists but is a regular register "
                + "(runtime only); use ISA_MODE for disassembly context.");
            return;
        }
        println("Mips16eSetup: ISA_MODE register = " + isaModeReg.getName()
            + " (base: " + isaModeReg.getBaseRegister().getName() + ")");

        // Verify ISA_MODE shares the base context register (contextreg)
        Register baseCtxReg = currentProgram.getProgramContext().getBaseContextRegister();
        if (baseCtxReg == null) {
            println("Mips16eSetup: WARNING — no base context register found");
        } else if (!isaModeReg.getBaseRegister().equals(baseCtxReg)) {
            println("Mips16eSetup: WARNING — ISA_MODE base (" + isaModeReg.getBaseRegister()
                + ") != programContext base (" + baseCtxReg + ")");
        } else {
            println("Mips16eSetup: ISA_MODE confirmed in base context register "
                + baseCtxReg.getName());
        }

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

        // --- Clear existing code units BEFORE setting context ---------------
        // setRegisterValue throws ContextChangeException if code units exist in the range.
        currentProgram.getListing().clearCodeUnits(seedAddr, maxAddr, false);
        println("Mips16eSetup: cleared code units [" + seedAddr + ", " + maxAddr + "]");

        // --- Set ISA_MODE=1 via all available mechanisms --------------------
        RegisterValue isaModeOn = new RegisterValue(isaModeReg, BigInteger.ONE);

        // 1. Persist ISA_MODE=1 across the full code range in the program DB.
        try {
            currentProgram.getProgramContext().setRegisterValue(
                seedAddr, maxAddr, isaModeOn);
            println("Mips16eSetup: setRegisterValue ISA_MODE=1 [" + seedAddr
                + ", " + maxAddr + "]");
        } catch (Exception e) {
            println("Mips16eSetup: WARNING — setRegisterValue: " + e.getMessage());
        }

        // 2. Set program-wide default so newly-discovered code paths inherit
        //    MIPS16E mode without explicit per-address context.
        try {
            currentProgram.getProgramContext().setDefaultDisassemblyContext(isaModeOn);
            println("Mips16eSetup: setDefaultDisassemblyContext ISA_MODE=1");
        } catch (Exception e) {
            println("Mips16eSetup: WARNING — setDefaultDisassemblyContext: "
                + e.getMessage());
        }

        // 3. Build the seed context for the Disassembler API.
        //    Disassembler.disassemble() requires a RegisterValue for the BASE
        //    context register (contextreg), not a sub-register.
        RegisterValue disasmCtx;
        if (baseCtxReg != null && isaModeReg.getBaseRegister().equals(baseCtxReg)) {
            disasmCtx = new RegisterValue(baseCtxReg).assign(isaModeReg, BigInteger.ONE);
            println("Mips16eSetup: disassembly seed context: "
                + baseCtxReg.getName() + " with ISA_MODE=1");
        } else {
            disasmCtx = isaModeOn;
            println("Mips16eSetup: ISA_MODE is base-level; using directly as seed context");
        }

        // --- Phase 1: entry-point disassembly via Disassembler API ----------
        Disassembler dis = Disassembler.getDisassembler(currentProgram, monitor, null);
        AddressSet codeRange = new AddressSet(seedAddr, maxAddr);
        AddressSet disResult = dis.disassemble(seedAddr, codeRange, disasmCtx, true);
        println("Mips16eSetup: phase1 disassembled " + disResult.getNumAddressRanges()
            + " range(s), " + disResult.getNumAddresses() + " byte(s)");

        // --- Phase 2: ADJSP prologue scan -----------------------------------
        // MIPS16e function prologues: ADJSP with negative immediate decrements SP.
        // Encoding (LE 16-bit): lo=[0x80..0xFF], hi=0x63
        // Many functions are unreachable from the entry point via static call-following
        // (indirect branches, jump tables) — scan raw bytes to find them all.
        long codeLen = maxAddr.subtract(seedAddr) + 1;
        byte[] raw = new byte[(int) codeLen];
        currentProgram.getMemory().getBytes(seedAddr, raw);

        List<Address> prologues = new ArrayList<>();
        for (int i = 0; i + 1 < raw.length; i += 2) {
            int lo = raw[i]   & 0xFF;
            int hi = raw[i+1] & 0xFF;
            if (hi == 0x63 && lo >= 0x80) {
                prologues.add(seedAddr.add(i));
            }
        }
        println("Mips16eSetup: phase2 found " + prologues.size() + " ADJSP prologues");

        FunctionManager fm = currentProgram.getFunctionManager();
        int newDisas = 0;
        int newFuncs = 0;
        for (Address addr : prologues) {
            // Skip if already disassembled as part of a known function
            if (currentProgram.getListing().getInstructionAt(addr) != null) {
                continue;
            }
            // Pin ISA_MODE=1 at this address and disassemble forward
            try {
                currentProgram.getProgramContext().setRegisterValue(addr, addr, isaModeOn);
            } catch (Exception e) {
                // non-fatal: context already set from phase 1 range
            }
            AddressSet site = new AddressSet(addr, maxAddr);
            AddressSet r = dis.disassemble(addr, site, disasmCtx, true);
            if (r != null && r.getNumAddresses() > 0) {
                newDisas++;
            }
            if (fm.getFunctionAt(addr) == null) {
                Function f = createFunction(addr, null);
                if (f != null) {
                    newFuncs++;
                }
            }
        }
        println("Mips16eSetup: phase2 disassembled " + newDisas
            + " new site(s), created " + newFuncs + " new function(s)");

        // --- Fallback: ensure at least the entry point has a function -------
        int funcCount = 0;
        FunctionIterator fi = fm.getFunctions(true);
        while (fi.hasNext()) { fi.next(); funcCount++; }

        if (funcCount == 0) {
            println("Mips16eSetup: no functions found — creating entry function");
            Function f = createFunction(seedAddr, null);
            if (f != null) {
                println("Mips16eSetup: created entry function at " + seedAddr);
            }
        } else {
            println("Mips16eSetup: " + funcCount + " function(s) found");
        }

        // --- Finalize: resolve cross-refs, stack frames, call targets -------
        analyzeChanges(currentProgram);

        println("Mips16eSetup: script complete");
    }
}
