// Ghidra headless script: Find functions that reference strings matching a pattern.
//
// Usage with analyzeHeadless:
//   analyzeHeadless <project_dir> <project_name> \
//     -import <binary_path> \
//     -postScript FindStringRefs.java <regex_pattern> \
//     -deleteProject
//
// Outputs JSON between ===STRING_REFS_START=== / ===STRING_REFS_END===
// containing an array of {string_value, string_address, references: [{function, address, instruction}]}
//
// Implementation note: rather than relying on Ghidra's ASCII-Strings auto-
// analyzer to promote rodata into Data instances (which it does inconsistently
// across binaries — particularly stripped MIPS ELFs), we scan non-executable
// memory blocks directly for null-terminated printable ASCII sequences. This
// matches what a /usr/bin/strings invocation would find and works regardless
// of analyzer state.
//
// @category Wairz
// @author Wairz AI

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class FindStringRefs extends GhidraScript {

    private static final int MAX_RESULTS = 500;
    private static final int MAX_REFS_PER_STRING = 50;
    private static final int MAX_TOTAL_REFS = 200;
    private static final int MIN_STRING_LENGTH = 4;
    private static final int MAX_STRING_LENGTH = 4096;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: Regex pattern argument required");
            println("Usage: -postScript FindStringRefs.java <regex_pattern>");
            return;
        }

        String patternStr = args[0];
        Pattern pattern;
        try {
            pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            println("ERROR: Invalid regex pattern: " + e.getMessage());
            return;
        }

        Listing listing = currentProgram.getListing();
        ReferenceManager refManager = currentProgram.getReferenceManager();
        FunctionManager funcManager = currentProgram.getFunctionManager();
        Memory memory = currentProgram.getMemory();

        List<Map<String, Object>> results = new ArrayList<>();
        Set<String> seenAddresses = new HashSet<>();
        int totalRefs = 0;

        // Walk every initialized, non-executable memory block looking for
        // printable ASCII sequences terminated by NUL. Skipping executable
        // blocks avoids false positives on instruction-byte coincidences.
        for (MemoryBlock block : memory.getBlocks()) {
            if (monitor.isCancelled()) break;
            if (!block.isInitialized()) continue;
            if (block.isExecute()) continue;
            if (results.size() >= MAX_RESULTS || totalRefs >= MAX_TOTAL_REFS) break;

            Address blockStart = block.getStart();
            Address blockEnd = block.getEnd();
            Address cursor = blockStart;

            while (cursor.compareTo(blockEnd) <= 0) {
                if (monitor.isCancelled()) break;
                if (results.size() >= MAX_RESULTS || totalRefs >= MAX_TOTAL_REFS) break;

                StringBuilder sb = new StringBuilder();
                Address strStart = cursor;
                Address scanAddr = cursor;
                boolean terminated = false;

                while (scanAddr.compareTo(blockEnd) <= 0 && sb.length() < MAX_STRING_LENGTH) {
                    int b;
                    try {
                        b = memory.getByte(scanAddr) & 0xFF;
                    } catch (MemoryAccessException e) {
                        break;
                    }
                    if (b == 0) {
                        terminated = true;
                        break;
                    }
                    // Printable ASCII + tab/newline/cr (common in format strings)
                    if (b == 0x09 || b == 0x0A || b == 0x0D || (b >= 0x20 && b <= 0x7E)) {
                        sb.append((char) b);
                        try {
                            scanAddr = scanAddr.addNoWrap(1);
                        } catch (Exception e) {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if (!terminated || sb.length() < MIN_STRING_LENGTH) {
                    // Advance one byte and try again
                    try {
                        cursor = cursor.addNoWrap(1);
                    } catch (Exception e) {
                        break;
                    }
                    continue;
                }

                String strValue = sb.toString();

                // Test against the user-supplied regex
                if (!pattern.matcher(strValue).find()) {
                    // Skip past this string + its NUL terminator
                    try {
                        cursor = scanAddr.addNoWrap(1);
                    } catch (Exception e) {
                        break;
                    }
                    continue;
                }

                // Dedupe — strings landing at the same address shouldn't be
                // reported twice (can happen if blocks overlap).
                String addrKey = strStart.toString();
                if (seenAddresses.contains(addrKey)) {
                    try {
                        cursor = scanAddr.addNoWrap(1);
                    } catch (Exception e) {
                        break;
                    }
                    continue;
                }
                seenAddresses.add(addrKey);

                // Collect references to this string. We check the start
                // address only — Ghidra's MIPS constant-prop analyzer
                // typically emits the LUI+ADDIU result as a reference to
                // the string's first byte.
                List<Map<String, String>> refList = new ArrayList<>();
                int refsForThis = 0;
                ReferenceIterator refIter = refManager.getReferencesTo(strStart);

                while (refIter.hasNext()) {
                    if (refsForThis >= MAX_REFS_PER_STRING || totalRefs >= MAX_TOTAL_REFS) break;
                    Reference ref = refIter.next();

                    Address fromAddr = ref.getFromAddress();
                    Function containingFunc = funcManager.getFunctionContaining(fromAddr);
                    if (containingFunc == null) continue;

                    Instruction insn = listing.getInstructionAt(fromAddr);
                    String insnStr = (insn != null) ? insn.toString() : "unknown";

                    Map<String, String> refEntry = new LinkedHashMap<>();
                    refEntry.put("function", containingFunc.getName());
                    refEntry.put("function_address", containingFunc.getEntryPoint().toString());
                    refEntry.put("ref_address", fromAddr.toString());
                    refEntry.put("instruction", insnStr);

                    refList.add(refEntry);
                    refsForThis++;
                    totalRefs++;
                }

                if (!refList.isEmpty()) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("string_value", strValue);
                    entry.put("string_address", addrKey);
                    entry.put("references", refList);
                    results.add(entry);
                }

                // Resume scanning past this string + its NUL terminator
                try {
                    cursor = scanAddr.addNoWrap(1);
                } catch (Exception e) {
                    break;
                }
            }
        }

        // Output JSON
        println("===STRING_REFS_START===");
        println(toJson(results));
        println("===STRING_REFS_END===");
    }

    // Simple JSON serializer for our data structure
    private String toJson(List<Map<String, Object>> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");

        for (int i = 0; i < results.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("{");

            Map<String, Object> entry = results.get(i);
            sb.append("\"string_value\":").append(jsonString((String) entry.get("string_value"))).append(",");
            sb.append("\"string_address\":\"").append(entry.get("string_address")).append("\",");

            @SuppressWarnings("unchecked")
            List<Map<String, String>> refs = (List<Map<String, String>>) entry.get("references");
            sb.append("\"references\":[");

            for (int j = 0; j < refs.size(); j++) {
                if (j > 0) sb.append(",");
                Map<String, String> ref = refs.get(j);
                sb.append("{");
                sb.append("\"function\":").append(jsonString(ref.get("function"))).append(",");
                sb.append("\"function_address\":\"").append(ref.get("function_address")).append("\",");
                sb.append("\"ref_address\":\"").append(ref.get("ref_address")).append("\",");
                sb.append("\"instruction\":").append(jsonString(ref.get("instruction")));
                sb.append("}");
            }

            sb.append("]}");
        }

        sb.append("]");
        return sb.toString();
    }

    private String jsonString(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
