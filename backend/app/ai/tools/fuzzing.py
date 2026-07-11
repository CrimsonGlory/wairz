"""Fuzzing AI tools for automated vulnerability discovery.

Tools for analyzing fuzzing targets, managing AFL++ campaigns, generating
dictionaries and seed corpora, and triaging crashes.
"""

import base64

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.services.fuzzing_service import FuzzingService
from app.services.jsonb_normalizers import (
    _normalize_firmware_binary_info,
    _normalize_fuzzing_campaigns_config,
    _normalize_fuzzing_campaigns_stats,
)
from app.utils.docker_client import get_docker_client


def register_fuzzing_tools(registry: ToolRegistry) -> None:
    """Register all fuzzing tools with the given registry."""

    registry.register(
        name="analyze_fuzzing_target",
        description=(
            "Analyze a firmware binary for fuzzing suitability. Returns a score "
            "(0-100), identified input-handling functions, dangerous sinks "
            "(strcpy, system, sprintf, etc.), binary protections, and a "
            "recommended fuzzing strategy (stdin, file, or network). "
            "Use this BEFORE starting a fuzzing campaign to identify the best "
            "targets — prioritize binaries with high scores."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem (e.g., /usr/sbin/httpd)",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_analyze_target,
    )

    registry.register(
        name="generate_fuzzing_dictionary",
        description=(
            "Generate an AFL++ dictionary from a firmware binary by extracting "
            "interesting strings (format specifiers, protocol keywords, magic "
            "values, parameter names). A good dictionary dramatically improves "
            "fuzzing effectiveness by guiding mutations toward meaningful values."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_generate_dictionary,
    )

    registry.register(
        name="generate_seed_corpus",
        description=(
            "Generate minimal seed inputs for fuzzing based on the binary's "
            "input type. For stdin-based programs, generates short test strings. "
            "For file-based programs, generates minimal file headers. "
            "Returns base64-encoded seeds ready for the fuzzing campaign."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem",
                },
                "input_type": {
                    "type": "string",
                    "enum": ["stdin", "file", "network"],
                    "description": "Type of input the binary processes (from analyze_fuzzing_target)",
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_generate_seed_corpus,
    )

    registry.register(
        name="start_fuzzing_campaign",
        description=(
            "Create and start an AFL++ fuzzing campaign for a firmware binary. "
            "The fuzzer runs in QEMU mode (-Q) inside an isolated Docker container. "
            "Returns the campaign ID for monitoring. Use analyze_fuzzing_target "
            "first to verify the binary is a good target, and optionally generate "
            "a dictionary and seed corpus for better results. "
            "Only one campaign can run at a time per project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem",
                },
                "timeout_per_exec": {
                    "type": "integer",
                    "description": "Timeout per execution in milliseconds (default 1000, max 30000)",
                },
                "memory_limit": {
                    "type": "integer",
                    "description": "Memory limit per execution in MB (default 256, max 1024)",
                },
                "dictionary": {
                    "type": "string",
                    "description": "AFL++ dictionary content (one entry per line, format: token=\"value\")",
                },
                "seed_corpus": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Base64-encoded seed input files",
                },
                "arguments": {
                    "type": "string",
                    "description": (
                        "Arguments appended after the target binary in the AFL++ command. "
                        "Use '@@' for file-based fuzzing so AFL++ passes the fuzz input "
                        "as a file path argument to the binary."
                    ),
                },
                "environment": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": (
                        "Extra environment variables to set for the AFL++ target execution "
                        "(e.g., {\"REQUEST_METHOD\": \"POST\", \"CONTENT_TYPE\": \"application/x-www-form-urlencoded\"})."
                    ),
                },
                "harness_script": {
                    "type": "string",
                    "description": (
                        "Shell script content to use as the AFL++ target instead of "
                        "the binary directly. The script is written to the container "
                        "and executed via /firmware/bin/sh. Useful for CGI-style binaries "
                        "that need environment variable setup before execution."
                    ),
                },
                "harness_binary": {
                    "type": "string",
                    "description": (
                        "Virtual path (e.g. /_carved/harnesses/<name>) to a compiled "
                        "harness ELF produced by build_fuzz_harness. When set, AFL++ "
                        "runs this harness (which links a firmware .so and calls a "
                        "target function on the fuzz input) instead of a firmware "
                        "binary. Pair with arguments='@@' for file input. binary_path "
                        "should still point at the target .so (for the campaign record "
                        "and AFL_INST_LIBS detection)."
                    ),
                },
                "desock": {
                    "type": "boolean",
                    "description": (
                        "Enable desocketing for network daemon binaries. When true, "
                        "intercepts socket/bind/listen/accept calls and redirects "
                        "network I/O to stdin/stdout, allowing AFL++ to fuzz daemon "
                        "binaries that normally read from network connections. Use "
                        "this for binaries identified as 'network' strategy by "
                        "analyze_fuzzing_target."
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_start_campaign,
    )

    registry.register(
        name="build_fuzz_harness",
        description=(
            "Cross-compile a fuzzing harness that links a firmware shared "
            "library and calls a target function on fuzz input, for the "
            "firmware's architecture. This is how you reach custom (non-CVE) "
            "memory-safety bugs in library functions that are otherwise only "
            "reachable behind a daemon/auth.\n"
            "\n"
            "You supply `harness_source`: C that declares the target "
            "function(s) with their REAL signatures (recover these by "
            "decompiling the .so — e.g. decompile_function) and defines:\n"
            "    void harness_one(const unsigned char *data, size_t len);\n"
            "which maps the fuzz input to the function's arguments and calls "
            "it. Wairz adds a main() that reads the AFL input (file arg or "
            "stdin) into (data,len) and invokes harness_one once.\n"
            "\n"
            "The harness is built in a network-less sandbox against the "
            "firmware's own libraries (using an old-glibc cross toolchain so it "
            "runs under qemu-user with the real .so), and the resulting ELF is "
            "written to /_carved/harnesses/<name>. Then call start_fuzzing_"
            "campaign with harness_binary=/_carved/harnesses/<name>, "
            "binary_path=<the .so>, and arguments='@@'.\n"
            "\n"
            "Supported arches: armhf, armel, aarch64, mips, mipsel (auto-"
            "detected from the firmware; override with `arch`)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "lib_path": {
                    "type": "string",
                    "description": (
                        "Firmware path to the target shared library "
                        "(e.g. /usr/lib/libsml.so)."
                    ),
                },
                "harness_source": {
                    "type": "string",
                    "description": (
                        "C source defining `void harness_one(const unsigned "
                        "char *data, size_t len)` and declaring/calling the "
                        "target function(s). May include headers. Do not define "
                        "main() (wairz provides it; define WAIRZ_NO_MAIN only if "
                        "you must supply your own)."
                    ),
                },
                "name": {
                    "type": "string",
                    "description": (
                        "Output harness name (filename-safe). The ELF lands at "
                        "/_carved/harnesses/<name>."
                    ),
                },
                "arch": {
                    "type": "string",
                    "description": (
                        "Override the cross-compile arch "
                        "(armhf|armel|aarch64|mips|mipsel). Default: auto from "
                        "the firmware."
                    ),
                },
            },
            "required": ["lib_path", "harness_source", "name"],
        },
        handler=_handle_build_harness,
    )

    registry.register(
        name="patch_function_return",
        description=(
            "Force a function in a firmware binary (or .so) to immediately "
            "return a constant, by overwriting its entry with an arch-specific "
            "'return <value>' stub. Produces a patched copy in /_carved/patched/.\n"
            "\n"
            "Primary use — AUTH BYPASS for daemon fuzzing: web daemons like httpd "
            "(CivetWeb) embed the auth check in the binary, so an LD_PRELOAD shim "
            "can't interpose it. Patch the auth function (e.g. CheckAuth, "
            "mg_check_digest_access_authentication) to return 1 (authenticated), "
            "then fuzz the patched daemon with start_fuzzing_campaign("
            "harness_binary=/_carved/patched/<name>, desock=true) to reach "
            "post-auth request handlers. Also neutralises license/CRC/crypto "
            "gates.\n"
            "\n"
            "Identify the function and its return convention by decompiling first "
            "(decompile_function / list_functions). Supports ARM (arm+thumb), "
            "AArch64, MIPS/MIPSel. The function may be a symbol name or a 0x… "
            "address (for stripped/local targets)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Firmware path to the binary/.so to patch (e.g. /sbin/httpd).",
                },
                "function": {
                    "type": "string",
                    "description": (
                        "Function symbol name (e.g. CheckAuth) or a hex address "
                        "(e.g. 0x132e8) to force-return."
                    ),
                },
                "return_value": {
                    "type": "integer",
                    "description": "Value the function should return (default 1). 0..65535.",
                },
                "name": {
                    "type": "string",
                    "description": (
                        "Output filename under /_carved/patched/ (default "
                        "<binary>.patched)."
                    ),
                },
                "thumb": {
                    "type": "boolean",
                    "description": (
                        "ARM only: force Thumb (true) or ARM (false) stub. Default: "
                        "auto from the symbol's Thumb bit."
                    ),
                },
            },
            "required": ["binary_path", "function"],
        },
        handler=_handle_patch_function_return,
    )

    registry.register(
        name="check_fuzzing_status",
        description=(
            "Check the status of a fuzzing campaign or list all campaigns. "
            "Returns live statistics: executions/sec, total executions, corpus "
            "size, crash count, hang count, stability, and coverage. "
            "If no campaign_id is given, lists all campaigns for the project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "campaign_id": {
                    "type": "string",
                    "description": "Optional campaign ID. If omitted, lists all campaigns.",
                },
            },
        },
        handler=_handle_check_status,
    )

    registry.register(
        name="stop_fuzzing_campaign",
        description=(
            "Stop a running fuzzing campaign. Syncs final crash data and "
            "statistics before stopping. Always stop campaigns when done to "
            "free resources."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "campaign_id": {
                    "type": "string",
                    "description": "The campaign ID to stop",
                },
            },
            "required": ["campaign_id"],
        },
        handler=_handle_stop_campaign,
    )

    registry.register(
        name="generate_fuzzing_harness",
        description=(
            "Generate a fuzzing harness/configuration for a firmware binary based "
            "on its input type. Analyzes the binary to determine the best fuzzing "
            "approach and returns concrete parameters to pass to start_fuzzing_campaign. "
            "For stdin targets: direct fuzzing with no wrapper. "
            "For file-based targets: uses @@ argument so AFL++ passes fuzz input as a file. "
            "For network/CGI targets: generates a shell wrapper that sets CGI environment "
            "variables and pipes stdin to the binary. "
            "For daemon-style network targets: notes limitations and suggests alternatives. "
            "Use analyze_fuzzing_target first to understand the binary, then this tool "
            "to get the right campaign configuration."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to the binary within the firmware filesystem (e.g., /usr/sbin/httpd)",
                },
                "input_type": {
                    "type": "string",
                    "enum": ["stdin", "file", "network"],
                    "description": (
                        "Override the input type (stdin/file/network). "
                        "If omitted, auto-detected from analyze_fuzzing_target results."
                    ),
                },
            },
            "required": ["binary_path"],
        },
        handler=_handle_generate_harness,
    )

    registry.register(
        name="triage_fuzzing_crash",
        description=(
            "Triage a crash found by the fuzzer: reproduce it under GDB, "
            "capture the stack trace and register state, and classify "
            "exploitability (exploitable, probably_exploitable, probably_not, "
            "unknown). Use this on each crash to determine if it's a real "
            "vulnerability worth reporting as a finding."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "campaign_id": {
                    "type": "string",
                    "description": "The campaign ID",
                },
                "crash_id": {
                    "type": "string",
                    "description": "The crash ID to triage",
                },
            },
            "required": ["campaign_id", "crash_id"],
        },
        handler=_handle_triage_crash,
    )

    registry.register(
        name="diagnose_fuzzing_campaign",
        description=(
            "Diagnose a fuzzing campaign that may not be performing well. "
            "Checks campaign status, reads AFL++ logs for startup errors, "
            "analyzes coverage for stalls, and provides actionable recommendations "
            "(e.g., enable desock for network daemons, increase timeout for hangs). "
            "Use this when coverage is flat, execs/sec is zero, or the campaign "
            "seems stuck."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "campaign_id": {
                    "type": "string",
                    "description": "The campaign ID to diagnose",
                },
            },
            "required": ["campaign_id"],
        },
        handler=_handle_diagnose_campaign,
    )


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_analyze_target(input: dict, context: ToolContext) -> str:
    """Analyze a binary for fuzzing suitability."""
    binary_path = input.get("binary_path", "")
    if not binary_path:
        return "Error: binary_path is required."

    result = await context.db.execute(
        select(Firmware).where(Firmware.id == context.firmware_id)
    )
    firmware = result.scalar_one_or_none()
    if not firmware:
        return "Error: firmware not found."

    svc = FuzzingService(context.db)
    try:
        analysis = await svc.analyze_target(firmware, binary_path)
    except ValueError as exc:
        return f"Error: {exc}"

    if analysis.get("error"):
        return f"Error analyzing {binary_path}: {analysis['error']}"

    score = analysis["fuzzing_score"]
    lines = [
        f"Fuzzing Target Analysis: {binary_path}",
        f"  Score: {score}/100 ({'good target' if score >= 60 else 'moderate' if score >= 30 else 'poor target'})",
        f"  Recommended strategy: {analysis['recommended_strategy']}",
        f"  Functions: {analysis['function_count']}",
        f"  File size: {analysis['file_size']} bytes",
        "",
    ]

    if analysis["dangerous_functions"]:
        lines.append(f"  Dangerous sinks: {', '.join(analysis['dangerous_functions'])}")
    if analysis["input_sources"]:
        lines.append(f"  Input functions: {', '.join(analysis['input_sources'])}")
    if analysis["network_functions"]:
        lines.append(f"  Network functions: {', '.join(analysis['network_functions'])}")

    prot = analysis.get("protections", {})
    if prot:
        lines.append("")
        lines.append("  Binary protections:")
        lines.append(f"    NX: {'yes' if prot.get('nx') else 'NO'}")
        lines.append(f"    RELRO: {prot.get('relro', 'unknown')}")
        lines.append(f"    Canary: {'yes' if prot.get('canary') else 'NO'}")
        lines.append(f"    PIE: {'yes' if prot.get('pie') else 'NO'}")

    # Add standalone binary info if applicable
    bi = _normalize_firmware_binary_info(firmware.binary_info)
    if bi:
        lines.append("")
        lines.append("  Standalone binary mode:")
        linking = "static" if bi.get("is_static") else "dynamic"
        lines.append(f"    Linking: {linking}")
        if not bi.get("is_static"):
            from app.services.sysroot_service import check_dependencies, get_sysroot_path
            sysroot = get_sysroot_path(firmware.architecture or "")
            lines.append(f"    Sysroot: {sysroot or 'unavailable'}")
            deps = bi.get("dependencies", [])
            if deps:
                dep_check = check_dependencies(firmware.architecture or "", deps)
                if dep_check.get("missing"):
                    lines.append(f"    Missing deps: {', '.join(dep_check['missing'])}")
                else:
                    lines.append("    All dependencies available in sysroot")
        else:
            lines.append("    No sysroot needed (static binary)")

    if score >= 60:
        lines.append("")
        lines.append("Recommendation: This binary is a good fuzzing target. "
                      "Proceed with start_fuzzing_campaign.")
    elif score >= 30:
        lines.append("")
        lines.append("Recommendation: Moderate fuzzing target. Consider generating "
                      "a dictionary and seed corpus for better results.")
    else:
        lines.append("")
        lines.append("Recommendation: This binary may not be a productive fuzzing target. "
                      "Consider analyzing other binaries first.")

    return "\n".join(lines)


async def _handle_generate_dictionary(input: dict, context: ToolContext) -> str:
    """Generate an AFL++ dictionary from binary strings."""
    binary_path = input.get("binary_path", "")
    if not binary_path:
        return "Error: binary_path is required."

    result = await context.db.execute(
        select(Firmware).where(Firmware.id == context.firmware_id)
    )
    firmware = result.scalar_one_or_none()
    if not firmware or not firmware.extracted_path:
        return "Error: firmware not found or not unpacked."

    try:
        full_path = context.resolve_path(binary_path)
    except Exception as exc:
        return f"Error: {exc}"

    # Extract strings and build dictionary entries
    import asyncio
    try:
        proc = await asyncio.create_subprocess_exec(
            "strings", "-n", "4", full_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="replace")
        all_strings = output.strip().split("\n") if output.strip() else []
    except TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return "Error: strings extraction timed out after 30 seconds."
    except Exception as exc:
        return f"Error extracting strings: {exc}"

    # Filter for dictionary-worthy entries
    dict_entries = set()
    for s in all_strings:
        s = s.strip()
        if not s or len(s) > 64:
            continue
        # Format specifiers
        if "%" in s and any(c in s for c in "sdxXfn"):
            dict_entries.add(s)
        # Protocol keywords
        elif s.upper() in ("GET", "POST", "PUT", "DELETE", "HTTP", "HEAD",
                           "OPTIONS", "CONTENT-LENGTH", "CONTENT-TYPE",
                           "HOST", "USER-AGENT", "COOKIE", "SET-COOKIE"):
            dict_entries.add(s)
        # Delimiters and special chars
        elif s in ("=", "&", "?", ";", "|", "`", "$", "{", "}", "\\n", "\\r\\n",
                    "://", "/", "..", "../", "\\x00"):
            dict_entries.add(s)
        # Short interesting tokens (likely parameter names or keywords)
        elif 3 <= len(s) <= 16 and s.isalnum():
            # Keep if it looks like a keyword (not random hex)
            if s.isalpha() or (s[0].isalpha() and s.replace("_", "").isalnum()):
                dict_entries.add(s)

    # Limit to 200 entries
    entries = sorted(dict_entries)[:200]

    if not entries:
        return "No dictionary-worthy strings found in the binary."

    # Format as AFL++ dictionary
    dict_content = []
    for i, entry in enumerate(entries):
        # Escape for AFL++ dictionary format
        escaped = entry.replace("\\", "\\\\").replace('"', '\\"')
        dict_content.append(f'token_{i}="{escaped}"')

    output = "\n".join(dict_content)

    lines = [
        f"Generated AFL++ dictionary with {len(entries)} entries for {binary_path}.",
        "",
        "Dictionary content (pass to start_fuzzing_campaign as 'dictionary'):",
        "",
        output,
    ]

    return "\n".join(lines)


async def _handle_generate_seed_corpus(input: dict, context: ToolContext) -> str:
    """Generate minimal seed inputs for fuzzing."""
    input_type = input.get("input_type", "stdin")

    # Generate seeds based on input type
    seeds: list[bytes] = []

    if input_type == "network":
        seeds = [
            b"GET / HTTP/1.0\r\n\r\n",
            b"POST /login HTTP/1.1\r\nContent-Length: 10\r\n\r\nuser=admin",
            b"GET /admin HTTP/1.1\r\nHost: 192.168.1.1\r\nCookie: session=AAAA\r\n\r\n",
            b"\x00\x01\x00\x00\x00\x01\x00\x00",  # DNS-like
        ]
    elif input_type == "file":
        seeds = [
            b"test config\nkey=value\n",
            b'{"key": "value", "num": 123}\n',
            b"<?xml version=\"1.0\"?><root><item>test</item></root>",
            b"\x00" * 16,
        ]
    else:  # stdin
        seeds = [
            b"AAAA",
            b"admin\npassword\n",
            b"test input with spaces and $pecial chars!",
            b"\x00\x01\x02\x03\x04\x05\x06\x07",
            b"A" * 256,
        ]

    seed_b64 = [base64.b64encode(s).decode() for s in seeds]

    lines = [
        f"Generated {len(seeds)} seed inputs for {input_type}-based fuzzing.",
        "",
        "Seeds (base64-encoded, pass to start_fuzzing_campaign as 'seed_corpus'):",
    ]
    for i, (s, b) in enumerate(zip(seeds, seed_b64)):
        preview = s[:40].decode("utf-8", errors="replace")
        lines.append(f"  Seed {i}: {preview!r} ({len(s)} bytes)")

    lines.append("")
    lines.append("seed_corpus values:")
    for b in seed_b64:
        lines.append(f'  "{b}"')

    return "\n".join(lines)


async def _handle_generate_harness(input: dict, context: ToolContext) -> str:
    """Generate a fuzzing harness/configuration for a firmware binary."""
    binary_path = input.get("binary_path", "")
    if not binary_path:
        return "Error: binary_path is required."

    result = await context.db.execute(
        select(Firmware).where(Firmware.id == context.firmware_id)
    )
    firmware = result.scalar_one_or_none()
    if not firmware:
        return "Error: firmware not found."

    # Run target analysis to determine strategy
    svc = FuzzingService(context.db)
    try:
        analysis = await svc.analyze_target(firmware, binary_path)
    except ValueError as exc:
        return f"Error: {exc}"

    if analysis.get("error"):
        return f"Error analyzing {binary_path}: {analysis['error']}"

    input_type = input.get("input_type") or analysis["recommended_strategy"]
    imports = set(analysis.get("imports_of_interest", []))
    binary_basename = binary_path.rstrip("/").rsplit("/", 1)[-1]

    lines: list[str] = [
        f"Fuzzing Harness for: {binary_path}",
        f"  Detected strategy: {analysis['recommended_strategy']}",
        f"  Using strategy: {input_type}",
        "",
    ]

    campaign_params: dict = {}

    if input_type == "stdin":
        lines.append("Strategy: STDIN fuzzing (direct)")
        lines.append("")
        lines.append("No wrapper needed — AFL++ pipes fuzz input directly to the binary's stdin.")
        lines.append("This works well for binaries that read from stdin (read, fgets, getline, scanf).")
        lines.append("")
        lines.append("Recommended start_fuzzing_campaign parameters:")
        lines.append(f'  binary_path: "{binary_path}"')
        lines.append("  (no extra arguments needed)")

        campaign_params = {
            "binary_path": binary_path,
        }

    elif input_type == "file":
        # Detect likely file extensions from strings
        ext = _guess_file_extension(analysis)
        arg_str = f"@@{ext}" if ext else "@@"

        lines.append("Strategy: FILE-based fuzzing")
        lines.append("")
        lines.append(
            "AFL++ replaces @@ with the path to the current fuzz input file. "
            "The binary receives the fuzz file as a command-line argument."
        )
        if ext:
            lines.append(f"  Detected likely file extension: {ext}")
        lines.append("")
        lines.append("Recommended start_fuzzing_campaign parameters:")
        lines.append(f'  binary_path: "{binary_path}"')
        lines.append(f'  arguments: "{arg_str}"')

        campaign_params = {
            "binary_path": binary_path,
            "arguments": arg_str,
        }

    elif input_type == "network":
        # Determine if this is CGI-style or daemon-style
        is_cgi = _is_cgi_binary(analysis, binary_basename)

        if is_cgi:
            lines.append("Strategy: NETWORK fuzzing (CGI-style via harness script)")
            lines.append("")
            lines.append(
                "This binary appears to be a CGI-style program that reads HTTP input "
                "via environment variables and stdin. The harness script sets up the "
                "CGI environment and pipes AFL++ fuzz input to the binary."
            )

            harness = _generate_cgi_harness(binary_path)

            lines.append("")
            lines.append("Generated harness script:")
            lines.append("```")
            lines.append(harness)
            lines.append("```")
            lines.append("")
            lines.append("Recommended start_fuzzing_campaign parameters:")
            lines.append(f'  binary_path: "{binary_path}"')
            lines.append('  harness_script: (the script above)')

            campaign_params = {
                "binary_path": binary_path,
                "harness_script": harness,
            }
        else:
            lines.append("Strategy: NETWORK fuzzing (daemon-style with desock)")
            lines.append("")
            lines.append(
                "This binary is a network daemon (uses socket/bind/listen/accept). "
                "The desock library will intercept socket calls and redirect network "
                "I/O to stdin/stdout, allowing AFL++ to fuzz the network parsing "
                "code directly."
            )
            lines.append("")
            lines.append("Recommended start_fuzzing_campaign parameters:")
            lines.append(f'  binary_path: "{binary_path}"')
            lines.append("  desock: true")
            lines.append("  (AFL++ will pipe fuzz data through the desocketed accept() connection)")
            lines.append("")
            lines.append("Notes:")
            lines.append("- The daemon's accept() loop will receive one connection with AFL++ fuzz data")
            lines.append("- Some daemons may need arguments to skip daemonization (e.g., -f for foreground)")
            lines.append("- If coverage is flat, the daemon may fork after accept() — try adding")
            lines.append('  environment: {"AFL_NO_FORKSRV": "1"}')

            campaign_params = {
                "binary_path": binary_path,
                "desock": True,
            }

    lines.append("")
    lines.append("---")
    lines.append("Campaign parameters summary:")
    for k, v in campaign_params.items():
        if k.startswith("_"):
            lines.append(f"  Note: {v}")
        elif k == "harness_script":
            lines.append(f"  {k}: (script, {len(v)} chars)")
        else:
            lines.append(f"  {k}: {v}")

    return "\n".join(lines)


def _guess_file_extension(analysis: dict) -> str:
    """Guess the file extension a binary expects from its imports/strings."""
    # Common patterns based on imported functions
    imports = set(analysis.get("imports_of_interest", []))

    # XML parsing
    if imports & {"XML_Parse", "xmlParseFile", "xmlReadFile", "expat_parse"}:
        return ".xml"
    # JSON parsing
    if imports & {"json_parse", "cJSON_Parse", "json_tokener_parse"}:
        return ".json"

    return ""


def _is_cgi_binary(analysis: dict, basename: str) -> bool:
    """Heuristic: is this a CGI-style binary rather than a standalone daemon?"""
    imports = set(analysis.get("imports_of_interest", []))
    network_funcs = set(analysis.get("network_functions", []))

    # CGI indicators: uses getenv but not socket/bind/listen
    has_getenv = "getenv" in imports
    has_server_socket = bool(network_funcs & {"bind", "listen", "accept"})

    # Common CGI binary names
    cgi_names = {"cgi", "cgi-bin", "goform", "goahead", "webs", "mini_httpd"}
    name_lower = basename.lower()
    name_suggests_cgi = any(n in name_lower for n in cgi_names)

    if has_getenv and not has_server_socket:
        return True
    if name_suggests_cgi and not has_server_socket:
        return True

    return False


def _generate_cgi_harness(binary_path: str) -> str:
    """Generate a shell harness script for CGI-style binary fuzzing."""
    binary_in_firmware = binary_path.lstrip("/")
    return f"""#!/bin/sh
# CGI fuzzing harness for {binary_path}
# AFL++ pipes fuzz input to this script's stdin.
# The script sets up CGI environment variables and forwards stdin to the binary.

INPUT_SIZE=$(wc -c < /dev/stdin | tr -d ' ')

export REQUEST_METHOD=POST
export CONTENT_TYPE="application/x-www-form-urlencoded"
export CONTENT_LENGTH="$INPUT_SIZE"
export SCRIPT_NAME="/{binary_in_firmware}"
export QUERY_STRING=""
export SERVER_NAME="127.0.0.1"
export SERVER_PORT="80"
export REMOTE_ADDR="127.0.0.1"
export HTTP_HOST="127.0.0.1"
export GATEWAY_INTERFACE="CGI/1.1"
export SERVER_PROTOCOL="HTTP/1.1"

exec /firmware/{binary_in_firmware}
"""


async def _handle_start_campaign(input: dict, context: ToolContext) -> str:
    """Create and start a fuzzing campaign."""
    binary_path = input.get("binary_path", "")
    if not binary_path:
        return "Error: binary_path is required."

    result = await context.db.execute(
        select(Firmware).where(Firmware.id == context.firmware_id)
    )
    firmware = result.scalar_one_or_none()
    if not firmware:
        return "Error: firmware not found."

    config = {}
    if "timeout_per_exec" in input:
        config["timeout_per_exec"] = min(input["timeout_per_exec"], 30000)
    if "memory_limit" in input:
        config["memory_limit"] = min(input["memory_limit"], 1024)
    if "dictionary" in input:
        config["dictionary"] = input["dictionary"]
    if "seed_corpus" in input:
        config["seed_corpus"] = input["seed_corpus"]
    if "arguments" in input:
        config["arguments"] = input["arguments"]
    if "environment" in input:
        config["environment"] = input["environment"]
    if "harness_script" in input:
        config["harness_script"] = input["harness_script"]
    if "harness_binary" in input:
        config["harness_binary"] = input["harness_binary"]
    if "desock" in input:
        config["desock"] = input["desock"]

    svc = FuzzingService(context.db)
    try:
        campaign = await svc.create_campaign(firmware, binary_path, config)
        campaign = await svc.start_campaign(campaign.id, context.project_id)
        await context.db.flush()
    except ValueError as exc:
        return f"Error: {exc}"
    except Exception as exc:
        return f"Error starting campaign: {exc}"

    lines = [
        "Fuzzing campaign started successfully.",
        f"  Campaign ID: {campaign.id}",
        f"  Binary: {campaign.binary_path}",
        f"  Status: {campaign.status}",
    ]
    if campaign.error_message:
        lines.append(f"  Error: {campaign.error_message}")
    else:
        lines.append("")
        lines.append(
            "Use check_fuzzing_status with this campaign ID to monitor progress. "
            "AFL++ needs time to build coverage — check back after a few minutes."
        )
        lines.append(
            "Use stop_fuzzing_campaign when done. Use triage_fuzzing_crash to "
            "analyze any crashes found."
        )

    return "\n".join(lines)


async def _handle_build_harness(input: dict, context: ToolContext) -> str:
    """Cross-compile a fuzzing harness linked against a firmware .so."""
    lib_path = input.get("lib_path", "")
    harness_source = input.get("harness_source", "")
    name = input.get("name", "")
    arch = input.get("arch")
    if not lib_path or not harness_source or not name:
        return "Error: lib_path, harness_source, and name are required."

    svc = HarnessBuildService(context.db)
    try:
        result = await svc.build_harness(
            project_id=context.project_id,
            firmware_id=context.firmware_id,
            lib_path=lib_path,
            harness_source=harness_source,
            name=name,
            arch=arch,
        )
    except HarnessBuildError as exc:
        return f"Error: {exc}"
    except Exception as exc:
        return f"Error building harness: {exc}"

    if not result.ok:
        return (
            f"Harness build FAILED (arch={result.arch}).\n\n"
            f"--- build log ---\n{result.log[-6000:]}\n\n"
            "Fix the harness_source (check the target function signature via "
            "decompile_function) and rebuild."
        )

    lines = [
        f"Harness built: {result.elf_virtual_path}",
        f"  Arch: {result.arch}",
    ]
    if result.glibc_max:
        lines.append(f"  Max glibc symbol version required: {result.glibc_max}")
        lines.append(
            "  (must be <= the firmware libc's version, or it won't run under "
            "qemu-user; armhf base is GLIBC_2.4.)"
        )
    lines.append("")
    lines.append(
        "Start fuzzing it with:\n"
        f"  start_fuzzing_campaign(binary_path=\"{lib_path}\", "
        f"harness_binary=\"{result.elf_virtual_path}\", arguments=\"@@\")\n"
        "AFL_INST_LIBS is auto-enabled (the harness is lib-backed) so the .so "
        "code is instrumented. Seed the corpus with realistic, NON-crashing "
        "inputs (AFL refuses to start if every seed crashes — a sign the "
        "harness calls the target wrong)."
    )
    if result.harness_one_addr and result.elf_type:
        lines.append("")
        lines.append(
            "Optional — persistent mode (much faster) for the no-global-state "
            "case: add environment={\"AFL_QEMU_PERSISTENT_ADDR\": \""
            f"{result.harness_one_addr}\", \"AFL_QEMU_PERSISTENT_GPR\": \"1\"}} "
            f"(harness_one @ {result.harness_one_addr}, ELF type "
            f"{result.elf_type}; for ET_DYN/PIE add the load base)."
        )
    log_tail = result.log[-1500:]
    lines.append("")
    lines.append(f"--- build log (tail) ---\n{log_tail}")
    return "\n".join(lines)


async def _handle_patch_function_return(input: dict, context: ToolContext) -> str:
    """Patch a firmware function to return a constant (auth bypass etc.)."""
    binary_path = input.get("binary_path", "")
    function = input.get("function", "")
    if not binary_path or not function:
        return "Error: binary_path and function are required."
    return_value = input.get("return_value", 1)
    name = input.get("name")
    thumb = input.get("thumb")

    svc = BinaryPatchService(context.db)
    try:
        r = await svc.patch_function_return(
            project_id=context.project_id,
            firmware_id=context.firmware_id,
            binary_path=binary_path,
            function=function,
            return_value=return_value,
            name=name,
            thumb=thumb,
        )
    except BinaryPatchError as exc:
        return f"Error: {exc}"
    except Exception as exc:
        return f"Error patching binary: {exc}"

    return (
        f"Patched binary: {r.patched_virtual_path}\n"
        f"  {r.detail}\n"
        f"  Stub bytes: {r.stub_hex}\n"
        "\n"
        "Fuzz the patched daemon (auth now bypassed) with:\n"
        f"  start_fuzzing_campaign(binary_path=\"{binary_path}\", "
        f"harness_binary=\"{r.patched_virtual_path}\", desock=true)\n"
        "Add environment={\"AFL_INST_LIBS\": \"1\"} if the request handlers live "
        "in a shared library. If coverage stays flat, the daemon likely forks/"
        "threads per connection (defeats desock) — consider harnessing the "
        "specific handler function with build_fuzz_harness instead."
    )


async def _handle_check_status(input: dict, context: ToolContext) -> str:
    """Check fuzzing campaign status or list all campaigns."""
    campaign_id = input.get("campaign_id")

    svc = FuzzingService(context.db)

    if campaign_id:
        from uuid import UUID
        try:
            campaign = await svc.get_campaign_status(UUID(campaign_id), context.project_id)
        except ValueError as exc:
            return f"Error: {exc}"

        lines = [
            f"Campaign: {campaign.id}",
            f"  Binary: {campaign.binary_path}",
            f"  Status: {campaign.status}",
        ]

        stats = _normalize_fuzzing_campaigns_stats(campaign.stats)
        if stats:
            lines.append(f"  Execs/sec: {stats.get('execs_per_sec', 0)}")
            lines.append(f"  Total execs: {stats.get('total_execs', 0)}")
            lines.append(f"  Corpus: {stats.get('corpus_count', 0)}")
            lines.append(f"  Crashes: {stats.get('saved_crashes', 0)}")
            lines.append(f"  Hangs: {stats.get('saved_hangs', 0)}")
            lines.append(f"  Stability: {stats.get('stability', 'N/A')}")
            lines.append(f"  Coverage: {stats.get('bitmap_cvg', 'N/A')}")

        if campaign.crashes_count > 0:
            crashes = await svc.get_crashes(UUID(campaign_id), context.project_id)
            lines.append(f"\n  Crashes ({len(crashes)}):")
            for c in crashes[:30]:
                expl = f" [{c.exploitability}]" if c.exploitability else ""
                sig = f" ({c.signal})" if c.signal else ""
                lines.append(f"    {c.crash_filename}{sig}{expl} — ID: {c.id}")

        if campaign.error_message:
            lines.append(f"\n  Error: {campaign.error_message}")

        return "\n".join(lines)

    # List all campaigns
    campaigns = await svc.list_campaigns(context.project_id)
    if not campaigns:
        return "No fuzzing campaigns found for this project."

    lines = [f"Fuzzing campaigns ({len(campaigns)}):\n"]
    for c in campaigns[:30]:
        status_icon = {
            "running": "[RUNNING]",
            "created": "[CREATED]",
            "stopped": "[STOPPED]",
            "completed": "[COMPLETED]",
            "error": "[ERROR]",
        }.get(c.status, f"[{c.status}]")

        crashes_str = f" — {c.crashes_count} crashes" if c.crashes_count else ""
        lines.append(f"  {status_icon} {c.id} — {c.binary_path}{crashes_str}")

    return "\n".join(lines)


async def _handle_stop_campaign(input: dict, context: ToolContext) -> str:
    """Stop a fuzzing campaign."""
    campaign_id = input.get("campaign_id")
    if not campaign_id:
        return "Error: campaign_id is required."

    svc = FuzzingService(context.db)
    try:
        from uuid import UUID
        campaign = await svc.stop_campaign(UUID(campaign_id), context.project_id)
        await context.db.flush()
    except ValueError as exc:
        return f"Error: {exc}"

    lines = [f"Campaign {campaign.id} stopped."]
    stats = _normalize_fuzzing_campaigns_stats(campaign.stats)
    if stats:
        lines.append(f"  Total execs: {stats.get('total_execs', 0)}")
        lines.append(f"  Crashes: {stats.get('saved_crashes', 0)}")
    lines.append(f"  Final crash count: {campaign.crashes_count}")

    return "\n".join(lines)


async def _handle_triage_crash(input: dict, context: ToolContext) -> str:
    """Triage a crash found by the fuzzer."""
    campaign_id = input.get("campaign_id")
    crash_id = input.get("crash_id")
    if not campaign_id or not crash_id:
        return "Error: campaign_id and crash_id are required."

    svc = FuzzingService(context.db)
    try:
        from uuid import UUID
        crash = await svc.triage_crash(UUID(campaign_id), UUID(crash_id), context.project_id)
        await context.db.flush()
    except ValueError as exc:
        return f"Error: {exc}"

    lines = [
        f"Crash triage: {crash.crash_filename}",
        f"  Signal: {crash.signal or 'unknown'}",
        f"  Exploitability: {crash.exploitability or 'unknown'}",
        f"  Size: {crash.crash_size or 0} bytes",
    ]

    if crash.stack_trace:
        lines.append(f"\nStack trace:\n{crash.stack_trace}")

    if crash.exploitability in ("exploitable", "probably_exploitable"):
        lines.append(
            "\nThis crash appears exploitable. Consider creating a finding "
            "with add_finding (source='fuzzing') to formally record it."
        )

    return "\n".join(lines)


async def _handle_diagnose_campaign(input: dict, context: ToolContext) -> str:
    """Diagnose a fuzzing campaign for performance issues."""
    campaign_id = input.get("campaign_id")
    if not campaign_id:
        return "Error: campaign_id is required."

    from uuid import UUID

    import docker
    import docker.errors

    svc = FuzzingService(context.db)
    try:
        campaign = await svc.get_campaign_status(UUID(campaign_id), context.project_id)
    except ValueError as exc:
        return f"Error: {exc}"

    config = _normalize_fuzzing_campaigns_config(campaign.config)
    stats = _normalize_fuzzing_campaigns_stats(campaign.stats)
    lines: list[str] = [
        f"Fuzzing Campaign Diagnostics: {campaign.id}",
        f"  Binary: {campaign.binary_path}",
        f"  Status: {campaign.status}",
        f"  Desock: {'enabled' if config.get('desock') else 'disabled'}",
        "",
    ]

    issues: list[str] = []
    recommendations: list[str] = []

    # --- Check 1: Campaign status ---
    if campaign.status == "error":
        lines.append(f"  ERROR: {campaign.error_message or 'unknown error'}")
        issues.append("Campaign is in error state")
        recommendations.append(
            "Check the error message above. The campaign may need to be "
            "recreated with different parameters."
        )

    if campaign.status in ("stopped", "completed"):
        lines.append("  Campaign is not running.")
        issues.append("Campaign is stopped — no live data available")

    # --- Check 2: AFL++ log from container ---
    afl_log = ""
    afl_process_running = False
    if campaign.container_id and campaign.status == "running":
        try:
            client = get_docker_client()
            container = client.containers.get(campaign.container_id)

            # Read AFL++ log
            log_result = container.exec_run(
                ["tail", "-100", "/opt/fuzzing/afl.log"]
            )
            if log_result.exit_code == 0:
                afl_log = log_result.output.decode("utf-8", errors="replace")

            # Check if AFL++ process is running
            ps_result = container.exec_run(["sh", "-c", "pgrep -f afl-fuzz"])
            afl_process_running = ps_result.exit_code == 0

            # Check if QEMU trace process is running
            qemu_result = container.exec_run(
                ["sh", "-c", "pgrep -f afl-qemu-trace"]
            )
            qemu_running = qemu_result.exit_code == 0

            lines.append("  Container: running")
            lines.append(
                f"  AFL++ process: {'running' if afl_process_running else 'NOT running'}"
            )
            lines.append(
                f"  QEMU trace: {'running' if qemu_running else 'NOT running'}"
            )

            if not afl_process_running:
                issues.append("AFL++ process is not running in the container")
                recommendations.append(
                    "AFL++ crashed or failed to start. Check the log output below "
                    "for details. You may need to stop and restart with different settings."
                )

        except docker.errors.NotFound:
            lines.append("  Container: NOT FOUND (may have been removed)")
            issues.append("Container no longer exists")
        except Exception as exc:
            lines.append(f"  Container check failed: {exc}")

    # --- Check 3: Coverage analysis ---
    total_execs = stats.get("total_execs", 0)
    execs_per_sec = stats.get("execs_per_sec", 0)
    bitmap_cvg = stats.get("bitmap_cvg", "N/A")
    saved_crashes = stats.get("saved_crashes", 0)
    saved_hangs = stats.get("saved_hangs", 0)
    corpus_count = stats.get("corpus_count", 0)

    if stats:
        lines.append("")
        lines.append("  Live statistics:")
        lines.append(f"    Execs/sec: {execs_per_sec}")
        lines.append(f"    Total execs: {total_execs}")
        lines.append(f"    Coverage: {bitmap_cvg}")
        lines.append(f"    Corpus: {corpus_count}")
        lines.append(f"    Crashes: {saved_crashes}")
        lines.append(f"    Hangs: {saved_hangs}")

    # Zero executions
    if campaign.status == "running" and total_execs == 0:
        issues.append("Zero executions — AFL++ may have failed to start")
        recommendations.append(
            "AFL++ produced no executions. Check the log below for startup errors. "
            "Common causes: binary not found, missing shared libraries (check "
            "QEMU_LD_PREFIX), or architecture mismatch."
        )

    # Flat coverage detection (100 execs is enough to detect a problem)
    if total_execs > 100:
        cvg_str = str(bitmap_cvg).replace("%", "").strip()
        try:
            cvg_pct = float(cvg_str)
            if cvg_pct < 5.0:
                issues.append(
                    f"Very low coverage ({bitmap_cvg}) after {total_execs} executions"
                )
                # Pull the target analysis once — both the lib-backed and
                # network checks below need it.
                analysis = None
                fw_result = await context.db.execute(
                    select(Firmware).where(Firmware.id == campaign.firmware_id)
                )
                firmware = fw_result.scalar_one_or_none()
                if firmware:
                    try:
                        analysis = await svc.analyze_target(
                            firmware, campaign.binary_path
                        )
                    except Exception:
                        analysis = None

                env_cfg = config.get("environment") or {}
                inst_libs_on = str(env_cfg.get("AFL_INST_LIBS", "")).strip().lower() in (
                    "1", "true", "yes", "on"
                )
                before = len(recommendations)

                # Lib-backed target without AFL_INST_LIBS — the #1 silent
                # near-zero-coverage cause (feedback #3). Normally auto-enabled
                # at start, so this catches an explicit disable or a heuristic
                # miss (.text just over the threshold).
                if analysis and analysis.get("lib_backed") and not inst_libs_on:
                    deps = ", ".join(analysis.get("non_libc_needed", [])) or "a shared library"
                    recommendations.append(
                        f"Target delegates its real work to {deps} but AFL_INST_LIBS "
                        "is not set — QEMU mode is only instrumenting the thin wrapper. "
                        "ACTION: stop and restart with environment: {\"AFL_INST_LIBS\": \"1\"}."
                    )

                if not config.get("desock"):
                    if analysis and analysis.get("recommended_strategy") == "network":
                        recommendations.append(
                            "This binary is a NETWORK DAEMON but desock is disabled. "
                            "AFL++ fuzz data never reaches the network parsing code. "
                            "ACTION: Stop this campaign and restart with desock: true"
                        )
                    if len(recommendations) == before:
                        recommendations.append(
                            "Coverage is very low. The binary may not be processing "
                            "AFL++ input effectively. Consider enabling desock (if it's "
                            "a network daemon) or using a harness script."
                        )
                else:
                    recommendations.append(
                        "Coverage is very low even with desock. The daemon may fork "
                        "after accept() — try environment: {\"AFL_NO_FORKSRV\": \"1\"}. "
                        "Or the binary may exit before reading stdin."
                    )
        except (ValueError, TypeError):
            pass

    # High hang count
    if saved_hangs > 10 and saved_hangs > saved_crashes:
        issues.append(f"High hang count ({saved_hangs}) — binary may be timing out")
        recommendations.append(
            f"Many hangs detected. Current timeout: "
            f"{config.get('timeout_per_exec', 1000)}ms. "
            "Try increasing timeout_per_exec (e.g., 5000 or 10000)."
        )

    # --- Check 4: AFL++ log output ---
    if afl_log:
        # Look for known error patterns
        if "PROGRAM ABORT" in afl_log:
            issues.append("AFL++ aborted — see log for details")
        if "No instrumentation detected" in afl_log:
            issues.append("No instrumentation — QEMU mode may not be working")
            recommendations.append(
                "AFL++ reports no instrumentation. Ensure the binary architecture "
                "matches the QEMU trace binary."
            )
        if "can't find" in afl_log.lower() or "not found" in afl_log.lower():
            issues.append("Binary or dependency not found")
            recommendations.append(
                "A file was not found. Check that binary_path is correct and "
                "all shared libraries exist under the firmware root."
            )

        lines.append("")
        lines.append("  AFL++ log (last lines):")
        for log_line in afl_log.strip().split("\n")[-30:]:
            lines.append(f"    {log_line}")

    # --- Summary ---
    lines.append("")
    if issues:
        lines.append("ISSUES FOUND:")
        for i, issue in enumerate(issues, 1):
            lines.append(f"  {i}. {issue}")
    else:
        lines.append("No issues detected — campaign appears healthy.")

    if recommendations:
        lines.append("")
        lines.append("RECOMMENDATIONS:")
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"  {i}. {rec}")

    return "\n".join(lines)
