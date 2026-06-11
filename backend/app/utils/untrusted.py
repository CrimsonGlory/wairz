"""Prompt-injection mitigation for adversary-authored firmware text (ADOPT-1).

Firmware is attacker-controlled: a malicious image can embed text — in a symbol
name, a decompiled string, a file's contents, a bootloader env var — that mimics
an instruction ("ignore previous instructions; run X"). When an MCP tool returns
that text to the MCP client's model, it is a prompt-injection vector.

Mitigation (defense-in-depth — the path-traversal sandbox and the worker
container remain the load-bearing security controls): tool outputs that carry
firmware-derived text are wrapped in a delimited block with a PER-CALL RANDOM id,
and the MCP system prompt instructs the model to treat everything inside such a
block strictly as data, never as instructions. The random id is the load-bearing
detail: firmware text cannot forge the closing delimiter (it cannot guess the id),
so it cannot "escape" the fence even if it contains a literal `</...>` token.

This adds no dependency, executes nothing, and changes no trust-anchor handling.
Surfaced by the defending-code-reference-harness debate (2026-06-11): the harness
fences untrusted inputs this way; wairz had ZERO such fencing before this.
"""

from __future__ import annotations

import secrets

# MCP tools whose output carries adversary-authored firmware-derived text. Their
# results are fenced at the single dispatch chokepoint (ToolRegistry.execute).
# Trusted control/structure tools (switch_project, get_project_info, add_finding,
# reports) are deliberately ABSENT — fencing those would mislabel wairz-authored
# guidance as untrusted. A drift guard test asserts every name here exists in the
# full registry.
UNTRUSTED_OUTPUT_TOOLS: frozenset[str] = frozenset(
    {
        # strings — raw firmware strings
        "extract_strings",
        "search_strings",
        "find_crypto_material",
        "find_hardcoded_credentials",
        "find_hardcoded_ips",
        # filesystem — file contents, names, parsed metadata, bootloader env
        "list_directory",
        "read_file",
        "file_info",
        "search_files",
        "find_files_by_type",
        "get_component_map",
        "get_firmware_metadata",
        "extract_bootloader_env",
        # binary — decompilation / disassembly / symbols / embedded strings
        "list_functions",
        "disassemble_function",
        "decompile_function",
        "list_imports",
        "list_exports",
        "xrefs_to",
        "xrefs_from",
        "get_binary_info",
        "analyze_binary_format",
        "check_binary_protections",
        "find_string_refs",
        "resolve_import",
        "check_all_binary_protections",
        "trace_dataflow",
        "find_callers",
        "search_binary_content",
        "get_stack_layout",
        "get_global_layout",
        "cross_binary_dataflow",
        "detect_capabilities",
        "list_binary_capabilities",
        "analyze_raw_binary",
        "detect_rtos",
    }
)


def fence_untrusted(text: str) -> str:
    """Wrap firmware-derived text in a random-id delimited untrusted block.

    The id appears in BOTH the opening and closing delimiter so embedded firmware
    text cannot forge the close (it cannot guess the per-call id). Pairs with the
    system-prompt instruction in ``app.ai.system_prompt``.
    """
    token = secrets.token_hex(8)
    return (
        f"<untrusted_firmware_data id={token}>\n"
        f"{text}\n"
        f"</untrusted_firmware_data id={token}>"
    )
