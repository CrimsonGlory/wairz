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
        # --- Slice 2: remaining firmware/adversary-derived-text categories ---
        # android — the APK IS the firmware artifact
        "analyze_apk",
        "list_apk_permissions",
        "check_apk_signatures",
        "scan_apk_manifest",
        "scan_apk_bytecode",
        "scan_apk_sast",
        # network — pcap contents are attacker-authored traffic
        "analyze_network_traffic",
        "get_protocol_breakdown",
        "identify_insecure_protocols",
        "get_dns_queries",
        "get_network_conversations",
        # uefi — firmware volumes / modules / NVRAM
        "list_firmware_volumes",
        "list_uefi_modules",
        "extract_nvram_variables",
        "identify_uefi_module",
        "read_uefi_module",
        # hardware firmware — blobs / drivers / DTB / HBOM
        "lookup_similar_blobs_across_firmwares",
        "list_hardware_firmware",
        "analyze_hardware_firmware",
        "list_firmware_drivers",
        "find_unsigned_firmware",
        "export_hardware_firmware_hbom",
        "extract_dtb",
        # comparison — firmware/binary/decompilation diffs
        "list_firmware_versions",
        "diff_firmware",
        "diff_binary",
        "diff_decompilation",
        # uart — device serial OUTPUT (adversarial for a compromised device)
        "uart_read",
        "uart_get_transcript",
        "uart_send_command",
        "uart_send_raw",
        # security — tools that echo extracted firmware text (certs, scripts,
        # config, policy, yara matches). Pure wairz verdicts / NVD / external
        # threat-intel / CRA-authoring tools are deliberately NOT fenced.
        "analyze_config_security",
        "check_setuid_binaries",
        "analyze_init_scripts",
        "check_filesystem_permissions",
        "analyze_certificate",
        "scan_with_yara",
        "extract_kernel_config",
        "analyze_selinux_policy",
        "scan_scripts",
        "shellcheck_scan",
        "bandit_scan",
        # sbom — component inventory (names/versions parsed from firmware)
        "generate_sbom",
        "get_sbom_components",
        "export_sbom",
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
