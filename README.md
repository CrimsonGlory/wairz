<p align="center">
  <img src="frontend/src/assets/wairz_banner.png" alt="Wairz - Every Firmware Has Secrets... WAIRZ Finds Them" width="100%">
</p>

---

Upload firmware images, unpack them, explore the filesystem, analyze binaries, and conduct security assessments — all powered by AI analysis via [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

Connect any MCP-compatible AI agent to Wairz's 383 analysis tools — [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Claude Desktop](https://claude.ai/download), [OpenCode](https://opencode.ai/), [Codex](https://github.com/openai/codex), [Cursor](https://cursor.com/), [VS Code + Copilot](https://code.visualstudio.com/docs/copilot/), [Gemini CLI](https://github.com/google-gemini/gemini-cli), [Windsurf](https://windsurf.com/), and more.

[Watch the demo video](https://www.youtube.com/watch?v=gDLhtMFMmMM)

## Features

- **Firmware Unpacking** — Automatic extraction of SquashFS, JFFS2, UBIFS, CramFS, ext, CPIO, and Intel HEX filesystems via binwalk3 and unblob, with multi-partition support
- **RTOS Support** — Auto-classifies firmware as `linux | rtos | unknown` on unpack (FreeRTOS / Zephyr / baremetal Cortex-M), with manual override. RTOS projects get a dedicated tool category for vector-table parsing, task enumeration, base-address recovery, and memory-map analysis on raw `.axf` / `.elf` blobs
- **File Explorer** — Browse extracted filesystems with a virtual tree, view text/binary/hex content, and search across files
- **Binary Analysis** — Disassemble and decompile binaries using radare2 and Ghidra headless, with cross-reference, taint analysis, and capability detection (capa)
- **Component Map** — Interactive dependency graph showing binaries, libraries, scripts, and their relationships
- **Security Assessment** — Detect hardcoded credentials, crypto material, hardcoded IPs, setuid binaries, insecure configs, weak permissions, and network dependencies
- **Attack Surface Scoring** — Automated 0-100 risk scoring across network exposure, CGI, setuid, dangerous functions, and known daemons
- **SAST** — ShellCheck for shell scripts and Bandit for Python scripts, with CWE mapping
- **cwe_checker** — Binary vulnerability pattern detection (17 CWEs) via Docker sidecar with ARM/MIPS/x86 support
- **YARA Scanning** — Custom rules + ~5000 YARA Forge community rules, with on-demand updates
- **Threat Intelligence** — ClamAV malware scanning, VirusTotal hash lookups (privacy-first, no file upload), abuse.ch suite (MalwareBazaar, ThreatFox, URLhaus, YARAify), and CIRCL Hashlookup for known-good binary identification via NSRL
- **SBOM & CVE Scanning** — Generate Software Bill of Materials (CycloneDX 1.7, SPDX 2.3, CycloneDX VEX) with generic binary version detection fallback, CPE enrichment via NVD dictionary, and vulnerability scanning against the NVD
- **Firmware Emulation** — User-mode (QEMU) for single binaries, system-mode (FirmAE) for full OS boot in isolated containers, with GDB, pcap capture, and web endpoint interaction
- **Network Protocol Analysis** — Capture and analyze traffic from emulated firmware: protocol breakdown, insecure protocol detection, DNS queries, TLS metadata
- **Fuzzing** — AFL++ with QEMU mode for cross-architecture binary fuzzing, with automatic dictionary/corpus generation and crash triage
- **Firmware Comparison** — Diff filesystem trees, binaries, and decompiled functions across firmware versions
- **RTOS & Bare-Metal Support** — Detection of FreeRTOS, VxWorks, Zephyr, ThreadX and companion components (lwIP, FatFs, etc.)
- **UEFI Firmware Support** — UEFIExtract for firmware volumes, module listing, NVRAM variable extraction, and PE32+ scanning
- **Android Firmware** — Multi-phase APK security scanning: 18 manifest security checks (MobSF-equivalent), DEX bytecode pattern detection (~30 insecure API patterns), jadx decompilation + mobsfscan SAST (43 rules), with firmware-aware severity adjustment for system/priv-app APKs. Includes batch scanning of all APKs, decompiled source viewer, permission analysis, signature verification, and Android device-posture auditing
- **Device Acquisition** — Pull firmware directly from ADB-connected Android devices via a host-side bridge
- **Firmware Update Detection** — Identify SWUpdate, RAUC, Mender, opkg, U-Boot, and custom update mechanisms with security gap analysis
- **CRA Compliance** — EU Cyber Resilience Act Annex I assessment (20 requirements), auto-populate from existing findings, Article 14 notification export
- **Live Device UART** — Connect to physical devices via a host-side serial bridge for interactive console access
- **Windows Forensic Artifacts** — Registry hives, EVTX event logs, Prefetch, SRUM, MFT, USN Journal, LNK files, Scheduled Tasks, WMI persistence, DPAPI master keys, EFS-encrypted files, BCD/ESP boot chain, MBR/VBR, ETL traces, AppCompat/Shim DB, driver signing & BYOVD detection, .NET single-file bundles & R2R stomping, and archive/installer formats (MSI, MSIX, MSU, CAB, INF)
- **Linux Forensic Artifacts** — systemd units, journald logs, container artifacts, persistence mechanisms, and kernel hardening config, each with cross-firmware lookup
- **ICS/OT Protocol Detection** — Extensible YAML-driven catalog identifying Modbus/TCP, DNP3, Siemens S7comm, and other industrial protocols embedded in firmware
- **Bare-Metal / MCU Chip Analysis** — Schema-driven chip-family catalog (e.g. TI C28x DSPs) for security posture auditing of raw MCU/DSP firmware blobs, extensible via operator-supplied YAML descriptors
- **Firmware Carving Sandbox** — Isolated, network-less shell environment with a full reverse-engineering toolset (binwalk, unsquashfs, jefferson, ubireader, mkimage, etc.) for manual extraction of non-standard vendor envelopes
- **Cross-Firmware Lookup** — Dozens of `lookup_*_across_firmwares` MCP tools let an agent query artifacts (drivers, registry keys, systemd units, ICS protocols, chip families, and more) across the entire project corpus in one call, not just the active firmware
- **Ghidra Research Workspace** — Persistent research scripts, logs, and archive imports across sessions, plus a `run_ghidra_headless` tool for ad hoc headless analysis
- **AI Analysis via MCP** — 383 analysis tools (across 34 categories) exposed to any MCP-compatible AI agent for autonomous security research
- **Findings & Reports** — Record security findings with severity ratings and evidence, export as Markdown or a structured narrative report, with full assessment orchestration

## Architecture

```
Claude Code / Claude Desktop / OpenCode
        │
        │ MCP (stdio)
        ▼
┌─────────────────┐     ┌──────────────────────────────────┐
│   wairz-mcp     │────▶│         FastAPI Backend           │
│  (MCP server)   │     │                                    │
│  383 tools      │     │  Services: firmware, analysis,     │
│                 │     │  emulation, fuzzing, sbom, uart    │
└─────────────────┘     │                                    │
                        │  Ghidra headless · QEMU · AFL++    │
                        └──────────┬───────────────────────┘
                                   │
┌──────────────┐    ┌──────────────┼──────────────┐
│   React SPA  │───▶│  PostgreSQL  │  Redis       │
│  (Frontend)  │    │              │              │
└──────────────┘    └──────────────┴──────────────┘

Optional:
  wairz-uart-bridge.py (host) ←─ TCP:9999 ─→ Docker backend
```

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (for local development only)

## About This Fork

This repository is a fork of [digitalandrew/wairz](https://github.com/digitalandrew/wairz) with a large number of additional commits on top of upstream, growing the MCP tool surface from upstream's baseline to 383 tools across 34 categories:

- **eastmadc** — a broad expansion of the analysis "walker" pipeline and corresponding MCP tools: a large suite of Windows forensic artifact parsers (registry hives, EVTX event logs, Prefetch, SRUM, MFT, USN Journal, LNK, Scheduled Tasks, WMI persistence, DPAPI, EFS, BCD/ESP boot chain, MBR/VBR, ETL traces, AppCompat/Shim DB, driver signing & BYOVD, .NET bundles, and archive/installer formats), Linux forensic artifact parsers (systemd, journald, containers, persistence, kernel hardening), ICS/OT protocol detection, a schema-driven bare-metal/MCU chip-family catalog, Android posture auditing, a firmware carving sandbox, and hardware-firmware/SBOM extensions — each with its own MCP tools, migrations, and (where applicable) cross-firmware lookup support.
- **CrimsonGlory** — mainly focused on making the Ghidra MCP integration more flexible: support for raw MIPS16E binaries, a `run_ghidra_headless` tool, persistent Ghidra research files/scripts/logs across sessions, plus assorted CI, lint, and dev-server (CORS/host-check) fixes.

See the git history for the full list of changes relative to upstream.

## Public Beta

WAIRZ is currently in **public beta**. You may encounter bugs or rough edges. If you run into any issues, please [open an issue on GitHub](https://github.com/digitalandrew/wairz/issues) or reach out at andrew@digitalandrew.io.

WAIRZ supports **embedded Linux**, **RTOS/bare-metal** (FreeRTOS, VxWorks, Zephyr, ThreadX), **UEFI**, and **Android** firmware. Auto-detection runs on unpack and can be overridden from the project page. Linux-specific tools (emulation, init-script analysis, SBOM, etc.) are hidden on RTOS projects, and a dedicated RTOS tool category is exposed in their place. See [RTOS support](docs/features/rtos.md) for details.

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/digitalandrew/wairz.git
cd wairz
cp .env.example .env
# Edit .env and set POSTGRES_PASSWORD and FIRMAE_DB_PASSWORD to strong random values:
#   python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
# (Any value works for a fresh local install; the placeholder will not start the stack.)
docker compose up --build
```

- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs

### Docker with Hot-Reload (development)

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Backend Python changes are picked up automatically via uvicorn `--reload`. Frontend uses Vite dev server with HMR. No rebuild needed for code changes — only rebuild when dependencies change (`pyproject.toml` or `package.json`).

### Local Development

```bash
# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Backend
cd backend
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Or use the helper script:

```bash
./launch.sh
```

## Connecting AI via MCP

Wairz uses MCP to give AI agents access to firmware analysis tools. After starting the backend, register the MCP server with your preferred client:

`--project-id` is optional — omit it on shared/team instances where you want to switch between projects from inside the agent. The agent will call `list_projects` on first use and ask which project you mean.

### Claude Code

```bash
claude mcp add wairz -- docker exec -i wairz-backend-1 uv run wairz-mcp --project-id <PROJECT_ID>
```

For a shared Wairz server reached over SSH (no project pinned at boot):

```bash
claude mcp add wairz -- ssh wairz-host docker exec -i wairz-backend-1 uv run wairz-mcp
```

### Claude Desktop

Add to your Claude Desktop config (`~/.config/Claude/claude_desktop_config.json` on Linux, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "wairz": {
      "command": "docker",
      "args": [
        "exec", "-i", "wairz-backend-1",
        "uv", "run", "wairz-mcp",
        "--project-id", "<PROJECT_ID>"
      ]
    }
  }
}
```

### OpenCode

Add to your `opencode.json` (project root or `~/.config/opencode/opencode.json`):

```json
{
  "mcp": {
    "wairz": {
      "type": "local",
      "command": ["docker", "exec", "-i", "wairz-backend-1", "uv", "run", "wairz-mcp", "--project-id", "<PROJECT_ID>"],
      "timeout": 30000,
      "enabled": true
    }
  }
}
```

> **Note:** The `timeout` must be increased from the default 5000ms because Wairz registers 383 tools.

Once connected, your AI agent can autonomously explore firmware, analyze binaries, run emulation, fuzz targets, and generate security findings. The MCP server supports dynamic project switching via the `switch_project` tool — no restart needed to change projects.

#### Projects with multiple firmware versions

When a project has more than one firmware uploaded (useful for diffing across versions via `diff_firmware`), the MCP server picks the earliest-uploaded unpacked firmware by default. To target a specific version, add `--firmware-id <FIRMWARE_ID>` to the launch command, or pass `firmware_id` to the `switch_project` MCP tool. Use `list_firmware_versions` to find IDs.

### MCP Tools (383 across 34 categories)

Source-of-truth count: `create_tool_registry()` (`backend/app/ai/__init__.py`) registers 379 tools across 32 category files under `backend/app/ai/tools/`; `backend/app/mcp_server.py` registers 4 more directly (`get_project_info`, `switch_project`, `list_projects`, `save_code_cleanup`) for 383 total.

| Category | Count | Tools |
|----------|-------|-------|
| **Windows Forensics** | 126 | `list_appcompat_entries`, `lookup_appcompat_entry`, `lookup_appcompat_entry_across_firmwares`, `appcompat_walk_status`, `trigger_appcompat_walk`, `list_cab_contents`, `read_msix_manifest`, `dump_msi_custom_actions`, `parse_inf_basic`, `identify_psf_baseline`, `classify_driver_package_subtype`, `search_bcd_entries`, `bcd_walk_status`, `trigger_bcd_walk`, `lookup_bcd_entry_across_firmwares`, `list_dotnet_bundles`, `get_bundle_metadata`, `list_extracted_assemblies`, `get_assembly_il`, `scan_r2r_stomping`, `trigger_dotnet_decompile`, `list_dpapi_master_keys`, `lookup_dpapi_master_key`, `lookup_dpapi_master_key_across_firmwares`, `dpapi_walk_status`, `trigger_dpapi_walk`, `list_drivers`, `get_driver_info`, `list_signed_drivers`, `get_signing_tier_histogram`, `scan_inf_imports`, `diff_driver_matrix`, `lookup_byovd_driver`, `list_efs_encrypted_files`, `lookup_efs_encrypted_file`, `search_efs_by_sid`, `efs_walk_status`, `trigger_efs_walk`, `lookup_efs_recovery_agent_across_firmwares`, `search_esp_entries`, `esp_walk_status`, `trigger_esp_walk`, `lookup_esp_chain`, `lookup_esp_entry_across_firmwares`, `list_etl_events`, `lookup_etl_event`, `search_etl_events`, `etl_walk_status`, `trigger_etl_walk`, `lookup_etl_provider_across_firmwares`, `list_evtx_files`, `parse_evtx_file`, `query_evtx_events`, `evtx_walk_status`, `trigger_evtx_walk`, `search_events`, `evtx_walk_summary`, `lookup_event_record_across_firmwares`, `list_windows_injection_detections`, `windows_injection_walk_status`, `trigger_windows_injection_walk`, `lookup_volatility_injection_across_firmwares`, `search_lnk_records`, `lnk_walk_status`, `trigger_lnk_walk`, `lookup_lnk_record_across_firmwares`, `list_mbr_vbr_sectors`, `lookup_mbr_vbr_sector`, `lookup_mbr_vbr_sector_across_firmwares`, `search_mft_records`, `mft_walk_status`, `lookup_mft_record_across_firmwares`, `trigger_mft_walk`, `verify_authenticode`, `decode_rich_header`, `scan_dbx_revocation`, `detect_pe_arch_view`, `list_signatures`, `get_signature_chain`, `search_prefetch_records`, `prefetch_walk_status`, `trigger_prefetch_walk`, `lookup_prefetch_record_across_firmwares`, `list_windows_processes`, `windows_processes_walk_status`, `trigger_windows_processes_walk`, `lookup_windows_process_across_firmwares`, `list_hives`, `walk_hive`, `get_run_keys`, `scan_persistence`, `dump_subkey`, `diff_hives`, `trigger_registry_hive_walk`, `lookup_registry_extract_across_firmwares`, `search_scheduled_tasks`, `scheduled_task_walk_status`, `trigger_scheduled_task_walk`, `lookup_scheduled_task_across_firmwares`, `list_sdb_entries`, `lookup_sdb_shim`, `summarize_sdb_anomalies`, `lookup_sdb_entry_across_firmwares`, `search_srum_records`, `srum_walk_status`, `trigger_srum_walk`, `lookup_srum_record_across_firmwares`, `list_vhdx_partitions`, `list_bcd_entries`, `list_esedb_tables`, `dump_esedb_table`, `get_storage_summary`, `list_update_packages`, `get_package_metadata`, `get_supersedence_chain`, `list_kb_files`, `diff_kb_packages`, `list_usnjrnl_entries`, `lookup_usnjrnl_entry`, `lookup_usnjrnl_entry_across_firmwares`, `usnjrnl_walk_status`, `trigger_usnjrnl_walk`, `search_wmi_events`, `wmi_walk_status`, `trigger_wmi_walk`, `lookup_wmi_persistence` |
| **Linux Forensics** | 27 | `list_journald_entries`, `lookup_journald_entry`, `search_journald_messages`, `journald_walk_status`, `trigger_journald_walk`, `lookup_journald_entry_across_firmwares`, `list_systemd_units`, `lookup_systemd_unit`, `search_systemd_units`, `systemd_walk_status`, `trigger_systemd_walk`, `lookup_systemd_unit_across_firmwares`, `list_container_artifacts`, `lookup_container_artifact`, `search_container_images`, `container_walk_status`, `trigger_container_walk`, `lookup_container_image_across_firmwares`, `list_linux_persistence_entries`, `lookup_linux_persistence_entry`, `lookup_linux_persistence_across_firmwares`, `linux_persistence_walk_status`, `trigger_linux_persistence_walk`, `audit_kernel_config_firmware`, `lookup_kernel_config_across_firmwares`, `trigger_kernel_config_walk`, `get_kernel_config_extraction` |
| **Security** | 26 | `check_known_cves`, `analyze_config_security`, `check_setuid_binaries`, `analyze_init_scripts`, `check_filesystem_permissions`, `analyze_certificate`, `check_kernel_hardening`, `scan_with_yara`, `extract_kernel_config`, `check_kernel_config`, `analyze_selinux_policy`, `check_selinux_enforcement`, `check_compliance`, `scan_scripts`, `shellcheck_scan`, `bandit_scan`, `check_secure_boot`, `update_yara_rules`, `detect_network_dependencies`, `detect_update_mechanisms`, `analyze_update_config`, `create_cra_assessment`, `auto_populate_cra`, `update_cra_requirement`, `export_cra_checklist`, `generate_article14_notification` |
| **Binary Analysis** | 29 | `start_binary_analysis`, `check_binary_analysis_status`, `start_function_decompile`, `check_function_decompile_status`, `list_functions`, `disassemble_function`, `decompile_function`, `batch_decompile_functions`, `list_imports`, `list_exports`, `xrefs_to`, `xrefs_from`, `get_binary_info`, `analyze_binary_format`, `check_binary_protections`, `find_string_refs`, `resolve_import`, `check_all_binary_protections`, `trace_dataflow`, `find_callers`, `search_binary_content`, `get_stack_layout`, `get_global_layout`, `cross_binary_dataflow`, `detect_capabilities`, `list_binary_capabilities`, `analyze_raw_binary`, `detect_rtos`, `get_ghidra_analysis_logs` |
| **Emulation** | 25 | `list_available_kernels`, `download_kernel`, `start_emulation`, `run_command_in_emulation`, `stop_emulation`, `check_emulation_status`, `get_emulation_logs`, `diagnose_emulation_environment`, `troubleshoot_emulation`, `enumerate_emulation_services`, `get_crash_dump`, `run_gdb_command`, `save_emulation_preset`, `list_emulation_presets`, `start_emulation_from_preset`, `emulate_with_qiling`, `check_qiling_rootfs`, `start_system_emulation`, `system_emulation_status`, `list_firmware_services`, `run_command_in_firmware`, `stop_system_emulation`, `capture_network_traffic`, `get_nvram_state`, `interact_web_endpoint` |
| **Hardware Firmware** | 10 | `list_hardware_firmware`, `analyze_hardware_firmware`, `list_firmware_drivers`, `check_firmware_cves`, `find_unsigned_firmware`, `export_hardware_firmware_hbom`, `extract_dtb`, `verify_cve_attribution`, `describe_advisory`, `list_extension_points` |
| **Threat Intelligence** | 10 | `scan_with_clamav`, `scan_firmware_clamav`, `check_virustotal`, `scan_firmware_virustotal`, `check_malwarebazaar_hash`, `check_threatfox_ioc`, `check_urlhaus_url`, `enrich_firmware_threat_intel`, `check_known_good_hash`, `scan_firmware_known_good` |
| **Android** | 9 | `analyze_apk`, `list_apk_permissions`, `check_apk_signatures`, `scan_apk_manifest`, `scan_apk_bytecode`, `scan_apk_sast`, `trigger_android_posture_walk`, `get_android_posture`, `lookup_android_posture_across_firmwares` |
| **Fuzzing** | 9 | `analyze_fuzzing_target`, `generate_fuzzing_dictionary`, `generate_seed_corpus`, `generate_fuzzing_harness`, `start_fuzzing_campaign`, `check_fuzzing_status`, `stop_fuzzing_campaign`, `triage_fuzzing_crash`, `diagnose_fuzzing_campaign` |
| **SBOM** | 9 | `generate_sbom`, `get_sbom_components`, `check_component_cves`, `run_vulnerability_scan`, `list_vulnerabilities_for_assessment`, `export_sbom`, `push_to_dependency_track`, `assess_vulnerabilities`, `set_vulnerability_status` |
| **Ghidra Research** | 9 | `list_ghidra_research_files`, `read_ghidra_script`, `save_ghidra_script`, `import_ghidra_archive`, `get_ghidra_import_status`, `resolve_firmware_path`, `run_ghidra_headless`, `list_ghidra_logs`, `read_ghidra_log` |
| **Documents** | 7 | `read_scratchpad`, `update_scratchpad`, `save_document`, `read_project_instructions`, `list_project_documents`, `read_project_document`, `save_code_cleanup` |
| **Filesystem** | 8 | `list_directory`, `read_file`, `search_files`, `file_info`, `find_files_by_type`, `get_component_map`, `get_firmware_metadata`, `extract_bootloader_env` |
| **UART** | 8 | `uart_connect`, `uart_send_command`, `uart_read`, `uart_send_break`, `uart_send_raw`, `uart_disconnect`, `uart_status`, `uart_get_transcript` |
| **Reporting** | 6 | `add_finding`, `list_findings`, `update_finding`, `generate_assessment_report`, `generate_executive_summary`, `run_full_assessment` |
| **Strings** | 5 | `extract_strings`, `search_strings`, `find_crypto_material`, `find_hardcoded_credentials`, `find_hardcoded_ips` |
| **Network** | 5 | `analyze_network_traffic`, `get_protocol_breakdown`, `identify_insecure_protocols`, `get_dns_queries`, `get_network_conversations` |
| **UEFI** | 5 | `list_firmware_volumes`, `list_uefi_modules`, `extract_nvram_variables`, `identify_uefi_module`, `read_uefi_module` |
| **RTOS** *(applies_to `rtos`)* | 5 | `detect_rtos_kernel`, `enumerate_rtos_tasks`, `analyze_vector_table`, `recover_base_address`, `analyze_memory_map` |
| **Comparison** | 4 | `list_firmware_versions`, `diff_firmware`, `diff_binary`, `diff_decompilation` |
| **Bare-Metal / MCU** | 4 | `list_chip_families`, `audit_bare_metal_firmware`, `submit_bare_metal_descriptor`, `lookup_bare_metal_findings_across_firmwares` |
| **ICS Protocol** | 4 | `trigger_ics_protocol_walk`, `list_ics_protocols`, `lookup_ics_protocol_across_firmwares`, `describe_ics_protocol_anomalies` |
| **Python AST** | 4 | `python_ast_walk_status`, `trigger_python_ast_walk`, `get_python_ast_summary`, `lookup_python_ast_across_firmwares` |
| **Project** | 3 | `get_project_info`, `switch_project`, `list_projects` |
| **cwe_checker** | 3 | `cwe_check_status`, `cwe_check_binary`, `cwe_check_firmware` |
| **VulHunt** | 3 | `vulhunt_scan_binary`, `vulhunt_scan_firmware`, `vulhunt_check_available` |
| **Report Writer** | 3 | `report_start`, `report_write_section`, `report_render` |
| **File Format Detection** | 3 | `validate_file_format`, `list_file_formats`, `cross_firmware_format_collision_audit` |
| **Module Reachability** | 3 | `trigger_module_reachability_walk`, `get_module_reachability`, `lookup_module_across_firmwares` |
| **Network Exposure** | 3 | `trigger_network_exposure_walk`, `get_network_exposure`, `lookup_network_listener_across_firmwares` |
| **DS1QRSetup Callgraph** | 3 | `ds1qrsetup_callgraph_walk_status`, `trigger_ds1qrsetup_callgraph_walk`, `lookup_ds1qrsetup_callgraph_across_firmwares` |
| **Attack Surface** | 2 | `detect_input_vectors`, `analyze_binary_attack_surface` |
| **Taint LLM** | 2 | `scan_taint_analysis`, `deep_dive_taint_analysis` |
| **Carving Sandbox** | 1 | `run_shell` |

Many categories above ship a `lookup_*_across_firmwares` tool — a cross-project aggregation query (e.g. "which firmwares share this driver hash / registry key / systemd unit / ICS protocol / chip family") answerable in a single MCP call instead of iterating per firmware.

## UART Bridge (Optional)

For live device access via UART, run the bridge on the host machine (USB serial adapters can't easily pass through to Docker):

```bash
pip install pyserial
python3 scripts/wairz-uart-bridge.py --bind 0.0.0.0 --port 9999
```

The bridge is a TCP server — the serial device path and baud rate are specified via the `uart_connect` MCP tool, not on the command line.

On Linux, allow Docker traffic to reach the bridge and ensure `.env` is configured correctly:

```bash
sudo iptables -I INPUT -p tcp --dport 9999 -j ACCEPT
```

`UART_BRIDGE_HOST` in `.env` must be `host.docker.internal` (not `localhost`). Restart the backend after changing `.env`: `docker compose restart backend`.

See [UART Console docs](docs/features/uart.md) for full setup details.

## Device Acquisition Bridge (Optional)

For pulling firmware directly from ADB-connected Android devices, run the device bridge on the host:

```bash
python3 scripts/wairz-device-bridge.py --bind 0.0.0.0 --port 9998
```

For development without a real device, use mock mode:

```bash
python3 scripts/wairz-device-bridge.py --mock --port 9998
```

Setup is the same pattern as the UART bridge: set `DEVICE_BRIDGE_HOST=host.docker.internal` in `.env` and allow Docker traffic on port 9998.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, Vite, TypeScript, Tailwind CSS, shadcn/ui |
| Code Viewer | Monaco Editor |
| Component Graph | ReactFlow + Dagre |
| Terminal | xterm.js |
| State Management | Zustand |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Alembic |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Firmware Extraction | binwalk3, unblob, sasquatch, jefferson, ubi_reader, cramfs-tools, UEFIExtract |
| Binary Analysis | radare2 (r2pipe), pyelftools, LIEF, capa |
| Decompilation | Ghidra 11.3.1 (headless) with custom analysis scripts |
| Vulnerability Detection | cwe_checker (17 CWEs), VulHunt, YARA (~5000 Forge rules), ShellCheck, Bandit |
| Threat Intelligence | ClamAV, VirusTotal, abuse.ch (MalwareBazaar, ThreatFox, URLhaus, YARAify), CIRCL Hashlookup (NSRL) |
| Emulation | QEMU user-mode + system-mode, FirmAE, Qiling (ARM, MIPS, MIPSel, AArch64) |
| Network Analysis | Scapy (pcap capture + protocol analysis from emulated firmware) |
| Fuzzing | AFL++ with QEMU mode |
| SBOM | CycloneDX 1.7, SPDX 2.3, CycloneDX VEX, NVD API (nvdlib), Grype, Syft |
| Android | Androguard (APK analysis), ADB (device acquisition) |
| UART | pyserial (host-side bridge) |
| Compliance | EU CRA Annex I (20 requirements), ETSI EN 303 645 |
| AI Integration | MCP (Model Context Protocol) |
| Containers | Docker + Docker Compose |

## Project Structure

```
wairz/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── config.py            # Settings (pydantic-settings)
│   │   ├── database.py          # Async SQLAlchemy engine/session
│   │   ├── mcp_server.py        # MCP server with dynamic project switching
│   │   ├── models/              # SQLAlchemy ORM models
│   │   ├── schemas/             # Pydantic request/response schemas
│   │   ├── routers/             # REST API endpoints
│   │   ├── services/            # Business logic
│   │   ├── ai/                  # MCP tool registry + 383 tool implementations
│   │   │   └── tools/           # 32 category files (filesystem, binary, security, emulation, hardware_firmware, windows_*, linux_*, ics_protocol, bare_metal, cwe_checker, vulhunt, attack_surface, network, uefi, taint_llm, etc.)
│   │   └── utils/               # Path sandboxing, output truncation
│   ├── alembic/                 # Database migrations
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── pages/               # Route pages (explorer, emulation, fuzzing, SBOM, etc.)
│   │   ├── components/          # UI components (file tree, hex viewer, component map, etc.)
│   │   ├── api/                 # API client functions
│   │   ├── stores/              # Zustand state management
│   │   └── types/               # TypeScript type definitions
│   └── package.json
├── ghidra/
│   ├── Dockerfile               # Ghidra headless container
│   └── scripts/                 # Custom Java analysis scripts
├── emulation/
│   ├── Dockerfile               # QEMU container (ARM, MIPS, MIPSel, AArch64)
│   └── scripts/                 # Emulation helper scripts
├── fuzzing/
│   └── Dockerfile               # AFL++ container with QEMU mode
├── scripts/
│   ├── wairz-uart-bridge.py     # Host-side UART serial bridge
│   └── wairz-device-bridge.py   # Host-side ADB device acquisition bridge
├── docker-compose.yml
├── launch.sh                    # Local development launcher
├── .env.example
└── CLAUDE.md
```

## Configuration

All settings are configured via environment variables or `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | *(set via `POSTGRES_PASSWORD` in `.env`)* | PostgreSQL connection |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection |
| `STORAGE_ROOT` | `/data/firmware` | Firmware storage directory |
| `MAX_UPLOAD_SIZE_MB` | `2048` | Maximum firmware upload size |
| `MAX_TOOL_OUTPUT_KB` | `30` | MCP tool output truncation limit |
| `GHIDRA_PATH` | `/opt/ghidra` | Ghidra installation path |
| `GHIDRA_TIMEOUT` | `300` | Ghidra decompilation timeout (seconds) |
| `FUZZING_IMAGE` | `wairz-fuzzing` | Fuzzing container image name |
| `FUZZING_TIMEOUT_MINUTES` | `120` | Max fuzzing campaign duration |
| `FUZZING_MAX_CAMPAIGNS` | `1` | Max concurrent fuzzing campaigns |
| `UART_BRIDGE_HOST` | `host.docker.internal` | UART bridge hostname |
| `UART_BRIDGE_PORT` | `9999` | UART bridge TCP port |
| `DEVICE_BRIDGE_HOST` | `host.docker.internal` | Device acquisition bridge hostname |
| `DEVICE_BRIDGE_PORT` | `9998` | Device acquisition bridge TCP port |
| `NVD_API_KEY` | *(empty)* | Optional NVD API key for higher rate limits |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Optional VirusTotal API key (hash-only lookups, no file upload) |
| `ABUSECH_AUTH_KEY` | *(empty)* | Optional abuse.ch auth key for higher rate limits |
| `CLAMAV_HOST` | `clamav` | ClamAV daemon hostname (Docker service) |
| `CLAMAV_PORT` | `3310` | ClamAV daemon TCP port |
| `API_KEY` | *(empty)* | Optional API key for REST endpoint authentication |
| `LOG_LEVEL` | `INFO` | Logging level |

## Security

Wairz ingests and analyses untrusted firmware binaries; the deployment surface itself also needs care. The following rules are enforced by the default `docker-compose.yml`:

**Required secrets.** `POSTGRES_PASSWORD` and `FIRMAE_DB_PASSWORD` are mandatory — `docker compose up` errors out if they are not set in `.env`:

```
$ docker compose config
error while interpolating services.postgres.environment.POSTGRES_PASSWORD:
  required variable POSTGRES_PASSWORD is missing a value
```

Generate strong values with:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Do not commit `.env`. Use `.env.example` as a template only.

**Binding defaults.** Backend (`:8000`) and frontend (`:3000`) default to `127.0.0.1` — local access only. The `/ws` WebSocket endpoint is not yet authenticated, so exposing the backend to LAN is unsafe until `API_KEY` is set *and* the WebSocket is auth-gated. To allow LAN access after you understand the tradeoffs:

```bash
# .env
API_KEY=<strong-random-key>
BACKEND_HOST_BIND=0.0.0.0
FRONTEND_HOST_BIND=0.0.0.0
```

Postgres (`:5432`) and Redis (`:6379`) are always loopback-bound — there is no override. Use `docker compose exec postgres psql ...` for host-side DB access, not a network socket.

**Rotating credentials.** Edit `.env`, then recreate the affected containers:

```bash
docker compose up -d
```

For postgres specifically, changing `POSTGRES_PASSWORD` against an existing `pgdata` volume requires either `ALTER USER wairz WITH PASSWORD ...` inside the running container, or a fresh volume. The `pg-backup` service (nightly `pg_dump` into `${BACKUP_DIR:-./backups}`) makes rotation-via-dump-and-restore safe to experiment with.

**Production.** For production deployments, consider an external secret manager (HashiCorp Vault, AWS Secrets Manager, SOPS-encrypted `.env` files) rather than plaintext `.env`. A `docker-compose.prod.yml` Docker-secrets variant is on the roadmap but not yet in-tree.

## Testing Firmware

Good firmware images for testing:

- **[OpenWrt](https://downloads.openwrt.org/)** — Well-structured embedded Linux (MIPS, ARM)
- **[DD-WRT](https://dd-wrt.com/)** — Similar to OpenWrt
- **[DVRF](https://github.com/praetorian-inc/DVRF)** (Damn Vulnerable Router Firmware) — Intentionally vulnerable, great for security testing

## License

[AGPL-3.0](LICENSE)
