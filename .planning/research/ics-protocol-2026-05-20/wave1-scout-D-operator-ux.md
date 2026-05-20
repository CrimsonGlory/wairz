# Wave-1 Scout D — Operator-UX Report — ICS Protocol Decoders

**Target:** OT/ICS firmware reverse engineer (Schneider Electric, Siemens, Rockwell, ABB, Honeywell, GE, Mitsubishi, Allen-Bradley, Beckhoff).

## Top 10 Operator Queries (verbatim) + MCP tool answers

| # | Query | MCP tool |
|---|---|---|
| 1 | "I just uploaded a Siemens S7-1500 firmware. Which ICS protocols + versions does this PLC support?" | `list_ics_protocols(firmware_id)` |
| 2 | "Show me every firmware in the corpus that ships a DNP3 stack with known CVEs." | `lookup_ics_protocol_across_firmwares(protocol_family="dnp3", with_cve_only=true)` |
| 3 | "Did Schneider drop legacy Modbus RTU between v1 and v2?" | `diff_ics_protocols(firmware_id_a, firmware_id_b)` |
| 4 | "List every ICS protocol family across the corpus grouped by family + vendor." | `summarize_ics_protocol_coverage(scope="global", group_by=["protocol_family","vendor"])` |
| 5 | "Are there firmwares with vendor-extended Modbus function codes that might bypass auth?" | `list_ics_function_code_extensions(firmware_id, mode="non_standard_only")` |
| 6 | "Modbus TCP on a non-default port — show me firmwares with port != 502." | `lookup_ics_protocol_across_firmwares(protocol_family="modbus_tcp", port_anomaly_only=true)` |
| 7 | "Which firmwares appear vulnerable to TRITON / TRISIS?" | `describe_ics_advisory(advisory_id="ADVISORY-TRITON")` + `lookup_ics_protocol_across_firmwares(advisory_id="ADVISORY-TRITON")` |
| 8 | "This PLC has an OPC UA endpoint — what authentication modes does it advertise?" | `analyze_ics_protocol_endpoint(firmware_id, protocol_family="opcua")` |
| 9 | "Drop a new YAML for a Beckhoff ADS stack I extracted — does catalog see it?" | `list_ics_protocol_families()` + `list_extension_points(surface_filter="ics_")` |
| 10 | "I'm triaging CVE-2017-12741 — what's the chain that attributed it to this Siemens blob?" | `verify_cve_attribution(cve_id, blob_id)` (EXISTING tool, reuse) |

## MCP Tool Inventory (minimum viable, vetted)

### Tier-1 (mandatory, heavy use)

- **`list_ics_protocols(firmware_id, protocol_family?)`** — per-firmware results
- **`lookup_ics_protocol_across_firmwares(...)`** — Rule #44 mandatory cross-firmware
- **`list_ics_protocol_families(vendor?)`** — catalog discovery (mirrors `list_chip_families`)
- **`describe_ics_advisory(advisory_id)`** — mirrors `describe_advisory` in hardware_firmware.py:549
- **`verify_cve_attribution`** — REUSE EXISTING

### Tier-2 (deep triage)

- **`analyze_ics_protocol_endpoint(firmware_id, protocol_family)`** — per-endpoint detail
- **`list_ics_function_code_extensions(firmware_id, mode)`** — function-code drilldown
- **`diff_ics_protocols(firmware_id_a, firmware_id_b)`** — version diff
- **`summarize_ics_protocol_coverage(scope, group_by)`** — corpus aggregate

### Tier-3 (walker management — Rule #33 .a triplet)

- **`trigger_ics_protocol_walk(firmware_id)`** — idempotent POST + 409
- **`ics_protocol_walk_status(firmware_id)`** — state-machine reader
- **`submit_ics_protocol_descriptor(firmware_id, ...)`** — operator hint (mirrors `submit_bare_metal_descriptor`)

**Total: 10 new tools + 1 reuse.**

## Hover-Panel / Dashboard Expectations

After `ics_protocol_walk` completes:
- **ICS Protocols card**: protocol-family chip (color-coded by criticality) + version + default-vs-observed port (highlight mismatch) + function-code summary + inline CVE badge
- **Cross-firmware row**: "This DNP3 stack version 3.6 also appears in 4 other firmwares; 2 share CVE-2023-XXXX"
- **Hover tooltip**: spec citation (IEC 60870-5-104 / NIST SP 800-82r3)
- **HBOM export integration**: extend CycloneDX `components[].properties` with `ics_protocols`

## CVE-Attribution Integration (Rule #50)

ICS CVE clusters span vendors and protocols. **Shared `advisory_id` candidates:**

- **ADVISORY-TRITON / TRISIS** (CVE-2018-7522 + CVE-2018-8872) — Schneider Tricon TriStation 1131 + safety-system PLCs across multiple Tricon firmware versions
- **ADVISORY-FROSTYGOOP** — Modbus-protocol-level abuse (2024); applies across all Modbus-TCP-speaking firmware where auth bypass is exploitable; `vendor_regex: ".*"` + `protocol_family: modbus_tcp` + `shared_advisory_id: true`
- **ADVISORY-INDUSTROYER2** — multiple IEC 60870-5-104 stacks across Siemens / Ovation / Rockwell
- **ADVISORY-MODBUS-WEAK-AUTH** — generic Modbus FC 0x08 Diagnostic sub-function 0x01 Restart without auth

**Curated YAML extension shape:** mirror `known_firmware.yaml` exactly; add new `protocol_family_regex` field. Existing `cve_matcher._KNOWN_FIRMWARE_NARROWING_FIELDS` allowlist needs extension (Rule #25 single-slice exception #2).

**Forward-prepared CVE pin discipline (Rule #49):** ship hard-reject `version_regex` for CVEs targeting future-extracted protocol versions. Zero matches today; activation = ZERO YAML edits.

## Cross-Firmware Aggregation — ICS-Specific Queries

1. "Which firmwares share an outdated DNP3 stack version?"
2. "Which firmwares contain function-code extensions outside standard range?" (Schneider UMAS — CVE-2018-7240)
3. "Which firmwares advertise OPC UA but accept SecurityPolicy#None?"
4. "Compare firmwares from same PLC family — which dropped a protocol between versions?"
5. "Which firmwares ship unpatched IEC-104 stack vulnerable to CVE-2022-XXXX after vendor advisory date?"
6. "Which firmwares share the same vendor-specific Profinet device-name string across supposedly-independent vendors?"

All map cleanly onto `lookup_ics_protocol_across_firmwares` with structured filters. **REJECT vanity:** don't ship one-tool-per-query.

## Documentation / Discovery — extension recipe

Mirror `docs/features/extending-firmware-patterns.md`. Required sections:
- **Step 0:** Where to write — `<vendor>/<protocol>.yaml` core OR `.local/<protocol>.yaml` operator
- **Step 1:** Gather the fingerprint (magic / port / function codes / banner strings)
- **Step 2:** Pick a `family_id` — convention `<vendor>/<protocol>`
- **Step 3:** Closed-grammar policy authoring (no regex / no script / no eval)
- **Step 4:** Verify discovery — `list_extension_points` returns `last_warning: null`
- **Step 5:** Test against real firmware — `trigger_*` + poll + inspect
- **Step 6:** NDA discipline — notes field max 8192

## Top 3 Surprises (red-team / architecture would miss)

1. **OT operators run their entire investigation through ONE chat session per firmware.** Walker should auto-fire post-unpack via Rule #47 consumer-hook discipline; operator never types `trigger_*` unless re-running.

2. **`function_code_outside_allowlist` is the operator's #1 finding shape — but they need per-vendor `vendor_extended_allowlist`.** Schneider UMAS, Siemens private profile, Rockwell CIP custom services are legitimately documented vendor extensions. Operators need `.local/<vendor>.yaml` overlay declaring "FCs 0x5A, 0x5B, 0x5C are Schneider UMAS, treat as legit." The closed-grammar should ship `vendor_extended_allowlist: [...]` per-protocol-per-vendor from day one.

3. **The operator wants to ASK "is this a PLC?" before knowing it's a PLC.** Typical workflow: upload 60 MB unknown blob → "what is this?" The ICS-protocol walker should set `device_metadata["device_classification"]["category"] = "plc"|"rtu"|"hmi"|"safety_controller"|"motor_drive"` when an ICS family is detected. MCP system prompt should learn: *"If `device_metadata.device_classification.category` is `plc`/`rtu`/`hmi`/`safety_controller`, prefer `list_ics_protocols` over generic network analysis."*

## Reject list (vanity capabilities)

- `emulate_ics_endpoint` — Rule #36 no-execute discipline
- `generate_ics_protocol_documentation` — Claude is already an LLM
- `recommend_ics_protocol_hardening` — crosses from RE tool to compliance auditor
- `compare_to_iec_62443_zone_model` — out of scope; that's Claroty/Nozomi/Tenable.ot
- One MCP tool per protocol family — closed-grammar `protocol_family` parameter does the discrimination

## Recipe Cross-References

- Rule #44 mandatory `lookup_ics_protocol_across_firmwares` REQUIRED in `.E` close commit
- Rule #52 closed-grammar — protocol_family + finding_source + policy_operator all closed Literals
- Rule #36+#45 walker parse-only (never invokes pymodbus/snap7 against parsed content)
- Rule #39 inner/outer/safe triplet
- Rule #16 detection roots
- `.mex/patterns/add-ics-protocol-yaml.md` recipe — author + cross-link from Rule #52 worked examples
