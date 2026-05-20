# Wave-1 Scout B — Adjacency / Current-State — ICS Protocol Decoders

## Headline finding

Wairz today has **effectively zero firmware-embedded ICS protocol identification capability**. Entire ICS surface across 9000+ Python LOC = **6 line items in `backend/app/services/sbom/constants.py:126,171-176`** (libcoap, libmodbus, open62541, libopen62541, opcua, bacnet, libcanopen — SBOM CPE mappings only).

**Greenfield surface — perfect Rule #52 worked-example #3 candidate.**

## Today's protocol-identification capabilities

**Runtime (pcap-based, post-emulation):**
- `network.py` (329 LOC, 5 MCP tools): `analyze_network_traffic`, `get_protocol_breakdown`, `identify_insecure_protocols`, `get_dns_queries`, `get_network_conversations` — ALL operate on captured pcap, NOT on firmware blobs at rest.
- `pcap_analysis_service.py:28-54` maps 25 IT ports. **Zero ICS ports.**
- `_detect_insecure_protocols` has 13 rules. **Zero ICS rules.**

**Static (firmware-blob-based):**
- `strings.py` + `find_crypto_material` + `find_hardcoded_credentials` — **0 references** to ICS identifiers.
- `parsers/` (19 parsers): chip / image formats only. No protocol-stack extraction.
- `known_firmware.yaml` + `firmware_patterns.yaml` + `bt_banner_cve_pins.yaml` — **0 hits** for ICS vendor strings (Schneider/Siemens/Rockwell/etc.).
- `yara_rules/*.yar` — **0 hits** for ICS terms.

**SBOM (component-level only):**
- `sbom/constants.py` CPE_VENDOR_MAP lists 6 ICS-relevant entries — but scanner has NO logic to actually identify these from blob contents.

## Gap analysis — what's missing

For firmware-embedded ICS identification, wairz lacks **every layer**:

1. **No static-string ICS detector.**
2. **No port-default cross-reference.** (502/20000/4840/102/47808/44818/2222/4900 — none mapped.)
3. **No function-code / op-code table.**
4. **No vendor-banner / vendor-prefix surface.**
5. **No ICS CVE pins.**
6. **No MCP tool surface.**
7. **No walker.**
8. **No YARA ICS rule sets.**
9. **No closed-grammar Pydantic schema.**
10. **No JSONB normaliser.**
11. **No DB CHECK constraint** on a finding-source enum value covering ICS.

## Adjacent patterns to mirror

**`file_format_catalog/` is the right template** (closer than `hardware_firmware/parsers/`):
- mtime-cached YAML loader with hot-reload
- closed dispatch via `PLUGIN_REGISTRY`
- tiered directories: `_system/` (canonical) + `<vendor>/` (core) + `.local/` (operator)
- 5-source `ManifestSource` Literal
- HYBRID plugin escape hatch via `register_matcher` + `freeze_plugin_registry`
- A1–A9 cross-feature validators
- Bundled `rtos_detection_default` is the canonical "operator-extensible family discovery" precedent

**Recommendation:** new `backend/app/services/ics_protocol_catalog/` subpackage with same structure as file_format_catalog.

## Walker-vs-detector decision

**Walker (post-unpack, Rule #39 triplet) is the right shape.**

Reasoning: File-format detection runs at upload/unpack time on archive containers (routing decision). ICS protocol identification operates on already-extracted artifacts (forensic/security finding, not a routing decision). Rule #39 triplet exactly matches the precedent (efs_walker, etl_walker, registry_hive_walker, dpapi_walker, etc.).

Sequence: `file_format_catalog.classify` → unpack → `auto_ics_protocol_walk_firmware_safe(firmware_id)` post-unpack hook fires → walker iterates blobs → emits Finding rows with `source` like `ics_modbus_stack_detected`.

## MCP tool surface — extend or sibling?

**NEW `app/ai/tools/ics_protocol.py` category** (NOT extending network.py).

Reasoning: network.py is pcap-bound — every handler routes through `_load_pcap_analysis(session_id)`. ICS detection operates on firmware blobs at rest. The 18 existing `lookup_*_across_firmwares` tools live in dedicated category files; adding a 32nd `register_*_tools` registration in `ai/__init__.py` follows convention.

Minimum tools (Rule #44 Rule-of-Nine):
- `detect_ics_protocols_in_firmware(firmware_id)`
- `lookup_ics_protocol_across_firmwares(protocol, scope)` ← Rule #44 mandatory
- `get_ics_protocol_details(firmware_id, protocol)`
- `list_ics_protocol_findings(firmware_id)`

## Top 5 mechanical signals for ICS detection

1. **ASCII protocol-name strings in `.rodata` / `.text`** — high-confidence, low-precision. Canonical strings: `"Modbus"`, `"MBAP"`, `"DNP3"`, `"OPC UA"`/`"OPC.UA"`, `"BACnet/IP"`, `"S7Comm"`/`"SIMATIC"`/`"S7-1500"`, `"IEC 61850"`/`"GOOSE"`/`"MMS"`, `"EtherNet/IP"`/`"CIP"`, `"EtherCAT"`, `"PROFINET"`, `"DLMS"`/`"COSEM"`, `"HART"`, `"CANopen"`. **Risk:** mention in unrelated docs/debug — mitigated by combining with #2-#5.

2. **Port-default constants embedded in `.rodata` as LE uint16 or ASCII decimal** — medium-confidence, medium-precision. Modbus 502 (0x01F6 LE), DNP3 20000 (0x4E20 LE), OPC-UA 4840, S7Comm 102, BACnet/IP 47808, EtherNet/IP 44818, EtherCAT 34980, HART-IP 4900. **Risk:** coincidental constants — mitigate by checking xref to bind/listen/socket.

3. **Function-code / object-group lookup tables** — high-confidence, high-precision. Modbus switch-case with codes 0x01/0x02/0x03/.../0x2B. DNP3 object-group code tables. S7Comm job-codes 0x04/0x05/0x1A. CIP service codes (0x4C Read Tag, 0x4D Write Tag).

4. **Library SONAMEs / version strings** — high-confidence when present, low-recall. `libmodbus.so.5`, `libopen62541.so.1`, `libdnp3-cpp.so`. Version patterns: `"libmodbus version %d.%d.%d"`, `"open62541 v1.3.X"`, `"S7CommPlus v0.6.0"`.

5. **Magic-byte stream patterns** — high-confidence when present, very-low-recall. OPC-UA Binary `"HEL"`/`"ACK"`/`"OPN"`/`"MSG"`/`"CLO"`. S7Comm TPKT `\x03\x00` + COTP `\x02\xf0\x80`. Modbus/TCP MBAP transaction-id header.

## Risk assessment — false-positive likelihood

`"Modbus"` is highest-risk signal. Mitigations via closed-grammar schema:

- **`combine: all_required`** — force ≥ 2 of 5 signals to hit before classifying.
- **Closed-grammar `confidence` enum** (Literal high/medium/low) per manifest.
- **Negative-evidence signals** mirror `pe_negative_evidence.yaml` — REJECT classification if anti-patterns appear.
- **`finding_source` distinct per detection mode** — `ics_modbus_stack_high_confidence` vs `ics_modbus_string_only`.
- **`vendor_authority` derived from `manifest_source`** — operator-supplied entries are INFORMATIONAL only.
- **Rule #46 META-CANARY paired tests** — synthetic-violation canary confirms gate fires + rejects negative-evidence inputs.
- **Cross-firmware corroboration via Rule #44 MCP tool** — low-confidence "Modbus string" on firmware A becomes high-confidence supply-chain signal when SAME hash recurs across vendors B/C/D.

## Bottom line

Greenfield ICS surface — no legacy code to refactor around. Mirror `file_format_catalog` pattern. v1 = 3-5 canonical protocols + Rule #39 triplet walker + Rule #44 cross-firmware MCP tool + Rule #46 META-CANARIES + Rule #52 closed-grammar discipline. Worked example #3 → promotes Rule #52 to Rule-of-Three.
