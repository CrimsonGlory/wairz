# Wave-1 Scout A — Architecture — ICS Protocol Decoders (B.3)

## TL;DR

**SIBLING SUBPACKAGE** at `backend/app/services/ics_protocol_catalog/` with its own resolver, mirroring `file_format_catalog/` exactly. Walker = blob-and-binary walker (filtered set, not every file). v1 scope: **5 canonical protocols** (Modbus/TCP, DNP3, OPC-UA Binary, S7Comm, BACnet/IP) plus 1 plugin-driven catch-all for the long-tail.

Schema = closed-grammar Pydantic with **6 new closed Literals** + a **PROTOCOL-CENTRIC detection signal grammar** (function-code signature, port signature, magic, OID/object-type, embedded ASCII banner, library symbol, config file path).

## Closed Literals (new for ICS lane)

```python
IcsProtocolFamily = Literal[
    "modbus", "dnp3", "opc_ua", "iec_61850_mms", "iec_60870_5_104",
    "s7comm", "bacnet_ip", "ethernet_ip", "ethercat", "profinet",
    "dlms_cosem", "fins", "melsec", "unknown_ics",
]

IcsLayer = Literal["application", "transport", "data_link", "session"]
IcsTransport = Literal["tcp", "udp", "ethernet_raw", "serial_rs485", "any"]
IcsSignalKind = Literal[
    "magic_bytes", "port_signature", "function_code_set",
    "string_in_binary", "oid_or_object_type", "library_symbol",
    "config_file_path", "always_matches",
]
IcsArtifactSource = Literal["binary", "config_file", "embedded_blob", "any"]
IcsCertainty = Literal["stack_present", "config_present", "string_only"]
```

## Schema sketch (mirrors file_format.py)

`IcsProtocolManifest` (top-level) → `IcsDetection` → `IcsDetectionSignal` (closed by `IcsSignalKind`) + `IcsOutput` + `Plugin` + `Deprecation` + `ProvenanceStub`.

**Reuses verbatim:** ManifestSource, OverlayMode, EvaluationMode, Combine, SortTier, Confidence, TieBreaker, DeprecationStatus, Deprecation, ProvenanceStub, ExternalManifestsPolicy, Plugin/PluginRef.

## Plugin contract (HYBRID — yes)

```python
class IcsMatcherProto(Protocol):
    name: str
    cost_class: int
    applicable_manifest_ids: frozenset[str]
    protocol_families: frozenset[str]
    def detect(self, blob_head, path, size, ctx: IcsDetectionContext) -> IcsProtocolDetection | None: ...
```

Bundled plugins (v1): `ics_string_scanner_default`, `ics_elf_symtab_default`, `ics_pe_imports_default` — each ~CHEAP CACHE invoked ONCE per binary; results stashed on `IcsDetectionContext`. Per-manifest signals consult the cache, NOT each plugin individually.

`freeze_plugin_registry()` post-startup (W2-β attack I closure mirror).

## Walker shape — Rule #39 inner/outer/safe

**Filtered walk set, NOT every blob:**
1. Every `HardwareFirmwareBlob` row.
2. Every ELF / PE binary (`linux_elf` / `pe_executable` per file_format catalog output).
3. Every config file matching path heuristics (`/etc/*.conf|.xml|.json|.cfg`).

Triplet:
- `_do_ics_protocol_audit_run(db, firmware_id) -> dict` — INNER pure-logic, uses Rule #16 detection roots
- `run_ics_protocol_audit_background(firmware_id) -> None` — OUTER Rule #33.a state machine
- `auto_ics_protocol_audit_firmware_safe(firmware_id) -> None` — SAFE post-unpack hook

State machine column: `firmware.ics_protocol_audit_status` ∈ `{idle, queued, running, completed, failed}` with DB CHECK + Pydantic Literal + frontend mirror.

JSONB result column: `firmware.ics_protocol_audit_result` per Rule #35c.

Rate-limit tier: `TIER_A_LIGHT_ACK` (30/hour) per Rule #51.

## Cross-firmware MCP tool (Rule #44 mandatory)

`lookup_ics_protocol_across_firmwares(query, scope="project")`:
- Filter dimensions (closed-domain): protocol_family, port, function_code_hex, object_type, version_substring, vendor, layer, transport.
- SQL: JOIN firmware ON detection.firmware_id = firmware.id; GROUP BY firmware.id with match_count, supply_chain_signal = (match_count >= 2).

Per-firmware tools: audit_ics_protocols, list_ics_protocols, inspect_ics_protocol_detection.

## Sibling vs Extending file_format_catalog

**SIBLING.** Justification: file-format is single-format-per-blob; ICS is multi-protocol-per-binary. Cardinality differs; detection grammar differs (function codes vs filename). Sibling subpackage avoids cross-catalog hijack attacks.

Loose coupling via TWO touch points:
1. ICS walker consumes file_format output to filter walk set.
2. ICS walker MAY register a plugin in `file_format_catalog.PLUGIN_REGISTRY` for v2 (forward-prepared).

## Top 3 RISKS

1. **False positives from library SONAME / string matches (HIGH).** `libmodbus.so.5` in rootfs ≠ device speaks Modbus. **Mitigation:** `IcsCertainty` Literal caps Output.confidence per certainty tier. `string_only` → low; `library_symbol + function_code_set` co-occurrence → high.

2. **Port-signature confusion with non-ICS services (MEDIUM).** Modbus port 502 in inetd.conf doesn't prove implementation. **Mitigation:** REJECT manifest where only signal is `port_signature` AND `manifest_source != "_system"` AND `precedence < 5000`.

3. **Cross-feature attack #SC5-NEW: ICS YAML override of file_format detection (MEDIUM).** Operator pushes ICS manifest with `manifest_id = pe_executable`. **Mitigation:** Sibling-subpackage isolation; loader REJECTS cross-catalog reference; Rule #46 META-CANARY synthesises hostile ICS YAML with format_id collision + asserts loader rejects.

## Single-Session Feasibility — v1 Scope

**SHIP IN ONE SESSION:**
- Schema (~600 LOC) — file_format.py mirror
- Catalog package (~1200 LOC) — mtime-cached loader + closed-grammar resolver
- 3 bundled plugins (~600 LOC) — string scanner + ELF symtab + PE imports
- 5 canonical YAMLs (~300 LOC) — Modbus, DNP3, OPC-UA, S7Comm, BACnet/IP
- Walker (~800 LOC) — Rule #39 triplet
- Alembic migration — adds `ics_protocol_audit_status` + `ics_protocol_audit_result` JSONB + DB CHECK
- MCP category (~600 LOC) — per-firmware + cross-firmware tools
- Frontend mirror commit — `IcsProtocolFamily` Literal
- Tests — per-evaluator + cross-stack alignment + Rule #45/#46 META-CANARIES

**DEFER to v2:** EtherNet/IP (CIP complex), IEC-61850 MMS (ASN.1 BER), EtherCAT data_link, Profinet RT + DCP, DLMS-COSEM. Each = Rule #25 Shape-1 commit + YAML.

Promotes Rule #52 to Rule-of-Three.
