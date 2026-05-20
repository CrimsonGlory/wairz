# Wave-2 Alpha Convergence — ICS Protocol Catalog (B.3) — 2026-05-20

> Synthesizes Wave-1 reports A (architecture) + B (adjacency) + C (red-team) +
> D (operator-UX) + E (precedence). Locks the FINAL v0 implementation
> contract for the ICS protocol decoder catalog. v0 ships in a single
> 4-6 hour session per Rule #28 yardstick (target ~3,000-3,500 net LOC,
> bench against P3.2's +2,689 net / 6 commits).

## §1 Lock the lane — sibling subpackage CONFIRMED

**Decision:** `backend/app/services/ics_protocol_catalog/` as a SIBLING
subpackage to `file_format_catalog/` — mirror layout 1:1 (`catalog.py` +
`resolver.py` + `plugins/` + `data/` + `snapshot.py` + `__init__.py`).

**Scouts A+B+D+E all unanimously sibling.** Scout C's red-team #18
attack ("ICS YAML hijacks file_format dispatch") locks this in as
ARCHITECTURAL ISOLATION (separate `SIGNAL_EVALUATORS` + separate
`PLUGIN_REGISTRY` + separate resolver) — not a soft convention but a
hard `from app.services.file_format_catalog import *` REJECT at catalog-load.

Loose-coupling touchpoints (2 only, both ICS→file_format, never the reverse):

1. ICS walker reads `blob.classifier_format` from file_format output to
   filter the walk set (binaries + config-file-categorized blobs).
2. v1+ extension: ICS plugin MAY register in `file_format_catalog.PLUGIN_REGISTRY`
   under the bundled-plugin protocol (forward-prepared, not v0).

**Rejecting:** Scout C #18 + Scout A #SC5-NEW. Cross-catalog manifest_id
collision is REJECTED at ICS catalog-load (mirror `_expected_source_for_path`
at file_format_catalog/catalog.py:270-278 — but for the manifest_id namespace).

## §2 v0 scope NARROWING — 3 protocols (Modbus + DNP3 + S7Comm)

**Decision:** v0 ships **3 canonical protocols** — Modbus/TCP + DNP3 + S7Comm.

**Justification:**

- Schneider/Honeywell/Siemens triad covers >60% of the operator-UX top-10
  queries (Scout D #1, #2, #3, #5, #6, #7, #8, #10).
- Simplest detection grammars — all three resolve via the FIVE base
  signal kinds (`magic_bytes`, `port_signature`, `function_code_set`,
  `string_in_binary`, `library_symbol`) with no exotic protocol-specific
  evaluator extensions.
- Function-code / op-code lookup tables are well-documented in public
  ICS-CERT advisories.
- TRITON (ADVISORY-TRITON, Schneider) + INDUSTROYER2 (ADVISORY-INDUSTROYER2,
  IEC-104 but Scout D notes Siemens/Ovation/Rockwell coverage) +
  ADVISORY-MODBUS-WEAK-AUTH (Rule #50 candidate) all land on this triad.
- 3 protocols × ~60 LOC YAML = 180 LOC. 5 would be 300 LOC. The savings
  go into Rule #46 META-CANARY coverage.

**Defer to v1 follow-on** (1 commit each, Rule #25 Shape-1):

- **v1a — OPC-UA Binary** (HEL/ACK/OPN/MSG/CLO magic + port 4840). Single
  YAML + advisory pin.
- **v1b — BACnet/IP** (port 47808 + APDU magic). Single YAML.
- **v1c — IEC-104** + Siemens/Ovation/Rockwell IEC-104 advisory cluster
  (`ADVISORY-INDUSTROYER2` shared-advisory_id per Rule #50).
- **v1d — EtherNet/IP + CIP** (port 44818 + CIP service codes 0x4C/0x4D
  + UMAS vendor extension via `vendor_extended_allowlist`). Defers
  because CIP semantics are complex (service-codes + class-codes + ENI
  encapsulation) — Scout D #5 highlights vendor-extended Modbus FCs as
  the operator's #1 finding shape, but UMAS specifically is a Schneider
  extension over Modbus FCs, NOT EtherNet/IP — so v0 Modbus handles the
  UMAS allowlist; EtherNet/IP defers to v1.
- **v1e — Profinet** + **IEC-61850 MMS** + **EtherCAT** + **DLMS-COSEM**.

**v0 anti-pattern (rejected):** "ship 5 protocols thin." Better to ship
3 protocols deep with Rule #46 META-CANARY coverage on all 5 base signal
evaluators, then add 5 more protocols thin via Rule #25 Shape-1 commits.

## §3 Resolve contradictions

### §3.1 Plugin escape hatch — DAY 0 BUNDLED ONLY (no operator plugins)

**Scout A:** HYBRID plugin escape hatch from day 1, 3 bundled plugins
(`ics_string_scanner_default`, `ics_elf_symtab_default`, `ics_pe_imports_default`).

**Scout C:** REJECT operator-supplied plugins entirely — Rule #36 + Rule
#45 + §SC5 triple-breach risk. In-tree only.

**RESOLVED:** Scout A's BUNDLED plugins ship in v0. Scout C's REJECT
applies to OPERATOR-SUPPLIED plugins — v0 does NOT support
`WAIRZ_ICS_PLUGIN_PATH` env-var or `.local/<plugin>.py` operator
modules. The catalog's `PLUGIN_REGISTRY` is FROZEN at startup via
`freeze_plugin_registry()` (mirror file_format_catalog after W2-β
attack-I closure). Only bundled in-tree plugins register.

Catalog `data/ics_protocols.local/` accepts YAML ONLY — same shape as
file_format_catalog. The closed-grammar `Plugin` model carries
`plugin_id: str` pointing to a BUNDLED plugin name — operator YAML can
reference a bundled plugin but cannot ship a new one.

Operator-supplied Python plugins deferred to v2 as side-container
(Exception 3, mirror P3.2.f's `WAIRZ_FORMAT_PLUGIN_PATH` deferral).

### §3.2 Walker iteration set — Rule #16 detection roots + filtered binary set

**Scout A:** "filtered set (binaries + config files)".

**Scout E:** Rule #16 `get_detection_roots(firmware)` MUST be the walker's
entry point.

**RESOLVED:** Both apply — they operate at different layers.

```python
async def _do_ics_protocol_audit_run(db, firmware_id):
    firmware = await db.get(Firmware, firmware_id)
    roots = get_detection_roots(firmware)  # Rule #16 — iterate ALL extracted trees
    binaries = []
    for root in roots:
        # Inside each root, FILTER to binaries + config blobs via classifier_format
        async for blob_row in _iter_classified_binaries(db, firmware_id, root):
            binaries.append(blob_row)
    # Iterate the FILTERED set, NOT every blob in the root
    ...
```

Rule #16 is the OUTER iteration (detection roots — multi-archive,
scatter-zip safe). The INNER filtering is by `blob.classifier_format ∈
{linux_elf, pe_executable, ascii_config, xml_config, json_config}` —
keyed off file_format_catalog output. Both invariants hold.

### §3.3 MCP tool inventory — 5 tier-1 + 3 tier-2 (8 total v0)

**Scout D:** 10 new tools + 1 reuse.
**Scout E:** ≥5.

**RESOLVED:** 8 tools v0 (5 mandatory + 3 deep-triage). The 2 Scout D
tools that defer to v1 are:

- `list_ics_function_code_extensions` — defers because UMAS / Siemens
  private profiles need `vendor_extended_allowlist` per-vendor — that
  schema field ships in v0 but the dedicated drilldown tool waits for
  enough operator feedback to lock the right grouping.
- `summarize_ics_protocol_coverage` — corpus aggregate is well-served
  by `lookup_ics_protocol_across_firmwares` with `group_by` parameter
  in v0; dedicated summarize tool deferred until usage shows the need.

`verify_cve_attribution` reuses the EXISTING tool (no change).

### §3.4 Cross-feature gates I1-I13 — Scout C's full 13 ship in v0

**Scout C:** I1-I13 (13 gates).
**Scout E:** doesn't list all 13.

**RESOLVED:** Scout C is correct — all 13 gates ship in Phase B. Scout
E was scoped to the consumer-hook enumeration (Rule #47), not the
catalog-load gate enumeration. The two scouts answer different questions
and don't actually contradict — E listed the consumer-hook gates (17
points in §A-K); C listed the catalog-load gates (I1-I13).

Total in v0: 13 catalog-load gates (I1-I13) + 17 consumer-hook touchpoints
+ ~12 Rule #46 META-CANARIES.

## §4 Closed Literals — final v0 declarations

```python
# In backend/app/services/ics_protocol_catalog/schema.py

# Core protocol taxonomy (v0 = 3 protocols; v1 extends via Rule #25 Shape-1)
IcsProtocolFamily = Literal[
    "modbus_tcp",   # v0 — Schneider M340, M580, Quantum
    "dnp3",         # v0 — DNP3 SCADA RTU/OS
    "s7comm",       # v0 — Siemens S7-300, S7-400, S7-1200, S7-1500
    "unknown_ics",  # v0 — catch-all when signals don't converge above floor
]

# v1 extension list (DOCUMENTED IN COMMENT, NOT IN v0 LITERAL):
# - opc_ua_binary, bacnet_ip, iec_60870_5_104, ethernet_ip,
#   profinet_rt, iec_61850_mms, ethercat, dlms_cosem, hart_ip, fins,
#   melsec, modbus_rtu, modbus_ascii
# Each v1 protocol ships as a Rule #25 single-slice Shape-1 commit.

IcsLayer = Literal["application", "transport", "data_link", "session"]

# Closed canonical transport allowlist — defense against Scout C #2 alias attack
IcsTransport = Literal["tcp", "udp", "ethernet_raw", "serial_rs485", "any"]

# Closed canonical port allowlist (Scout C #2 mitigation)
# Operator override requires precedence >= 5000 AND manifest_source attested_external
IcsTransportPort = Literal[
    502,    # Modbus/TCP
    20000,  # DNP3
    4840,   # OPC-UA (reserved for v1)
    102,    # S7Comm (RFC1006 over TPKT)
    47808,  # BACnet/IP (reserved for v1)
    44818,  # EtherNet/IP (reserved for v1)
    34980,  # EtherCAT (reserved for v1)
    4900,   # HART-IP (reserved for v1)
    0,      # SENTINEL — "any port" for protocols that float
]

# Signal grammar (Rule #46 META-CANARY M-EXH: SIGNAL_EVALUATORS dispatch exhaustive)
IcsSignalKind = Literal[
    "magic_bytes",       # raw byte patterns at offset (S7Comm TPKT, Modbus MBAP header)
    "port_signature",   # default-port constant embedded in .rodata as LE uint16
    "function_code_set", # closed-allowlist function-code/op-code byte values
    "string_in_binary",  # ASCII protocol-name needle in extracted strings
    "library_symbol",    # SONAME / dlsym name from ELF/PE imports
    "always_matches",   # sentinel — pairs with sort_tier='floor' only
]

# Artifact-source partition for context filtering
IcsArtifactSource = Literal["binary", "config_file", "embedded_blob", "any"]

# Certainty tier — caps Output.confidence (Scout B/A risk #1 mitigation)
IcsCertainty = Literal[
    "stack_present",   # library_symbol + function_code_set co-occurrence → high
    "config_present",  # config_file + magic_bytes → medium
    "string_only",     # ASCII needle only → low
]

# Category laundering defense (Scout C #15)
IcsCategory = Literal[
    "ics_protocol_stack",
    "ics_protocol_config",
    "ics_protocol_library",
    "ics_protocol_documentation",
    "ics_protocol_unknown",
]

# Walker state machine (Rule #33.a)
IcsProtocolWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed",
]

# Finding-source cross-stack alignment (Rule #25 Shape-1 — Phase E commit)
# v0 emits 6 finding source values across the 3 protocols.
IcsProtocolFindingSource = Literal[
    "ics_modbus_tcp_stack_detected",         # high-confidence Modbus
    "ics_modbus_tcp_string_only",            # low-confidence Modbus string
    "ics_dnp3_stack_detected",               # high-confidence DNP3
    "ics_dnp3_string_only",                  # low-confidence DNP3
    "ics_s7comm_stack_detected",             # high-confidence S7Comm
    "ics_s7comm_vendor_extension_anomaly",   # FC outside vendor_extended_allowlist
]
```

## §5 Cross-feature gates I1-I13 — final decisions

| Gate | Description | v0? | Severity | Justification |
|---|---|---|---|---|
| I1 | `mode=override` × `manifest_source` rank parity | YES | REJECT | Direct A1 mirror; load-time |
| I2 | `vendor_authority` from manifest_source, NEVER dispatch entry | YES | REJECT | Direct A2 mirror, terminus-aware |
| I3 | `dispatch.cases.*` × `deprecation.status: removed` | YES | WARN | Downgraded per §SC5-NEW-ICS-3 |
| I4 | Cross-vendor same-precedence same-magic collision | YES | REJECT | A4 mirror; DNP3/IEC-104 collision case |
| I5 | `dispatch.depth_max >= 2` × eager expensive plugin | YES | REJECT | A5 mirror |
| I6 | Dispatch-rank-monotonicity (terminus authority) | YES | REJECT | A6 mirror TIGHTENED (CVE-feeding) |
| I7 | Plugin-namespace-disjointness | YES | REJECT | A7 mirror |
| I8 | High-collision floor: operator weak signal × precedence < 5000 | YES | REJECT | A8 mirror — `string_only` certainty + operator+low-precedence = REJECT |
| I9 | `protocol_id` sanitization | YES | WARN | A9 mirror |
| I10 | Transport-port × protocol-family agreement | YES | REJECT | NEW; closes Scout C #2 |
| I11 | F-FORENSIC-10 analog — CVE-bearing entry requires narrowing | YES | REJECT | NEW; closes Scout C #8 + §SC5-NEW-ICS-4 |
| I12 | Refinement `applies_when: any` REJECTED for operator | YES | REJECT | NEW; closes Scout C #19 |
| I13 | Dispatch-cycle detection BFS | YES | REJECT | NEW; closes Scout C #14 |

**All 13 ship in v0 Phase B.** Each gets a paired META-CANARY (Rule #46
mandatory) under `test_ics_protocol_catalog.py`. Synthesize the gate's
specific hostile-YAML in memory; load via `catalog._load_one()`; assert
`ValueError` raised OR `catalog.last_warning` contains the expected
substring per severity.

## §6 Bundled plugins — 1 in v0, 2 deferred to v1

**Decision:** v0 ships **ONLY `ics_string_scanner_default`**. ELF/PE
binary-symtab plugins defer to v1.

**Justification:**

- String-scanner catches >70% of detection signal load — Scout B's #1
  signal (ASCII protocol-name strings) and #2 signal (port constants
  embedded in .rodata as LE uint16) both fall to a unified string-scan
  pass.
- ELF symtab + PE imports require introducing pyelftools+pefile as
  worker-image dependencies and adding ~600 LOC of plugin code; the
  v0 budget (3,000-3,500 net LOC) can't accommodate without scope cut
  elsewhere.
- v1a ships `ics_elf_symtab_default` (~300 LOC + tests) as one Rule #25
  Shape-1 commit.
- v1b ships `ics_pe_imports_default` (~300 LOC + tests) as another
  Rule #25 Shape-1 commit.

### `ics_string_scanner_default` — contract

```python
class IcsStringScannerDefault:
    """Bundled string-scanner plugin. Runs ONCE per binary, caches results
    in IcsDetectionContext. Per-manifest signals consult the cache."""

    name: ClassVar[str] = "ics_string_scanner_default"
    cost_class: ClassVar[int] = 2  # cheap; extract once + cache
    applicable_manifest_ids: ClassVar[frozenset[str]] = frozenset({
        "modbus_tcp", "dnp3", "s7comm",
    })
    protocol_families: ClassVar[frozenset[str]] = frozenset({
        "modbus_tcp", "dnp3", "s7comm",
    })
    requires_network: ClassVar[bool] = False
    side_effects: ClassVar[Literal["none"]] = "none"

    def detect(
        self, blob_head: bytes, path: str, size: int,
        ctx: IcsDetectionContext,
    ) -> IcsProtocolDetection | None:
        """Scan blob for ASCII needles + LE uint16 port constants.
        Cache result keyed by blob path. Returns Detection with
        evidence list + IcsCertainty caps."""
```

Token-scan gate per Rule #45 + Rule #46:
- Forbidden tokens: `subprocess`, `socket`, `requests`, `httpx`,
  `aiohttp`, `urllib`, `eval(`, `exec(`, `__import__`, `compile(`,
  `decrypt`, `Crypto.Cipher`, `cryptography.fernet`, `dpapi`,
  `CryptUnprotectData`, `os.system`, `os.popen`, `pty.spawn`,
  `asyncio.create_subprocess`.
- Paired META-CANARY: synthesize hostile plugin source IN MEMORY
  (concatenated lines, NOT f-string per Rule #46); assert tokenize-scan
  REJECTS.

## §7 MCP tool inventory — v0 final (8 tools)

### Tier-1 mandatory (5 tools — including Rule #44 mandatory)

1. **`list_ics_protocols(firmware_id, protocol_family?)`** — per-firmware reader.
   ```python
   input_schema = {
       "type": "object",
       "properties": {
           "firmware_id": {"type": "string", "format": "uuid"},
           "protocol_family": {"type": "string"},  # closed-Literal validated server-side
       },
       "required": ["firmware_id"],
   }
   # Output: {"detections": [{...}], "by_protocol_family": {...}, "total": N}
   ```

2. **`lookup_ics_protocol_across_firmwares(...)`** — **Rule #44 MANDATORY**.
   See §9 for SQL shape.

3. **`list_ics_protocol_families(vendor?)`** — catalog discovery (mirror
   `list_chip_families`).

4. **`describe_ics_advisory(advisory_id)`** — mirror `describe_advisory`
   in `hardware_firmware.py:549`. v0 ships pins for `ADVISORY-TRITON`,
   `ADVISORY-MODBUS-WEAK-AUTH`, `ADVISORY-INDUSTROYER2` (forward-prepared
   per Rule #49 — fires when v1c IEC-104 ships).

5. **`trigger_ics_protocol_walk(firmware_id)`** — Rule #33.a idempotent
   POST + 409. Backed by REST router endpoint
   `POST /api/v1/firmware/{firmware_id}/ics-protocol-walk` returning 202
   + `IcsProtocolWalkStatus` literal.

### Tier-2 deep-triage (3 tools)

6. **`ics_protocol_walk_status(firmware_id)`** — state-machine reader
   for polling.

7. **`get_ics_protocol_details(firmware_id, protocol_family)`** — full
   evidence list per detection.

8. **`analyze_ics_protocol_endpoint(firmware_id, protocol_family)`** —
   endpoint detail (OPC-UA SecurityPolicy, Modbus FC list, S7Comm
   job-codes). v0 surfaces the evidence FROM walker output;
   protocol-specific deep-analysis grammars defer to v1.

### Deferred to v1+

- `diff_ics_protocols` (v1 — version diff workflow needs operator-feedback before locking shape)
- `list_ics_function_code_extensions` (v1 — UMAS allowlist needs lockup)
- `summarize_ics_protocol_coverage` (covered by Rule #44 cross-firmware
  + `group_by` parameter; revisit after operator usage)
- `submit_ics_protocol_descriptor` (v1 — operator hint surface needs
  precedence arbitration design parallel to bare-metal descriptor)

### Reuse existing (1 tool)

- `verify_cve_attribution(cve_id, blob_id)` — REUSE. Walker-emitted
  detections will be visible through the existing matcher chain.

## §8 Phase commit shape — 7 phases per Rule #25

### Phase A — Schema + closed Literals + catalog scaffold (~600 LOC net)

**Files:** new `backend/app/services/ics_protocol_catalog/{__init__,catalog,resolver,snapshot,schema}.py`,
`backend/app/services/ics_protocol_catalog/data/` directory scaffold.

**Includes:** all 11 closed Literals from §4. Pydantic v2 models
(`IcsProtocolManifest`, `IcsDetection`, `IcsDetectionSignal`,
`IcsOutput`, `Plugin`, `Deprecation`, `ProvenanceStub`,
`TextFormatConstraint` reuse-or-mirror) with `extra="forbid"`. Mtime-cached
loader.

**Rule #46 META-CANARIES in this commit:** M1 (closed Literal exhaustive
in `SIGNAL_EVALUATORS` skeleton — empty body OK in Phase A; B fills it).

**Estimated net:** +650 LOC (schema 350 + catalog 200 + resolver skeleton 100).

### Phase B — Resolver + plugins + cross-feature load gates I1-I13 (~900 LOC net)

**Files:** complete `resolver.py`, `plugins/__init__.py`,
`plugins/ics_string_scanner_default.py`, all 13 gate implementations in
`catalog.py`.

**Includes:** `SIGNAL_EVALUATORS` dispatch table (closed by
`IcsSignalKind`); `PLUGIN_REGISTRY` with `freeze_plugin_registry()`;
all 13 cross-feature gates I1-I13.

**Rule #46 META-CANARIES in this commit:** M2 (SIGNAL_EVALUATORS
exhaustive), M3 (PLUGIN_REGISTRY post-freeze immutability), M4-M16 (one
META-CANARY per gate I1-I13 — paired with hostile-YAML synthesis +
load + assert), M17 (plugin token-scan no-execute / no-network /
no-decrypt — Rule #45 partner).

**Estimated net:** +900 LOC (resolver 350 + plugins 250 + gates 200 +
META-CANARIES 100).

### Phase C — v0 YAMLs + corpus fixtures (~250 LOC net)

**Files:** `data/_system/modbus_tcp.yaml`, `data/_system/dnp3.yaml`,
`data/_system/s7comm.yaml`, test fixtures.

**Rule #46 META-CANARIES in this commit:** M18 (YAML corpus loads
clean; `catalog.last_warning is None`).

**Estimated net:** +250 LOC (YAMLs 180 + corpus fixtures 70).

### Phase D — Walker + ORM + alembic + state machine + JSONB normaliser + orphan reaper (~900 LOC net)

**Files:**
- new `backend/app/services/ics_protocol_walker.py` (inner/outer/safe triplet per Rule #39)
- new `backend/app/models/ics_protocol_detection.py` (ORM for detection rows)
- `backend/app/models/firmware.py` (+5 columns: `ics_protocol_walk_status`,
  `_started_at`, `_finished_at`, `_error`, `_result`)
- new `backend/alembic/versions/<sha>_add_ics_protocol_walk_columns_and_detection_table.py`
- `backend/app/services/jsonb_normalizers.py` (+`_normalize_firmware_ics_protocol_walk_result` + stamp helper + `ICS_PROTOCOL_WALK_RESULT_SCHEMA_VERSION = 1`)
- `backend/app/schemas/firmware.py` (+ `IcsProtocolWalkStatus` Literal)
- `backend/app/main.py` (+orphan reaper block, mirror vuln-scan shape per Rule #51)

**Includes:** Rule #39 triplet (`_do_ics_protocol_audit_run`,
`run_ics_protocol_audit_background`, `auto_ics_protocol_audit_firmware_safe`);
DB CHECK on `ics_protocol_walk_status`; `extra="forbid"` on response
Pydantic schema; Rule #51 orphan reaper.

**Rule #46 META-CANARIES in this commit:** M19 (walker no-decrypt /
no-execute — Rule #45 token-scan over walker source); M20 (orphan reaper
synthesizes 'running' row + restarts lifespan + asserts row → 'failed');
M21 (JSONB normaliser 3-canary battery — canonical / wrong-type / None).

**Estimated net:** +900 LOC (walker 400 + ORM 150 + alembic 100 +
normaliser 80 + reaper 50 + schema 50 + tests 70).

### Phase E — Walker auto-trigger + finding-source cross-stack alignment (Rule #25 Shape-1, ~250 LOC net)

**Files (SINGLE-SLICE COMMIT per Rule #25 exception #2):**

1. `backend/app/workers/walker_registry.py` (+1 entry — auto-trigger import + append)
2. `backend/alembic/versions/<sha>_extend_findings_source_ics_protocol.py`
   (extend `ck_findings_source` CHECK constraint with 6 new values)
3. `backend/app/schemas/finding.py` (+ `IcsProtocolFindingSource` Literal — 6 values)
4. `frontend/src/types/index.ts:226` (extend `FindingSource` union with 6 values)
5. `frontend/src/constants/statusConfig.ts:85` (extend `FINDING_SOURCE_CONFIG` with 6 entries)
6. `backend/tests/test_finding_source_alignment.py` (extend `_EXPECTED_SOURCES_SIZE` + parametrized acceptance battery per Rule #48 5-part)

**Rule #46 META-CANARIES in this commit:** M22 (Rule #48 part-5 META-CANARY —
gate's WARN message contains the rejected entry name + enumeration of accepted
narrowing fields); M23 (consumer-hook enumeration grep — walker_registry
contains `ics_protocol`).

**Estimated net:** +250 LOC (alembic 60 + schema 20 + frontend 30 +
walker_registry 5 + tests 135).

### Phase F — MCP tools (Rule #44 mandatory, ~600 LOC net)

**Files:** new `backend/app/ai/tools/ics_protocol.py` with all 8 v0 tools.
`backend/app/ai/__init__.py` (+import + call register_ics_protocol_tools).
`backend/app/routers/firmware.py` (+ POST `/firmware/{id}/ics-protocol-walk`
endpoint with Rule #51 `TIER_A_LIGHT_ACK` rate-limit decorator + Rule
#33.a 409-on-conflict shape).

**Rule #46 META-CANARIES in this commit:** M24 (Rule #44 cross-firmware
tool exists in `register_ics_protocol_tools` — gate scans for
`lookup_ics_protocol_across_firmwares` registration); M25 (rate-limit
tier alignment — `test_rate_limit_tiers._EXPECTED_TIERS` extended for
the new endpoint).

**Estimated net:** +600 LOC (tool handlers 350 + registrations 50 +
router endpoint 80 + tests 120).

### Phase G — Postmortem + /citadel:learn + Rule #52 promotion

**Files:** `.planning/postmortems/postmortem-ics-protocol-2026-05-20.md`;
extracts to `.planning/knowledge/ics-protocol-2026-05-20-{patterns,antipatterns}.md`
via `/citadel:learn`; CLAUDE.md Rule #52 promoted Rule-of-Two →
Rule-of-Three DURABLE BEYOND DEBATE.

**Estimated net:** +10 LOC (docs only — CLAUDE.md insertion + postmortem
extraction).

### Total v0 net estimate

| Phase | Net LOC |
|---|---:|
| A | +650 |
| B | +900 |
| C | +250 |
| D | +900 |
| E | +250 |
| F | +600 |
| G | +10 |
| **Total** | **+3,560** |

**Vs P3.2 baseline (+2,689 net / 6 commits / single session — confirmed
W2-γ feasible at 0.18× P3.1):** ICS v0 is +32% over P3.2 baseline. Above
the P3.2 target of 3,000-3,500. Two scope-cut options if Wave-2 gamma
flags overrun:

- **Option 1** — Defer `ics_string_scanner_default` plugin to v1
  (-300 LOC). Walker uses inline byte-scan code in Phase D. Cost: no
  caching across manifests; ~5x perf cost on multi-manifest blobs.
- **Option 2** — Defer 5 of 13 gates to v1 (-200 LOC). Keep I1, I2,
  I6, I8, I10, I11, I13 (CVE-feeding / dispatch-rank / port-alias /
  cycle-detect / refinement-abuse — security-critical); defer I3, I4,
  I5, I7, I9, I12 to v1. Cost: less defense-in-depth at load time.

**Recommend NEITHER cut.** v0 at 3,560 net is within margin of P3.2's
+2,689. Gamma scout will measure independently.

### Phase combine/split notes

- **Combine A+B?** NO — A ships closed Literals + scaffold (importable but
  inert); B ships resolver + gates (executable). Splitting keeps Phase A
  bisect-clean for a fast revert if a Literal shape needs adjustment.
- **Split D?** NO — single Rule #25 single-slice commit per the
  walker/ORM/normaliser/reaper pattern (mirror prefetch_walker, srum_walker).
- **Combine E+F?** NO — E is Rule #25 Shape-1 cross-stack alignment
  (alembic + Pydantic + frontend + test alignment); F is MCP tool
  category. Different responsibility boundaries.

## §9 lookup_ics_protocol_across_firmwares SQL shape

Mirror `linux_systemd.py:437,772` verbatim:

```python
async def _handle_lookup_ics_protocol_across_firmwares(
    input: dict, context: ToolContext,
) -> str:
    """CROSS-FIRMWARE AGGREGATION — given a protocol_family + optional
    filters, return ALL firmware images that have a matching ICS
    detection. wairz competitive differentiator — supply-chain
    indicator identifying the same vendor-pushed protocol stack
    across firmware captures.
    """
    protocol_family = input.get("protocol_family")
    VALID_FAMILIES = frozenset({"modbus_tcp", "dnp3", "s7comm", "unknown_ics"})
    if protocol_family and protocol_family not in VALID_FAMILIES:
        return json.dumps({
            "error": f"protocol_family must be one of {sorted(VALID_FAMILIES)}",
        })

    port = input.get("port")
    function_code_hex = input.get("function_code_hex")
    version_substring = input.get("version_substring")
    vendor = input.get("vendor")
    scope = input.get("scope", "project")
    limit = max(1, min(int(input.get("limit", 100)), 500))

    where_clauses: list = []
    if protocol_family:
        where_clauses.append(IcsProtocolDetection.protocol_family == protocol_family)
    if port is not None:
        where_clauses.append(IcsProtocolDetection.port == int(port))
    if function_code_hex:
        where_clauses.append(
            IcsProtocolDetection.evidence.cast(JSONB).contains({
                "function_codes": [function_code_hex.lower()],
            })
        )
    if version_substring:
        where_clauses.append(
            IcsProtocolDetection.version_substring.ilike(f"%{version_substring}%")
        )
    if vendor:
        where_clauses.append(IcsProtocolDetection.vendor.ilike(f"%{vendor}%"))

    if scope == "project":
        if not context.project_id:
            return json.dumps({
                "error": (
                    "scope='project' requires an active project — "
                    "call switch_project first or use scope='global'."
                )
            })
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = (
            select(IcsProtocolDetection, Firmware, Project)
            .join(Firmware, IcsProtocolDetection.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where_clauses)
            .order_by(Firmware.created_at)
            .limit(limit)
        )
    else:
        stmt = (
            select(IcsProtocolDetection, Firmware, Project)
            .join(Firmware, IcsProtocolDetection.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(*where_clauses)
            .order_by(Firmware.created_at)
            .limit(limit)
        )

    rows = (await context.db.execute(stmt)).all()
    # GROUP BY firmware bucket; supply_chain_signal = (total_match_count >= 2)
    by_firmware: dict[str, dict] = {}
    for detection, firmware, project in rows:
        fid = str(firmware.id)
        by_firmware.setdefault(fid, {
            "firmware_id": fid,
            "project_id": str(project.id),
            "project_name": project.name,
            "firmware_filename": firmware.original_filename,
            "match_count": 0,
            "sample_detections": [],
        })
        by_firmware[fid]["match_count"] += 1
        if len(by_firmware[fid]["sample_detections"]) < 3:
            by_firmware[fid]["sample_detections"].append({
                "protocol_family": detection.protocol_family,
                "certainty": detection.certainty,
                "evidence_kinds": detection.evidence_kinds,
            })
    total_matches = sum(b["match_count"] for b in by_firmware.values())
    supply_chain_signal = sum(
        1 for b in by_firmware.values() if b["match_count"] >= 2
    )
    return json.dumps({
        "matches_by_firmware": list(by_firmware.values()),
        "firmware_count": len(by_firmware),
        "total_match_count": total_matches,
        "supply_chain_signal_firmware_count": supply_chain_signal,
        "scope": scope,
    })
```

Registration in `register_ics_protocol_tools`:

```python
registry.register(
    name="lookup_ics_protocol_across_firmwares",
    description=(
        "CROSS-FIRMWARE AGGREGATION — find every firmware in the project "
        "(or globally) that carries a matching ICS protocol detection. "
        "Optional filters: protocol_family, port, function_code_hex, "
        "version_substring, vendor. Output groups matches by firmware "
        "with supply_chain_signal flag where match_count >= 2."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "protocol_family": {
                "type": "string",
                "enum": ["modbus_tcp", "dnp3", "s7comm", "unknown_ics"],
            },
            "port": {"type": "integer"},
            "function_code_hex": {"type": "string"},
            "version_substring": {"type": "string"},
            "vendor": {"type": "string"},
            "scope": {"type": "string", "enum": ["project", "global"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500},
        },
        "required": [],  # at least one filter recommended; none = corpus-wide
    },
    handler=_handle_lookup_ics_protocol_across_firmwares,
)
```

## §10 Phase E Rule #25 Shape-1 surfaces — full inventory

ONE atomic commit landing all surfaces simultaneously:

| # | Surface | File | Change |
|---|---|---|---|
| 1 | DB CHECK constraint extension | `backend/alembic/versions/<sha>_extend_findings_source_ics_protocol.py` | ALTER TABLE findings DROP CONSTRAINT ck_findings_source; ADD constraint with 6 new values |
| 2 | Pydantic Literal | `backend/app/schemas/finding.py` (new section) | `IcsProtocolFindingSource = Literal[...]` (6 values) |
| 3 | Frontend type union | `frontend/src/types/index.ts:226` | extend `FindingSource` union with 6 string values |
| 4 | Frontend config map | `frontend/src/constants/statusConfig.ts:85` | extend `FINDING_SOURCE_CONFIG: Record<FindingSource, ...>` with 6 entries |
| 5 | Alignment regression canary | `backend/tests/test_finding_source_alignment.py` | extend `_EXPECTED_SOURCES_SIZE` pin + parametrize acceptance battery |
| 6 | Walker auto-trigger registration | `backend/app/workers/walker_registry.py:57-98` | import + append `(ics_protocol_walker.auto_ics_protocol_audit_firmware_safe, "ics_protocol")` |
| 7 | Walker mod alignment | `backend/app/services/ics_protocol_walker.py` | export `auto_ics_protocol_audit_firmware_safe` callable signature matches registry |

**Rule #48 5-part test shape** in test_finding_source_alignment.py:

- (1) **Paired rejection** — each layer rejects synthetic unknown source `xyz_protocol_unknown` in its dialect (DB CHECK raises IntegrityError; Pydantic raises ValidationError; frontend Record lookup returns undefined fallback).
- (2) **Paired acceptance** — parametrize over 6 new source values; each asserted accepted by DB + Pydantic + frontend.
- (3) **Size-lock** — `len(IcsProtocolFindingSource.__args__) == 6` AND `_EXPECTED_SOURCES_SIZE_AFTER_ICS == previous + 6`.
- (4) **Cross-layer alignment** — synthesize `ics_zzz_unknown` IN BOTH dialects in ONE test; assert BOTH layers reject (per their idiomatic shape).
- (5) **META-CANARY (Rule #46)** — assert the gate's rejection message contains the rejected source name AND the list of accepted source names (so operators can self-recover).

## §11 Top 3 contradictions / surprises resolved

### Contradiction 1 — Plugin escape hatch breadth (Scout A vs Scout C)

**Surprise depth:** Scout A enthusiastically proposed 3 bundled plugins
+ HYBRID escape hatch as a competitive feature; Scout C structurally
rejected operator plugins entirely as a Rule #36+#45+§SC5 triple-breach.

**Resolution:** they're answering different questions. v0 ships
BUNDLED-ONLY (Scout A's 3 plugins, narrowed to 1 in v0 + 2 v1
deferrals); v0 BLOCKS operator-supplied plugins (Scout C's REJECT).
Operator extensibility is YAML-only in v0. Operator Python plugins
defer to v2 as side-container (Exception 3, mirror P3.2.f's
`WAIRZ_FORMAT_PLUGIN_PATH` deferral pattern).

### Contradiction 2 — Walker iteration set (Scout A vs Scout E)

**Surprise depth:** Scout A said "filtered set" (binaries + config
files); Scout E said `get_detection_roots(firmware)` (Rule #16).
Initially looked like architectural conflict — walker should iterate
ALL blobs vs filter early.

**Resolution:** both apply at different layers. Rule #16 detection
roots is the OUTER iteration (multi-archive + scatter-zip safety); the
INNER filtering is by `blob.classifier_format` (binaries + config blobs
only). The two together: iterate every detection root → within each
root, filter to classified blobs. Scout B's pattern (file_format_catalog
output gates ICS walker entry set) closes the loop.

### Contradiction 3 — MCP tool count (Scout D vs Scout E)

**Surprise depth:** Scout D wanted 10 tools + 1 reuse; Scout E said ≥5.
Looked like a scope contradiction. On read-through it's a
question-difference: D enumerated tools to answer the operator's top-10
queries; E enumerated minimum-viable tools to meet Rule #44.

**Resolution:** v0 ships 8 (5 mandatory + 3 deep-triage). The 2 Scout
D tools deferred to v1 — `diff_ics_protocols` and
`list_ics_function_code_extensions` — both need design decisions that
operator-feedback should drive (diff-shape granularity; per-vendor FC
allowlist grouping). Shipping them v0 risks locking the wrong UX shape.

### Bonus surprise — Scout C's §SC5-NEW-ICS-1 promotes to Rule #52 worked-example #3

The dispatch-chain authority-laundering attack (§SC5-NEW-ICS-1) is
structurally identical to P3.2.c's A6 gate — different consumer (CVE
matcher vs format dispatch), same attack shape. The Rule #52 promotion
to Rule-of-Three lands precisely because this pattern recurs with the
same structural answer (gate at terminus; REJECT for CVE-feeding
catalogs; WARN-degrade for non-CVE-feeding when downgrade is
defensible). This is the Wave-1+Wave-2 methodology validating itself —
W2-β cross-feature critique on a third worked-example confirms the
recurrence pattern.

## §12 Single-session feasibility verdict

**Locked design net: ~3,560 LOC** across 7 phases (A-G), 6 commits if
G is documentation-only (matches P3.2 cadence), or 7 commits if G is
counted (matches P3.1 cadence).

**P3.2 baseline:** +2,689 net / 6 commits / shipped in single session
per W2-γ verdict (0.18× P3.1).

**ICS v0:** +3,560 net / 7 phases / 6-7 commits. **+32% over P3.2.**
**Confidence: MEDIUM-HIGH single-session feasible.** Gamma scout
measures independently; if gamma's yardstick flags overrun, drop Phase
F's `analyze_ics_protocol_endpoint` (Tier-2 tool with most protocol-specific
code) to defer to v1 — net savings ~200 LOC, brings v0 to ~3,360, within
P3.2 baseline 1.25× margin.

**v1 follow-on plan (post-postmortem):**
- v1a: OPC-UA Binary YAML + ADVISORY-INDUSTROYER2 pin extension (Rule #25 Shape-1, ~300 LOC)
- v1b: BACnet/IP YAML + IEC-104 YAML cluster (Rule #25 Shape-1, ~400 LOC)
- v1c: ELF symtab plugin + PE imports plugin (2 commits, ~600 LOC)
- v1d: `diff_ics_protocols` + `list_ics_function_code_extensions` MCP tools (1-2 commits, ~400 LOC)
- v1e: EtherNet/IP + CIP grammar + UMAS vendor extension (Rule #25 Shape-1, ~500 LOC)
- v2: side-container operator Python plugin path (Exception 3, ~600 LOC)

---

**Bottom line:** v0 is FEASIBLE, design is LOCKED, contradictions are
RESOLVED, gate I1-I13 + META-CANARY discipline is INHERITED from P3.2.
Wave-2 gamma scout validates the LOC estimate; β scout cross-feature
critique pre-mortem looks for §SC5-NEW-ICS-N attacks that Wave-1
single-axis scouts couldn't surface. Ship as 6-7 commits, bisect-clean,
direct-push per Rule #25.
