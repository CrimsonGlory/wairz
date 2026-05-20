# Wave-1 Scout E — Precedence + Cross-Feature Integration Map

## Consumer Hook Enumeration (Rule #47 exhaustive — 17 points)

### A. Walker auto-trigger registration

1. **`backend/app/workers/walker_registry.py:57-98`** — add import + append to `_load_walker_safe_runners()`. WITHOUT this, walker never fires.
2. `backend/app/services/firmware_service.py:817-822` — _post_process_pipeline iterates via registry (NO change required — registry is SoT).
3. `backend/app/workers/unpack.py:120-154` — same registry iteration (NO change).

### B. Firmware ORM + per-walker columns (Rule #33 .a + Rule #35c)

4. **`backend/app/models/firmware.py`** — add 5 columns mirroring SRUM shape at `:233-243`:
   - `ics_protocol_walk_status: Mapped[str]` String(20) default "idle"
   - `ics_protocol_walk_started_at`, `_finished_at`, `_error`, `_result` JSONB
5. **`backend/alembic/versions/<new>_add_ics_protocol_walk_columns.py`** — DDL + `op.create_check_constraint("ck_firmware_ics_protocol_walk_status", "firmware", "...IN ('idle','queued','running','completed','failed')")`

### C. JSONB normaliser + stamp (Rule #35c)

6. **`backend/app/services/jsonb_normalizers.py`** — `_normalize_firmware_ics_protocol_walk_result` + `_stamp_*` + `ICS_PROTOCOL_WALK_RESULT_SCHEMA_VERSION = 1`
7. **`backend/tests/test_jsonb_normalizers.py`** — 3-canary battery

### D. Walker triplet (Rule #39)

8. **`backend/app/services/ics_protocol_walker.py`** — inner/outer/safe triplet

### E. Pydantic walk_status

9. **`backend/app/schemas/firmware.py`** — `IcsProtocolWalkStatus = Literal[...]`

### F. Orphan reaper (Rule #51 companion)

10. **`backend/app/main.py` lifespan** — 4th reaper block mirroring vuln-scan shape; UPDATE firmware SET ics_protocol_walk_status='failed' WHERE status IN ('queued','running')

### G. MCP tool surface

11. **`backend/app/ai/tools/ics_protocol.py`** — NEW category with trigger + lookup + lookup_*_across_firmwares + describe + register_ics_protocol_tools
12. **`backend/app/ai/__init__.py`** — import + call register_ics_protocol_tools

### H. Findings source cross-stack alignment (Rule #25 Shape-1)

13. **`backend/alembic/versions/<new>_extend_findings_source_ics_protocol.py`** — extends ck_findings_source CHECK
14. **`backend/app/schemas/finding.py`** — add `IcsProtocolFindingSource = Literal[...]`
15. **`frontend/src/types/index.ts:226`** — extend `FindingSource` union
16. **`frontend/src/constants/statusConfig.ts:85`** — extend `FINDING_SOURCE_CONFIG: Record<FindingSource, ...>`
17. **`backend/tests/test_finding_source_alignment.py`** — Rule #48 5-part alignment regression canary

### I. Rate-limit tier (Rule #51)

18. **`backend/tests/test_rate_limit_tiers.py:47`** — extend `_EXPECTED_TIERS` if hint router endpoint added

### J. Recipe + skip-list docs (Rule #21)

19. **`.mex/context/conventions.md`** Verify Checklist + **`.mex/patterns/INDEX.md`** + **`.mex/patterns/add-ics-protocol-decoder.md`**

### K. Test gates (Rule #45 + Rule #46)

20. **`backend/tests/test_ics_protocol_walker.py::test_walker_no_decrypt_or_command_emit`** + paired META-CANARY

## Unpack-Pipeline vs Walker Decision

**Walker, not pipeline augmentation.** Reasoning:
- File-format = single-blob classification (routing decision); ICS = cross-blob property (semantic finding)
- Walker matches efs/etl/registry/dpapi precedent exactly
- Pipeline augmentation would force ICS detection synchronously inline — multi-minute work on large firmware blocks `upload_stage='ready'` (Rule #51 wrong-shape)
- Operator hint router (analog of `bare_metal-hint`) ships as ADJACENT REST endpoint — fast-ACK + Rule #51 TIER_A_LIGHT_ACK

## Cross-Firmware MCP SQL Shape (Rule #44 — mirror linux_systemd.py:437,772)

```python
async def _handle_lookup_ics_protocol_across_firmwares(input, context) -> str:
    protocol_family = input.get("protocol_family")
    if protocol_family not in VALID_FAMILIES:
        return error
    
    binary_substring = input.get("binary_path_substring")
    scope = input.get("scope", "project")
    limit = max(1, min(int(input.get("limit", 100)), 500))

    stmt = (
        select(IcsProtocolDetection, Firmware, Project)
        .join(Firmware, IcsProtocolDetection.firmware_id == Firmware.id)
        .join(Project, Firmware.project_id == Project.id)
        .where(IcsProtocolDetection.protocol_family == protocol_family, *where_clauses)
        .order_by(Firmware.created_at)
        .limit(limit)
    )
    # Group by firmware bucket; supply_chain_signal = (total_match_count >= 2)
    ...
```

## JSONB stamp + normaliser shape

```python
ICS_PROTOCOL_WALK_RESULT_SCHEMA_VERSION = 1

def _normalize_firmware_ics_protocol_walk_result(value: Any) -> dict | None:
    """Canonical shape:
    {
        "schema_version": 1,
        "run_seconds": float,
        "binaries_scanned": int,
        "detections_persisted": int,
        "by_protocol_family": dict[str, int],
        "by_evidence_kind": dict[str, int],
        "supply_chain_signal_count": int,
        "anomaly_total": int,
        "errors": list[str],
        "per_binary": list[dict],
    }
    """
```

## CVE Matcher Integration

**Curated-tier extension via `ics_protocol_family_regex` narrowing field.**

- Add `ics_protocol_family_regex` to `_KNOWN_FIRMWARE_NARROWING_FIELDS` (`cve_matcher.py:125`)
- Walker populates `blob.metadata_["ics_protocol_families"]` (JSONB list)
- Matcher requires regex to match against the list
- Rule #49 forward-prepared: ship pins TODAY with `strict_ics: true`; ZERO matches until walker ships and populates metadata; ZERO YAML edits at activation

**Tier 4 CPE matching:** NOT applicable directly. ICS family is not a CPE attribute. Indirect via `blob.product_extra` ("Modicon M340 Modbus stack version 2.50") which Tier 4 fuzzy-matcher already consumes.

**Rule #50 candidate:** CVE-2020-7458 (multi-vendor Modbus implementation flaw) — `ADVISORY-CVE-2020-7458` shared across all matching ICS protocol-family entries.

## Cross-Stack Alignment (Rule #25 Shape-1, Rule #48 5-part)

ONE atomic commit:

1. `backend/alembic/versions/<sha>_extend_findings_source_ics_protocol.py`
2. `backend/app/schemas/finding.py:570` — `IcsProtocolFindingSource = Literal[...]`
3. `frontend/src/types/index.ts:226` — extend `FindingSource`
4. `frontend/src/constants/statusConfig.ts:85` — extend `FINDING_SOURCE_CONFIG`
5. `backend/tests/test_finding_source_alignment.py` — pinned size constants + parametrized acceptance battery

Rule-of-Nine in CLAUDE.md confirms this shape is durable.

## Top 3 Hidden Integration Risks

1. **Walker silently no-ops because auto-trigger registration is missed.** Rule #47 worked-example #1 reproduction. Synthesized-row canary uploads test firmware + asserts walk_status NOT 'idle'.

2. **Orphan reaper for `ics_protocol_walk_status` is forgotten.** Rule #51 Rule-of-Two if missed. Test: synthesize 'running' row via make_live_db + restart lifespan + assert row → 'failed'.

3. **CVE-matcher `ics_protocol_family_regex` field added but walker never populates the expected metadata KEY.** Rule #25 Rule-of-Nine `d641f28` analog. Mitigation: Rule #48 5-part cross-stack alignment test pinning `_KNOWN_FIRMWARE_NARROWING_FIELDS` ↔ walker output JSONB key ↔ YAML schema field name in pairwise agreement.
