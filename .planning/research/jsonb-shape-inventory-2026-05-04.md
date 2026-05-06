---
title: JSONB column shape inventory + normaliser strategy (Rule #35c)
status: living
generated: 2026-05-06
session: audit-jsonb-schema-version-rule35c-2026-05-04
---

# JSONB shape inventory — production data, 2026-05-06

Per acceptance criteria #1 of `audit-jsonb-schema-version-rule35c-2026-05-04`. Measured via `SELECT jsonb_typeof(<col>) GROUP BY 1` against the live wairz database. The rule (CLAUDE.md #35c) is forward-looking discipline; current shape uniformity does NOT exempt a column from getting a normaliser, because legacy rows accumulate indefinitely and future writers may drift.

## Threshold rule

Per the user's autopilot prompt: pick the strategy per column by consumer count.

- **≥3 consumers** → add `schema_version: int` discriminator to the writer-side payload + boundary normaliser. Readers dispatch via `match value.get("schema_version", 1):`. Marker survives shape changes.
- **<3 consumers** → boundary normaliser only. Cheaper; no writer churn.

Either way every column gets a `_normalize_<col>` helper at `backend/app/services/jsonb_normalizers.py`.

## Per-column inventory

| # | Table.column | Default shape | Prod shape (rows) | Consumer files | Strategy |
|---|---|---|---|---|---|
| 1 | firmware.device_metadata | dict\|None | object (16), no nulls | 19 | schema_version |
| 2 | firmware.binary_info | dict\|None | object (3), null (13) | 12 | schema_version |
| 3 | firmware.cve_match_result | dict\|None | object (1), null (15) | 2 | normaliser only |
| 4 | conversations.messages | list (default []) | empty table | 7 | schema_version |
| 5 | analysis_cache.result | dict\|None | object (7980) | 4 | schema_version |
| 6 | sbom_components.metadata | dict (default {}) | object (3970) | 2 | normaliser only |
| 7 | hardware_firmware_blobs.metadata | dict (default {}) | object (1696) | 4 | schema_version |
| 8 | fuzzing_campaigns.config | dict (default {}) | empty table | 5 | schema_version |
| 9 | fuzzing_campaigns.stats | dict (default {}) | empty table | 4 | schema_version |
| 10 | emulation_sessions.port_forwards | list[dict]\|None | array (4) | 9 | schema_version |
| 11 | emulation_sessions.discovered_services | list[dict]\|None | null (4) | 3 | schema_version |
| 12 | emulation_sessions.nvram_state | dict\|None | null (4) | 2 | normaliser only |
| 13 | emulation_presets.port_forwards | list[dict]\|None | empty table | 9 (shared with above) | schema_version |
| 14 | attack_surface_entries.score_breakdown | dict (default {}) | object (3053) | 3 | schema_version |
| 15 | attack_surface_entries.dangerous_imports | list (default []) | array (3053) | 4 | schema_version |
| 16 | attack_surface_entries.input_categories | list (default []) | array (3053) | 4 | schema_version |
| 17 | cra_requirement_results.finding_ids | list[str] | empty table | 2 | normaliser only |
| 18 | cra_requirement_results.tool_sources | list[str] | empty table | 2 | normaliser only |
| 19 | cra_requirement_results.related_cwes | list[str] | empty table | 2 | normaliser only |
| 20 | cra_requirement_results.related_cves | list[str] | empty table | 2 | normaliser only |

**Already protected (do not touch):**
- device_dump_sessions.partitions / .result — `_normalize_partitions` exists; `DUMP_PARTITIONS_SCHEMA_VERSION` / `DUMP_RESULT_SCHEMA_VERSION` constants stamped (commit 875aa11 era).

**Sub-key normaliser already present:**
- `firmware.device_metadata['vendor_decryption']` — `_normalize_vendor_decryption` at `unpack_audit_service.py:104` (Rule #35c canonical reference shape).

## Production shape uniformity note

Current production data shows **no shape divergence at the column level** for any of the 20 columns. The rule applies anyway: shape divergence accumulates over time, and the unpack-audit-vendor_decryption incident (5/4) demonstrated that sub-key shape drift exists even when column-level shape is uniform. The boundary normaliser is forward-looking infrastructure.

## Implementation order (per-column commits, Rule #25)

Highest-priority first:
1. firmware.device_metadata (most active, sub-key drift precedent)
2. conversations.messages (AI history, future LLM features multiply consumers)
3. analysis_cache.result (multi-tool cache)
4. firmware.binary_info
5. firmware.cve_match_result
6. fuzzing_campaigns.config / .stats
7. attack_surface_entries × 3
8. emulation_sessions × 3 + emulation_presets × 1
9. sbom_components.metadata + hardware_firmware_blobs.metadata
10. cra_requirement_results × 4 (batched — homogeneous list[str], trivially identical normaliser)
11. Docs: CLAUDE.md + .mex/patterns/INDEX.md updates

## Normaliser conventions

- File: `backend/app/services/jsonb_normalizers.py` (single module hosts all 20).
- Naming: `_normalize_<table>_<column>` (e.g. `_normalize_firmware_device_metadata`).
- Signature: `(value: dict | list | None) -> <canonical>`.
- Idempotent: passing a canonical value through returns it unchanged.
- Defensive: returns the canonical empty default (`{}`, `[]`) for `None` / wrong-type / unparseable inputs rather than raising — this is the boundary, not the inner logic.
- Tests: parameterised fixture per known shape variant.

## Schema_version mechanics

- Constants live in `jsonb_normalizers.py`: `<TABLE>_<COLUMN>_SCHEMA_VERSION = 1`.
- Writers stamp the version into the dict payload:
  ```python
  payload = {"schema_version": FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION, ...rest}
  firmware.device_metadata = payload
  ```
- Readers route through `_normalize_<col>`, which dispatches:
  ```python
  match value.get("schema_version", 1):
      case 1: return value  # canonical
      case _: ...  # future-proof
  ```
- Existing rows lacking `schema_version` are treated as v1 (the canonical shape today).
- Bump only on backwards-incompatible shape change.
