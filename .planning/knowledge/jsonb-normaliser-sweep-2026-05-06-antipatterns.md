---
title: JSONB normaliser sweep — anti-patterns
session: audit-jsonb-schema-version-rule35c-2026-05-04
session_date: 2026-05-06
commits: 9fcd2b9..9ff6d9c (14 commits)
campaign: audit-2026-05-04 / Rule #35c
related_rules: [35, 35c, 11]
---

# Anti-patterns — JSONB normaliser sweep

## Anti-pattern #1 — Forgetting the import update for a per-column commit

Commit `4bf11c0` (`emulation_sessions.port_forwards`) edited `ai/tools/emulation.py` to USE `_normalize_emulation_sessions_port_forwards` at line 990 but left the file's import block at the previous commit's state (only `_normalize_firmware_binary_info`). Result: that single commit, in isolation, would raise `NameError` on the function being used.

The bug was masked because the smoke test ran AFTER the next commit's change to the import block (multi-line consolidation) — the smoke was against the file's then-current state, not the prior commit's state.

Mitigation:
- Per-column commit checklist: import update belongs in the SAME commit as the consumer change.
- Mechanical detection: post-stage, `git diff --cached` and grep for the new function name; if it appears in a usage but not in an import line, fix before commit.
- The fix shipped in the next commit (`567044d`); commit `4bf11c0` alone is broken when checked out in isolation. Bisect penalty: bisecting through this point requires also applying the import fix.

## Anti-pattern #2 — Normaliser "all in commit 1, consumers later"

Considered initially: write all 20 normalisers in one foundation commit, then ship per-column commits with consumer updates only. Rejected because:

- The foundation commit would be a giant file dump (~700 LOC) without any callers — dead code at the moment of commit.
- Reverting any column's strategy decision requires rewriting the foundation commit instead of cleanly reverting that column's commit.
- The per-column-commit unit IS "module addition + consumer updates + tests"; bundling the module addition for all columns into commit 1 violates Rule #25's "independently-verifiable" boundary.

What actually shipped: foundation in commit `9fcd2b9` covering ONLY `firmware.device_metadata` (the canonical first column from the intake). Subsequent commits append one column's helpers + consumer updates + tests. Each commit is the right unit.

## Anti-pattern #3 — Pre-mature schema_version dispatch when no v2 exists

The normalisers do NOT currently dispatch on `schema_version`:

```python
def _normalize_firmware_device_metadata(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    return {}
```

Considered: `match value.get("schema_version", 1): case 1: ...; case _: ...` from day one. Rejected because:

- There IS only v1 today. The dispatch arm for "future versions" would be unreachable code.
- Adding a v2 = bumping the constant + extending the normaliser. The dispatch logic is added IN that commit, not speculatively.
- Forward-discipline is the writer-side STAMP (so future readers can dispatch), not reader-side dispatch ahead of need.

## Anti-pattern #4 — Wrapping a Pydantic model directly with the normaliser

Consumers like `routers/hardware_firmware.py:_firmware_to_status` build a Pydantic response with `CveMatchRunResult(**raw) if raw else None`. Wrapping `raw` with `_normalize_firmware_cve_match_result(raw)` was the right call (returns dict → spread or None → skip). But the alternative considered — passing the normaliser AS the Pydantic field validator — was rejected:

- Pydantic v2 field validators are typed at the schema level, not the column level. They'd fire on every API request, not just at the JSONB read boundary.
- Mixing the two concerns (column shape + API shape) makes future column normaliser changes Pydantic-coupled.
- The router-layer wrap is one extra line per consumer with explicit responsibility.

## Anti-pattern #5 — Stamping a non-stampable shape

`emulation_sessions.port_forwards` is `list[dict]`. Initial design considered embedding `schema_version` as the first dict in the list (`[{"schema_version": 1}, *real_entries]`) so consumers iterating the list would have to filter the marker out. Rejected because:

- Consumers iterate via `for pf in session.port_forwards:` and call `pf['host']` immediately. A schema_version dict in the list would crash on the first iteration.
- Adding `if pf.get("schema_version"): continue` to every consumer is the same touch-site cost as just omitting the marker.

Decision: list-shaped columns get a SCHEMA_VERSION constant for forward-discipline (e.g. when v2 lands and the writer stores `{"schema_version": 2, "items": [...]}` — a wrapper-dict shape that the normaliser then dispatches), but NO in-line stamp at v1. The normaliser's coercion already handles the wrapper-dict case if/when it lands.

## Anti-pattern #6 — `expire_on_commit=True` assumption in the writer flow

Tempting at the stamp helper: `db.refresh(obj)` after `db.commit()` to reload schema_version into the in-memory ORM object. Wairz's session factory at `database.py:24` sets `expire_on_commit=False`, so refresh is a no-op (Rule #32). Avoided.

## Anti-pattern #7 — Skipping live canary because tests pass

Tempted on commits with no live consumer of the column (e.g. `conversations.messages` — dormant table, no live reads). Avoided by running the live canary against the database anyway, which surfaced "0 rows" as the result — confirming the normaliser path is sound but no real production data exists yet. The exercise is about the canary contract, not just finding bugs. Companion to Rule #11 — runtime smoke is required even when "obviously fine".

## Anti-pattern #8 — Bundling `port_forwards` for EmulationSession + EmulationPreset

These two columns share the EXACT same shape (`list[dict]` of host/guest pairs). Considered a shared `_normalize_port_forwards` helper used by both. Rejected:

- Per-column boundary discipline: each column has its own SCHEMA_VERSION constant. Sharing the function means the constants must update together, OR diverge silently.
- Future shape evolution may diverge — preset-level might add a `description` field that session-level doesn't. Keeping helpers separate makes the divergence cheap.
- The implementations are 4 LOC each; the duplication cost is trivial.

What shipped: separate `_normalize_emulation_sessions_port_forwards` and `_normalize_emulation_presets_port_forwards` with identical bodies. Tests for both. The `cra_requirement_results × 4 list[str]` columns DID share an internal `_normalize_str_list` helper — but the public boundary was 4 distinct functions, each delegating to it. Same discipline, different optimisation point because four columns of the same shape on the same model crossed a duplication threshold.

## Anti-pattern #9 — Stamping on import without normalising first

In `import_service.py` for fuzzing.config, the imported value `c.get("config")` could be from an older wairz version with a pre-Rule-35c shape. Tempting to do `_stamp_fuzzing_campaigns_config(c.get("config"))` directly, which would mutate the imported dict and stamp it. Risk: if the imported dict is wrong-typed (`list` instead of `dict`), the stamp helper would `payload["schema_version"] = ...` raising on the list.

What shipped: `_stamp_fuzzing_campaigns_config(_normalize_fuzzing_campaigns_config(c.get("config")))` — normalise to canonical dict first, THEN stamp. Two function calls; defensible.

## Anti-pattern #10 — Updating consumers in one giant grep-replace

Tempted to `sed` across all 13 device_metadata read sites in the foundation commit. Avoided because:

- Each site has different surrounding context (`getattr` vs direct attribute access; `or {}` vs no fallback; merge-then-write vs read-only).
- Mechanical replacement misses the surrounding `dict(...)` wrap that some sites need before mutation.
- Per-site review caught two writers (`firmware_paths.py:_persist_roots`, `firmware_paths.py:invalidate_detection_roots`) that needed `_stamp_*` not just `_normalize_*` — sed would have stamped only one.

What shipped: per-site Edit calls with focused `old_string`/`new_string` pairs. Slower per commit, but every change reviewed.
