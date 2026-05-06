---
title: JSONB normaliser sweep — patterns
session: audit-jsonb-schema-version-rule35c-2026-05-04
session_date: 2026-05-06
commits: 9fcd2b9..9ff6d9c (14 commits)
campaign: audit-2026-05-04 / Rule #35c
related_rules: [35, 35c, 19, 25, 11]
---

# Patterns — JSONB normaliser sweep (Rule #35c)

Rolling 14-commit sweep that retrofitted boundary normalisers + schema_version constants onto all 20 unprotected JSONB columns in the wairz schema. The intake projected ~57 commits and "multi-session"; the actual outcome was 14 commits in one session because shared infrastructure (single central module) + per-column commits with focused diffs make this kind of sweep capacity-bound by reading the consumers, not by typing helpers.

## Pattern #1 — Central module + per-column commits

Foundation commit (`9fcd2b9`) created `backend/app/services/jsonb_normalizers.py` with the first column's helpers. Every subsequent commit added one column's worth (or one tightly-coupled group) by **appending** to that single module + adding tests in one shared test file + updating only that column's consumers. Concrete shape:

```
commit N:
  backend/app/services/jsonb_normalizers.py      | grew by ~20-50 LOC
  backend/tests/test_jsonb_normalizers.py        | grew by ~30-60 LOC
  backend/app/<consumer1>.py                      | 1-4 line changes
  backend/app/<consumer2>.py                      | ditto
  ...
```

Why central module > per-table module:

- Single import surface across the codebase: `from app.services.jsonb_normalizers import _normalize_<table>_<column>`.
- Future audit grep is trivial (`grep _normalize_ jsonb_normalizers.py`).
- New JSONB columns are one append; the recipe is the file's existing structure.
- Test file becomes the canonical contract — Pydantic-style fixture set per column with idempotency assertion.

## Pattern #2 — Threshold rule decides strategy mechanically

User's directive: count consumer **files** (writers don't count). ≥3 → schema_version + normaliser. <3 → normaliser only.

Mechanical grep:

```
grep -rln "<column>" backend/app/ --include="*.py" | grep -v "test_\|/models/\|/schemas/" | wc -l
```

Filtering out tests, ORM models, and Pydantic schemas isolates real consumers. Decision applied 20 times this session:

| Strategy | Columns |
|---|---|
| schema_version + normaliser + stamp | 12 (device_metadata, binary_info, analysis_cache.result, conversations.messages, fuzzing.{config,stats}, attack_surface × 3, hardware_firmware_blobs.metadata, emulation_sessions.{port_forwards,discovered_services}, emulation_presets.port_forwards) |
| normaliser only | 8 (cve_match_result, sbom.metadata, emulation_sessions.nvram_state, cra_requirement_results × 4) |

For list-shaped columns the SCHEMA_VERSION constant is declared for forward-discipline, but no in-line stamp helper (the marker can't live INSIDE the list cleanly).

## Pattern #3 — Idempotent stamp + idempotent normaliser

Every stamp helper:
- Mutates-in-place, returns the same dict.
- Re-stamping a payload that already has the current version is a no-op.
- For nullable columns: empty/None payload → None preserved.

Every normaliser:
- Returns the canonical empty value (`{}`, `[]`, or `None` per column semantics) for unparseable inputs.
- Returns the input as-is when canonical (cheap pass-through; idempotent).
- Drops stray non-canonical entries from list-shaped columns (`[s for s in value if isinstance(s, str)]`).

Test contract:

```python
def test_normalize_*_idempotent():
    canonical = <known-good>
    once = _normalize_*(canonical)
    twice = _normalize_*(once)
    assert once == twice == canonical
```

## Pattern #4 — Live canary against ≥3 production rows per column

Rule #35b applied in batches of ≥3 rows. After mock unit tests passed for each commit, ran:

```python
async def main():
    async with async_session_factory() as db:
        result = await db.execute(select(Model).limit(5))
        for r in result.scalars().all():
            normalized = _normalize_*(r.<column>)
            print(...)
```

Live canary surfaces:
- Wrong-typed legacy rows (none observed this sweep — column-level shape was uniform across all 20 columns).
- Sub-key drift (the `vendor_decryption` precedent — covered by the existing sub-key normaliser, not this sweep).

Cost: ~2 seconds per column. Eliminates "tests pass but prod row blows up" failure mode (Rule #35b sub-bullet (b) generalised).

## Pattern #5 — Consumer-update grep is the per-column scope

Per-column commit shape was: ALL consumers of THAT column AND ONLY that column. Mechanical:

1. `grep -rn "<column>\b\|\.<column>\b" backend/app/ --include="*.py" | grep -v test_ | grep -v "/models/"` to enumerate sites.
2. Edit each site (read site → normaliser; write site → stamp).
3. Update the consumer's `from app.services.jsonb_normalizers import` to add the new helper(s).
4. Run `pytest test_jsonb_normalizers.py` + Rule #11 import smoke + Rule #35b live canary.
5. Commit.

The grep IS the per-commit scope. Anything not matching the column name is out of scope, even if it's "in the same file".

## Pattern #6 — Forward-discipline applies even to dormant columns

Two columns this sweep had ZERO live read-site consumers (`conversations.messages` — AI conversation table is registered but unread; `emulation_sessions.nvram_state` — writer's return value is what consumers get, no reads of `session.nvram_state`). Both still got normalisers per Rule #35c — the rule is forward-looking, not reactive.

Concretely: the day a future LLM feature wires up `Conversation.messages` reads, the normaliser already exists. No "let me add the helper while I'm at it" tax on that future commit.

## Pattern #7 — Single-file test growth is the canonical "shared spec" shape

`test_jsonb_normalizers.py` grew from 13 → 119 cases across 14 commits — every commit added 4-13 cases. The test file is the contract; the module is the implementation. Adding a new column to the module without adding to the test file is the failure mode.

Test patterns recurring across columns:

```python
@pytest.mark.parametrize(
    "value,expected",
    [
        # Canonical pass-through.
        (<canonical>, <canonical>),
        # Server default.
        (<empty>, <empty>),
        # None — preserved or coerced per column semantics.
        (None, <expected>),
        # Wrong type — list when expecting dict, dict when expecting list, etc.
        ([1, 2], <expected>),
        # Wrong type — string.
        ("not a dict", <expected>),
        # Mixed list (only for list-shaped) — non-conforming entries dropped.
        ([<good>, <stray>, <good>], [<good>, <good>]),
    ],
)
def test_normalize_*(value, expected):
    assert _normalize_*(value) == expected


def test_normalize_*_idempotent(): ...

# When stamping:
def test_stamp_*_adds_version(): ...
def test_stamp_*_idempotent(): ...
def test_stamp_*_preserves_none(): ...  # nullable columns
```

## Pattern #8 — `docker cp` accelerates per-column smoke

Rule #20 applied 14× — each commit's Rule #11 import smoke went via `docker cp` of touched files into the running backend container, then `docker compose exec backend /app/.venv/bin/python -c "import ..."`. No rebuild between commits. The class-shape exception (Rule #20 caveat) didn't apply because the new module is a fresh file, not an edit to a class definition with cached singletons.

Cost: ~3 seconds per smoke. Total saved time across 14 commits: ~30 minutes vs full `up -d --build backend worker`.

## Pattern #9 — `wc -l` re-measure caught the intake's miscount

Intake said "19/20". Actual count after `grep -rn "JSONB" backend/app/models/ | grep mapped_column` returned 22 columns, of which 2 (device_dump.partitions / .result) already had schema_version stamping (commit 875aa11 era). 20 to address, not 19. Companion to Rule #28 (re-measure intakes); the discipline is the same: the spec describes intent, the codebase describes truth.

## Pattern #10 — Per-column commits with shared scaffolding compose cleanly

Total session count: 14 commits, all bisect-clean (each builds on prior; each is independently revertable for that column's normaliser). Rule #25 satisfied without mechanical splitting — natural commit boundaries are the columns.

The only "bundled" commits were:
- fuzzing_campaigns.{config,stats} — same model, atomic write site.
- attack_surface_entries × 3 columns — atomic write site (3 columns assigned in one `Model(...)` call).
- sbom_components.metadata + hardware_firmware_blobs.metadata — paired because both touch import_service.py minimally.
- cra_requirement_results × 4 — homogeneous list[str] columns, single service file.

The bundling was justified each time in the commit message — "splitting into N commits would leave a half-stamped state between them" or "same file repeatedly touched for trivial diffs". This is in keeping with Rule #25's "natural splits" clause.
