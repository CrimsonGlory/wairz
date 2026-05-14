# Antipatterns: Rule #44 backfill + deep multi-persona review (Issue #15)

> Extracted: 2026-05-14
> Campaign: rule-44-cross-firmware-backfill (Issue #15) + Phase A/B/C/D follow-up
> Postmortem: .planning/postmortems/postmortem-rule-44-cross-firmware-backfill-plus-deep-review-2026-05-14.md

## Antipatterns observed

### 1. Shipping cross-firmware identity keys WITHOUT a forensic-domain sanity check

- **What happened:** 3 of 11 walkers (BCD, EVTX, scheduled_task) shipped with `supply_chain_signal = match_count >= 2` — the literal precedent from `lookup_systemd_unit_across_firmwares`. The precedent shape is correct for systemd (where same `unit_name` across firmwares is a genuine signal) but FORENSICALLY WRONG for these three:
  - BCD `{bootmgr}` GUID is identical in every Windows install → triggers `supply_chain_signal=True` on baseline.
  - EVTX events (Security 4624, Sysmon 1) fire on every captured system → triggers on baseline.
  - Vendor-shipped scheduled tasks (ProactiveScan, WinDefend) ship everywhere → triggers on baseline.

  All 3 over-flagged baseline as supply_chain_signal=True, which would have produced operator noise in real DFIR use.
- **Why it happened:** The Rule #44 precedent ship discipline ("mirror lookup_systemd_unit_across_firmwares" per Issue #15 directive) was followed mechanically. The author did NOT pause to ask "would this identity key produce false positives on a normal Windows corpus?"
- **How to avoid:** When introducing a new Rule #44 walker, BEFORE shipping the .E commit, mentally test the identity key against 3 scenarios:
  1. "Does this exact key appear in EVERY clean Windows install?" (BCD GUID — yes; EVTX events — yes; scheduled_task — yes). If yes, the bare `match_count >= 2` will fire on baseline; calibrate with an anomaly dimension (testsigning, threshold raise, encoded-PS, etc.).
  2. "Does the walker store the data in a normalized form the analyst might NOT know?" (prefetch CMD.EXE uppercase — yes). If yes, normalize at the handler boundary.
  3. "Would a typical wairz corpus produce 100 false-positive matches before 1 true-positive?" If yes, raise the threshold or condition on a signal dimension.

  This is a 30-second mental check; saves 3+ follow-up commits.

### 2. Per-walker registration test only — no Rule #35b live canary at ship time

- **What happened:** Each of the 11 Issue #15 backfill commits shipped a single `test_register_X_includes_cross_firmware_lookup` test asserting the tool name appears in the registry. That's a DISPATCH-SHAPE test — it proves the tool was registered, not that it produces the right output given known inputs. Rule #35b explicitly states "mocks verify dispatch shape, not value flow". A value-flow canary (seed records → call handler → assert match_firmware_count + supply_chain_signal) was shipped as a SEPARATE follow-up commit (test_rule_44_cross_firmware_canaries.py).
- **Why it happened:** Issue #15 directive said "Add a Rule #44 acceptance test asserting the tool is registered." Author interpreted this strictly. The directive is technically satisfied but Rule #35b's value-flow requirement was not.
- **How to avoid:** Every Rule #44 walker ship commit should include BOTH (a) the registration test (dispatch shape) AND (b) at least ONE value-flow canary that seeds 2 firmwares with matching records and asserts the per-tool `supply_chain_signal` computes correctly. The 2nd test is ~20 lines extra per walker — well under Rule #25's per-commit threshold. Bundle in the same Rule #25 commit as the walker; don't split.

  Generalised principle: when a service has BOTH a dispatch contract AND a value-flow contract, ship BOTH gates in the same commit. The dispatch test is the cheap canary that prevents the slot from regressing accidentally; the value-flow canary catches the calibration / shape / aggregation bugs that mocks structurally cannot.

### 3. Reusing precedent migration without inspecting the column-nullability fields

- **What happened:** λ.β.A and λ.γ.A migrations (this week) created `created_at` columns with `server_default=now()` but did NOT declare `nullable=False`. The ORM declared `Mapped[datetime]` (non-Optional ⇒ NOT NULL). Result: `alembic check` detected modify_nullable drift on the boundary commit `bc91a4a`; CI failed. Required a new ALTER migration to recover.
- **Why it happened:** The precedent migrations the author copied from didn't have `nullable=False` either. The Python-side ORM declaration changed (Mapped[datetime] vs Mapped[Optional[datetime]]) but the migration template stayed the same.
- **How to avoid:** When authoring an alembic migration that creates a column with `server_default`:
  - If the corresponding ORM field is `Mapped[T]` (non-Optional), the migration MUST declare `nullable=False`.
  - If the corresponding ORM field is `Mapped[T | None]`, omit `nullable` (default True is fine).

  Mechanical check before shipping any migration with `created_at` / `updated_at` / `started_at` / `finished_at` columns: grep the ORM model for the column, check the type annotation, mirror to the migration.

### 4. Initial canary fixture not matching the persisted JSONB envelope shape

- **What happened:** First version of `_scheduled_task_with_encoded_ps` fixture wrote actions JSONB as `{"schema_version": 1, "actions": [...]}`. The normaliser `_normalize_windows_scheduled_tasks_actions` expects `{"schema_version": ..., "items": [...]}` envelope (or a bare list). The fixture's `actions` key wasn't recognized, normaliser returned `[]`, `any_encoded_powershell` stayed False, `supply_chain_signal` didn't fire — test assertion failed.
- **Why it happened:** Author guessed the envelope shape from the walker's pre-normalisation code (which may have stored the actions under a different key historically) rather than reading the normaliser definition. The walker DOES `_stamp_windows_scheduled_tasks_actions(items: list[dict])` which produces `{"schema_version": V, "items": list(items)}` — that's the canonical shape.
- **How to avoid:** When writing a tier-1 live canary that seeds JSONB columns, **read the corresponding `_normalize_<table>_<column>` function first** (or the `_stamp_*` writer) to determine the canonical envelope. Don't guess from the walker's internal shape. Mechanical: `grep -A 30 "def _normalize_<table>_<column>" backend/app/services/jsonb_normalizers.py` — the function signature + body tell you the expected shape.

### 5. Initial test run revealed pre-existing alembic-coupling failure (test_alembic_autogenerate_empty)

- **What happened:** Running the new canary file in isolation triggered `NoReferencedTableError: Foreign key 'volatility_injection_records.memory_image_id' could not find table 'memory_dump_image'`. This is because `app/ai/tools/windows_processes.py` (transitively loaded via the canary file imports) imports `VolatilityProcessRecord`, but `MemoryDumpImage` (the FK target) isn't in `app/models/__init__.py.__all__` so it's not registered with Base.metadata.
- **Why it happened:** The `app/models/__init__.py` only lists ~25 of the ~40 models in the project. The unregistered ones (memory_dump_image, volatility_*_record, several others) get registered transitively when the right test files happen to be collected by pytest. In CI's 5524-test collection, everything happens; in isolated runs, gaps surface.
- **How to avoid:** Two valid responses:
  (a) **Short-term workaround**: every new test file that uses `make_live_db()` AND transitively triggers an unregistered model's FK should add an explicit `from app.models.X import Y  # noqa: F401` for the FK target. The canary file in this session adopted this pattern.
  (b) **Long-term fix**: register every Base-derived model in `app/models/__init__.py.__all__`. Single Rule #25 commit that hardens every future test. Deferred this session; should be filed as a follow-up issue.

  Until the long-term fix lands, any new test file using make_live_db should grep the imported tool/service modules for `from app.models.<X> import` and verify all `X` are present in `app/models/__init__.py.__all__`. If not, add the import to the test file.

### 6. Initial HardwareFirmwareBlob fixture missed a NOT NULL column (detection_source)

- **What happened:** First version of `_registry_blob` factory omitted `detection_source`. SQLite IntegrityError on the canary's `db.commit()`. Two iterations to fix.
- **Why it happened:** Author wrote the fixture from a partial model read (lines 18-44 showed firmware_id / blob_path / blob_sha256 / file_size / category / format / signed / ...) and missed `detection_source` further down in the model.
- **How to avoid:** When writing a fixture for a model with many fields, instead of guessing required fields, **let the test fail once** and read the SQLAlchemy IntegrityError. The error message tells you exactly which NOT NULL column is missing. Two iterations cost ~30 seconds; reading the entire 250-line model docstring upfront would have cost more. This is a Pattern P5 application — write-fail-fix-fail-fix is faster than write-all-upfront when the failure-mode signal is precise (NOT NULL violations are pinpoint).

  Note: this is OPPOSITE to Rule #19 (evidence-first), which applies to spec-vs-DB-truth mismatches. For fixture authoring against a known DB schema, write-then-fix is cheaper than read-everything-then-write. The two patterns are not contradictory — Rule #19 is about not writing CODE for non-existent data; this antipattern is about fixture-authoring efficiency.

## Decisions worth re-examining if pattern repeats

- **C3 EVTX threshold = 5**: chosen on the forensic expert's "≥ 5 firmwares" recommendation. Should be sanity-checked against actual wairz corpus data. If most wairz operator corpora have <5 firmwares per project, the threshold may be too HIGH (never fires). Counter-recommendation: scale the threshold to `min(5, max(2, total_corpus_count / 4))` — but that adds complexity. Defer the calibration tuning until 30+ days of operator usage data accumulates.

- **C2 BCD calibration**: requires `any_testsigning OR any_no_integrity_checks`. This catches BlackLotus/Bootkitty/BYOVD-precursor cases. A more sophisticated calibration would also fire on description anomalies (description ≠ standard bootloader) or suspicious image_path values. Defer to a future "Rule #44 BCD signal hardening" pass.

- **C4 scheduled_task calibration**: requires `any_encoded_powershell`. Misses non-PowerShell attacker shapes (e.g. wmic-via-cscript, mshta-launch, regsvr32-payload). Defer extension to a future pass.

These are correct defaults today; the postmortem flags them for re-examination because each is a single-axis calibration that COULD be enriched.
