# Anti-patterns: Emulation + Fuzzing 202+Polling Refactor

> Extracted: 2026-04-21
> Campaign: `.planning/campaigns/completed/emulation-fuzzing-202-polling-2026-04-20.md`

## Failed Patterns

### 1. Trusting campaign-brief enum values without a live re-grep
- **What was done:** Campaign pre-flight stated fuzzing status values were `queued|running|crashed|completed`. β's implementer initially took that at face value, assumed no enum change was needed, and started implementing against the stated 4 values.
- **Failure mode:** Actual tree had `created|running|crashed|completed` — no `queued` state existed. β's "pending / container-spawning" intermediate state had no natural home. The mismatch surfaced when β went to annotate the status for the new 202 response.
- **Evidence:** β discovery #1: "queued status added despite brief suggesting it wasn't needed. Campaign pre-flight listed existing values as queued|running|crashed|completed but the tree actually had created|running|crashed|completed."
- **How to avoid:** Rule #19 (evidence-first) + Rule #28 (re-measure) apply here. Before implementing against a spec's stated enum/type/interface, run the one-line grep:
  ```bash
  grep -rn 'FuzzingStatus\|fuzzing_campaign.status\|= Column(String(' backend/app/models/ backend/app/schemas/ frontend/src/types/ 2>&1
  ```
  Takes 1 second. Catches brief-drift before any code is written.

### 2. Assuming "runtime enum additions" are safe because typecheck + unit tests pass
- **What was done:** α added `pending` and `booting` values to the emulation status set. pydantic schemas accepted the literals. SQLAlchemy Mapped[str] accepted them. Unit tests passed. The implementer almost shipped without the alembic migration.
- **Failure mode:** The `emulation_sessions.status` column had a `CHECK` constraint from migration `54c8864fbe0c` allowing only 6 pre-202 values. The first real `POST /emulation/start` returned 500 because the INSERT violated the CHECK. Only the real integration probe caught it.
- **Evidence:** α discovery #1: "DB CHECK constraint surfaced at runtime, not typecheck. ... The migration was commit 5 of 5, written AFTER service/router/frontend were in place."
- **How to avoid:** When adding a new status/enum literal, RUN a live INSERT probe against the real DB before declaring the change complete. The probe can be as simple as:
  ```bash
  docker compose exec -T postgres psql -U wairz -d wairz -c "INSERT INTO emulation_sessions (id, status, ...) VALUES (gen_random_uuid(), 'pending', ...);"
  ```
  Catches missing CHECK-widening migrations in seconds. Also: grep for `CHECK (` in the alembic `versions/` dir against the model's table name — cheap pre-flight.

### 3. Under-specified scope language ("user-mode" vs "user-mode and system-mode")
- **What was done:** Rule #29 named "emulation user-mode" as the DEFERRED endpoint. The campaign brief inherited that wording. α's implementer had to decide mid-session whether `POST /emulation/system` (FirmAE system emulation) was in scope. Both endpoints inherit the 1800s `firmae_timeout=1800` ceiling.
- **Failure mode:** α correctly inferred that FirmAE was out of scope (it uses its own `SystemEmulationService` with pre-existing polling via `system_emulation_stage`), but the rationale had to be reconstructed. A downstream reviewer could legitimately argue the fix was incomplete because the rule said "emulation user-mode" without explicitly excluding FirmAE.
- **Evidence:** α discovery #4: "FirmAE system emulation (`POST /emulation/system`) was out of scope. Uses its own `SystemEmulationService` with existing polling already. Rule #29 closure here applies ONLY to the `/emulation/start` flow. FirmAE's own 1800s alignment is orthogonal; flag for a follow-up if it ever re-surfaces."
- **How to avoid:** When a rule or campaign brief names a defect, it should ALSO name the specific endpoint path(s) in scope AND any adjacent-but-out-of-scope paths. Good form: `DEFERRED: POST /api/v1/projects/{pid}/emulation/start — out of scope: POST /api/v1/projects/{pid}/emulation/system (FirmAE, handled separately)`. One extra line per scope decision, eliminates ambiguity.

### 4. Structurally-identical shortcuts that silently skip recursion (related latent bug)
- **What was done:** (Not from this campaign, but surfaced in the follow-on tar-shortcut investigation.) The same pattern that produced Rule #29's DEFERRED items — "upload-time archive shortcut bypasses the recursive pipeline" — exists in `firmware_service.py:338-406` (tar shortcut) AND `firmware_service.py:430-484` (zip-rootfs shortcut). Each has its own silent-partial-unpack risk.
- **Failure mode:** The generic family of "shortcut path for the common case, but the common case isn't the ONLY case" tends to fail when reality drifts past the shortcut's original assumptions (ADB device dumps in the tarball shortcut case; pure-rootfs zips in the zip-rootfs shortcut case).
- **Evidence:** The Eaton Network M3 firmware (this session's 2nd investigation) hit the tar shortcut; the zip-rootfs shortcut has no known victim YET, but structural analysis showed it has the same defect class.
- **How to avoid:** When designing a "fast-path / common-case shortcut" that bypasses a more general pipeline, add a gate that detects when the common case's assumption is VIOLATED and falls through. Principle: "the shortcut must know when to say no." Applied in commit 38d01d8 (tighten `find_filesystem_root` to refuse raw-image-containing dirs).

## Lessons applied to follow-ups

- `SECURITY_SCAN_TIMEOUT=600_000` is redeclared in 8 files. Consolidation deferred — flagged for a future cleanup. Would make Rule #29's derivation discipline easier to audit.
- `test_emulation_auth.py` 401 pre-existing failure on main flagged into the backend-pytest-unstable-tests campaign (Session +2 per the multi-session seed). The pattern of "pre-existing test failures surface as false signals on PR reviews" is worth a general discipline: run the test suite on main FIRST, so "did my PR cause this?" is answerable without triage.
