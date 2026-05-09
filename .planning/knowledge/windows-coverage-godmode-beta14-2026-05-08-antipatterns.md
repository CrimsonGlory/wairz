# Anti-Patterns: Windows-Coverage God-Mode β.14 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta14-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: `77b257d` (β.14a), `893dcac` (β.14b)
> Status: 2 sub-tasks completed; campaign Phase β CLOSED (γ + δ pending)

This is an incremental extraction layered on top of the previous β.X
antipatterns files. Patterns already captured there are not re-stated;
this file captures only the β.14-delta failure modes.

## Anti-Patterns

### 1. Trusting kickoff-prompt URL approximations without grep verification

- **Description:** The β.14 kickoff prompt's URL `POST /api/v1/projects/{id}/firmware/{fw}/authenticode-chain` was approximate — the actual route is mounted under `/hardware-firmware` (β.11a placed the authenticode-chain endpoint there) and `firmware_id` is a query parameter via the resolver, not a path segment. Authoring the HTTP-layer test against the prompt's URL produced a 404 on first run. The kickoff prompt is a SPEC, not the source of truth for code shape — Rule #19 evidence-first applies to URL shapes too.
- **Detection:** When authoring an HTTP-layer test from a kickoff-prompt URL: grep the actual router for the prefix + handler signature BEFORE writing the test:
  ```
  grep -n 'APIRouter\|^router\s*=\|prefix=\|@router\.\(post\|get\)' backend/app/routers/<router>.py
  grep -n '<endpoint>' backend/app/routers/*.py
  ```
  Confirm the route prefix, path segments, and which params are query-string vs path-segment. The grep takes ~5 sec; saves a debug iteration.
- **Mitigation:** Pre-test URL-shape grep is mandatory for any kickoff-prompt-derived HTTP-layer test. β.14a session caught this on first POST (404); recovered in ~30 sec by checking `hardware_firmware.py:93 prefix="/api/v1/projects/{project_id}/hardware-firmware"` and adjusting the test URL. Future sessions: grep first, write test second.

### 2. Adding rule promotions without auditing rule-count cross-references

- **Description:** β.13's `f80d606` promoted Rule #36 (no-execute) + Rule #37 (offline-trust-anchor) to canonical. Both new rules were correctly added to CLAUDE.md and mirrored in `.mex/context/conventions.md` Verify Checklist per Rule #21. BUT the CLAUDE.md `.mex/`-companion-scaffold section still said "rules 1–35 above" — β.13 missed updating this stale cross-reference. The mirror was technically complete (both surfaces had Rules #36 + #37), but the cross-reference text in CLAUDE.md was 2 rules behind.
- **Detection:** When promoting a new Learned Rule to CLAUDE.md, grep ALL cross-reference phrases that name a rule count:
  ```
  grep -n 'rules 1[–-][0-9]\+\|Rule[s]\? 1[–-][0-9]\+\|rules 1\.\.\.[0-9]\+' CLAUDE.md
  ```
  Check that every match either (a) says "above" / "the list" and matches the new total, or (b) is intentional (e.g. a historic snapshot that shouldn't move). The audit takes ~5 sec; saves a stale-state rot.
- **Mitigation:** Bundle the companion-phrase audit + fix into the same Rule #21 mirror commit that introduces the new rule. β.14b caught the β.13 miss + the new Rule #38 + the cross-reference fix in one atomic commit; out-of-sync state didn't propagate further. Long-term: a CI grep (Recommendation #1 in the postmortem) automates the audit so future agents don't need to remember.

### 3. Skipping the resolver-gate inventory before authoring HTTP-layer tests

- **Description:** β.14a's HTTP-layer test seeded a Firmware row via `_live_db.make_live_db()` + `_seed_firmware()` and POSTed against `/authenticode-chain`. The `_seed_firmware` helper didn't set `extracted_path`; the resolver `app.routers.deps.resolve_firmware:33` 400s on null `extracted_path` ("Firmware not yet unpacked"). Authoring the test without reading the resolver's gate produced a confusing 400 on second run.
- **Detection:** When authoring an HTTP-layer test that seeds a fixture row through `_live_db`, READ the resolver / dependency the route uses BEFORE writing the seed helper:
  ```
  grep -n '@router\.\(post\|get\) ' backend/app/routers/<router>.py | head
  grep -n 'def <handler>\|Depends(' backend/app/routers/<router>.py
  cat backend/app/routers/deps.py  # or the relevant deps file
  ```
  List the field accesses each dependency does on the resolved row; set placeholder values for any that the test doesn't explicitly want to exercise.
- **Mitigation:** Update the seed helper to set the placeholder field with an inline comment explaining why ("the chain runner reads `HardwareFirmwareBlob.blob_path`, not this field — the placeholder satisfies the resolver"). Future tests using the helper inherit the working shape. β.14a's `_seed_firmware` set `extracted_path="/tmp/test-fw-extracted"` after the second 400; once-and-done. Pattern #4 in the patterns file documents the durable mitigation.

## Cross-references back into existing knowledge

- **Anti-pattern #1 (kickoff-prompt URL approximations)** is the
  inverse of Pattern #5 (real-artefact verdict probe). Both apply
  Rule #19 evidence-first to test-authoring: probe / grep BEFORE
  writing the test, not after the first failure. Same shape, different
  surface (URL shape vs verdict shape).

- **Anti-pattern #2 (rule-count cross-references)** is the inverse of
  Pattern #3 (companion-phrase audit). The negative case (β.13 miss)
  and positive case (β.14b catch) reinforce each other — the audit
  pattern IS the durable mitigation; the anti-pattern documents the
  failure mode that motivates the audit. Rule-of-Two within the
  campaign (β.13 miss + β.14b catch).

- **Anti-pattern #3 (resolver-gate inventory)** is the inverse of
  Pattern #4 (function-local resolver-gate placeholder). Same shape
  as anti-pattern #1 — Rule #19 evidence-first applies; grep / read
  BEFORE writing.

- All three anti-patterns share a common shape: **assuming the
  high-level spec / prompt / mental-model matches reality without
  grep verification**. This is the test-authoring counterpart to
  Rule #19's spec-vs-DB-truth discipline. The mechanical mitigation
  is consistent across all three: ~5 sec of grep BEFORE writing the
  test, vs a ~30-sec recovery + revision cycle AFTER the first failure.
  Cost is symmetric; benefit (deterministic first-run pass) is
  better in the pre-grep flow.
