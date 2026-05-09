# Patterns: Windows-Coverage God-Mode β.14 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta14-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: `77b257d` (β.14a real-firmware canary), `893dcac` (β.14b rule promotions)
> Status: 2 sub-tasks completed; campaign Phase β CLOSED (γ + δ pending)

This is an incremental extraction layered on top of:
- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α + β.1–β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta7-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta8-beta9-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta10-beta13-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta11-2026-05-08-{patterns,antipatterns}.md`
- `windows-coverage-godmode-beta12-2026-05-08-{patterns,antipatterns}.md`

Patterns already captured there are not re-stated; this file captures
only the β.14-delta learnings.

## Successful Patterns

### 1. Real-PE canary skip-tier discipline

- **Description:** When a Rule #35b live canary needs to exercise a
  pipeline against REAL artefacts (real PE files, real archives, real
  firmware blobs) but the universal-availability fixture is heavy
  (Win11 ISO, signed driver), split the canary into 3 tiers:
  - **Tier 1 (always runs):** uses host-system-available real artefacts
    (mingw-w64 DLLs, systemd-boot EFI, system PEs) that any dev / CI
    host has installed. Asserts the criteria reachable with these
    artefacts (typically signed=False / chain_status=unknown). Provides
    durable always-on coverage of the cumulative pipeline surface.
  - **Tier 2 (skip-unless-fixture):** asserts criteria that need a
    SIGNED fixture (chains-to-MS-roots). Skip with a docstring that
    documents the fixture-acquisition path.
  - **Tier 3 (skip-unless-fixture):** asserts criteria that need a
    REVOKED-or-otherwise-special fixture (DBX-revoked PE, malicious
    cert). Skip with provisioning instructions.
  Tier 1 always-runs gives durable always-on coverage; tier-2/3
  document the path-to-pass without code changes once fixtures are
  committed. The canary set graduates from "partial" to "full" via
  fixture commits, not test edits.
- **Evidence:** β.14a commit `77b257d`,
  `backend/tests/test_authenticode_chain_real_firmware.py`. 5 tests:
  3 tier-1 (runner-direct smoke + HTTP-layer round-trip + outer-runner
  state machine, all using `_HOST_UNSIGNED_PE_CANDIDATES` =
  mingw-w64 DLLs / systemd-bootx64.efi) + 2 tier-2/3 (skip-unless
  `_MS_SIGNED_PE_FIXTURE` / `_DBX_REVOKED_PE_FIXTURE` present, with
  docstring-documented provisioning paths). Final result on this host:
  3 passed, 2 skipped — operator can graduate the skips to passes by
  committing fixtures.
- **Applies when:** Any Rule #35b real-artefact canary where (a) some
  acceptance criteria are reachable with host-available artefacts and
  (b) other acceptance criteria need specific fixtures. The discipline
  generalises from PE-Authenticode (β.14a) to other forensic-pipeline
  canaries — registry walkers (.hive fixtures), driver-package
  matrices (.inf/.cat fixtures), .NET decompilation (signed-bundle
  fixtures), update-diff (KB-vs-KB fixtures), etc. Rule-of-One in this
  campaign; expect Rule-of-Two when Phase γ ships its registry-hive
  canary set.

### 2. TestClient + httpx ASGITransport + asyncio.create_task capture for 202+polling tests

- **Description:** A 202+polling endpoint (per Rule #33 / Rule #29)
  fires `asyncio.create_task(background_runner(...))` and returns
  immediately. A naive TestClient round-trip races the runner — the
  GET /status call returns `queued` / `running` instead of
  `completed`, making the test non-deterministic. The fix has 3
  surfaces:
  1. Patch `asyncio.create_task` in the router module to capture the
     spawned coroutine into a list (`captured.append(t)`).
  2. Override the runner's own `async_session_factory` (the runner
     opens its OWN session, not the one we override via FastAPI
     `dependency_overrides[get_db]`) to redirect to the live SQLite
     session.
  3. After the POST returns 202, `await captured[0]` directly inside
     the test before the GET status call. Completion is now
     deterministic; the GET status returns `completed` reliably.
  No `time.sleep` / polling loop / `pytest-asyncio.timeout` needed.
- **Evidence:** β.14a commit `77b257d`,
  `test_http_layer_post_authenticode_chain_round_trip` in
  `test_authenticode_chain_real_firmware.py:230-330`. The test
  patches `app.routers.hardware_firmware.asyncio.create_task` with a
  capturing shim, patches
  `app.services.authenticode_chain_runner.async_session_factory` with
  an asynccontextmanager yielding the live SQLite session, then
  awaits the captured task before the GET-status assertion. Also
  exercises the Rule #33 .a 409-on-conflict idempotency contract by
  POST-ing twice in a row.
- **Applies when:** Any Rule #33 202+polling endpoint test that wants
  deterministic completion ordering through the FastAPI HTTP layer.
  The pattern generalises from authenticode-chain to firmware-unpack,
  emulation-start, fuzzing-campaign-start, cve-match — all 5 current
  applications of the 202+polling shape. Rule-of-One in this codebase
  (this is the first deterministic HTTP-layer test of a 202+polling
  endpoint); promotable to a `.mex/patterns/test-202-polling-endpoint.md`
  recipe on the second application. Companion to Rule #33 .d
  (asyncio.create_task vs arq rubric) — same shape: in-process work
  via create_task is the rubric, deterministic test ordering is the
  test-side counter-piece.

### 3. Companion-phrase audit at rule-promotion time

- **Description:** When promoting a new Learned Rule (e.g. β.13 added
  Rule #36 + #37; β.14b added Rule #38), CLAUDE.md may carry
  cross-reference text that names the previous total ("rules 1–35
  above" in the .mex companion-scaffold section). β.13's promotion
  missed updating this stale phrase; β.14b caught it during the
  Rule #38 promotion edit. Mechanical heuristic: any rule promotion
  should grep `grep -n 'rules 1[–-][0-9]' CLAUDE.md` and confirm the
  count matches the new total. Bundle the fix into the same Rule #21
  mirror commit — the cross-reference is between CLAUDE.md and the
  .mex Verify Checklist; both should agree on the count.
- **Evidence:** β.14b commit `893dcac`. The CLAUDE.md `.mex/`-companion
  section line "The Verify Checklist in `conventions.md` is the
  task-time gate derived from rules 1–35 above" was updated to
  "rules 1–38 above" alongside the new Rule #38 addition. β.13's
  `f80d606` had updated the .mex Verify Checklist with new bullets
  for Rule #36 + #37 but missed the CLAUDE.md cross-reference phrase
  — out-of-sync state would have rotted further with each subsequent
  promotion.
- **Applies when:** Any rule-promotion commit that adds to the Learned
  Rules list. The audit is cheap (~5 sec grep + count check); the
  companion-phrase fix bundles with the rule edit per Rule #21
  spirit. Rule-of-One in this campaign (β.14b is the first
  intentional companion-phrase audit). Promotable to a CI grep on the
  third application — see Recommendation #1 in the postmortem.
  Companion to Rule #21 (mirror discipline — same shape: out-of-sync
  state rots fast; co-locate the audit with the edit that introduces
  the drift).

### 4. Function-local resolver-gate placeholder

- **Description:** When a FastAPI dependency resolver gates on a row
  field (here: `app.routers.deps.resolve_firmware` requires
  `firmware.extracted_path` to be non-null), an HTTP-layer test that
  seeds a Firmware row through `_live_db` MUST set the placeholder
  field even if the test doesn't otherwise care about it. The chain
  runner reads `HardwareFirmwareBlob.blob_path` rather than
  `Firmware.extracted_path`, so the placeholder is purely to satisfy
  the resolver — set it once in the seed helper with an inline
  comment explaining why. Future tests using the helper inherit the
  working shape without rediscovering the gate.
- **Evidence:** β.14a commit `77b257d`. The
  `_seed_firmware(db) -> Firmware` helper at line 122 sets
  `extracted_path="/tmp/test-fw-extracted"` with the inline comment
  "The HTTP-layer test goes through `app.routers.deps.resolve_firmware`
  which 400s if `extracted_path` is null. Set a placeholder; the
  chain runner reads `HardwareFirmwareBlob.blob_path`, not this
  field." Tier-1 / 2 / 3 tests all use the same helper without
  hitting the gate.
- **Applies when:** Any HTTP-layer test that seeds a Firmware /
  Project / similar fixture row through `_live_db.make_live_db()` and
  goes through a FastAPI dependency that gates on field presence.
  Generalisable from `extracted_path` to other gating fields
  (`device_metadata['vendor_decryption']`, `analysis_cache.operation`,
  status columns, etc.). Mechanical discipline: read the resolver /
  dependency BEFORE writing the test seed helper; set placeholders
  for any gate that the test doesn't explicitly want to exercise.
  Companion to Rule #19 (evidence-first — read the resolver shape
  before assuming it'll let your fixture through).

### 5. Real-artefact verdict probe before assertion design

- **Description:** When designing assertions for a Rule #35b canary
  that drives REAL artefacts through an unmocked pipeline, run the
  pipeline ONCE against a representative real artefact BEFORE writing
  the assertions. The probe surfaces what verdicts the pipeline
  actually produces under real-world inputs — informing what the test
  can confidently assert (vs. what needs to be skip-unless-fixture
  per pattern #1). β.14a probed `verify_pe_file` against 4 host PEs
  (mingw-w64 DLLs + systemd-bootx64.efi); all returned
  `signed=False, chain_status=unknown, sigs=0`. That informed the
  tier-1 assertions: (a) row count > 0 ✓, (c) histogram non-empty ✓,
  (b)/(d)/(e) NEED fixtures → tier-2/3.
- **Evidence:** β.14a session — the probe was a single 30-line
  Python `uv run python -c "..."` invocation that printed verdicts
  for each candidate path. The output drove the test design;
  without it, the test author would have been guessing what the
  pipeline produces and risk over-asserting (e.g. asserting at least
  one signed PE, which would always fail on a typical Linux dev host).
- **Applies when:** Any Rule #35b canary against real artefacts where
  the verdict shape isn't predictable from the artefact's static
  metadata alone. Generalises from `verify_pe_file` to other
  forensic-pipeline entrypoints — registry hive scanners, driver INF
  parsers, .NET decompilers, update-package classifiers. Cost: one
  ad-hoc Python invocation; benefit: assertions match real verdicts,
  no test-design rework after first run. Companion to Rule #19
  (evidence-first — extends from "read the spec" to "run the pipeline
  once against real input").

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | β.14a ships as test-only commit; no production code change | The deferred Rule #35b canary set is purely a test-coverage gap — the production runner already exists (β.4-β.12 shipped); β.14a's job is to drive it through real artefacts, not modify it | Test-only commit bisects cleanly; if a future regression breaks the new tests, `git revert 77b257d` reverts only test code |
| 2 | β.14b bundles CLAUDE.md + .mex/context/conventions.md mirror in one commit | Per Rule #21 mirror discipline — out-of-sync state rots fast (β.13 worked example: missed companion phrase rotted across 1 sub-task before β.14b caught it) | One atomic commit; alignment is preserved across bisect lanes |
| 3 | Tier-2/3 use skip-unless-fixture rather than vendoring fixtures inline | (a) Win11 / VC++ Redistributable license terms preclude committing PEs to git; (b) the skip-with-documentation pattern lets the canary graduate from skip → pass without code edits when the operator provisions fixtures | Tier-2/3 stay in the file as documentation; the canary set graduates from "partial" to "full" through a separate fixture-provisioning workflow |
| 4 | "Rules 1–35 above" companion-phrase fix bundled into β.14b commit | Per Rule #21 spirit — the cross-reference is between CLAUDE.md and .mex Verify Checklist; bundling fixes the drift in the same atomic commit that introduces the new rule | One commit covers both the new rule + the cross-reference correction; bisect-clean |
| 5 | asyncio.create_task capture vs sleep-poll for HTTP-layer test determinism | sleep-poll is timing-sensitive and flaky under load; capture-and-await is deterministic and matches the runner's actual completion ordering | Test runs in ~1s with deterministic completion; no flake risk |
| 6 | Real-firmware HTTP-layer test alongside runner-direct test (not just one or the other) | Different surfaces: runner-direct tests verify_firmware_pe_chain in isolation; HTTP-layer test verifies the FastAPI dependency-injection chain + 409-on-conflict + status-snapshot + rate-limiter wrapper in addition. Rule #11 endpoint round-trip discipline applied at the API surface | Both tests pass; coverage spans the runner internals AND the HTTP wrapper independently |
| 7 | New top-level Rule #38 (Bash absolute-path discipline) rather than sub-clause on Rule #20 / #35 | β.10 + β.12 incident pair is independent enough from Rule #20's docker-cp scope and Rule #35's verification-artefact scope; a top-level rule with worked-example incidents is the cleanest place. Mirrors β.13's Rule #36/#37 promotion shape | Rule #38 lands cleanly; no sub-clause overload on existing rules |

## Cross-references back into existing knowledge

- **Pattern #1 (real-PE canary skip-tier discipline)** is the
  generalised form of α.6's pattern (cab + msu canaries activated
  via gcab availability). Same shape: tier-1 always-runs given
  host-installed tooling/fixtures; tier-N skip-unless-fixture for
  more specific cases. β.14a is the first PE/security-side
  application; expect Rule-of-Two when Phase γ ships its registry
  hive canary set (host-installed regipy + system .hive files vs
  operator-provided custom hives).

- **Pattern #2 (asyncio.create_task capture for 202+polling tests)**
  is novel within this codebase — no prior 202+polling endpoint had a
  deterministic HTTP-layer test. The 4 prior 202+polling endpoints
  (firmware-unpack, emulation-start, fuzzing-start, cve-match) all
  have runner-direct tests but no FastAPI-layer tests. Pattern is
  ready for a `.mex/patterns/test-202-polling-endpoint.md` recipe.

- **Pattern #3 (companion-phrase audit at rule-promotion time)**
  extends Rule #21 (mirror discipline) with a specific mechanical
  check. Rule #21 says "update both surfaces in the same commit";
  pattern #3 says "and audit cross-references between them while
  you're there". Rule-of-One in β.14b; promotable to a CI grep on
  the third application.

- **Pattern #4 (function-local resolver-gate placeholder)** is a new
  test-shape discipline. Generalisable to any HTTP-layer test seed
  helper. Companion to Rule #19 (evidence-first — read the resolver
  shape before authoring the seed helper).

- **Pattern #5 (real-artefact verdict probe)** is a generalised form
  of Rule #19's evidence-first discipline applied to test-design.
  Probe before assertion drafting; one ad-hoc invocation saves
  multi-iteration test-design churn.

- **Rule #25 per-sub-task commits** held under β.14 — 2 commits, both
  bisect-clean, no `--no-verify`, no `--amend`. Now Rule-of-Ten across
  the campaign (β.5 through β.14). Discipline is durable.

- **Rule #35a pipe-trap reproducibility** stayed clean — Rule-of-Five
  across the campaign (β.8 + β.9 + β.10 sibling + β.11 + β.14).
  File-redirect muscle memory holding firm.

- **Rule #35b live canary** is now Rule-of-Ten across the campaign.
  β.14a added 5 new live canaries (3 tier-1 + 2 tier-2/3). Cumulative
  ~80 live canaries across β.4 through β.14.

- **Rule #38 (just promoted in β.14b)** held its first session under
  the codified rule — 100+ Bash invocations with `git -C` discipline,
  zero CWD drift. Rule-of-Three when the next session also holds
  clean.

- **Rule #21 mirror discipline** is Rule-of-Two within the campaign:
  β.13 (Rule #36/#37 promotion + missed companion phrase) and β.14b
  (Rule #38 promotion + caught companion phrase). The negative-case
  (β.13 miss) and positive-case (β.14b catch) make pattern #3 above
  durable.
