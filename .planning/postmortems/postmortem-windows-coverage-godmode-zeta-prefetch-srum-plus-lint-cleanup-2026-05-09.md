# Postmortem — Windows-Coverage God-Mode ζ.2 Prefetch + ζ.3 SRUM + Lint Tech-Debt Cleanup

> Campaign: `windows-coverage-godmode-zeta-prefetch-srum-plus-lint-cleanup-2026-05-10`
> Period: 2026-05-09 (post-merge feat branch) → 2026-05-10 (campaign close)
> Status: shipped (14 commits ahead of `13ef37f` baseline; final HEAD `0949851`)
> Direction: "do them all and you decide" — full autonomy

## Summary

Continuation of the windows-coverage-godmode campaign. Three phase-tier
deliverables shipped to main as small, individually-revertable commits:

1. **Phase ζ.2 — Windows Prefetch walker** (4 commits, ~600 LOC).
   Pure-Python `windowsprefetch>=4.0.3` ingest of `.pf` files;
   `windows_prefetch_records` table; Rule #39 inner/outer/safe runner
   triplet; cross-stack alignment for the `windows_prefetch_execution`
   finding source; 3 MCP tools (search/status/trigger).

2. **Phase ζ.3 — Windows SRUM walker** (4 commits, ~900 LOC).
   `libesedb-python>=20240420` ingest of SRUDB.dat (ESEDB);
   `windows_srum_records` table with `record_type` discriminator;
   Rule #39 triplet; cross-stack alignment for both
   `windows_srum_network_activity` and `windows_srum_application_runtime`
   sources (single-slice exception #2 — bundled in one commit per
   Rule #25); 3 MCP tools.

3. **Phase Lint — tech-debt cleanup** (5 commits, B.1–B.4 + Z).
   Removed 5 ruff suppressions (S314, F601, F811, E741, F402) and 1
   bandit suppression (B314) by fixing the underlying issues at
   source. 4 real bugs caught + fixed (UEFI dup GUID, `_firmware_tar_filter`
   shadowing, 2× untrusted-XML XXE-vulnerable parsing); 4 cosmetic
   loop-variable renames. Net: 35→30 ruff ignores; 16→15 bandit skips.

Continuation discipline (Rule-#11/#19/#25/#33/#35/#36/#38/#39) held across
the session boundary — the prior session's continuation prompt fully
specified state, the new session resumed inside the autonomy budget, and
no work was lost or reverted.

## What Worked

### 1. Continuation prompt as durable hand-off (Rule #21 mirror discipline)

The prior Archon session shipped 9 commits then exhausted context with a
detailed continuation prompt embedded in the campaign file. The prompt
specified: branch tip + main HEAD SHA, CI status of each, exact lint fixes
remaining (B.2 + B.3 + Z scope), Rule #38 absolute-path discipline, the
4-bullet end-conditions list, and the failure pivot policy. The new
session bootstrapped to productive work in ~5 tool calls (campaign file
read, git log, gh run list, lint triage read). Zero re-discovery cost.

### 2. Single-slice cross-stack alignment commits (Rule #25 exception #2)

Each ζ phase shipped a dedicated cross-stack alignment commit
(ζ.2.C `a6be708`, ζ.3.C `04a3c55`) that bundled in one atomic commit:
- alembic migration extending `ck_findings_source`
- backend `WindowsFindingSource` Literal addition
- backend classifier helper + emit method
- frontend `FindingSource` union extension
- frontend `FINDING_SOURCE_CONFIG` mirror

`test_finding_source_alignment.py` enforces strict pairwise agreement;
splitting these into separate commits would leave the test red between
commits. Rule-of-Eight precedent now firmly established (β.12a, γ.7,
δ.8, ε.1.b.4, ζ.1, ζ.2.C, ζ.3.C, plus the 7079b4d 2026-05-06 base).

### 3. Inner/outer/safe runner triplet (Rule #39 Rule-of-Five)

Both ζ walkers shipped the canonical 3-function shape:
- `_do_prefetch_run(db, firmware_id) -> dict` / `_do_srum_run(...)` —
  pure-logic inner orchestrator, accepts caller's session, returns
  unstamped result dict, no row.status mutation.
- `run_prefetch_background(firmware_id)` / `run_srum_background(...)` —
  outer state-machine wrapper, owns Rule #33 .a 5-state transitions
  via `async_session_factory()`, outer-guard exception handling, fresh
  session for failure persistence.
- `auto_prefetch_walk_firmware_safe(...)` / `auto_srum_walk_firmware_safe(...)`
  — unpack-post-detection hook, swallows exceptions, never blocks unpack,
  doesn't mutate status (leaves `idle` so manual re-trigger via MCP works).

Tier-1 tests called the INNER runner via `make_live_db()` — fast, no
Docker DNS dependency. Outer + safe wrappers validated via integration
tests + factory mocks.

### 4. Lint cleanup as bug-discovery exercise

Removing each suppression surfaced a real defect, not just style noise:
- **F601 UEFI dup key** (B.1) — silently overrode the correct
  `EFI_VARIABLE_GUID` mapping with a wrong `FaultTolerantWriteDxe` label.
- **F811 firmware_service dup def** (B.2) — local `_firmware_tar_filter`
  shadowed the imported one, which has hardlink-target validation the
  local version lacks. Net result: every caller gets the safer filter.
- **S314 untrusted-XML ×2** (B.3) — both call sites parsed XML from
  extracted firmware archives (Android NSC, MSIX manifest) without XXE
  defense. Real CWE-611 / CWE-776 risk reduction.
- **E741 + F402** (B.4) — purely cosmetic, but ship-now since the rule
  was already-suppressed and removing it requires zero risk.

The discipline of "rule-suppression as a temporary marker, not a
permanent state" produced 4 bug fixes the campaign would otherwise have
missed.

### 5. CI concurrency-cancellation as cost-saving

The Lint workflow's `concurrency.cancel-in-progress: true` setting let
the rapid-fire B.1 → B.2 → B.3 → B.4 push cadence cancel superseded
Backend Tests runs while keeping each Lint run independent. Net cost:
1× full Backend Tests run (on the final HEAD) instead of 4×. Runner
minutes saved: ~40 minutes.

## What Broke (and What Caught It)

### 1. `_firmware_tar_filter` exception type mismatch (B.2)

**Failure mode:** the imported `_firmware_tar_filter` raises
`tarfile.AbsolutePathError` (a `FilterError` subclass, NOT a
`ValueError`). The local version raised `ValueError`. The existing
test `test_rejects_path_traversal` expected `ValueError`.

**What caught it:** Rule #35b live canary BEFORE the commit. Ran the
new code path manually via `docker cp + python -c "..."` against a real
tarinfo object; the `AbsolutePathError` surfaced immediately. Updated
the test to expect the new exception class with an inline rationale
comment. Mock-only test would have passed (mocks verify dispatch shape,
not exception types).

**Cost:** ~2 minutes of investigation; zero shipped regression.

### 2. defusedxml does not re-export `Element` (B.3)

**Failure mode:** initial import shape attempted to monkey-patch
`defusedxml.ElementTree.Element = xml.etree.ElementTree.Element` —
hacky and fragile. Better shape: keep the stdlib `import` for type
annotations only, use `defusedxml.ElementTree.fromstring` for the
actual parsing.

**What caught it:** running `python3 -c "import defusedxml.ElementTree;
print('Element' in dir(...))"` BEFORE editing. Rule #19 evidence-first.
The 30-second probe saved 30 minutes of class-shape spelunking.

### 3. Bandit B405 fires on ANY `xml.etree.ElementTree` import

**Failure mode:** removing B405 from bandit skips after the S314 swap
caused bandit to flag the residual type-only stdlib import. defusedxml
documentation acknowledges this — bandit's blacklist does not have a
"type-only-import" exemption.

**What caught it:** running bandit with explicit `--tests B405,B408`
BEFORE the commit. The remediation was to keep B405 in skips with
refined rationale (it's a known limitation; the CALL-SITE signal B314
is what actually matters and that's removed).

**Cost:** ~1 minute investigation; clear documentation in the commit
message explaining why B405 stays.

## Patterns Reinforced (Promotion Candidates)

### Rule #25 single-slice exception #2 — Rule-of-Eight

Eight independent applications of "cross-stack alignment is one atomic
commit" (β.12a, γ.7, δ.8, ε.1.b.4, ζ.1, ζ.2.C, ζ.3.C, plus 2026-05-06
base 7079b4d). The pattern is durable beyond debate. CLAUDE.md update
in this campaign promotes the count from Rule-of-Six to Rule-of-Eight.

### Rule #39 inner/outer/safe runner — Rule-of-Five

Five independent walkers ship this triplet shape: registry_hive_walker
(γ.4 implicit), windows_update_diff_service (δ.5 explicit codification),
evtx_service (ε.1.b.3), prefetch_walker (ζ.2.B), srum_walker (ζ.3.B).
The shape is durable; the pitfall (DO NOT call outer wrapper from tier-1
tests because of `async_session_factory` Docker DNS dependency) is now
documented.

### Pattern #6 lower-bound count assertions — Rule-of-Four

Four cumulative count-relaxations to date: `test_registry_tool_count_is_213`
(5c14be2), `test_tier1_mcp_registry_count_is_219_post_epsilon` (13ef37f),
plus the implicit ζ.2.E + ζ.3.E adjustments. With each new MCP tool
category triggering the same exact mechanism, this is approaching numbered-
Rule promotion territory. **Decision deferred** for one more cycle —
ship one more (η or θ phase) and promote at that point, since the cost
of waiting is one more `>= N` relaxation commit and the benefit is a
cleaner promotion narrative with five worked examples.

## Anti-Patterns Reinforced

### A1. Trusting "exit 0" without a canary (Rule #17 / Rule #35a)

The prior session's CI-recovery experience (postmortem-windows-coverage-
godmode-final-eps2c-zeta1-ci-recovery-2026-05-09 antipattern #2) stayed
front of mind throughout this session. Every "passes locally" claim was
re-verified with the EXACT CI command (`uv run ruff check --no-cache .`,
not a habit-shaped invocation). Zero CI-vs-local divergence this campaign.

### A2. Ruff cache permission tarpit

The `backend/.ruff_cache/` directory is owned by root (legacy from a
container running as root). Local `uv run ruff check` fails with
permission denied unless `--no-cache` is added. Workaround documented
in the campaign; long-term fix is a startup hook to chown the cache
back to the user, deferred (low cost; running with `--no-cache` adds
~1 second per run).

### A3. Bandit's blacklist coarse-grained (B405 limitation)

Documented above (What Broke #3). Rule-of-One; not yet a promotable
anti-pattern; will become one if a second project hits the same
defusedxml-vs-bandit-B405 friction.

## Telemetry

| Metric | Start | Final | Delta |
|---|---|---|---|
| main HEAD | `13ef37f` | `0949851` | +14 commits |
| Alembic head | `f2b3c4d5e6f7` | `c5f6e7d8a9b0` | +4 revisions |
| MCP tool count | 220 | 226 | +6 |
| WindowsFindingSource Literal | 11 | 14 | +3 |
| Finding source allowlist | 29 | 32 | +3 |
| Tests added | baseline | baseline + ~25 | +25 |
| Rule #25 single-slice exception #2 | Rule-of-Six | Rule-of-Eight | +2 |
| Rule #39 inner/outer/safe runner | Rule-of-Three | Rule-of-Five | +2 |
| Pattern #6 lower-bound assertions | informal | Rule-of-Four | +1 |
| Suppressions removed | 0 | 6 | 5 ruff + 1 bandit |
| Hours of context | ~2.5 (continuation session) | — | — |
| Reverts | 0 | 0 | — |
| CI failures recovered | 0 | 0 | — |

## Next Steps

- **`lint-defer-async-correctness.md` follow-up campaign** — 320
  ASYNC240/230/109/221 hits across many service files. Multi-session
  refactor; estimated 3-5 sessions per the prior triage. Schedule when
  another high-leverage Windows-coverage opportunity ships.
- **`lint-defer-frontend-react-hooks.md`** — 40 react-hooks warnings
  for per-page review.
- **Pattern #6 numbered-Rule promotion** — schedule for the next
  campaign that ships an MCP tool category, treat that as the 5th
  worked example.
- **B405 reconsideration** — if defusedxml ever ships an `Element`
  re-export, the stdlib type-only import becomes unnecessary and B405
  can come out of bandit skips entirely.

## Final consolidation PR decision

**Skipped.** Per user directive ("Final consolidation PR is optional").
The 14 commits are individually revertable + bisect-clean per Rule #25;
each carries its own rationale + validation in the commit message;
this postmortem + the knowledge files provide the documentation value
a PR description would have provided. Direct-push-to-main per-piece
cadence kept the feedback loop tight and made each step independently
verifiable. The campaign branch (`feat/post-merge-eps2c-zeta1-2026-05-09`)
remains as a navigation artefact in the local repo.
