# Patterns: Coverage-Godmode Phase ι (cross-platform expansion)

> Extracted: 2026-05-12
> Campaign: `.planning/campaigns/completed/windows-coverage-godmode-iota-2026-05-12.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-iota-2026-05-12.md`
> Audit telemetry: not separately filtered (campaign artefacts cover the run)

## Successful Patterns

### 1. Single-sub-agent + precedent file-by-file reuse — Rule-of-Ten (decimal milestone)

- **Description:** Each ι stream dispatched as a single sub-agent with the prior stream as its primary precedent. ι.A used θ.A BCD walker as shape template; ι.B-E each used the immediately-prior ι stream as primary precedent. Sub-agent prompts cited specific files to read for shape inheritance.
- **Evidence:** 5 ι streams in single session; mean **26.3 min agent-wall** (from `duration_ms`); range 24.4-28.3 min. Floor is CI-bounded, not sub-agent productivity-bounded. Pattern P1 chain extends η-θ-ι: Rule-of-Five (η) → Rule-of-Five (θ extended) → **Rule-of-Ten (ι extended).**
- **Applies when:** Walker streams or any sub-task ladder where the precedent shape is mature (Rule #39 triplet, Rule #25 cross-stack, Rule #33 .a state machine).

### 2. Cross-firmware aggregation MCP tool ships at walker-stream time — Rule-of-Four (DURABLE BEYOND DEBATE)

- **Description:** Every new walker MCP category includes ONE `lookup_<X>_across_firmwares` tool alongside the per-firmware tools (`list / lookup / search / trigger / status`) in the same `ι.X.E` commit. Provides the wairz-unique competitive differentiator: supply-chain / insider-threat detection via cross-firmware fingerprint matching.
- **Evidence:** ι.B (`lookup_systemd_unit_across_firmwares`) + ι.C (`lookup_etl_provider_across_firmwares`) + ι.D (`lookup_efs_recovery_agent_across_firmwares`) + ι.E (`lookup_container_image_across_firmwares`) — Rule-of-Four within a single campaign. ι.A.E shipped per-firmware tools only (deferred backfill noted as κ candidate).
- **Applies when:** Any new walker MCP category. Codification candidate for new top-level CLAUDE.md rule + `.mex/patterns/cross-firmware-aggregation-at-walker-stream.md` recipe.

### 3. Parse-only metadata walker — Rule-of-One (NEW pattern; codification candidate)

- **Description:** Walkers surfacing METADATA without decryption, execution, or plaintext recovery. Pairs with a **Rule #36 EXTENSION test gate** that scans walker code for forbidden tokens (`decrypt`, `DPAPI`, `CryptUnprotectData`, `cryptography.fernet`) using `tokenize`-based STRING+COMMENT stripping to avoid docstring false-positives.
- **Evidence:** ι.D EFS DDF/DRF walker — surfaces user SIDs + cert thumbprints + recovery agent SIDs WITHOUT decrypting the FEK or recovering plaintext. Test gate `test_efs_walker_no_decrypt_attempt` enforces structural discipline. Companion to Rule #36 no-execute discipline.
- **Applies when:** Walkers for cryptographic / authentication / secret-stash artefacts where the forensic value is "who can decrypt / who is the recovery agent / what's the credential lineage" rather than the secret content itself. Future applications: DPAPI master keys, BitLocker recovery, PGP keyring, TPM-sealed blobs.

### 4. Rule #39 inner/outer/safe runner triplet — Rule-of-Nineteen

- **Description:** Every walker stream authored the 3-function triplet — `_do_<op>_walk` (inner, pure-logic, accepts db) + `run_<op>_walk_background` (outer Rule #33 .a state machine, async_session_factory) + `auto_<op>_walk_firmware_safe` (unpack hook, swallows exceptions, never mutates row.status).
- **Evidence:** 5 ι streams × Rule #39 triplet = Rule-of-Fourteen → Rule-of-Nineteen. Shape is fully retired-as-decision; sub-agents apply from precedent without redrafting.
- **Applies when:** Any new walker stream. Established Rule #39 in CLAUDE.md.

### 5. Rule #25 single-slice exception #2 cross-stack alignment — Rule-of-Twenty-Three

- **Description:** Multi-surface FindingSource extensions ship as ONE atomic commit covering DB CHECK + Pydantic Literal + frontend `FindingSource` union + frontend `FINDING_SOURCE_CONFIG` + backend classifier + emit hook. Test `test_finding_source_alignment.py` enforces pairwise agreement (extended in ι.A.D to enforce BOTH WindowsFindingSource AND new LinuxFindingSource families).
- **Evidence:** 5 ι.X.D commits (ι.A.D introduced LinuxFindingSource; ι.B/E extended Linux; ι.C/D extended Windows) all single-slice atomic. Pattern matured Rule-of-Eighteen → Rule-of-Twenty-Three.
- **Applies when:** Any new FindingSource value or family. The "introduce new family" boundary is the trickiest — ι.A.D is the precedent for two-family alignment.

### 6. Pattern P7 — Orchestrator-side trust-but-verify gate — Rule-of-Six

- **Description:** After each sub-agent return, run ~5-7 independent verification commands: `git log --oneline -N`, `git status`, `alembic heads`, ORM imports via container Python, MCP count, `gh run list --workflow=lint.yml`. Treat sub-agent self-report as a CLAIM, not evidence (per Agent tool docstring).
- **Evidence:** Pattern P7 caught ALL 4 "What Broke" items in this campaign — ι.C lint claim mismatch, ι.D lint cascade, ι.C alembic state claim mismatch, multiple A4 wall-time inflations. Without this gate, 2 cleanup commits would have shipped to κ as orphan debt.
- **Applies when:** Every sub-agent return. The discipline is the load-bearing trust mechanism for Pattern P5 per-piece direct-push at Trust=trusted.

### 7. Rule #19 evidence-first library API probe before walker code

- **Description:** Before authoring walker code that depends on a new OSS library, probe the library's actual API surface via `pip show`, `inspect.getsource`, `dir()`, or a small standalone script. Settle library availability + interface before drafting consumer code.
- **Evidence:** ι.A probed `dissect.journal` → doesn't exist → pivoted to clean-room parser. ι.C probed `dissect.etl` → fresh + maintained → used library (saved ~3K LOC vs clean-room). ι.D probed `dissect.ntfs._safe_attribute_value` → confirmed API surface from η.A precedent → reused. 3 of 5 streams ran explicit Rule #19 probe; saved ~30 min × 3 = ~90 min of trial-and-error.
- **Applies when:** Any walker stream OR refactor that depends on an OSS library not previously used in wairz.

### 8. Pattern P5 — per-piece direct-push to main

- **Description:** Each sub-task ships as its own commit + immediate push (Trust=trusted). Concurrency-cancel-aware Lint must-complete sibling (Rule #41 mechanism a) provides per-commit safety net.
- **Evidence:** 30 phase commits + 2 cleanup + 4 pre-ι = 36 commits in ~3h orchestrator-wall, all per-piece pushed. Each sub-task is independently revertable; bisect-clean. Zero cross-stream commit sweeps (sequential single-sub-agent dispatch per Rule #23).
- **Applies when:** Trust=trusted + sub-task ladder yields >2 independently-verifiable slices.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Scope shift: Vol3+hibernate → cross-platform Linux + Windows | 2/3 scouts DEFER Vol3; persona review 2/7 SHIP for Vol3 vs 7/7 for Linux journald; MemProcFS already ships MCP eroding wairz's wedge; brief authorized "scope TBD from research-fleet" | 5 ι streams shipped vs partial Vol3 architecture. Net coverage gain. Vol3 carryover to κ with refreshed competitive analysis. |
| Order: ι.A Linux first (not safe ι.D NTFS) | Strongest cross-lens convergence (Scouts 2 + 3 HIGH); first-Linux-walker novelty doesn't get de-risked by doing a safer stream first | ι.A precedent-set in 28.3 min; ι.B-E amortized cleanly. LinuxFindingSource framework in place at ι.A.D enabled ι.B + ι.E without re-introduction. |
| ι.E inclusion despite Scout 2's κ candidate framing | "Do them all" directive + 5/7 personas borderline-SHIP + Pattern P1 compounding gives low-risk capacity | ι.E shipped 26.4 min, zero new deps, ALL 6 commits CI-green first try. Cross-firmware aggregation Rule-of-Four matured. |
| Defer Vol3+hibernate to κ | Architectural prerequisite is own multi-session campaign; MemProcFS MCP wedge needs re-evaluation | Vol3 marked for κ kickoff with refreshed competitive analysis. |
| Sequential per-stream dispatch (NOT parallel Fleet per Rule #23) | Rule #23 worktree-discipline lesson — parallel sub-agent fleet had cross-stream commit sweeps + worktree-not-actually-isolated issues | Zero cross-stream commit sweeps across 30 ι phase commits. |
| Defer Rule #8 rebuild to end-of-session | Rule #20 fast iteration (docker cp + alembic upgrade head + restart) covered tier-1 verification for 5 streams; rebuild adds 5-8 min × 5 = 25-40 min savings | All 5 streams verified tier-1 via Rule #20 fast iteration; end-of-session rebuild scheduled (dissect.etl image-layer + 15 alembic migrations + 5 ORM models). |
| Add explicit `ruff check --no-cache` discipline to ι.E prompt after ι.C/D regression | Pattern P7 trust-but-verify caught ι.C/D lint cascade across 12 commits; ι.E hadn't dispatched yet — opportunity to prevent recurrence | ι.E shipped 6 commits ALL CI-green first try. Validated that prompt-side fix works. Antipattern A7 codified for κ+. |
| Two cleanup commits mid-campaign vs end-of-session sweep | Lint failures must NOT cascade into κ; per-piece direct-push philosophy + Rule #41 mechanism (a) caught early; immediate cleanup | CI back to green within ~5 min of each detection. All ι.E + postmortem CI-green. |

## Pattern progressions documented this campaign

| Pattern | At ι open | At ι close | Delta |
|---|---:|---:|---:|
| Pattern P1 single-sub-agent + precedent reuse | Rule-of-Five | **Rule-of-Ten** (decimal milestone) | +5 |
| Rule #39 inner/outer/safe runner triplet | Rule-of-Thirteen | **Rule-of-Nineteen** | +6 (incl. cleanup commits) |
| Rule #25 single-slice exception #2 cross-stack | Rule-of-Eighteen | **Rule-of-Twenty-Three** | +5 |
| Pattern P7 orchestrator-side trust-but-verify | Rule-of-Five | **Rule-of-Six** | +1 (campaign-level catch) |
| Cross-firmware aggregation at walker-stream time | (didn't exist) | **Rule-of-Four (DURABLE)** | +4 (new pattern) |
| Parse-only metadata walker | (didn't exist) | **Rule-of-One** | +1 (new pattern, ι.D) |
| Rule #36 EXTENSION (no-decrypt test gate) | (didn't exist) | **Rule-of-One** | +1 (new pattern, ι.D) |
