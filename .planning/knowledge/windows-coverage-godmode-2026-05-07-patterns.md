# Patterns: Windows-Coverage God-Mode Campaign (2026-05-07)

> Extracted: 2026-05-07
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: not found (extracting from intake + git log + audit telemetry)
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: `git log d174a62~..HEAD` (17 commits)
> Status: Phase α complete; Phase β at 4/9 sub-tasks

## Successful Patterns

### 1. Five-persona parallel research fleet → synthesis → execution

- **Description:** Before any code, spawn 5 expert-persona research agents in parallel: (A) format taxonomist, (B) OSS tooling surveyor, (C) RE workflow architect, (D) Wairz platform integrator, (E) adversary / completionist. Each returns a structured brief (~600-1000 words) with citations. Then I cross-read, identify contradictions, and converge into a PRD with explicit decision log (D1-D9) before any commit.
- **Evidence:** Phase 0-3 of the campaign produced `.planning/intake/windows-coverage-godmode-2026-05-07.md` with 12 cross-persona contradictions resolved. Phase α executed 12 commits across the 4-phase rollout WITHOUT a single architecture revert. Persona-E flagged R2R-stomping and ARM64EC/X bimorphic detection (god-mode-vs-good-enough discriminator) that were absent from the other personas' briefs.
- **Applies when:** Major (≥10-commit) campaigns where the problem space is poorly defined or where Persona-A taxonomy + Persona-B tooling availability + Persona-D platform constraints all genuinely interact. Single-format additions don't need this.

### 2. Phase 2 handler mirror shape (two-phase subprocess + defensive)

- **Description:** Every CLI-tool unpack worker mirrors `unpack_wim.py`: (1) cheap probe subprocess (`--list` / `--info` / `suminfo` / `magic-validate`) for validity + index capture, (2) full extract subprocess. Defensive `FileNotFoundError` + `TimeoutError` + non-zero-exit handling. `run_in_executor` for blocking I/O. `find_filesystem_root` then either Linux-rootfs path OR success-with-no-rootfs fallback (Windows-flat trees). 30-300 sec timeouts aligned to Rule #29 frontend tiers.
- **Evidence:** Reused 7 times across `unpack_cab.py`, `unpack_msi.py`, `unpack_msix.py`, `unpack_msu.py`, `unpack_psf.py`, `unpack_driver_package.py`, `unpack_vhdx.py` in commits `e21545a..b9d124d` — zero rework or revert. Each worker shipped with 5-10 mock contract tests covering missing-binary, unreadable, timeout, non-zero-exit, success-with-payload, progress-callback paths.
- **Applies when:** Wrapping any CLI extraction tool. Particularly any tool with separate validate-then-extract flows (cabextract `--list`/`-d`, msitools `msiinfo`/`msiextract`, qemu-img `info`/`convert`, 7z `l`/`x`).

### 3. Rule #21 mirror discipline catches silent-omission with exhaustiveness test

- **Description:** Every `DetectedFormat` enum value mirrored in BOTH `EXTRACTION_CAPABILITY` AND `STRATEGIES` dictionaries. A `test_no_unmapped_windows_format` exhaustiveness test asserts the count and that EVERY `WINDOWS_*` enum appears in BOTH maps — catches the "added enum, forgot to wire strategy" silent-omission pattern.
- **Evidence:** Phase α.3 commit `49e5b6b`. The exhaustiveness test in `test_windows_format_detection.py` would have caught a missing STRATEGIES entry at PR time; passes green at 28 tests.
- **Applies when:** Any new format-detection / strategy-dispatch / capability-map triplet. The exhaustiveness assertion is the durable gate against the silent-omission drift Rule #21 was created to prevent.

### 4. NamedTuple/dataclass verdict mapping 1:1 to ORM columns + drift-detection test

- **Description:** Service-layer verdict types (`AuthenticodeVerdict` dataclass) mirror their target ORM table columns (`WindowsPESignature`) field-for-field. A test asserts the field name set matches at module import time — `test_verdict_maps_to_windows_pe_signature_columns` catches schema drift without manual review.
- **Evidence:** Phase β.4 commit `d12f64e`. The test caught my initial verdict skipping `dbx_revoked` — added before commit.
- **Applies when:** A service produces values that round-trip through a database. Any time you have a "verdict" / "result" type that's persisted, this drift-detection pattern keeps the contract fresh.

### 5. JSONB normalizer + stamp + schema_version triplet (Rule #35c) for sub-keys

- **Description:** Each new JSONB sub-key gets THREE artefacts: `<TABLE>_<COLUMN>_SCHEMA_VERSION = 1` constant, `_normalize_<table>_<column>(value: Any) -> <canonical>`, `_stamp_<table>_<column>(payload) -> payload | None` (idempotent, mutating, preserves None). Tests assert canonical-pass-through + None-coercion + wrong-type-coercion + idempotency + stamp-version-add + stamp-idempotency + schema-version-constant. Pattern repeated for `firmware.device_metadata['windows_artifacts']` (α.1) AND `firmware.authenticode_chain_result` (β.3).
- **Evidence:** Phase α.1 (`d174a62`) + Phase β.3 (`057bdba`). 12 + 6 = 18 normalizer tests across both. The pattern is now the established way to introduce JSONB shapes in wairz.
- **Applies when:** Any new JSONB column or sub-key with ≥3 consumer files. The schema_version stamping isn't required for ≤2 consumers (per Rule #35c).

### 6. Live canary auto-skip on missing tool until cut-over rebuild activates

- **Description:** Rule #35b live canaries (real-tool round-trip tests) call `pytest.skip()` when the required CLI tool isn't on PATH — `gcab` for CAB synthesis, `msitools` for MSI, `qemu-img` for VHDX. The Phase α.6 Dockerfile cut-over adds the tools; canaries activate post-rebuild WITHOUT touching test code.
- **Evidence:** Phase α.6 cut-over (`eaf94d2`) shipped: pre-rebuild = 213 pass + 3 skip. Post-rebuild = 235 pass + 1 skip (CAB and MSU-of-CAB canaries activated; MSI still skips needing fixture). Same test code, different tool availability.
- **Applies when:** Any test that exercises an external tool. Auto-skip means the test ships green at every commit while real-tool validation activates at the right time.

### 7. Empirical REPL-validation of persona-brief library claims

- **Description:** Before adopting a library version constraint or class name from a research persona's brief, validate empirically in the running container's Python REPL. The persona's brief reflects research-time state; library APIs drift; validating against the actual installed version catches stale info BEFORE it lands in `pyproject.toml`.
- **Evidence:** Phase β.1 (`9db7992`). Persona-B brief had `uefi-firmware>=1.12` which doesn't exist on PyPI (latest is 1.11) AND `signify.SignedPEFile` which was renamed to `AuthenticodeFile` in signify 0.9.x. REPL exploration in the container python caught both BEFORE I committed broken constraints. Saved a wasted rebuild + revert cycle.
- **Applies when:** Adopting any external library based on third-party research (persona briefs, blog posts, docs > 6 months old). One-minute REPL validation is much cheaper than a deps-revert cycle.

### 8. Rule #25 per-sub-task commits with isolated test acceptance

- **Description:** Each sub-task gets its own commit with its own pytest acceptance command in the commit message. 17 commits in this campaign — every commit is independently revertable; `git bisect` is clean; PR review is per-feature; rollback drift is bounded to one sub-task.
- **Evidence:** All 17 commits in the campaign log. Zero reverts, zero bundled "feat: all of Phase α" omnibus commits. Each commit message lists the specific test command that proved it (`pytest tests/test_<file>.py -v → N passed`).
- **Applies when:** Any campaign with ≥3 independently-verifiable sub-tasks. Bundled commits cost nothing during execution but become catastrophic at revert/bisect time.

### 9. Real-exit-code capture (Rule #35a) — `cmd; rc=$?` not `cmd | tail; rc=$?`

- **Description:** When validating a command's success, NEVER capture `$?` after a pipe — the pipe captures the LAST command's exit (typically `tail`'s 0), not the actual command's. Use direct `cmd; rc=$?` OR `cmd > /tmp/out; rc=$?; tail -10 /tmp/out` OR `set -o pipefail`.
- **Evidence:** I fell into this trap exactly once on the Rule #24 typecheck canary (it printed the TS error AND exit=0, which is impossible). Caught and fixed in the same response. Future commands used the direct pattern.
- **Applies when:** Any validation script or CI step where exit code is the success criterion. The Rule #35a documentation in CLAUDE.md should always be referenced when capturing exit codes from piped commands.

### 10. Hybrid JSONB-aggregate + per-row-table for cross-firmware queryable data

- **Description:** Resolve the "JSONB on device_metadata vs new table" architectural tension via hybrid: aggregate counts/summaries land in a schema-versioned JSONB sub-key (`firmware.device_metadata['windows_artifacts']`); per-blob queryable rows land in a dedicated table (`windows_pe_signatures`) with FK + indexes for cross-firmware `WHERE leaf_serial IN (dbx_set)`-style queries.
- **Evidence:** Persona-D wanted JSONB; Persona-E wanted real table for the DBX cross-reference workflow. The hybrid satisfies both: D2 decision in the campaign log; β.2 commit `5fba530` ships the table; α.1 commit `d174a62` ships the normalizer.
- **Applies when:** Any new feature where ONE consumer wants aggregate counts (cheap dashboard render) AND ANOTHER consumer wants per-row queries (cross-row JOIN / SELECT WHERE). Don't pick one — ship both with the JSONB sub-key sourcing its counts from `SELECT count(*) FROM <table> WHERE firmware_id = ...`.

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|---|---|---|
| 1 | 5-persona parallel research fleet before any code | User direction "deep research + persona debate"; major campaigns benefit from cross-perspective debate | All 5 briefs returned with citations + cross-persona convergence prompts; 12 contradictions resolved before any line of code; Phase α had zero architectural reverts |
| 2 | Hybrid JSONB-aggregate + per-row table for windows_pe_signatures | Persona-D wanted JSONB; Persona-E wanted indexed table for DBX cross-reference; both correct in their domain | Both shipped (α.1 normalizer + β.2 table); aggregate counts power frontend chips, per-row queries power DBX cross-firmware rollups |
| 3 | Skip authenticode-py for β.4 baseline; use signify only | signify covers happy-path; authenticode-py is dual-sig edge-case specific; don't import unused complexity | β.4 ships with `iter_signatures()` enumerating all sigs; authenticode-py reservable for β.7 if a real dual-sig PE surfaces an edge case signify mishandles |
| 4 | 4-phase Archon rollout (α/β/γ/δ) instead of one mega-PR | Phase boundaries are the natural review/PR breakpoints; merging Phase α before β reduces review-surface explosion | Phase α complete (12 commits ready for review); Phase β at 4/9 (still on the same branch — split into PR α + PR β at PR time) |
| 5 | Custom-action discipline → Rule #36 candidate (codify in β.9) | Persona-E anti-pattern #3 + MSI Binary table is the most-common attack-payload vector; should be enforced not just documented | Codified in `unpack_msi.py` docstring + `dump_msi_custom_actions` MCP tool description + `WindowsHubPage` footer; `auto-msi-custom-action-execute-forbidden` quality rule appended (this /learn) |
| 6 | Offline trust anchor via signify's TRUSTED_CERTIFICATE_STORE → Rule #37 candidate | signify 0.9.2 ships MS Authenticode roots already; no separate Dockerfile bundling needed; refresh = bump signify quarterly | β.4 uses `TRUSTED_CERTIFICATE_STORE` directly; the Phase β.6 DBX bundling work simplifies to just `dbxupdate.bin` (signify covers the cert chain side) |
| 7 | Real-PE Rule #35b live canary deferred to β.7 (MCP integration) | No tiny.msi fixture committed; signed-PE samples live in firmware extraction trees; β.7 MCP tests have access | β.4 ships with mock-only tests; the deferred live canary will use a fixture PE in a real Win11 ISO via β.7 MCP integration tests — no test-side changes needed |
| 8 | Branch rename feat/windows-phase-alpha → feat/windows-coverage-godmode at session-end | Branch label mismatch is mostly cosmetic; rename when the campaign demonstrably spans α+β | Renamed at session-end via `git branch -m`; branch now reflects full campaign scope |
| 9 | docker cp + alembic upgrade head (Rule #20) for migrations during dev | Avoid full rebuild for each migration; class-shape changes don't apply (alembic is migrate-only) | Both Phase β migrations (`b1a2c3d4e5f6`, `b2a3c4d5e6f7`) applied via this pattern; both green against live PostgreSQL; cut-over rebuild only at α.6 + future β.9 |
| 10 | β.4 emits AuthenticodeVerdict that maps 1:1 to WindowsPESignature columns | Service layer's job is verdict, model layer's job is persistence; isomorphism keeps the boundary clean and drift-detectable | `test_verdict_maps_to_windows_pe_signature_columns` enforces drift-detection; the β.4 background runner (β.7 work) just `WindowsPESignature(**asdict(verdict), blob_id=...)` |
