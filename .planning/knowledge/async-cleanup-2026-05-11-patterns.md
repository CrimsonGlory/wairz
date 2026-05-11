# Patterns — ASYNC family lint cleanup (2026-05-11)

Campaign: `.planning/campaigns/async-cleanup-2026-05-11.md`
Range: `3fc48b3..396e155` (40 commits, 319 ASYNC hits + 1 latent F823 closed).

## Pattern P1: Per-FILE commits for multi-code lint sweeps (not per-code)

**Shape:** when closing N suppressed lint codes whose hits overlap across the
same hot files, commit per-FILE (closing all N codes in that file in one
slice), not per-CODE (closing one code across all files).

**Evidence (this campaign):** original briefing suggested per-code phases
(Async.B = all ASYNC240, Async.C = all ASYNC230). Inventory showed top files
had hits across multiple codes — `security.py` had 21 ASYNC240 + 7 ASYNC230;
`binary.py` 11 + 7; `unpack_android.py` 8 + 12. Per-code shape would have
touched each hot file 2-3 times, generating bisect noise + partial-fix
intermediate states. Decision D1 rejected per-code. Result across 40 commits:
0 cross-code bisect surprises; every commit independently revertable.

**When to apply:** any multi-axis cleanup (N ruff codes, N mypy errors, N
deprecation warnings) where inventory shows hit overlap across the same files.
Mechanical test: `for code in <codes>; do ruff check --select $code . | awk '{print $1}' | sort -u; done | sort | uniq -c | sort -rn | head` — if the
top files appear under 2+ codes, prefer per-file.

**Relation to existing rules:** reinforces Rule #25 (small-commit / per-slice
discipline); does not replace it. Each per-file commit IS the Rule #25 slice
in this campaign shape. Rule-of-One in lint-sweep context; SHAPE generalises.

## Pattern P2: Helper extraction during per-file fix discovers reusable factorization

**Shape:** when a per-file fix produces an executor-wrapped sync helper, check
whether the same shape appears across sibling files in the same subsystem.
Extract the helper to a shared module, then roll out in a single batch commit
to the siblings.

**Evidence (this campaign):** D.34 (`821762a`) closed ASYNC240 in
`app/workers/unpack_cab.py` by extracting `reset_extraction_dir_sync` from a
3-call pattern (rm-existing → mkdir → return). The same shape lived in 6 other
unpack workers — D.35 (`a07ed26`) rolled out the helper across wim / qnx_ifs /
psf / msix / msi / iso9660 in one commit; D.37 (`a0ef530`) added
driver_package. 7 reuses total; the extraction was durable code, not just
lint-quiet code.

**When to apply:** any per-file fix where the conversion introduces a sync
helper of >2 lines. Before committing the per-file fix, grep sibling files
for the same call shape — if 3+ matches, extract first, roll out in batch.

**Relation to existing rules:** reinforces Rule #27 (additive-then-cut-over
shape) at function granularity instead of module granularity. Rule-of-One
(this campaign), but the shape mirrors Rule #27's evidence base.

## Pattern P3: Decision D4 generalised — per-line noqa-with-rationale extends to app/ files for bounded sync I/O

**Shape:** in async functions, `# noqa: ASYNC<code> — <one-line rationale>`
is the correct fix (not `run_in_executor`) when the call is one of:
(a) single pre-flight stat before a sync subprocess Rule #29 already wraps,
(b) pure-string `os.path.relpath / .join / .basename / .dirname`,
(c) `os.path.realpath` inside a small bounded loop (~1-3 entries) over
detection roots, or (d) caller-supplied `timeout=` param on an async helper
plumbed through to an awaited `wait_for` / `subprocess` per Rule #29 contract.
The rationale comment is non-negotiable — it communicates "looks like a
violation but is bounded / pure / contract-required".

**Evidence (this campaign):** Decision D4 originally test-only. Extended to
app/ in D.38 (`735d054`) for 19 hits across 16 files. An executor hop for a
single bounded stat costs more (thread context switch + ~50µs) than the
operation itself and obscures pre-flight intent. ~80+ noqa lines added across
the campaign, every one carrying a rationale.

**When to apply:** before adding `run_in_executor` for an ASYNC240/230 hit,
ask: is this call (a) bounded to O(1) ops, (b) pure-string, or (c) part of a
contract-required timeout plumb-through? If yes, per-line noqa is the cleaner
fix. If the call is inside an unbounded loop or does real I/O on a hot path,
executor-wrap.

**Relation to existing rules:** extends Decision D4 (campaign-local); does not
contradict Rule #5 (executor wrap for blocking I/O) — Rule #5 still applies
for unbounded / hot-path I/O. Rule-of-One; flag for promotion if a future
campaign hits the same bounded-stat shape.

## Pattern P4: Width-canary every ruff verification with `--no-cache` + `--select`, then a no-select sweep at phase end

**Shape:** every phase-end ruff verification uses two invocations: (1)
`ruff check --no-cache --select <code> <path>` to confirm the specific axis
is at zero, and (2) at the LAST commit before suppression removal,
`ruff check --no-cache <path>` with no `--select` filter — the widest
reasonable canary to surface any orthogonal regression.

**Evidence (this campaign):** every D.x and E.x commit verified the targeted
code; the final phase verification (`( cd backend && uv run ruff check --no-cache --select ASYNC240,ASYNC230,ASYNC109,ASYNC221 . --statistics )`)
ran the widened scan before pushing the suppression-removal commit. The
`--no-cache` flag is non-negotiable per Antipattern A6 (ruff cache dir is
root-owned from a legacy container; cached results lie). Width-canary catches
the failure mode where a narrow `--select` makes a tool look clean while a
sibling code lights up.

**When to apply:** every lint-sweep phase-end. Cost is ~10 s extra per phase;
catches the "fix lit up a different code" regression mode that per-code-only
verification misses.

**Relation to existing rules:** reinforces Rule #31 (width-canary discipline
on grep-derived scope counts) — same shape applied to ruff exit-status
verification.

## Pattern P5: Per-piece direct-push to main with concurrency-cancel CI

**Shape:** under trusted cadence (Rule #25 small-commit + established review
trust), every commit pushes immediately to main rather than batching into a
PR. GitHub Actions concurrency-cancel on the same workflow + ref cancels
intermediate Lint / Backend Tests runs; only the final commit's run completes.

**Evidence (this campaign):** 40 commits pushed individually; the Feature
Ledger shows `(superseded)` / `cancelled` for ~30 intermediate Backend Tests
runs and ~25 intermediate Lint runs. Estimated 30-60 runner-minutes saved per
campaign session. Inherited from parent-campaign Pattern P5; this is the 2nd
campaign applying the cadence — Rule-of-Two for the trusted-direct-push
shape.

**When to apply:** trusted (high-session-count) project + small-commit
discipline + a CI workflow that supports concurrency-cancel (every modern GHA
workflow with `concurrency: { group: ..., cancel-in-progress: true }`).
Antipattern A3 below documents the latent-bug masking failure mode — do NOT
apply for security-sensitive or first-pass-on-new-area commits.

**Relation to existing rules:** Rule #25 (per-sub-task commits) + this
campaign's trust gate. Rule-of-Two now (parent campaign + this).
