# Antipatterns — ASYNC family lint cleanup (2026-05-11)

Campaign: `.planning/campaigns/async-cleanup-2026-05-11.md`

## A1: Per-CODE phases for multi-code lint sweeps with file-overlap

**Failure shape:** organising a multi-code lint sweep as one phase per code
(Phase B = all ASYNC240; Phase C = all ASYNC230; …) when the inventory shows
the top hot files have hits across multiple codes. Each hot file gets touched
2-3 times across phases, generating bisect noise + partial-fix intermediate
states (file is "ASYNC240-clean but ASYNC230-dirty" between commits).

**Evidence (this campaign):** original briefing proposed per-code; inventory
showed `security.py` had 21+7 hits, `binary.py` 11+7, `unpack_android.py`
8+12. Decision D1 rejected per-code in favour of per-file. Capturing as
antipattern so the next multi-code campaign doesn't independently rediscover.

**Mitigation:** Pattern P1 — per-file commits closing all in-file codes in
one slice. Apply when `ruff check --select <each_code>` per-file aggregation
shows the top files appearing under 2+ codes.

**Relation to existing rules:** alternative-to-Pattern-P1 documentation.

## A2: Bare `# noqa: ASYNC<code>` without rationale

**Failure shape:** `# noqa: ASYNC240` with no trailing rationale comment.
Future maintainers cannot tell whether the noqa is legitimate (bounded / pure
/ contract-required per Pattern P3) or accumulated tech-debt; code review
cannot safely remove the suppression during cleanup.

**Evidence (this campaign):** Decision D4 explicit requirement — every noqa
carries `# noqa: ASYNC<code> — <one-line rationale>`. ~80+ noqa lines added,
all with rationale. Zero bare-noqa survivals at campaign close (verified by
`grep -RIn "# noqa: ASYNC" backend/ | grep -v ' — '`).

**Mitigation:** make the rationale a required-by-convention suffix. Rationale
categories (per Pattern P3) are: pure-string path math; bounded pre-flight
stat; bounded loop over detection roots; caller-supplied timeout per Rule #29.

**Relation to existing rules:** local-discipline; no CLAUDE.md rule yet.

## A3: Concurrency-cancel CI masking latent lint bugs

**Failure shape:** Pattern P5 (per-piece direct push) + GitHub Actions
concurrency-cancel saves runner minutes by cancelling intermediate workflow
runs — but ALSO delays defect detection. A latent bug in code that only the
Lint workflow surfaces sits undetected until a commit happens to be "last"
long enough for its Lint run to complete.

**Evidence (this campaign):** F823 in `app/ai/tools/emulation.py:2627`
(function-local `import asyncio` placed AFTER a use site → Python's
local-binding rule made the use a `referenced-before-assignment`) was latent
pre-campaign. It first surfaced on commit `cae7547` (Phase E.8) because that
commit's Lint run actually completed; the previous ~25 Lint runs had been
concurrency-cancelled. Caught + fixed in D.39 (`6376d8d`). Rule-of-One.

**Mitigation:** when removing a ruff suppression OR before a campaign close,
run the FULL ruleset locally (`( cd backend && uv run ruff check --no-cache . )` with no `--select`) before pushing. Periodically (every ~10
commits) let a commit sit long enough for CI to run to completion before
adding the next commit. Trade-off accepted: P5 still correct for trusted
cadence, but lint-sweep campaigns specifically MUST add the local full-ruleset
sweep before the suppression-removal commit.

**Relation to existing rules:** documents Pattern P5's failure mode. Pairs
with Pattern P4 (no-select width canary at phase end).

## A4: F823 — function-local imports placed AFTER first reference

**Failure shape:**

```python
async def f():
    await asyncio.sleep(0)   # <-- use site
    import asyncio           # <-- F823: local binding rule promotes asyncio
                             #     to local for the WHOLE function body;
                             #     the use above is now referenced-before-assignment
```

Python's local-binding rule: ANY `import X` inside a function body binds X as
a local for the function's entire scope, so a reference BEFORE the `import X`
line raises `UnboundLocalError` at runtime (and ruff F823 at lint time). The
trap is sharp because the module-level `import asyncio` exists at the top of
the file — the reader assumes the use site resolves against the module-level
binding. It does not.

**Evidence (this campaign):** `app/ai/tools/emulation.py:2627` carried this
shape pre-campaign; ruff's F823 was suppressed via the ASYNC-family cleanup
masking the file. Surfaced when commit `cae7547` actually completed a Lint
run; fixed in D.39 (`6376d8d`) by deleting the redundant function-local
`import asyncio` (the module-level import was sufficient).

**Mitigation:** function-local imports MUST be at the TOP of the function
body (or at minimum before any reference). Mechanical detection:
`grep -nE "^\s+(import|from) " <file>` then check that line N < line of first
use of the imported symbol within the same function. Modern ruff catches via
F823; ensure F823 is NOT in `[tool.ruff.lint] ignore`.

**Relation to existing rules:** adjacent to Rule #11 (post-split runtime
constant access) and Rule #30 (lazy-import patch targets — both involve
function-body imports). Rule-of-One; durable mechanical failure mode worth
flagging as a Rule #40 candidate if a second instance appears.

## A5: Local ruff verification using only `--select <current_code>`

**Failure shape:** verifying a lint-sweep commit locally with
`ruff check --no-cache --select ASYNC240 <file>` only. Confirms the targeted
axis is clean, but misses any pre-existing or fix-introduced violation under
a different code (F823, F401 unused-import-after-deletion, B007 …). The
remote Lint workflow runs the full ruleset and exposes the gap; if Pattern P5
+ concurrency-cancel is in play (A3), the gap may go undetected for several
commits.

**Evidence (this campaign):** the F823 incident (A4) was masked locally by
`--select ASYNC240,ASYNC230,…` invocations that never saw F823. Local
verification did its job for the campaign's scope but did NOT serve as a
full-CI proxy.

**Mitigation:** at every phase end (Pattern P4) AND before any
suppression-removal commit, run `( cd backend && uv run ruff check --no-cache . )` with no `--select` filter. Cost is ~5 s extra; eliminates the
A3 + A4 silent-mask combination.

**Relation to existing rules:** reinforces Rule #31 (width-canary on
grep-derived counts) extended to lint exit-status verification. Pairs with
Pattern P4.
