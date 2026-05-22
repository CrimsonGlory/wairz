# Antipatterns — Over-Constraint Sweep 2026-05-22

> Source: `.planning/postmortems/postmortem-over-constraint-sweep-2026-05-22.md`
> Date: 2026-05-22

## Antipattern #1 — Rule #51 tier classification by detached-work duration instead of event-loop pinning

**What it looks like.** An endpoint returns 202 with sub-second ACK, dispatches work to arq / `asyncio.create_task` / `run_in_executor`. The work itself takes 2-10 minutes. A reviewer tags the decorator `@limiter.limit(TIER_A_HEAVY)` (5/hour) because "the work takes a long time, so we should throttle it."

**Why it's wrong.** Rule #51's framework prescribes classification by **EVENT-LOOP PINNING**, not detached-work duration. The backend's event loop is FREE during arq dispatch, FREE during `asyncio.create_task`, FREE during `run_in_executor` (executor work is on a worker thread). The actual saturation surface depends on which RESOURCE the work consumes:
- arq worker depth → TIER_A_LIGHT_ACK (30/hour) is enough
- DB connection pool → TIER_A_LIGHT_ACK
- Threadpool size → TIER_A_LIGHT_ACK (executor work)
- Docker kernel resources → TIER_B_DOCKER (20/hour)
- Backend event loop time itself → TIER_A_HEAVY (5/hour)

Misclassifying as `TIER_A_HEAVY` throttles iterative research workflow with no real protection — the work would run fine at 30/hour because the BACKEND loop is free.

**How to detect.** For every `@limiter.limit(TIER_A_HEAVY)` decorator, ask: "does this endpoint's request handler return WITHIN ITS OWN INVOCATION (sync sleep / long subprocess held in the handler) — OR does it return 202 and let work continue in a background context?" If 202 + background, the tier is wrong.

**Worked example.** Commit `89b87d3` (2026-05-22) re-tiered 6 decorators:
- firmware.py:251 `/unpack`: 202 + arq dispatch → was HEAVY, should be LIGHT_ACK
- device.py:101 `/dumps`: 202 + detached runner → was HEAVY, should be LIGHT_ACK
- comparison.py:55 `/firmware`: `run_in_executor` filesystem diff → was HEAVY, should be LIGHT_ACK
- comparison.py:83 `/binary`: `run_in_executor` LIEF diff → was HEAVY, should be LIGHT_ACK
- comparison.py:129 `/text`: sub-second sync → was HEAVY, should be TIER_C_DEFAULT
- comparison.py:170 `/instructions`: μs-to-ms Capstone → was HEAVY, should be TIER_C_DEFAULT

**How to avoid.** Rule #51 framework + the `_EXPECTED_TIERS` test pinning + the META-CANARY now structurally prevent this — but the FIRST APPLICATION of the framework to any NEW endpoint requires the reviewer to apply the framework correctly. The original 2026-05-18 sweep that authored Rule #51 retroactively fixed 2 sites; this 2026-05-22 sweep fixed the remaining 6 that pre-existed Rule #51.

## Antipattern #2 — Bumping the DB connection pool without bumping the consumer-side caps

**What it looks like.** A Rule #51 .iv-style move: bump `pool_size + max_overflow` to support a new burst envelope (e.g. 30/hour TIER_A_LIGHT_ACK = 30 concurrent sessions in worst-minute). But the consumer-side caps that gate how the pool is actually USED stay at the old envelope: arq `max_jobs` stays at 4, semaphore caps stay at 4, etc.

**Why it's wrong.** The pool headroom is unusable in practice. After the rate limit relaxes to 30/hour, legitimate burst queues on the consumer caps instead of the pool. The user-facing improvement from the rate-limit bump is neutralized.

**How to detect.** When changing pool size, immediately grep for every CAP that gates how the pool is consumed:
- `max_jobs` in arq WorkerSettings
- `asyncio.Semaphore(N)` declarations in worker code
- `max_concurrent` parameters in service constructors
- Per-IP / per-API-key rate limits
- Docker container concurrency limits

Every one of these must be re-evaluated against the new envelope.

**Worked example.** Rule #51 .iv (2026-05-18) bumped DB pool 30 → 40. arq `max_jobs=4` and `_WALKER_FANOUT_SEMAPHORE=4` were NOT re-evaluated. Discovered 2026-05-22 during over-constraint sweep — Commit `df7d403` bumped both to 6 to match the 30/hour LIGHT_ACK burst envelope.

**How to avoid.** Pair every pool resize with a "consumer cap audit" line in the PR description: "Verified consumer-side caps: arq max_jobs=X, walker semaphore=Y, ... — all sized for new envelope of Z concurrent." Add a comment to the pool declaration that REFERENCES the consumer caps it co-evolves with.

## Antipattern #3 — Silent truncation without `+N more` sentinel

**What it looks like.** Code that caps a list/result at N entries via `result[:N]` or `if count >= MAX: return findings`, with no marker indicating truncation occurred.

**Why it's wrong.** Operator cannot distinguish "exactly N results" (legitimate) from "more results exist but were silently dropped" (truncated). On real-world large firmware (multi-GB, multi-thousand-finding), truncation routinely happens but is invisible. Operator makes decisions based on incomplete data.

**Worked examples discovered this sweep.**
- `security_audit/_base.py:13 MAX_FINDINGS_PER_CHECK = 50` — hard-stops every audit check at 50 findings across 13 call sites. No `+N more` notice. **Highest-impact silent cap in the codebase.**
- `services/abusech_service.py:235 rule_matches[:50]` — YARA rule matches per malware sample.
- `services/dotnet_decompile_service.py:406 errors[:50]` — .NET decompile warnings/errors.
- `ai/tools/sbom.py:799,861,880 json.dumps(...)[:30000]` — SBOM JSON document cut mid-token. Returns parse-broken JSON to MCP clients.
- `services/pcap_analysis_service.py:293 conversations[:50]` — pcap flows.
- `services/pcap_analysis_service.py:587 cipher_suites[:20]` — TLS ClientHello cipher suites.

**How to detect.** Grep `[:N]` (raw slice) and `if count >= MAX: return` patterns. For each, ask: "if this trims content, does the operator see a marker?"

**How to avoid.**
- For string output: append `"... +{N - cap} more items dropped (cap={cap})"`.
- For list output: append a sentinel string `"... +{N - cap} more"` as the final entry (the list type stays homogeneous string).
- For JSON output that may be truncated: replace the truncated-JSON with a STRUCTURED truncation marker (`{"status": "truncated", "original_size_bytes": N, "rest_endpoint": "..."}`) instead of cutting mid-token.
- For structured object output: add `truncated: bool` + `total_count: int` fields to the schema.

The discipline: every cap MUST produce an operator-visible marker when it bites.

## Antipattern #4 — `cmd | head -N` for exit code checking (Rule #35a pipe-induced silent exit)

**What it looks like.** Running a command and trying to check its exit code via a pipe:
```bash
npx tsc -b --force 2>&1 | head -10; echo "exit=$?"
```

**Why it's wrong.** The pipe captures `cmd`'s output but `$?` reflects the LAST command in the pipeline (`head -10`), which always returns 0. The command may have failed with errors visible in the output, but the shell reports `exit=0`. This is Rule #35a's pipe-induced silent exit instance — exactly the same defect family as Rule #17's tsc-cache-hit silent pass.

**How to detect.** Mismatch between visible output (tsc reporting type errors) and reported exit code (0). When the canary output PROVES the tool detected an error but `$?` reports success, the pipe is hiding the real exit code.

**How to avoid.**
- Direct invocation: `cmd; ec=$?` (no pipe, real exit code).
- Tee + PIPESTATUS: `cmd 2>&1 | tee /tmp/out; ec=${PIPESTATUS[0]}`.
- Split: `cmd > /tmp/out 2>&1; ec=$?; head -10 /tmp/out`.
- `set -o pipefail` if you want the pipeline's exit code to be the FIRST non-zero exit.

**Worked example.** Rule #24 mandatory tsc canary at the start of Commit 3:
```bash
echo 'const x: number = "nope"; export default x;' > frontend/src/__canary.ts
( cd frontend && npx tsc -b --force 2>&1 | head -10 ); echo "exit=$?"
rm -f frontend/src/__canary.ts
```
Output:
```
src/__canary.ts(1,7): error TS2322: Type 'string' is not assignable to type 'number'.
exit=0
```
The `error TS2322` proves tsc IS checking. The `exit=0` is the pipe-induced silent exit — `head -10`'s exit, not tsc's. Re-ran without the pipe (`npx tsc -b --force; echo "real exit=$?"`) and got `real exit=2`. tsc had been working all along; the canary's exit-check shape was broken.

**Lesson.** Rule #35a's "exit code via pipe is unreliable" generalizes to EVERY exit-code-checking command in a bash session, not just the specific instance Rule #35a was originally extracted from. When the canary's output and exit code disagree, suspect the pipe.
