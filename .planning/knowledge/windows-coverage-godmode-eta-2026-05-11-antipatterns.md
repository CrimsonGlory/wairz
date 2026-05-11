# Anti-patterns: Windows-Coverage God-Mode Phase η (2026-05-11)

> Extracted: 2026-05-11
> Campaign: `.planning/campaigns/windows-coverage-godmode-eta-2026-05-11.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-eta-2026-05-11.md`

## Failed Patterns

### 1. Trusting a stale intake's claimed status without git reconciliation

- **What was done:** The kickoff prompt directed `/citadel:archon` to "decompose remaining phases of `windows-coverage-godmode-2026-05-07`". The intake document listed only Phases α-δ as in-scope.
- **Failure mode:** Git log + `.planning/campaigns/completed/` listing showed α/β/γ/δ + Phase ε (EVTX walker + event records persistence) + Phase ζ.1/ζ.2/ζ.3 (Amcache + Prefetch + SRUM) ALL shipped + the campaign was explicitly CLOSED in commit `3fc48b3`. The kickoff's framing of "decompose remaining phases" had no remaining phases to decompose; intake document was stale relative to git reality.
- **Evidence:** Reconciliation step at session-start surfaced 4 prior windows-coverage closure postmortems in `.planning/postmortems/postmortem-windows-coverage-godmode-*.md` + `.planning/campaigns/completed/windows-coverage-godmode-*.md` listing.
- **How to avoid:** When a kickoff prompt references an intake but its status section is suspect (or git log timestamps are months newer), reconcile via `.planning/campaigns/completed/` listing + last 5 commits' subject lines BEFORE acting on the kickoff's framing. Same shape as Rule #19 evidence-first: "the spec describes intent, the DB describes truth — trust the DB"; here, "the intake describes intent, the git log describes truth — trust git." Reframe Archon's mandate from "decompose remaining" to "decompose next-frontier" if the campaign is genuinely closed.
- **Promotion threshold:** Rule-of-One for now (this session). If a second occurrence shows up (any future session where intake-vs-git divergence costs reframing time), promote to a `.mex/patterns/intake-vs-git-reconciliation.md` recipe + add CLAUDE.md rule.

### 2. Regex `\b` word-boundary fails at non-word-character flag prefix or character-class brackets — Rule-of-Two

- **What was done (η.B):** Classifier regex `r"\b-enc\b"` used to match the PowerShell `-enc` short-form flag in EVTX raw_xml event data.
- **What was done (η.C):** Classifier regex `r"\b\[char\[\]\]\("` used to match the `[char[]]` PowerShell shellcode-reassembly pattern in LNK target args.
- **Failure mode (both):** Python `re` engine's `\b` word-boundary metachar matches between a word character (`[a-zA-Z0-9_]`) and a non-word character. It does NOT match between two non-word characters OR at string-start when the next char is non-word. So:
  - `\b-enc\b` doesn't match the literal `-enc` at string-start (no word char preceding `-`)
  - `\b\[char` doesn't match `[char` at string-start (no word char preceding `[`)
  Both regex classifiers silently failed to match their intended targets; tier-1 tests failed at sub-agent time.
- **Evidence:** Two independent sub-agents (η.B + η.C) hit the SAME shape within ~2 hours of each other. Both caught by tier-1 tests BEFORE commit. Both fixed via the same `(?:^|[^A-Za-z0-9])<token>(?:[^A-Za-z0-9]|$)` lookaround replacement.
- **How to avoid:** When matching an adjacency-to-non-word boundary (CLI flag prefixes like `-enc`, character-class brackets like `[char[]]`, sigil-prefixed identifiers like `$var` or `@cmd`), DO NOT use `\b`. Use explicit `(?:^|[^A-Za-z0-9])<token>(?:[^A-Za-z0-9]|$)` lookarounds. Mechanical detection: any classifier regex pattern that includes `\b` followed by a non-word character is suspect.
- **Promotion threshold:** Rule-of-Two — promotion to CLAUDE.md anti-pattern A8 (or next available number) recommended. Quality rule candidate: append to `.claude/harness.json` `qualityRules.custom` with file pattern `backend/app/**/*.py` and regex pattern matching the SOURCE shape `\\b-` followed by a letter (catches the η.B shape; the η.C `\b\[` shape is harder to detect mechanically without false positives).

### 3. JSONB columns rejecting Python `datetime` / `UUID` / `bytes` from third-party parsers — needs `_jsonify` coercer at the boundary

- **What was done:** η.C `_do_lnk_run` walker called `LnkParse3.lnk_file(path).get_json()` which returns a dict with `header.creation_time` / `header.accessed_time` / `header.modified_time` as Python `datetime` objects (tz-aware UTC). Walker passed the dict directly to JSONB normalizer + asyncpg-backed persistence.
- **Failure mode:** asyncpg's JSONB encoder rejects Python `datetime` (and `UUID` + `bytes`) with `TypeError: Object of type datetime is not JSON serializable`. The third-party parser library returns these for legitimate reasons (preserving type information) but JSONB persistence requires JSON-primitive types only.
- **Evidence:** η.C sub-agent's tier-1 walker test against `tiny.lnk` fixture failed AT pytest run, BEFORE commit. Fixed via `_jsonify(value)` helper at module scope that recursively coerces `datetime` → ISO-8601 string, `bytes` → hex, `UUID` → str, unknown types → `repr()`.
- **How to avoid:** When a walker reads from a third-party parser library that returns Python-native types (datetime, UUID, bytes, Decimal, set, frozenset, etc.) into a dict that's then persisted to JSONB, ALWAYS apply a `_jsonify`-shape coercer at the boundary between parse output and JSONB normalizer. Mechanical detection: any walker calling `.get_json()` / `.to_dict()` / `.as_dict()` / `.parse()` on a third-party parser AND passing the result to `_normalize_*` / `_stamp_*` JSONB helpers is suspect — verify the parser's return-type schema before assuming JSON-primitive.
- **Promotion threshold:** Rule-of-One for now (η.C alone). If η.A NTFS walker (next session, `dissect.ntfs` is the parser) hits the same shape, becomes Rule-of-Two and `_jsonify` should be promoted to a shared utility in `app/services/jsonb_normalizers.py` + CLAUDE.md anti-pattern. NOTE: the `_jsonify` helper currently lives ONLY in `lnk_walker.py` as a 1-stream-specific piece of infrastructure.

### 4. Stacked Rule #20 docker cp + alembic upgrade head iterations cause container drift; alembic upgrade fails on missing model imports

- **What was done:** η.C sub-agent ran `docker cp <new η.C migration>.py wairz-backend-1:/app/...` then `alembic upgrade head`. The η.B model files (`windows_scheduled_task.py` + service + schema) were on the host disk + on the running container's host-side mounted path, but the container's `/app/app/models/__init__.py` listing was the pre-η.B version since η.B's docker cp was applied to the OLD container that's been since restarted-via-docker-cp-cycle.
- **Failure mode:** alembic's `env.py` couldn't import `windows_scheduled_task` → `ModuleNotFoundError: app.models.windows_scheduled_task` → `alembic upgrade head` exited non-zero.
- **Evidence:** η.C sub-agent's HANDOFF noted: "the running backend container is from before η.B; my initial alembic upgrade failed because env.py couldn't import `windows_scheduled_task`. Worked around by also `docker cp`-ing the η.B model + service + schema files into the container."
- **How to avoid:** When applying a Rule #20 migration as part of a session that has STACKED prior Rule #20 iterations from OTHER streams, EITHER (a) docker cp the OTHER streams' new model + service + schema files alongside your migration on each iteration (accumulates but works), OR (b) defer rebuild to end-of-session and rely on tier-1 tests against the host-side `.venv` for validation (the validated cadence this session). Option (b) is what η.B + η.C sub-agents both used; works cleanly when end-of-session Rule #8 rebuild closes the loop.
- **Promotion threshold:** Rule-of-Two now (this session's η.C + the prior windows-coverage-godmode lineage's similar shape). Reinforces existing Rule #20 caveat documentation; no new CLAUDE.md rule promotion needed.

### 5. CWD drift after `cd backend && uv run …` invocation — relative paths resolve against `/backend/...`

- **What was done:** η.C sub-agent ran an early `( cd backend && uv run pytest ... )` and a subsequent unscoped `cd backend && uv run ruff check backend/app/services/lnk_walker.py`.
- **Failure mode:** Second invocation resolved `backend/...` against the cwd `/home/dustin/code/wairz/backend/` → `backend/backend/...` → ruff E902 file-not-found.
- **Evidence:** η.C sub-agent's HANDOFF noted: "Net 0 commit-log incidents" — the catch was mid-flow. Caught immediately and switched to subshell-scoped `( cd backend && ... )` form for all subsequent invocations.
- **How to avoid:** Per CLAUDE.md Rule #38 (codified after a Rule-of-Three across γ/δ/this session): use `git -C /home/dustin/code/wairz <cmd>` for git invocations + subshell-scoped `( cd backend && <cmd> )` for tools that need a specific cwd (uv run / npx tsc / docker cp / alembic). Never bare `cd backend && cmd` that drifts CWD for the next call.
- **Promotion threshold:** Rule-of-Many (already codified as Rule #38). This session: zero commit-log incidents (one mid-flow catch in η.C). Discipline is durable; future occurrences should be flagged as a regression rather than a fresh discovery.

### 6. Backend container alembic command exit 137 (OOM-killed) when running during `health: starting`

- **What was done:** Post Rule #8 rebuild, ran `docker compose exec backend alembic heads` for cut-over verification. Backend container was still in `health: starting` state (just up 4 seconds); alembic Python process startup competed with still-booting uvicorn for memory.
- **Failure mode:** Backend received OOM SIGKILL during alembic startup → exit 137.
- **Evidence:** Single occurrence; Rule #35a `; ec=$?; echo "real heads exit=$ec"` captured the exit code authoritatively. Single retry succeeded.
- **How to avoid:** After `docker compose up -d --build`, wait for container `STATUS` to flip from `health: starting` to `(healthy)` BEFORE running heavy verification commands. Single retry on transient SIGKILL is acceptable; if 2+ retries fail, container memory limits or shared-resource pressure deserves investigation.
- **Promotion threshold:** Rule-of-One for now (this session). Single transient occurrence; not a Rule-of-Two. No promotion needed.

## Composite anti-pattern observations

- **Sub-agent regex bugs (anti-pattern #2) clustered in classifier code that pattern-matches against parsed event data.** Both bugs were in regex strings used to detect adversary tradecraft in raw_xml or LNK args. The classifier-pattern-matching code-shape is HIGH-RISK for `\b` failures because the targets (CLI flags, character-class shellcode) are non-word-character-prefixed by nature. This is a CONCENTRATED-risk zone; the proposed quality rule (file pattern `backend/app/services/finding_service.py` + `backend/app/services/*_walker.py`) would catch most of the surface.
- **Sub-agent JSONB datetime bug (anti-pattern #3) clustered in walker code that calls third-party parser libraries.** The third-party parsers all return their own preferred Python types; JSONB persistence requires JSON-primitive coercion. Walker code that calls `.get_json()` / `.to_dict()` is HIGH-RISK for this shape.

## Cross-references

- Companion to anti-pattern #2: `.planning/knowledge/windows-coverage-godmode-eta-2026-05-11-patterns.md` Pattern 5 (tier-1 tests catch sub-agent bugs BEFORE commit) — the safety net that turned both regex bugs from "post-merge revert cycle" into "30-second pre-commit fix."
- Companion to anti-pattern #4: same patterns file Pattern 4 (Rule #20 + end-of-session Rule #8 rebuild + Rule #11 import smoke) — the validated cut-over discipline that closes the loop.
