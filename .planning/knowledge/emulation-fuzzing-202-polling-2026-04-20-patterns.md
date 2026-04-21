# Patterns: Emulation + Fuzzing 202+Polling Refactor

> Extracted: 2026-04-21
> Campaign: `.planning/campaigns/completed/emulation-fuzzing-202-polling-2026-04-20.md`
> Postmortem: not found
> Sources: campaign file, fleet session file, wave-1 discovery brief, 26 audit telemetry entries

## Successful Patterns

### 1. Parallel Fleet wave on genuinely top-level-disjoint file surfaces
- **Description:** Two streams α (emulation) and β (fuzzing) edited entirely different router/service/page file trees. The only shared files were `CLAUDE.md` (Rule #29 table) and `frontend/src/types/index.ts` (disjoint enum additions). Zero cross-stream commit sweeps under Rule #23 worktree discipline.
- **Evidence:** Wave-1 discovery brief "Cross-stream overlap matrix" — α-only / β-only classification for every file except the two metadata files.
- **Applies when:** Campaign decomposes into 2+ streams where each stream's file list shares no parent directory with another stream. Validate BEFORE dispatch with `git diff --name-only` on proposed scopes; if any stream's scope list intersects another's, defer one stream or merge scopes.

### 2. Template-driven pattern reuse from existing in-tree precedent
- **Description:** Both streams followed `backend/app/routers/firmware.py:139` verbatim as the 202+polling template. Shape: `status_code=202` + arq `pool.enqueue_job` with `asyncio.create_task` fallback + row-status polling every 2s. No fresh design decisions; implementation was mechanical translation.
- **Evidence:** Both α's `routers/emulation.py` and β's `routers/fuzzing.py` show the arq-first / create_task-fallback pattern. α commits 2439365 and c5d2f74 mirror the firmware.py structure; β commits caf2370 and df30015 do the same.
- **Applies when:** A new feature/refactor mirrors an existing well-tested flow in the codebase. Identify the template by name in the campaign brief and instruct the implementer to "match this pattern verbatim" rather than redesigning from first principles.

### 3. Two-layer health gate for async state transitions (α emulation)
- **Description:** The `pending → booting → ready` transition is gated by BOTH a service-layer health probe (`_await_ready` checks for `/tmp/.standalone_mode` user-mode marker or `/tmp/qemu-serial.sock` system-mode marker) AND a router-layer WS status check (rejects with WS code 4004 if status is not in `{running, ready}`). Frontend terminal cannot race a still-booting container.
- **Evidence:** α commit 2439365 (service split) + c5d2f74 (router gate) + real-firmware end-to-end probe in the session.
- **Applies when:** An async state transition has a downstream consumer that must not fire until the transition is complete. Gate the transition itself on a real health signal (not on task-completion) AND gate the consumer on the state. Both gates must be in place; either alone has a race window.

### 4. Docker cp + restart iteration for rapid single-file development (Rule #20 applied)
- **Description:** α used `docker cp backend/app/... wairz-backend-1:/app/...` + `docker compose restart backend` for iteration. Per-change cycle was ~30s. The full Rule #8 rebuild ran ONCE at merge time. Dramatically faster than rebuild-per-change.
- **Evidence:** α session notes reference `docker cp` iteration; the Rule #8 rebuild ran ONCE at merge (commit sequence: 5 feature commits, then the rebuild).
- **Applies when:** (a) A change modifies an existing file under an existing bind mount OR (b) the change is a pure function/method tweak with no class-shape change (per Rule #20's caveats). If the diff adds/removes/renames a field on a cached class (Settings, @dataclass singleton, SQLAlchemy model registry), Rule #20 says restart-after-cp, or full rebuild if the container is slow to boot.

### 5. Real integration probe as the merge gate, not just typecheck + tests (Rule #11 applied)
- **Description:** α ran an actual `POST /emulation/start` on real firmware followed by status polling before declaring merge-ready. The probe surfaced an alembic CHECK constraint violation that typecheck + unit tests + pydantic all passed — caught only by a real INSERT attempt. Commit 5 (the alembic migration widening the CHECK) was written AFTER the service/router/frontend were in place.
- **Evidence:** α discovery #1: "DB CHECK constraint surfaced at runtime, not typecheck. Adding a new status enum value required an alembic migration; pydantic+SQLAlchemy types allowed the literal but the CHECK on `emulation_sessions.status` rejected the insert."
- **Applies when:** Any change that adds a new enum literal, status value, or database-constrained string. The typecheck/tests are NECESSARY but not SUFFICIENT. A single `curl -X POST` or equivalent real-write integration probe must run before merge. Discovery cost of doing this is ~2 minutes; cost of NOT doing it is a post-deploy 500 error.

### 6. Per-sub-task commit discipline preserved bisect-cleanliness
- **Description:** α shipped 5 commits (status migration / service split / router 202 / frontend terminal poll / docs flip), β shipped 4 commits (service split / router 202 / frontend poll / docs flip). Each commit is self-contained with its own test + typecheck. Revert per-commit in reverse order is clean; bisect isolates failures to a 1-commit window.
- **Evidence:** Rule #25 precedent plus this session's concrete outcome — no mixed-intent commits, no omnibus "feat: everything" squashes.
- **Applies when:** Any refactor with 3+ independently-verifiable sub-tasks. Commit per-layer (schema / service / router / frontend) rather than bundling. Rule #8 rebuild runs ONCE at the end of the stream, not per commit.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Queue as Fleet (2 streams), NOT /archon | Two truly-disjoint subsystems (emulation, fuzzing). No cross-stream dependencies. Fleet's wave mechanics overkill — single wave of 2 parallel streams suffices. | Both streams completed in one wave, one session, 9 commits + 2 merge commits + 1 mex mirror commit |
| Do NOT combine with `fuzzing_service.py` split | Scope creep. Rule #27 discipline: structural splits ship independently of behaviour changes. | β kept fuzzing_service.py at 1107 LOC; the 202 refactor added ~72 LOC inside existing methods. No half-split state. |
| Reuse existing status-enum on both sides | emulation_session.status and fuzzing_campaign.status already exist with ~4 values each. Adding a new `pending` or `booting` value is a trivial alembic migration; creating a separate jobs table is over-engineering. | α needed alembic migration (CHECK widening); β did NOT (no SQL-level CHECK). Both enum additions successful. |
| Do NOT ship until after a real system-mode boot is observed | Rule #11 runtime smoke: import checks pass when a method references a missing constant. Full boot on a real image is the only trustworthy verification. | α's real-firmware probe caught the alembic CHECK constraint that typecheck missed. Decision prevented a merge-then-revert cycle. |

## Scope-management decisions surfaced during execution

- **α accepted a minor scope expansion** into `backend/app/workers/arq_worker.py` (arq job registration for `spawn_emulation_session_job`) outside the declared file list. Registration is a pure-additive change and is structurally REQUIRED for the arq-first path to work. Accepted by the merge session without pushback.
- **β ADDED a `queued` status** despite the campaign brief saying no enum change should be needed. Campaign pre-flight listed enum values incorrectly; β did the re-grep (`grep -rn 'FuzzingStatus' frontend/src/`) and found the actual values, then added `queued` as the natural marker for "row exists, container spawn scheduled but not started." Backend column was VARCHAR(20) no-CHECK so no migration needed — contrast with α's CHECK-widening need.

## Workflow-level observations

- **Single-wave fleets are cheaper than multi-wave fleets** when streams are genuinely disjoint. No discovery-relay between waves means no compression step, no inter-wave context window consumption. The session dispatched two agents in parallel and collected both results in under 20 minutes each. Reserve multi-wave fleets for cases where wave N's output legitimately feeds wave N+1.
- **Merge order matters when conflicts are expected.** α merged first (more complex, terminal-WS race risk) before β. When β's merge conflicted on CLAUDE.md, the resolution was a pure combine (both rows flipped to FIXED) rather than a directional rebase. Picking the "more complex" stream to merge first reduces the resolution complexity on the second merge.
- **mex mirror update is a separate commit, not part of either stream.** Rule #21 says the mex checklist mirror must be updated in the same commit as the rule change — but in a Fleet setting, the rule lives in CLAUDE.md (which both streams edit) and the mirror in `.mex/context/conventions.md` (which neither stream touches). The merge session OWNS the mirror update as a post-merge commit. Session shipped commit d83095f for exactly this.
