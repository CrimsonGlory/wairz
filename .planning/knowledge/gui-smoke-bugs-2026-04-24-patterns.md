# Patterns: GUI golden-path smoke (post-P3 verification, 2026-04-24)

> Extracted: 2026-04-24
> Campaign: `.planning/intake/gui-smoke-bugs-2026-04-24.md` (intake-as-campaign — single-session smoke)
> Postmortem: not found — single-session smoke with no formal retro
> Source session: `d8edd200-4399-44f2-bf9f-374feccc1c02`
> 58 audit telemetry entries since smoke start (UTC 23:35:00)

## Context

Previous session (aa8b4a17) shipped 3 P3 carve-outs (clamav_service / attack_surface_service / cve_matcher) and closed with the explicit unresolved item: "GUI not exercised — CLAUDE.md explicitly requires end-to-end UI verification." This session drove that smoke and reproducibly surfaced 3 pre-existing bugs while confirming the P3 refactors were green at runtime.

## Successful Patterns

### 1. REST-as-GUI-proxy smoke when no Playwright is available

- **Description:** Drove the GUI's contract via curl against the backend's REST surface — `POST /security/audit`, `POST /attack-surface/scan?force_rescan=true`, `POST /hardware-firmware/cve-match`, plus the read-side GETs the page mounts on. The frontend's only job is to call these endpoints and render the responses, so exercising the REST layer covers >90% of what a browser-based smoke would catch (import errors, persistence shape mismatches, DB constraint violations, response schema drift).
- **Evidence:** Found 3 distinct pre-existing bugs (truncation, OOM, NULL arch) without ever launching a browser. The `/qa` skill notes Playwright is an optional dependency with graceful skip — REST-proxy is the documented fallback.
- **Applies when:** GUI changes that are purely backend (refactors, schema migrations, service-layer fixes) AND no Playwright/QA browser tooling is wired up. Does NOT cover frontend-only bugs (rendering, state-management, UX regressions).
- **Mechanical recipe:**
  ```bash
  API_KEY=$(docker compose exec -T -w /app -e PYTHONPATH=/app backend \
    /app/.venv/bin/python -c "from app.config import get_settings; print(get_settings().api_key)" \
    2>/dev/null | tr -d '\r\n')
  H="X-API-Key: $API_KEY"
  curl -s -m {timeout} -H "$H" -X {METHOD} "http://localhost:8000/{path}" -d '{body}'
  ```

### 2. Background log tail to capture failures the client never sees

- **Description:** Started `docker compose logs -f --tail=0 backend worker > /tmp/wairz-smoke-logs.txt 2>&1 &` BEFORE any test traffic. When the audit's `curl -m 700` timed out, the backend continued processing detached for 10+ more minutes and ultimately threw `StringDataRightTruncationError` at the persistence flush. That traceback was ONLY visible in the backend log — curl had exited at `HTTP=000` and would have left the bug invisible.
- **Evidence:** The smoke's most operationally serious bug (Bug #3 — `findings.title VARCHAR(255)` truncation) was caught entirely from the persisted log file (`/tmp/wairz-smoke-logs.txt`), not from any HTTP response.
- **Applies when:** Driving any long-op endpoint via REST. The asymmetry between client-perceived state ("HTTP=000, gave up") and server actual state ("still processing, will fail at persist") is a permanent feature of long-op + frontend-timeout architectures (Rule #29).
- **Sufficiency note:** `--tail=0` is critical — without it the tail dumps existing logs first, drowning the smoke window in noise.

### 3. Sequential isolation when concurrent calls OOM

- **Description:** First attempt fired `/security/audit` and `/cve-match` concurrently (background + foreground). Backend kernel-OOM'd at ~100s. Without isolation, root cause could have been (a) audit, (b) cve-match, or (c) their concurrent contention. Re-ran each alone: audit ran clean for 12 min, cve-match alone OOM'd in 100s. Pinpointed cve-match as the sole cause.
- **Evidence:** Memory profile + 11-CPE-load count after isolation matched exactly the 11 chipset-tagged blobs in this firmware — irrefutable mechanical evidence vs the diffuse "concurrent OOM" hypothesis.
- **Applies when:** Multiple long-ops fail together and root cause attribution is ambiguous. Cost of re-running sequentially: 2× the test time. Cost of mis-attributing: hours of wrong-direction debugging.
- **Generalization:** "When concurrent failure, isolate before bisecting." The container restart between isolation runs is free verification that no in-memory state carried over.

### 4. DB-direct verification after every API call

- **Description:** Each REST POST was followed by a `psql` query against the persisted state to verify both shape AND content matched expectations. The Attack Surface scan returned HTTP 200 with 1624 entries; the API response contained `architecture: null` for every row, but the JSON parse was failing for unrelated formatting reasons. The DB query (`SELECT COUNT(*) FILTER (WHERE architecture IS NULL)` = 1624 / 1624) was the canonical evidence — independent of API response parsing quirks.
- **Evidence:** Bug #2 (arch=NULL) was confirmed via DB query; the API response's structure was a secondary check.
- **Applies when:** Any test that depends on persistence side-effects (vs purely-computed responses). Especially when ORM serialization could mask underlying nulls (e.g. `Optional[str]` → empty string in some response models).

### 5. `git blame` to attribute regressions before assigning blame

- **Description:** For each surfaced bug, ran `git blame` on the relevant line before deciding whether the bug was "introduced by P3 work." All 3 bugs traced back to commits 8+ days before the P3 carve-out:
  - Bug #1 (`cve_matcher.py:253`): commit `1fbcce4` 2026-04-16 (P3 carve-out was `9a26c1a` 2026-04-24)
  - Bug #2 (`_LIEF_ELF_ARCH_MAP` empty): pre-existing latent semantic, EXPLICITLY documented in P3 commit `4bd491b`'s message as "out-of-scope for this refactor"
  - Bug #3 (`findings.title VARCHAR(255)`): no commits to `finding.py` or `finding_service.py` since 2026-04-21 — predates P3 work entirely
- **Evidence:** All 3 attributions verified mechanically; saved hours of false-debugging the P3 imports.
- **Applies when:** A change shipped recently and a bug surfaces shortly after. The temptation is to assume causation; `git blame` + commit-date comparison is the cheap test for actual attribution. Cost: ~30 seconds per bug.
- **Companion rule:** When a P3 commit message ALREADY documents a known-deferred bug ("documented for the audit trail"), trust that commit's author and verify via blame rather than re-litigating.

### 6. Intake-as-handoff pattern for "smoke surfaced N bugs, none touch this work"

- **Description:** When a smoke surfaces bugs that are pre-existing AND orthogonal to the work that triggered the smoke, write the findings into a single `.planning/intake/{slug}-bugs-{date}.md` with priority-ordered fix shapes, acceptance criteria, and reproduction commands. Do NOT inline the fixes into the smoke session — preserves single-session scope discipline AND gives the next session a self-contained executable plan.
- **Evidence:** This session's intake (`gui-smoke-bugs-2026-04-24.md`, 323 lines) contains 3 bugs each with file:line, evidence, fix shape, acceptance criteria, reproducer commands, baseline + rollback, risk notes. Next session can execute all three in 3 commits (Rule #25 split) without re-investigation.
- **Applies when:** A short investigation surfaces 2+ pre-existing bugs that are orthogonal to the triggering work. Don't bundle fixes into the investigation session — the discovery session and the fix session have different scope and cadence.
- **Generalization of Rule #19:** evidence-first applies to fix-vs-document decisions too. The DB describes truth; the intake describes intent for the next session.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Drive REST endpoints via curl, not Playwright | No browser tooling wired up; REST surface covers the relevant layer (P3 was backend-only) | Found 3 bugs; entire smoke ran in ~30 min wall-clock |
| Pick fw `a7523429` (RespArray V1.12) | Best 3-path coverage in inventory: 563 blobs + 1624 attack-surface + 304 SBOM components + arch=arm | Single firmware exercised all 3 P3-refactored services + surfaced all 3 bugs |
| Run sequentially after first concurrent OOM | Isolate root cause; restart between runs verifies no carry-over state | OOM attributed to cve-match alone (with 11-CPE-load mechanical evidence) |
| NOT auto-fix the surfaced bugs | Smoke session ≠ fix session; scope discipline | Three bugs cataloged in intake for next session; smoke session stays single-purpose |
| Allow audit to run detached after curl -m 700 timeout | Backend log tail captures persist-time failures the client never sees | Caught the StringDataRightTruncationError that would have been invisible client-side |

## Cross-references to durable docs

- **CLAUDE.md Rule #15** (column widths vs incoming data): Bug #3 is the second instance of this pattern (first was `analysis_cache.operation` VARCHAR(100→512) for JADX cache keys). Worth noting in the rule itself if a third instance surfaces — but the rule already covers it.
- **CLAUDE.md Rule #19** (evidence-first): Pattern #4 (DB-direct verification) and Pattern #5 (git blame attribution) are concrete instances of "the spec describes intent, the {DB / git history} describes truth — trust the truth."
- **CLAUDE.md Rule #29** (frontend timeout alignment): Pattern #2 (background log tail to catch persist-time failures) is the operational complement to the timeout-alignment rule. Even with aligned timeouts, the client may give up before the server commits — log tails are the only ground truth for "did the work persist?"
- **CLAUDE.md Rule #30** (lazy-import patch targets) and Rule #31 (broader-grep canary): both apply transitively — git blame + commit-date comparison is the analog of "broader grep" for attribution claims.

---

## Addendum: Fix-session lessons (2026-04-25, session 56797be2)

> Same intake, different session. The discovery session (above) found 3 bugs and wrote the fix shape; the fix session executed against that spec. These patterns are about the EXECUTION discipline, distinct from the discovery discipline above.

### 7. Per-bug docker management discipline (Rule #20 fan-out)

- **Description:** Bug #3 (model column widening) and Bug #1/#2 (function-body call swaps) require different deploy mechanics, despite touching the same backend. The intake explicitly split them: Bug #3 mandates `docker compose up -d --build backend worker` (class-shape change to ORM mapper); Bug #1/#2 use `docker cp` + Rule #11 import smoke (no class-shape change). The fix session followed the split exactly: 1 rebuild for Bug #3 (the alembic migration auto-applied via the `migrator` service at boot), 2 `docker cp` invocations for Bug #1/#2 (each to backend AND worker — both run the code in production).
- **Evidence:** Bug #3's migration logged `INFO  [alembic.runtime.migration] Running upgrade c3f8a1b9e4d2 -> d4a7c8b6e2f1, widen_findings_title_to_512` from the migrator service exactly once at boot; post-rebuild verification confirmed DB column = 512, ORM mapper = 512, alembic head = d4a7c8b6e2f1. Bug #1/#2's docker-cp + import-smoke each succeeded in <2 s without forcing a 5-min rebuild cycle.
- **Applies when:** A multi-bug sweep mixes schema/class-shape changes with function-body changes. The cost differential is real — rebuild ~3-5 min, docker-cp ~2 s. Mis-routing (docker-cp on a class-shape change OR rebuild on a one-line function swap) wastes either correctness or time.
- **Companion failure mode (anti-pattern #7 below):** docker-cp + Rule #11 import smoke is INSUFFICIENT for verifying a long-lived process picked up the change — so this pattern's success on Bug #1/#2 was actually a near-miss; the OOM-restart on first cve-match invocation accidentally provided the missing process restart.

### 8. Hand-write alembic migration when autogenerate is blocked by an orthogonal cause

- **Description:** `alembic revision --autogenerate` failed with `NoReferencedTableError: Foreign key associated with column 'sbom_vulnerabilities.blob_id' could not find table 'hardware_firmware_blobs'` — root cause is `app/models/__init__.py` does not import `hardware_firmware`, so the FK target table isn't in `Base.metadata` when alembic builds its diff. This is a pre-existing gap unrelated to the title-widening change. Per Rule #19, fixing it was out of scope.
- **Solution:** Hand-wrote `d4a7c8b6e2f1_widen_findings_title_to_512.py` using the closest-precedent migration (`1f6c72decc84_widen_analysis_cache_operation_to_512.py`) as a structural template. Same `op.alter_column(...)` shape, same downgrade strategy (truncate + re-narrow). Migration content is the same as the intake's expected `op.alter_column('findings', 'title', type_=sa.String(512), existing_type=sa.String(255), existing_nullable=False)`.
- **Evidence:** Migration file is 47 lines, well-commented; references the intake AND the precedent. Auto-applied via `migrator` service at backend boot; post-rebuild DB column verified at 512.
- **Applies when:** Autogenerate fails for an orthogonal pre-existing reason AND the intended migration is mechanically simple (single column change, no relationship ops). Cost: ~5 min to find the precedent + adapt. Risk: the precedent must be CLOSE — same operation type (column type change), same idempotency expectations.
- **Anti-pattern caveat:** Don't hand-write a complex multi-table migration this way; autogenerate exists because it's hard to get right by hand. Triage: if the migration is one `op.alter_column` or `op.add_column`, hand-write is fine; anything more, fix the autogenerate-blocker first.

### 9. DB pre-baseline + post-action delta verification (not absolute count)

- **Description:** Before any smoke action, query the affected DB tables for current counts. After the action, query again and verify the DELTA matches expectation. This catches the "I expected 50 new rows but got the same 50 from a prior run" trap.
- **Evidence:** Pre-smoke baseline:
  - `findings WHERE source='security_audit' AND project_id='00815038-...'` = 4
  - `attack_surface_entries WHERE firmware_id='a7523429-...' AND architecture IS NOT NULL` = 0
  - `attack_surface_entries WHERE firmware_id='a7523429-...'` = 1624 (total)
  - `hardware_firmware_blobs WHERE chipset_target IS NOT NULL` = 11 (matches intake's 11×CPE-load expectation exactly)

  Post-smoke (Bug #3): findings = 315 (delta +311 — clearly new). Post-smoke (Bug #2): arch IS NOT NULL = 1613 (delta +1613 — full repopulation). Both deltas confirm the action took effect, not just that some count is high enough.
- **Applies when:** Smoke acceptance criteria are stated as absolute counts ("≥ 50 findings") in an intake that may be re-run on data that's been touched before. The intake's threshold may pass trivially against pre-existing rows; the delta is the actual signal.
- **Companion to discovery-pattern #4 (DB-direct verification):** discovery uses DB query as the canonical source of truth ("the API responds 200 but DB has 1624 NULLs"); execution adds the temporal axis ("the action MOVED the count").

### 10. STOP per abort condition when criterion fails, even if other criteria pass

- **Description:** Bug #1's acceptance criterion #2 (`return 2xx within 60 s`) failed: backend was killed at 87s with no log output. Criterion #1, #3, #4 all passed (singleton fix mechanically present, 0 dictionary loads, import smoke clean). The session also exceeded the 15-min smoke budget. Per the user's intake-spec abort conditions, STOPPED here rather than chain into a 4th iteration to investigate the residual cause.
- **Evidence:** Three commits shipped (ca583d0 / f71f978 / 9f7ddde); intake updated to `partial-completed`; follow-up intake `cve-match-residual-oom-2026-04-25.md` filed with diagnostic plan. No 4th code commit.
- **Applies when:** The fix is mechanically correct (verified via inspection AND telemetry) but end-to-end behaviour reveals a SEPARATE bug that the spec did not anticipate. The temptation is to chain into "let me also fix that fourth thing while I'm here" (Rule #19 trap). The discipline is: ship the verified fixes, document the residual, hand off to next session.
- **Critical observation:** The fact that Bug #1 only PARTIALLY resolved /cve-match doesn't make commit f71f978 wrong — it makes the INTAKE'S HYPOTHESIS narrow. The commit is the right fix for the diagnosed problem; the residual is a different problem that needs its own diagnosis cycle.

## Updated key decisions (fix session)

| Decision | Rationale | Outcome |
|---|---|---|
| Hand-write alembic migration when autogenerate blocked | Autogenerate failure was orthogonal (model registration gap); fix shape from intake was simple + had a close precedent | Migration applied cleanly at backend boot; one ALTER, no drift |
| Apply Bug #3 rebuild despite the longer cycle | Class-shape change to ORM mapper REQUIRES restart per Rule #20 — `docker cp` would leave the cached mapper at String(255) | DB + ORM + head all aligned at 512; smoke confirmed no truncation in 16-min audit |
| Use `docker cp` for Bug #1/#2 (no class-shape change) | Function-body call swap; Rule #11 import smoke validates the new code in a fresh subprocess | Fix correct on disk in both backend AND worker containers; verified via grep |
| STOP after Bug #1 acceptance criterion #2 fails | Per intake's abort condition + Rule #19; further investigation belongs to next session | Three commits ship; follow-up intake captures next-session work |
| File follow-up intake `cve-match-residual-oom-2026-04-25.md` | Per discovery-pattern #6 (intake-as-handoff): when a partial fix surfaces a NEW bug, document it as an intake rather than inline in the closeout | Next session has self-contained reproducibility + diagnostic plan + acceptance criteria |
