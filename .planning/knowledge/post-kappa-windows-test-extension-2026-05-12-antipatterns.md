# Anti-patterns: Post-κ Windows-test extension

> Extracted: 2026-05-12
> Source postmortem: `.planning/postmortems/postmortem-post-kappa-windows-test-extension-2026-05-12.md`

## Failed patterns

### A12 (Rule-of-One) — Sub-agent smoke gap on service-module imports
- **What was done:** κ.B.D sub-agent added `_appcompat_evidence_lines(... last_modified_ts: datetime | None ...)` to `finding_service.py` without `from datetime import datetime` at module top. Sub-agent smoke test imported the WALKER + MCP tools cleanly but NOT `finding_service` itself.
- **Failure mode:** Backend uvicorn startup raised `NameError: name 'datetime' is not defined` on module-load. Container entered 53-restart loop. Bug masked for ~3 hours before operator observed HTTP 502.
- **Evidence:** `finding_service.py:3970` `last_modified_ts: datetime | None` parameter typing. 7 such references at lines 3970, 3995, 4118, 4188, 4225, 4421, 4457. Alignment test imports `app.schemas.finding` only (schemas, not service). Orchestrator Pattern P7 didn't probe `RestartCount`.
- **How to avoid:** when a stream's .D commit modifies `finding_service.py` (or any eagerly-imported service module), sub-agent smoke MUST `from app.services.finding_service import FindingService` AND assert the new method is present. Orchestrator Pattern P7 MUST add a backend container `RestartCount` probe post-rebuild.

### A13 (Rule-of-One — extends Rule #46 to ORCHESTRATOR-LAYER shell-script gates) — `grep -q -` silently broken on ugrep-aliased systems
- **What was done:** Orchestrator-side until-loop watcher used `grep -q -` to check "is there any output". On this system `grep` is aliased to `ugrep`.
- **Failure mode:** ugrep emits `ugrep: no PATTERN specified` and exits non-zero. The until-loop ran forever (until timeout). Operator waited 10+ minutes before flagging it.
- **Evidence:** Watcher output file `b2p7gzgf0.output` contained 11+ lines of `ugrep: no PATTERN specified`. First 2 watchers I dispatched both had the bug; both silently never fired.
- **How to avoid:** NEVER use `grep -q -` for "any output" check. Use `grep -q .` OR `[ -n "$(cmd)" ]` (POSIX-portable, no grep dependency). **Rule #46 partner — canary the watcher pre-trust** by forcing a synthetic positive: inject a fake row, verify the loop exits, remove the fake row. Rule #46 applies to ORCHESTRATOR-LAYER bash gates, not just sub-agent Python test gates.

### Intake under-count (NEW Rule-of-One within this extension) — width-canary should be applied to consumer-hook enumeration at intake-authoring time
- **What was done:** Walker-bridge intake said "21 walkers" based on a narrow grep audit. Actual count was 22.
- **Failure mode:** sub-agent re-counted during the fix and caught the discrepancy. Not blocking but a Rule #31 width-canary failure — broader grep would have caught it pre-intake.
- **Evidence:** intake `walker-auto-trigger-gap-after-upload-pipeline-refactor-2026-05-13.md` says "21 walkers"; `backend/app/workers/walker_registry.py` exports 22 auto-triggers.
- **How to avoid:** Rule #31 width-canary at intake-authoring time. For ANY count-claim in an intake ("N walkers", "M routes", "K migrations"), run the grep TWICE with progressively broader patterns and verify count is stable. Codified as a companion gotcha in Rule #47.

## How these extend prior rules

- **A12 + A13 both reinforce Rule #46 (canary discipline for "asserts absence" mechanisms):**
  - Rule #17 (original): silent-CLI-exit canary
  - Rule #24: mandatory tsc canary per-session
  - κ.D test-gate canary (Rule #46 codification): tokenize-whitespace gap
  - κ.E meta-canary: Rule #24 caught Rule #35a pipe issue WITHIN itself
  - **A13 (this extension):** orchestrator shell-script gates extension
- **Rule #46 evidence chain now Rule-of-Five.** Promotable to Rule-of-Six if a future verification gate fails its canary check.

## Forward — antipatterns to watch in λ + future sessions

- Service-module import smoke: λ.α sub-agent prompts MUST include a `from app.services.<service> import <symbol>` smoke step when the stream's .D commit modifies an eagerly-imported service module.
- Orchestrator shell-script discipline: ALL bash until-loops + watchers MUST use `[ -n "$()" ]` form or `grep -q .` — never `grep -q -`.
- Width-canary at intake-authoring time: ALL count-claims must survive a 2-grep width check.
