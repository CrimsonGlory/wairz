# Anti-patterns: P3 session 3d9d854e — 2 carve-outs + firmware_service de-risk

> Extracted: 2026-04-24
> Session: 3d9d854e (autopilot-triggered)
> Commits: 872cc06, 404f66d, d02af17, 781a30e, e8bd8bd, 8e99ec4, 3013124

## Failed Patterns (near-misses + one committed-then-corrected)

### 1. Writing ROUTER.md state claims without Rule #19 verification against code

- **What was done:** Commit `872cc06` updated `.mex/ROUTER.md` "Current Project State" as part of the Rule #21 companion sync. One of the edits moved items out of "Not yet built," but one specific item — B.1.c streaming upload-size check — was KEPT in "Not yet built" based on the outdated state in the previous ROUTER revision. No code verification was performed before that decision.
- **Near-miss failure mode (committed then corrected):** The wrong ROUTER claim stood on the branch for ~15 minutes. Had this session ended immediately after `872cc06`, the claim would have propagated to the next session and induced needless scope ("implement B.1.c") on already-shipped functionality. The false claim's downstream cost is the new session doing a redundant research loop to re-discover what's already in `firmware.py:56-66` `_check_upload_size`.
- **Evidence:** Commit `872cc06` ROUTER.md shows `- B.1.c streaming upload-size check.` in the "Not yet built" block. Commit `d02af17` corrects it: `- B.1.a require-API-key gate (asgi_auth.py) + B.1.b slowapi rate limit (rate_limit.py) + B.1.c streaming upload-size check (firmware.py:56-66 _check_upload_size + firmware_service.py:287-332 mid-transfer MAX_UPLOAD_SIZE_MB enforcement) — full security-auth-hardening intake closed.` The correction was triggered by Rule #19 applied to upstream research while prepping the next carve-out.
- **How to avoid:** Before writing ANY ROUTER.md "Recently shipped" or "Not yet built" state change, run one grep against code that SHOULD prove the claim. Claim: "X is not yet built." Disproof: `grep -rn '<X symbol or feature keyword>' backend/app/` returning actual implementation. Cost of this check: 1 grep, ~5s. Cost of an uncaught false claim: downstream session wastes context re-discovering. This is Rule #19 ("the DB describes truth") applied to doc-write operations, not just refactor-code operations. When the falsification is caught SAME-SESSION, correct it same-session; do not defer.

### 2. Grep-apparent count as refactor scope (docstring false-positive)

- **What was done:** Intake said wairz_runner.py had 3 function-local `app.*` imports. Pre-session grep `^\s+from app\.` confirmed 3 matches. Initial mental model: "promote 3 imports." Reading the file revealed L23 was inside the module docstring (`"""... from app.services.mobsf_runner import compare_findings ...\n"""`) as a caller-side usage example, NOT a runtime import.
- **Near-miss failure mode:** Treating the docstring line as a real import would produce one of three bad outcomes: (a) editing the docstring to remove the example (destroying caller guidance); (b) attempting to "promote" a non-import (confusing edit sequence, may corrupt docstring); (c) counting success as "3 imports → 1 remaining" and leaving a false ledger entry. All three damage the audit trail.
- **Evidence:** Initial grep output `23:    from app.services.mobsf_runner import compare_findings` — indentation is 4-space, matching a function body. Visual read of surrounding lines clarified the docstring context. ast.walk returned `Real function-body app.* imports: 0` post-edit even though grep returned `1` — the docstring line is a string literal, not an ImportFrom node.
- **How to avoid:** When grep-counted imports don't match ast.walk-counted imports, investigate the delta before committing. Docstring lines, commented-out lines, and multi-line continuations all skew grep. `ast.walk` is authoritative for runtime import behaviour. If you're about to write a number in a commit message or intake doc, get the ast count first.

### 3. Bulk-promoting firmware_service because the user said "continue burning down"

- **What was done:** Did NOT do this. After 2 clean carve-outs (hash_lookups, wairz_runner), firmware_service.py was the next-densest target at 14 imports. User had explicitly directed "continue burning down the backlog." Natural momentum → attempt firmware_service as a 3rd carve-out in the same session.
- **Near-miss failure mode:** Seed explicitly flagged firmware_service as non-mechanical with "cross-layer latent-cycle risk — needs individual Rule #30 legitimate-lazy audit." Skipping the audit in favor of momentum would have either (a) found a real latent-cycle mid-edit and required rollback, OR (b) shipped a bulk promotion that passes smoke but introduces a subtle runtime issue (e.g. worker-only module forced into backend startup). The seed's caution was evidence-free at the time of writing, but the RIGHT response is evidence-gathering, not override.
- **Evidence:** User's second prompt explicitly redirected: "stop here; let's unblock firmware_service.py (15) — still out-of-scope per seed (cross-layer latent-cycle risk) by providing details to derisk." This pivoted the session from execution-mode to audit-mode, which turned out to be the higher-leverage call: the committed de-risk (`8e99ec4`) unblocks ALL future firmware_service work, not just this session's.
- **How to avoid:** When momentum suggests tackling a seed-flagged "needs audit" target, STOP. Propose the audit as a separate deliverable. The audit is cheaper than the failed attempt + rollback + re-do, AND it produces a durable artifact. This is Rule #19 operating at the strategy layer — the spec (seed) said "needs audit"; execution without audit betrays the spec's intent. But ALSO: the evidence-first verification may SHOW the seed's caution was over-cautious, which is a valid outcome — just commit the evidence before claiming the override.

### 4. Treating Rule #31 as a complete solution to grep precision

- **What was done:** Did NOT do this. Rule #31's width-canary discipline (narrow vs. broad regex) is designed to catch UNDER-counting. This session discovered OVER-counting (docstring false-positive) AND a separate UNDER-counting mode (multi-line import continuation). Rule #31's canary doesn't address either — both greps (narrow and broad) will equally over-count docstring strings OR under-count multi-line continuations; the canary only catches the narrow-vs-broad regex choice.
- **Near-miss failure mode:** Assuming "Rule #31 canary ran green → counts are correct" would miss both new error modes. A narrow=broad agreement is necessary but NOT sufficient for count accuracy.
- **Evidence:** wairz_runner.py pre-edit: narrow=3, broad=3 (canary green by Rule #31) — yet ast said 2 real imports. firmware_service.py: narrow=? broad=14 (assumed green) — ast said 14 real imports including 5 duplicates in `upload()`. The ast measurement fundamentally differs from grep in that it understands Python syntax structure.
- **How to avoid:** Treat Rule #31's width-canary as a NECESSARY-BUT-NOT-SUFFICIENT step. For count claims that feed into scope decisions, cross-check against `ast.walk`. The ast check is the same 1-second cost as the extra grep; there's no reason to skip it on size-sensitive audits.

### 5. Chaining carve-outs without fresh per-target Rule #30 audit (predecessor antipattern #4 — reinforced)

- **What was done:** Did NOT do this. 5th P3 carve-out (wairz_runner) ran a fresh Rule #30 audit even though 4 prior carve-outs in the same theme had cleared with mechanical-safe profiles. Audit found that `wairz_runner.py`'s function-local `from app.services.androguard_service import AndroguardService` was a "layered lazy-import relic" (predecessor's pattern but encountered fresh in this file): `androguard_service.py` ITSELF lazy-imports the androguard library at function-body level (L508/523/640/861/891), so wairz_runner's outer lazy was defensive-of-defensive.
- **Near-miss failure mode:** Skipping the audit under the assumption "mechanical-safe profile holds for session 5" would have either (a) promoted an import that triggers a 500ms androguard cold-import at every backend startup, or (b) missed a legitimate-lazy reason and preserved an unnecessary lazy. The layered pattern is subtle and cannot be inferred from the outer file alone.
- **Evidence:** Audit grep `grep -n 'from androguard\|import androguard' backend/app/services/androguard_service.py` returned 5 function-body hits (L508/523/640/861/891) and zero top-level. This confirmed the layered pattern and made the promotion safe.
- **How to avoid:** Fresh per-target audit every session. Audit grep cost: ~5 seconds. The "mechanical-safe profile" is not a free pass — it's a statistical prior that each session must re-verify. The layered-lazy pattern specifically requires looking 2 modules deep, not just 1.

### 6. Treating de-risk audits as a defer-action rather than a deliverable

- **What was done:** Did NOT do this. The seed said firmware_service was "out-of-scope" with "needs individual audit." An alternate reading: "defer firmware_service to a future session that has the audit." This session instead RAN the audit, wrote it into the intake as committed evidence, and built a next-session seed that executes mechanically from the audit.
- **Near-miss failure mode:** If the audit were framed as "next session should do it first," responsibility for producing the audit would bounce between sessions — each one saying "the other session will audit." The seed chain would loop indefinitely without either execution or audit happening. This is a meta-anti-pattern at the multi-session coordination layer.
- **Evidence:** User's explicit direction: "stop here; let's unblock firmware_service.py (15) — still out-of-scope per seed (cross-layer latent-cycle risk) by providing details to derisk." "Provide details to derisk" is an AUDIT-AS-DELIVERABLE framing. The session produced a 28-line audit committed to the intake (`8e99ec4`) + a 189-line execution plan in the next-session seed (`3013124`). Next session reads both, executes, and is done.
- **How to avoid:** When a target is flagged "needs audit before execution," the audit IS a valid session outcome. Produce it, commit it, let the next session execute. Do NOT pass the audit responsibility forward unless you are willing to do the audit yourself — otherwise the seed chain stalls.

## Quality Rule Candidates

No high- or medium-confidence candidates emerge this session.

- **Rule #31 bidirectional grep errors:** The pattern is "grep-count diverges from ast-count." No single regex can catch this in source code — it's a workflow discipline (use ast when precision matters). Captured as a companion note in the intake log; promote to a standalone Rule #32 only after a 3rd incident (per Rule #31's own discipline).
- **De-risk-audit-as-deliverable:** A session-shape pattern, not a source-code pattern. No harness rule fits.
- **ROUTER.md state claim verification:** A doc-write discipline. A harness rule pattern that could match is `ROUTER.md(?:.*)(?:Not yet built|Known issues)` — but this fires on any legitimate state update, producing 100% false positives. Skip.
- **Rule #30 layered lazy-import audit:** The pattern is "when promoting import of module A, check if A uses its own internal lazy-imports." This is a 2-grep audit, not a regex; it doesn't fit the harness rule shape. Document in Rule #30's companion guidance if a 3rd incident surfaces.

No entries added to `.claude/harness.json` qualityRules.custom this session. Predecessors (mobsfscan session, fuzzing-emulation session) reached the same conclusion; the pattern is stable — P3 carve-out sessions produce durable workflow knowledge, not new harness rules.

## Quality Rule Review (existing rules touched this session)

- `auto-fleet-worktree-requires-worktree-add` — not relevant (solo autopilot session, no fleet).
- `auto-frontend-long-op-no-explicit-timeout` / `auto-frontend-multipart-no-explicit-timeout` — not relevant (no frontend edits).
- `auto-frontend-rebuild-not-restart` — not relevant (no frontend edits).
- `auto-pytest-mock-patch-androguard-at-service` — not relevant (no test patches edited).

No existing rule caught a false positive; no existing rule missed a true positive. Rule set is clean for this session's shape.
