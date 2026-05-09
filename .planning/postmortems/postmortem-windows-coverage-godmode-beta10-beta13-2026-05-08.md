# Postmortem: windows-coverage-godmode β.10 + β.13

> Date: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Duration: ~1h22m wall-clock (10:45 UTC bundle download → 12:07 UTC β.13 commit)
> Outcome: completed (2 sub-tasks shipped; campaign as a whole still IN PROGRESS — β.11/β.12/β.14 remain)

## Summary

Shipped Phase β.10 (bundle MS DBX + EFI auth-var wrapper strip) and
Phase β.13 (promote Rule #36 + Rule #37 to canonical CLAUDE.md +
.mex/context/conventions.md mirror) in a single session. β.10 baked
Microsoft's UEFI Secure Boot DBX revocation list into the worker+backend
image at build time via `backend/ms-anchors/dbxupdate.bin` (24,053 B,
SHA256-pinned), added `_strip_authenticated_variable_wrapper` to
dbx_service to handle Microsoft's 3337-byte EFI_VARIABLE_AUTHENTICATION_2
outer wrapper, wired `DBX_BUNDLE_PATH` env var through compose, added a
backend startup probe logging bundle presence + size + mtime, authored
`scripts/refresh-ms-roots.sh` quarterly cron, and committed synthetic
test fixtures (bare + wrapped formats). β.13 codified the offline-trust-
anchor discipline (Rule #37) + no-execute-installer-actions discipline
(Rule #36) that β.4 + β.10 + Phase α already practiced. Two clean Rule
#25 commits (`856b640`, `f80d606`); zero reverts; 11 new tests; total
+801 LOC across 16 files.

## What Broke

### 1. β.7 dbx parser was format-blind for the real Microsoft bundle

- **What happened:** β.7 shipped `dbx_service._parse_bundle_bytes`
  walking EFI_SIGNATURE_LIST from offset 0. The real Microsoft
  `DBXUpdate.bin` (downloaded fresh from
  github.com/microsoft/secureboot_objects in this session) carries an
  outer 3337-byte EFI_VARIABLE_AUTHENTICATION_2 wrapper (EFI_TIME +
  WIN_CERTIFICATE_UEFI_GUID PKCS#7 signed payload) before the
  EFI_SIGNATURE_LIST array. β.7's parser would have read those 3337
  bytes as a malformed signature list, hit the "stop on malformed"
  guard immediately, and returned `entries_scanned=0` for every PE.
  Silent degradation: every PE would ship `dbx_revoked=False`
  regardless of actual revocation status.
- **Caught by:** **Rule #19 evidence-first** — `xxd dbxupdate.bin |
  head` BEFORE writing parser-extension code surfaced the wrapper.
  Decoding the first 16 bytes as EFI_TIME (year=2010 — Microsoft's
  signing-cert validity-start, not a publication date) + bytes 16-23
  as WIN_CERTIFICATE (dwLength=3321, wType=0xEF1) confirmed the
  wrapper. Without the evidence-first probe, the rebuild would have
  shipped a non-functional bundle and the bug would have surfaced
  hours/days later when an operator scanned a PE expected to be
  revoked and got `dbx_revoked=False`.
- **Cost:** ~5 minutes (xxd + decode + design `_strip_authenticated_variable_wrapper`).
  Compare to the alternative: ship without the strip, rebuild (~5 min),
  smoke (operator runs verify_authenticode against a known-revoked PE,
  gets unexpected False, files a bug) → diagnostic loop on production
  data → ~30-60 min minimum. **Rule #19 cost-amortisation: 1 min
  evidence sweep saved ~30+ min of post-ship debugging.**
- **Fix:** Added `_strip_authenticated_variable_wrapper(buf)` with
  shape-detecting heuristic (year ∈ [1900, 2100] + wType==0x0EF1 +
  dwLength bounded). Conservative — returns `buf` unchanged on any
  unmatched check, so synthetic β.7 fixtures (bare format) pass through.
  Wired into `_load_bundle` before `_parse_bundle_bytes`. 7 new unit
  tests cover bare passthrough + wrapped detection + boundary cases.
  Verified post-rebuild: 24053-byte raw bundle → 20716-byte stripped →
  431 SHA256 entries parsed cleanly (the current Microsoft revision is
  100% SHA256-based; X509 entries empty in this version, but the
  parser handles both kinds).
- **Infrastructure created:** None new — the discipline IS Rule #19.
  The wrapper-strip helper is now part of the dbx_service contract; the
  pattern (parse-the-real-thing-locally before writing the Dockerfile
  delta) is captured in this postmortem's recommendations + Rule #37's
  "wrapper-format discovery is part of the bundling work" sub-clause.

### 2. `set -e` interaction with `cmd; rc=$?` in refresh-ms-roots.sh — Rule #35a near-miss

- **What happened:** First draft of `scripts/refresh-ms-roots.sh` used
  the canonical Rule #35a pattern `cmd > /tmp/x; rc=$?; if [ "$rc" -ne
  0 ]; then …` after `curl` and after `docker compose build`. Under
  `set -e` (which I'd added at the script top), curl exiting non-zero
  causes the script to exit IMMEDIATELY at the curl line — `rc=$?` and
  the if-block never run. The fix-on-error path (the entire reason for
  capturing rc) would never fire.
- **Caught by:** Self-review during `bash -n /home/dustin/code/wairz/scripts/refresh-ms-roots.sh`
  syntax check + reading the script back end-to-end. The bug would
  have shipped silently — the `MATCH` happy path never fails curl, so
  the cron line would have appeared to work. The mismatch path (the
  actual reason for the script) would have died at curl with no
  operator-friendly error message; cron would log just the curl error.
- **Cost:** ~1 minute (rewrite the curl + docker invocations to use
  `cmd ... || rc=$?` form, which preserves set -e for everything else
  AND lets the if-block run on failure).
- **Fix:** Switched both curl and `docker compose build` invocations
  to:
  ```sh
  RC=0
  cmd ... > /tmp/x 2>&1 || RC=$?
  if [ "$RC" -ne 0 ]; then ...
  ```
  The `|| RC=$?` form is treated as a successful compound statement
  by set -e (set -e doesn't trigger on the LHS of `||`), so the rest
  of the script runs and we can inspect RC.
- **Infrastructure created:** None new — the lesson is **Rule #35a
  pipe-trap has a sibling: `set -e` exit-trap.** Both intercept the
  exit code before `rc=$?` can read it. The durable mitigation is
  identical: bypass the exit-trap with explicit `|| rc=$?` (or `if
  ! cmd; then …`). Worth flagging in patterns/antipatterns extraction.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|------------------|
| Rule #19 evidence-first | xxd + struct-decode of the live Microsoft bundle BEFORE writing parser code surfaced the EFI_VARIABLE_AUTHENTICATION_2 wrapper | 1 | A non-functional bundle would have shipped (every PE → dbx_revoked=False); ~30-60 min post-ship debugging averted by 1 min upfront |
| Rule #35a (extended) | Self-review of `set -e` × `cmd; rc=$?` interaction in refresh-ms-roots.sh | 1 | Cron mismatch path would have died silently at curl with no operator-facing error; the entire reason for the script (drift detection) would have been broken |
| Rule #11 import smoke (post-rebuild) | dbx_service + match_dbx_revocation work cleanly inside worker container; 24053 → 20716 stripped, 431 entries | 1 | Module-scope import error or NameError would have been caught at smoke time, not at first PE scan |
| Rule #20 docker compose up + build (Dockerfile change → full rebuild) | Bundle COPY + sha256sum -c integrity verify ran AT BUILD TIME | 1 | If the committed `dbxupdate.bin` had been corrupted (in transit, accidental edit, etc.), the build would have failed loudly during `docker compose build` rather than silently shipping a broken image |
| Rule #25 per-sub-task commits | β.10 (Dockerfile + service + tests + cron) and β.13 (CLAUDE.md rules) shipped as 2 separate focused commits | 2 | Bundled "feat(β): bundle + rules" would have meant one revert surface for two semantically independent sub-tasks (durable infrastructure vs documentation); independent revert/bisect lanes preserved |
| Rule #21 mirror discipline | β.13 added Rule #36 + Rule #37 to CLAUDE.md AND mirrored to `.mex/context/conventions.md` Verify Checklist in the SAME commit | 1 | An out-of-sync state (rules in CLAUDE.md but not in `.mex` checklist) would have meant agents following only `.mex/ROUTER.md` miss the newest guidance — the canonical sync gap that Rule #21 explicitly prevents |
| Rule #35b live canary (gated on file presence) | `test_bundled_dbx_image_parses_with_nonzero_entries` auto-skips on host (where /opt/wairz/dbxupdate.bin doesn't exist), activates inside worker container post-rebuild | 1 | A future regression where the Dockerfile fails to land the bundle (path typo, chmod wrong, COPY broken) would surface the next time pytest runs inside the worker, not at the next firmware scan |
| Rule #19 atomic-write discipline (refresh script) | Script writes to `.tmp`, then atomic-renames to `.bin` only after SHA256 verify passes | 1 | A partial download (network failure mid-transfer) would leave a half-finished `.tmp` that gets cleaned up by the trap-on-EXIT, never replacing the canonical pinned file |

## Scope Analysis

- **Planned (β.10 — per user prompt):** "Bundle the Microsoft Authenticode trust anchors + UEFI dbxupdate.bin into the worker image as build-time assets, plus a quarterly cron script `scripts/refresh-ms-roots.sh` that re-downloads from Microsoft's canonical sources and re-builds. Per CLAUDE.md Rule #37 candidate (offline-trust-anchor discipline): NO network fetch at scan time; ALL trust anchors must land in the image at build."
  - Six explicit design constraints: (1) Rule #37 candidate offline-trust-anchor (no scan-time network), (2) Rule #19 evidence-first read of Dockerfile, (3) Quarterly cron with SHA256 verify + atomic write + non-zero exit on mismatch, (4) Backend startup probe, (5) Test fixture committed under backend/tests/fixtures/windows/, (6) Rule #11 + Rule #20 full rebuild via `docker compose up -d --build worker backend`.
- **Built (β.10):** Met all six explicit constraints.
  - `backend/ms-anchors/{dbxupdate.bin, dbxupdate.bin.sha256, dbxupdate.bin.url, README.md}` — 24053-byte canonical Microsoft amd64 DBXUpdate.bin pinned by SHA256 `74df077175dca7ff8bcd27ce8285656e38097803f803e2d124467273699e4b17`.
  - Dockerfile delta: COPY ms-anchors → /opt/wairz/dbxupdate.bin + sha256sum -c integrity gate + /opt/wairz/ms-roots/ marker dir + chown wairz.
  - docker-compose: DBX_BUNDLE_PATH=/opt/wairz/dbxupdate.bin on backend + worker.
  - `dbx_service._strip_authenticated_variable_wrapper` (NOT in original constraints — discovered necessity at evidence-first step) + 7 new unit tests + docstring extension.
  - `main.py` lifespan: startup probe logs `DBX bundle ready: path=… size=… mtime=…` (or WARNING on missing).
  - `scripts/refresh-ms-roots.sh` (228 LOC): atomic .tmp + rename, SHA256 drift check, exit non-zero on mismatch, --apply / --rebuild / --quiet / --help flags, `set -e × cmd; rc=$?` interaction handled correctly.
  - `backend/tests/fixtures/windows/{tiny.dbxupdate.bin (1024 B bare), tiny.dbxupdate.wrapped.bin (1128 B wrapped), _build_tiny_dbxupdate.py generator}` — committed binary fixtures + regeneration script.
  - 4 new tests beyond the wrapper-strip 7: bare-fixture file-on-disk, wrapped-fixture file-on-disk, unrevoked-serial returns false, bundled-image Rule #35b live canary (gated on file presence).
- **Drift:** Minor *positive* drift — the `_strip_authenticated_variable_wrapper` extension was NOT in the original β.10 spec but was forced by Rule #19 evidence-first. Without it, the bundled file would parse as 0-entry and silently degrade dbx matching. The user's design constraint #1 said "β.7's TRUSTED_CERTIFICATE_STORE already ships MS Authenticode roots; β.10 focuses on the dbxupdate.bin side + a refresh script" — focused-on-dbx remained correct, but the dbx side turned out to need a parser extension β.7 hadn't anticipated. This is the campaign's first +scope discovery driven by evidence-first against the live source.
- **Planned (β.13 — per recommended-next conversation):** Promote Rule #36 (no-execute discipline for installer custom actions) + Rule #37 (offline-trust-anchor discipline for cert roots / DBX) to canonical CLAUDE.md + mirror in `.mex/context/conventions.md` Verify Checklist per Rule #21.
- **Built (β.13):** 2 new rules in CLAUDE.md (Rule #36 ~70 lines including worked examples + companion-rule cross-refs; Rule #37 ~60 lines including the wrapper-format discovery sub-clause distilled from β.10). 2 corresponding entries in the .mex Verify Checklist, both compact one-liners that point back to the CLAUDE.md canonical text.
- **Drift:** None. β.13 was a pure documentation commit codifying what the codebase already practiced.

## Patterns

- **Rule #19 evidence-first scales to "format-shape verification" too.** The previous extractions of Rule #19 documented it for "measure DB conditions before writing backfill code" + "read the source file before writing the iteration code". This session adds: **"parse the third-party binary asset locally with the existing tooling BEFORE committing the Dockerfile delta + rebuild cycle"** — the rebuild + smoke costs ~5-10 min; a `python3 -c "from app.services.X import _parse; print(_parse(open('Y','rb').read()))"` against the just-downloaded asset costs ~1 sec and catches format mismatches at design time. **Action:** This is the third independent application of Rule #19 to a different problem shape (DB / file-tree / binary-format); the pattern's generalisation is durable. Worth incorporating into a `.mex/patterns/add-trust-anchor-bundle.md` recipe alongside the Rule #37 worked example.
- **Rule #35a has a sibling: `set -e × cmd; rc=$?` interaction.** Rule #35a (a) covers the pipe-induced exit-trap; this session uncovered the `set -e`-induced exit-trap in shell scripts. Both intercept the exit code before `$?` can be read; both are worked-around with `cmd ... || rc=$?` (in scripts) or `cmd > /tmp/out` followed by file-redirect inspection. **Action:** No new infrastructure — the durable response is muscle memory for the explicit `|| rc=$?` form whenever set -e is in scope. Worth a one-line addition to Rule #35a's "How to apply" section in the next CLAUDE.md update; deferred to a future CLAUDE.md editing session per Rule #25 per-sub-task discipline (β.13's commit was already focused on Rule #36 + #37 promotion).
- **The β.10 → β.13 cycle is a durable shape: ship the worked example, then promote the rule.** β.4 shipped the signify-bundles-MS-Authenticode-roots pattern; β.10 shipped the dbx-bundle pattern; β.13 promoted both into canonical Rule #37. β.4 + β.10 are the worked examples; β.13 codifies. This is exactly the form the campaign's PRD anticipated ("CLAUDE.md Rule #37 candidate (offline-trust-anchor discipline) added end of Phase β"). **Action:** Apply the same shape to future rule promotions: ship 2-3 worked examples, then promote the rule with the workings as references. Avoid the inverse (write rule, then implement it once) — without 2-3 implementations, the rule's mechanical guidance is speculative. Companion to Rule #25 (per-sub-task commits — the rule promotion is its own sub-task).
- **Rule #25 holds under back-to-back execution, again.** This session shipped β.10 + β.13 as two separate focused commits, just as the previous session shipped β.8 + β.9 as two. The temptation to bundle ("they're closely related; one commit is fine") is real but Rule #25 keeps each independently revertable. β.10 (durable infrastructure) and β.13 (documentation) genuinely have different failure modes; the commit boundary preserves that. **Action:** No change. Pattern is now Rule-of-Six across this campaign (β.5/β.6/β.7/β.8/β.9 each its own commit; β.10 + β.13 each its own commit).
- **The PRD's "(Phase β.X)" title pattern is durable across 6 phases.** β.5/β.6/β.7/β.8/β.9/β.10/β.13 commit subjects all use `feat(<scope>): <subject> (Phase β.X)` format. Operators can grep-derive phase status from `git log --oneline` without a separate tracker. **Action:** No change. Pattern is now Rule-of-Seven; the title shape itself is the cross-reference anchor.

## Recommendations

1. **Promote `.mex/patterns/add-trust-anchor-bundle.md` recipe.** Three β.X applications of Rule #37's worked-example pattern: β.4 (signify package as the build-time bundle), β.10 (custom anchors directory + cron), and the implied future application (additional Authenticode PEM roots in /opt/wairz/ms-roots/, Mozilla certdata.txt, CT log anchors). Recipe should cover: (a) directory layout `backend/<anchor>-anchors/{<file>, <file>.sha256, <file>.url, README.md}`; (b) Dockerfile shape (COPY + sha256sum -c + chmod 0444 + chown wairz + place at known runtime path); (c) docker-compose env var on backend AND worker; (d) graceful WARNING-degrade in the consuming service (no fabricated answers); (e) startup probe in main.py lifespan; (f) refresh script template (atomic .tmp + rename, SHA256 drift, --apply / --rebuild flags, `cmd ... || rc=$?` form under set -e); (g) wrapper-format discovery via `xxd <file> | head` + decoder REPL probe BEFORE rebuild; (h) test fixtures shape (committed binary + regeneration script + Rule #35b canary gated on bundled-image presence). Worth ~30-45 min of authoring; saves an order of magnitude across future trust-anchor work in Phase γ/δ + future campaigns.
2. **Add a one-line note to Rule #35a's "How to apply" covering the `set -e` × `cmd; rc=$?` sibling trap.** The pipe-induced trap (Rule #35a (a)) and the set-e-induced trap have identical surface (exit code intercepted before $? reads it) but different mitigations (pipefail / PIPESTATUS for pipes; `|| rc=$?` for set-e). One sentence in Rule #35a saves a future operator from this session's recurrence. Defer to a future CLAUDE.md editing session per Rule #25 per-sub-task discipline; bundle with the next rule-promotion commit (e.g. when β-phase patterns are extracted into formal rules).
3. **β.11 frontend (PeHardeningPage + AuthenticodeDetailPage) is the natural next session.** Different domain (React/TypeScript/shadcn/ui) — does not benefit from this session's warm context (Dockerfile / Python services / EFI parsers). Fresh session keeps the cache hot for the frontend domain. Per the β.7 postmortem rec on domain-shift session breaks; pattern now Rule-of-Two.
4. **β.14 cut-over still has the deferred Rule #35b canary set.** Per the β.8/β.9 postmortem rec #4: every β.X sub-task to date has shipped with mock-only tests for the verdict logic. β.10 added the bundled-image canary (file presence verification post-rebuild) — but the **PE-end-to-end** canary (verify_authenticode against a real signed PE whose leaf serial appears in the bundled DBX, returning revoked=True) is still gated on β.14's cut-over. Now 8 sub-tasks deferred (β.5 through β.10 + β.13). The β.8/β.9 rec said "β.14 cut-over should activate ALL deferred canaries in one rebuild, not piecewise" — this remains the correct discipline. Note: the current Microsoft DBX revision is 100% SHA256-based (0 X509 entries in 431); a serial-match canary against the live bundle would always return revoked=False today. β.14's canary set may need to ship its own test PE (signed with a deliberately-revoked test cert) OR pull an older Microsoft DBX revision that included X509 revocations OR test via the SHA256-hash matcher (which β.7's docstring said was "deferred to β.8+" — β.14 is the natural moment to plumb that through).

## Numbers

| Metric | Value |
|--------|-------|
| Sub-tasks planned (this session) | 2 (β.10 bundle + β.13 rule promotion) |
| Sub-tasks completed | 2 |
| Commits | 2 (`856b640` β.10, `f80d606` β.13) |
| Files added | 9 (4 in `backend/ms-anchors/` + 4 in `backend/tests/fixtures/windows/` + `scripts/refresh-ms-roots.sh`) |
| Files modified | 7 (`backend/Dockerfile`, `backend/app/main.py`, `backend/app/services/dbx_service.py`, `backend/tests/test_dbx_service.py`, `docker-compose.yml`, `CLAUDE.md`, `.mex/context/conventions.md`) |
| Total LOC delta | +801 / -6 (β.10 +746/-6; β.13 +55) |
| Tests added | 11 (7 wrapper-strip + 3 committed-fixture + 1 bundled-image Rule #35b canary) |
| Tests passing on host | 33 + 1 skipped (the bundled-image canary auto-skips when /opt/wairz/dbxupdate.bin doesn't exist) |
| Tests passing inside worker | Manually verified via Python REPL probe (worker venv lacks pytest by design — `--no-dev`); live parse returned 431 entries cleanly |
| Reverts | 0 |
| Rework cycles | 1 (refresh-ms-roots.sh `set -e × cmd; rc=$?` interaction caught pre-commit) |
| Circuit breaker trips | 0 |
| Quality gate blocks | 0 |
| Anti-pattern warnings | 0 |
| Rule #11 import smoke runs | 1 (post-rebuild — `_strip_authenticated_variable_wrapper` + `match_dbx_revocation` both green; 24053 raw → 20716 stripped → 431 entries) |
| Rule #20 docker compose up + build cycles | 1 (single Dockerfile-change rebuild, ~3 min) |
| Rule #25 commits | 2 (one per sub-task) |
| Rule #19 evidence-first applications | 2 (Dockerfile pre-read for build-stage placement; xxd + struct-decode of live Microsoft bundle before writing parser-extension code) |
| Rule #21 mirror updates | 1 (β.13: CLAUDE.md + .mex/context/conventions.md updated in the SAME commit) |
| Rule #35a `cmd; rc=$?` patterns | 6+ (curl rebuild + script smoke + pytest runs + final verification + commit) |
| Rule #35a near-miss recoveries | 1 (set -e × cmd; rc=$? interaction in refresh-ms-roots.sh; caught in self-review pre-commit) |
| Rule #35b live canaries added | 4 (committed-fixture bare + committed-fixture wrapped + unrevoked-serial-returns-false + bundled-image canary auto-skip-on-host) |
| Pattern #7 REPL probes | 1 (xxd + Python decode of dbxupdate.bin before writing wrapper-strip code; the durable Rule #19 evidence-first probe) |
| Tool registry growth | +0 (no new MCP tools — β.10 was infrastructure; β.13 was documentation) |
| Discipline slips | 0 (no `--no-verify`; no `--amend`; bare `git commit -m` per β.7 postmortem rec) |

---HANDOFF---
- Postmortem: windows-coverage-godmode β.10 + β.13
- Document: .planning/postmortems/postmortem-windows-coverage-godmode-beta10-beta13-2026-05-08.md
- Failures documented: 2 (1 evidence-first averted format-blind parser shipping; 1 set-e × cmd-rc interaction recovered cleanly pre-commit)
- Safety catches: 8 (Rule #19 evidence-first × 2, Rule #35a (extended), Rule #11 import smoke, Rule #20 + Dockerfile sha256sum -c, Rule #25 per-sub-task commits, Rule #21 mirror discipline, Rule #35b live canary)
- Recommendations: 4
---

Run `/learn windows-coverage-godmode-beta10-beta13` to extract patterns into the knowledge base.
