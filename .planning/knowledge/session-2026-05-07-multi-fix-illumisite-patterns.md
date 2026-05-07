# Patterns: 2026-05-07 multi-fix session (post-Phase-2 closure → Illumisite + multi-OS)

> Extracted: 2026-05-07
> Source: ad-hoc session work, NOT a single campaign — captures patterns from
> 11 commits between commit `2cd3cad` (Phase 2 Wave 7 close) and the
> Illumisite-driven UX + format-detection landings.
> Not eligible for /learn (no single campaign source); written manually
> per the spirit of /learn.

## Successful Patterns

### 1. Rule #33 has graduated to a "well-trodden conversion shape" — 5 applications, 0 reverts

The Rule #33 4-bullet contract has now landed against 5 endpoints across 5 sessions:
firmware unpack (precedent), emulation, fuzzing, cve-match (session 76fd9c3a),
vuln-scan (session 24c61c35 this turn), and firmware upload (also this session).
**Each application takes 3-5 commits + ~1 session.** The pattern is durable.

- **Description:** When a synchronous backend endpoint exceeds Rule #29's tier
  ceiling (or hits frontend axios timeout), convert to 202+polling per Rule #33's
  (a) idempotent POST + 409 conflict; (b) persist result on the canonical row,
  not a separate cache; (c) Pydantic Literal + DB CHECK constraint pair;
  (d) `asyncio.create_task` vs `arq` decision rubric.
- **Evidence:** Commits `a255a8b..61e814b` (vuln-scan) + `68dcc86..f93508d`
  (firmware upload). Both shipped with single-pass test green + Rule #11 smoke +
  Rule #8 rebuild without intermediate failures.
- **Applies when:** Any endpoint where backend work routinely exceeds 30-100s,
  especially behind a reverse proxy. Promote to ALWAYS the conversion shape;
  don't re-derive the structural template — it's now Rule #33's reference shape.

### 2. Intake hygiene pre-flight: read target files before re-implementing

This session re-investigated 3 intakes that turned out to already be shipped:
`findings-confidence-ui-display-2026-05-04`, `findings-source-tag-drift-ci-2026-05-04`,
and the bulk of `audit-quick-wins-bundle-2026-05-04` (11/14 items).

- **Description:** Before treating an intake as "implementation work to do",
  read the listed `target` files and confirm the acceptance criteria aren't
  already satisfied. Most stale `pending` intakes have shipped quietly without
  frontmatter updates.
- **Evidence:** Commits `e2ca6b1`, `431b991`, `5946b20` — 3 intake closures
  in this session that cost 1-2 file reads each instead of full re-implementation.
- **Applies when:** Picking up ANY intake older than ~7 days; multi-intake
  sweeps especially. Single mechanical check: `grep -l <key-symbol> <target-paths>`
  before committing to scope.

### 3. Rule #19 evidence-first generalizes from "DB row counts" to ALL count claims

Three count-claim corrections this session:
- Alembic intake said "5 dangling parents, 5 disconnected heads" — actual was 1 + 2
- Source-tag drift intake said "8 DB-only / 2 FE-only" — actual was 7 / 3 (corrected by alignment-test rewrite)
- Phase 2 Wave 9 closeout said "remaining 3 services" — actual was 5 (table was right; closeout was stale)

- **Description:** When an intake / postmortem / closeout claims a SCOPE COUNT,
  re-verify with a clean grep / SELECT before scoping the repair. The discipline
  cost is ~30 seconds; the cost of acting on a wrong count is full-session scope explosion.
- **Evidence:** Commit `bd4dff9` (alembic) — single 1-line fix vs. the intake's
  2-stage repair plan; commit `7079b4d` (source-tag) — 1 migration vs. the intake's
  multi-side classification work; Wave 10 dispatch protocol's mandatory `git ls-files`
  reconciliation step caught the count miss.
- **Applies when:** Any intake / closeout / spec describing scope as a count.
  Mechanical: `grep -c | wc -l | SELECT count(*)` BEFORE designing the repair.

### 4. Format-detection pre-flight is the right shape for "uncovered firmware format" UX

The Acronis `.tibx` Illumisite case demonstrated: when a user uploads firmware
that's outside the current extractor coverage, silent post-upload behavior wastes
time and confuses the operator. Surfacing the detection result + extraction_capability
mapping at upload time (not after Unpack) is much better UX.

- **Description:** Magic-byte detection runs as the first stage of upload
  post-processing (after bytes land + sha256 done) → `firmware.detected_format`
  set → frontend banner shows extraction_capability (full / partial / none) before
  the user's next action.
- **Evidence:** Commits `35a754f` (detection service) + `64e1d85` (frontend banner).
  Closes the asymmetric-time-cost gap where users invest minutes-to-hours before
  realizing format isn't covered.
- **Applies when:** ANY pipeline that has format-coverage variance. Generalizes
  beyond firmware: similar shape works for "we can't analyze this file format yet"
  pre-flight in document analysis, network capture parsers, etc.

### 5. Multi-OS scope correction: precision on what each TOOL handles, not project scope

This session's user correction: "we need to support windows and other OS's so saying
wairz only supports linux is a lie... it supports qnx and other rtos, etc..."

- **Description:** When discussing extraction or analysis tooling, frame
  capability per TOOL (unblob handles Linux blobs, jadx handles Android),
  not per PLATFORM. The platform (wairz) is multi-OS by design; the current TOOLS
  cover specific subsets.
- **Evidence:** The `firmware-format-detection-preflight` intake's banner
  language carefully says "unblob/zipfile/etc. CAN/CAN'T extract this format",
  NOT "wairz supports/doesn't support this firmware". The strategic
  `multi-os-firmware-extractor-roadmap` intake captures the path to add native
  handlers for partial / none capability formats.
- **Applies when:** Any user-facing copy or intake that scopes platform capability.
  Always tie capability claims to specific TOOLS, not the platform.

### 6. Documentation-as-mitigation for proprietary formats

The Acronis `.tibx` case: extracting via reverse-engineering the proprietary format
is multi-week RE work. The pragmatic close was documenting the external-tool workflow
(Acronis True Image → restore to virtual disk → re-upload the resulting filesystem)
in the format-detection banner.

- **Description:** When a format requires proprietary tooling and community RE
  hasn't matured, the right close is NOT "implement the extractor" — it's:
  (a) detect the format up front; (b) document the external workflow visibly to
  the user; (c) file an intake for native handler with HONEST priority (low, until
  workload demand justifies the RE work).
- **Evidence:** `multi-os-firmware-extractor-roadmap-2026-05-07` intake's
  "Phase 2 — handler additions, prioritized by workload demand" section explicitly
  defers Acronis with a workaround. This is honest scope management.
- **Applies when:** Any feature request whose direct implementation would be RE
  work or proprietary-licensed. Document workaround + file low-priority intake.

## Anti-patterns Observed (counter-examples)

### A1. `${VAR:-default}` in docker-compose override is a no-op when env explicitly sets VAR

Hit this twice during the upload-cap raise: the override's `MAX_UPLOAD_SIZE_MB: "${MAX_UPLOAD_SIZE_MB:-20480}"`
didn't actually override because `.env` already had `MAX_UPLOAD_SIZE_MB=2048`. The
`:-default` only fires when unset; explicit values always win.

- **Failure mode:** Container restart shows old value, debugger thinks the override
  isn't being read; in fact it IS being read but the substitution dereferences to the
  existing env value.
- **Avoidance:** In compose override files, use HARD-CODED values when you want override
  behavior: `MAX_UPLOAD_SIZE_MB: "20480"` (no `${...}` substitution). Reserve `${VAR:-default}`
  for "use existing if present, else default" semantics — NOT for override.

### A2. Multi-line `@router.post(...)` decorators break single-line test regexes

Phase 2 vuln-scan refactor reformatted the decorator to multi-line; an
existing test (`test_rate_limit_tiers.py`) used `r'@router\.post\("/vulnerabilities/scan"'`
which assumes single-line. Test suddenly failed because the regex couldn't match across
newlines.

- **Failure mode:** Refactor that LOOKS structurally clean (multi-line is more readable)
  silently breaks invariant tests that assert "this endpoint is rate-limited" via regex.
- **Avoidance:** Rate-limit / decorator-presence assertions should use
  `r'@router\.post\(\s*\n?\s*"/path"'` (multi-line tolerant) from day one. Apply
  retroactively when tests break on a refactor that doesn't change behavior.

### A3. Rule #5 violations multiply silently in upload-style endpoints

`firmware_service.upload()` had inline ZIP extraction + filesystem detection + arch /
endian / OS detection ALL synchronously in the request handler. Even though some steps
used `run_in_executor`, the total wall time hit 5+ minutes on a 16 GB file → blocked
event loop → axios 600s timeout → user confusion.

- **Failure mode:** Upload endpoint goes silent for minutes; frontend gives up; user
  thinks upload failed. Backend is still running; eventually commits the row, but the
  response is lost. User retries → duplicate upload.
- **Avoidance:** Upload-style endpoints should split into (a) bytes-write + hash
  (synchronous, OK to keep in handler), then (b) 202 ack, then (c) all post-processing
  in `asyncio.create_task` background runner with status polling. This is the Rule #33
  pattern, applied to upload-shaped endpoints. Generalizes: ANY endpoint where
  post-data work exceeds 30s should use this shape.

## Quality Rule Candidates (NOT auto-promoted)

Quality rule candidates from this session — surfaced for review, NOT auto-added to
`.claude/harness.json` because each needs human judgment on the file pattern + message.

### QR-1. Compose-override `${VAR:-`-pattern catcher (medium confidence)

- Pattern: `\$\{[A-Z_]+:-[^}]+\}` in `docker-compose.override.yml`
- Message: "compose override using `${VAR:-default}` — only fires when env is unset; for hard override use a literal value"
- Confidence: MEDIUM — the pattern is legitimate when you want fallback semantics, but in OVERRIDE files (specifically) it's nearly always a bug.

### QR-2. Single-line decorator regex in tests (low confidence — too narrow to auto-flag)

- Pattern: `r'@router\.[a-z]+\(\"/` in test files
- Message: "single-line decorator regex breaks if the endpoint is reformatted multi-line; use `r'@router\\.[method]\\(\\s*\\n?\\s*"/path"'` for tolerance"
- Confidence: LOW — too narrow; would fire on legitimate single-line-only assertions. Skip auto-promotion.

### QR-3. Synchronous extractall in async handlers (medium confidence)

- Pattern: `(?<!run_in_executor.*)(zipfile|tarfile|shutil\.unpack_archive).*\.extractall\(`
  in `app/services/*.py` (within `async def` blocks)
- Message: "synchronous archive extraction in an async handler blocks the event loop (Rule #5). Wrap in `await loop.run_in_executor(None, ...)`."
- Confidence: MEDIUM — the regex needs verification but the principle is solid.

## Key Decisions Made

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Repair alembic chain in 1 line, not the intake's 2-stage plan | Rule #19 evidence-first showed only 1 dangling parent, not 5 | Single commit `bd4dff9`; 0 follow-up issues |
| Defer Acronis `.tibx` extractor; ship format detection + workaround docs instead | Multi-week RE work vs. user actionable workaround now | Format detection covers the gap; strategic intake captures the long-term path |
| Bundle Rule #33 firmware upload + format detection in one dispatch | Both touch the upload path; refactoring twice would conflict | Single archon dispatch shipped 5 commits cleanly |
| Skip 11 pre-existing test failures even after surfacing them | Predate session by 10+ commits; not session's responsibility | Filed dedicated low-priority intake (`30a74f3`); session stays focused |
| Use sequential dispatch for Wave 9 + source-tag closure (NOT parallel) | Source-tag is judgment-heavy; would block on user input mid-stream | Both shipped cleanly; no contention on shared `docker compose exec` calls |

## Cross-Reference

- Phase 2 campaign learnings: `.planning/knowledge/phase-2-test-coverage-routers-services-{patterns,antipatterns}.md`
- Audit-2026-05-04 chapter close: closes 5 intakes total this session
- Multi-OS roadmap: `.planning/intake/multi-os-firmware-extractor-roadmap-2026-05-07.md`
