# Patterns: extended session 2026-05-12 → 2026-05-13

> Extracted: 2026-05-13
> Postmortem: `postmortem-extended-session-2026-05-12-to-13.md`
> Span: 22 commits, 2 effective sub-sessions

## Successful Patterns

### 1. 3-scout research-fleet — Rule-of-Four

- **Description:** Dispatch 3 parallel research scouts, each on a
  decomposed angle of the same question. Synthesize on completion.
- **Evidence this session:**
  - λ.α pre-pass: Vol3 library probe + ISF bundle dry-run + plugin
    taxonomy (5-7 min each)
  - tibx deep: format research + wairz integration + sandboxed extraction
  - tibx alternatives: QEMU-PE-boot + Wine acrocmd + format-RE refresh
- **Applies when:** Any "broad-research-driven implementation"
  directive with well-defined scope but unknown answers.
- **Promotion:** Rule-of-Four cumulative (user memory log shows two
  prior + λ.α + tibx-alternatives this session). Durable.

### 2. Probe-before-build for risky architectures

- **Description:** Run a minimal probe (~30-60 min context) before
  committing 6-16h to architecture-grade implementation. Cheaper
  signal than building sight-unseen + having to revert.
- **Evidence:** Probe #1 (UEFI bootx64.efi LOAD verified) + Probe #2
  (BCD-edit Fix B NO-GO) collectively saved 12-22h of implementation
  work that would have hit the same walls.
- **Applies when:** Any side-container or vendor-binary integration
  where the cheapest signal is "does the binary even execute".

### 3. Per-piece commits + per-piece revertability — Rule #25 durable

- **Description:** Even tightly-coupled work (Dockerfile + compose +
  worker + strategy + tests for the BYOB-SC architecture) shipped as
  ONE single-slice commit was cleanly revertable when scope changed.
- **Evidence:** `9428b5f` reverted three commits in one bisect-clean
  revert commit when the user said "scratch the work". No lost
  context.
- **Applies when:** Always. Rule #25 + Rule-of-X for cross-stack
  alignment.

### 4. Honest negative findings as deliverables

- **Description:** When a probe / approach fails, document the
  failure mode as cleanly as a success. Re-open triggers + decision
  matrices replace "we'll figure it out later".
- **Evidence:** `probe-1` + `probe-2` results + `tibx-byob-extraction-attempt`
  postmortems each document what was tried + what failed + what to do
  if revisiting. Issue #14 captures the re-open trigger (N=2).
- **Applies when:** Any deep-investigation closure. Saves the next
  operator from re-running the same probes.

### 5. GitHub Issues for deferred work — durable + discoverable

- **Description:** Mirror `.planning/intake/*.md` items into GitHub
  Issues with labels. The `.planning/` files become research
  artifacts; the issues become trackable work.
- **Evidence:** 8 issues filed (#11-#18) with labels (`priority/*`,
  `memory-forensic`, `tibx`, `rule-44-backfill`, etc.). Now visible
  to any contributor + dashboards without spelunking `.planning/`.
- **Applies when:** Any session-close. Mirror the intake → issue
  pipeline; preserve `.planning/` for the design rationale.

### 6. Multi-persona deciding-agent reasoning

- **Description:** When the user says "you decide using deep research
  and deep think across all relevant expert personas", enumerate
  the personas (forensics analyst, security architect, SRE,
  pragmatic engineer, risk reviewer), enumerate their conclusions,
  then synthesize.
- **Evidence:** Three explicit multi-persona decisions this session
  — probe approach (chose Fix B before Fix A based on cost),
  branch selection (Branch 3 over Branch 1/2 based on N=1 ROI),
  GitHub-features triage (Issues + Dependabot + CodeQL chosen over
  Wiki + Discussions based on actionability).
- **Applies when:** User explicit-delegation directives.

### 7. Operator-side recovery-PE walker recipe (NEW — Rule-of-One)

- **Description:** When a primary unpacker doesn't auto-descend into
  nested archives (zip-of-folder-with-boot.wim), operator-level
  `wimextract` + manual `detection_roots` update + walker re-trigger
  closes the gap without new code shipping.
- **Evidence:** ILLUMISITE this session — 322 driver packages + 9 BCD
  entries + 1 WMI binding + 3 signed-valid EFI files + 2 findings
  surfaced via this recipe without committing any code.
- **Codification:** Issue #16 — codify as a wairz pipeline step.

### 8. GitHub-features deep audit as session-close artifact

- **Description:** At session end, audit repo settings for
  high-value gaps (Issues enabled? Dependabot configured? CodeQL?
  Topics for discoverability?). Most repos have low-hanging
  GitHub-feature wins ignored by year.
- **Evidence:** wairz had Issues DISABLED + zero topics + no
  Dependabot config despite shipping security-tool features for
  months. 30 min audit + setup unlocked 8 tracked issues + supply
  chain coverage + CodeQL self-scan.
- **Applies when:** Any session ≥ 10 commits + the operator has
  GitHub admin. Cheap to do; durable benefit.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| `.tibx`: Branch 3 (accept opacity) | Probe #2 confirmed Fix B NO-GO; Fix A (MS WinPE ISO) needs Windows host; N=1 doesn't justify | Issue #14 captures re-open trigger |
| Vol3 via subprocess | Rule #29 timeout via `proc.kill()`; process isolation; heap reclaim | Locked in synthesis.md |
| ISF source: GitHub release | Apache mirror stale (last refresh 2024-11) per Scout 2 | Pin in λ.α.C Dockerfile gate |
| `ARG INCLUDE_VOL3=0` default | Mirrors `INCLUDE_DOTNET=0`; +925 MiB image size impact | Operator opt-in |
| Defer credentials family | Rule #45 metadata-walker discipline; needs operator sign-off | Beyond λ.δ |
| Branch protection: NO | Preserves Pattern P5 per-piece direct-push | Bypass not added on repo |
| Issues: ENABLED | Deferred work was invisible in `.planning/` only | 8 issues filed immediately |
| ILLUMISITE end-to-end via boot.wim manual extract | .tibx blocked but recovery PE has unique adversary surface | 322 drivers + findings in DB |

## Quality Rule Candidates

No high-confidence regex-expressible rules emerged from this session.
The patterns above are shape-discipline / mechanical reflex — regex
auto-enforcement would have too many false positives.

The closest candidate: a pre-commit hook for the `windows.malware.*`
deprecation deadline (issue #18) — grep for top-level deprecated
plugin names. But it's a one-off until 2026-06-07; after that the
top-level plugins simply don't exist + import errors catch it.
