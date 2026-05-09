# Anti-patterns: 2026-05-07 QNX_IFS PARTIAL handler

> Extracted: 2026-05-07
> Source: 6 commits between `4429f42` (baseline) and `ec687c3` (HEAD) on
> branch `clean-history`. Anti-patterns surfaced as risks rather than
> incidents — the session shipped without reverts. These are the failure
> modes the discipline guarded against, captured so future sessions
> don't drop the guards.

## Risks Surfaced (mitigations held; documented for durability)

### 1. Skip-on-no-corpus rotting into never-tested

The QNX_IFS live canary is `pytest.skip(reason="No QNX IFS test corpus
available; see .planning/intake/qnx-ifs-test-corpus-2026-05-07.md")`.
This is honest at ship time — there's no public corpus available — but
becomes silently dishonest if (a) the corpus intake is closed without a
fixture being sourced (e.g. flipped to "won't source" without a real
attempt), (b) the upstream `ifsdump` evolves and the worker's expected
behavior drifts but only the mock tests catch the drift, or (c) future
handlers copy the skip pattern WITHOUT filing a follow-up intake.

- **What was done:** Live canary skipped; capability claim PARTIAL;
  follow-up intake filed at the same handler-group commit boundary.
- **Failure mode (if guards drop):** The handler ships PARTIAL, the
  intake never gets actioned, the skip becomes permanent, and 6 months
  later someone "cleans up" the skipped test and the handler has zero
  real-input coverage.
- **How to avoid (durable discipline):** The capability invariant test
  (`test_capability_notes_only_for_partial_or_none`) ensures PARTIAL
  formats keep their notes — the notes are the user-facing record that
  this isn't a finished handler. The intake provides the path to FULL.
  When closing such an intake, EITHER promote PARTIAL→FULL (corpus
  landed) OR document explicitly that the format is permanently
  PARTIAL with a clear technical reason — never close as "won't fix"
  without a written rationale that survives the closer.
- **Companion to:** Rule #19 (evidence-first — PARTIAL with notes is
  the honest evidence; FULL without verification is the dishonest
  alternative); Rule #35b (mocks vs live canaries).

### 2. Source-build Dockerfile fragility vs apt-get

This handler is the first Phase 2 handler whose Dockerfile diff added
a source-build dependency (gcc + apt build deps + git clone) instead
of an apt-get one-liner. apt-get tools are stable across Debian
releases (versioning, security backports, deterministic builds);
source-build dependencies are NOT — they break on upstream repo
deletion/rename, build-system regressions (gcc flag drift, dep version
changes between Debian releases), and any github.com outage at build
time.

- **What was done:** Pinned SHA `c621029e` in the Dockerfile; build
  deps explicit in the same RUN layer; cleanup at the end.
- **Failure mode (when guards weaken):** Pinned SHA → upstream repo
  rename or deletion → `git clone` 404s → backend rebuild fails →
  every developer's `docker compose build` breaks until someone
  manually replaces the URL or vendors the source. Pinned SHA does
  NOT mitigate URL changes, only file changes within the URL.
- **How to avoid (durable discipline):** For source-build deps,
  consider vendoring the source into the Wairz repo at the pinned SHA
  (subtree merge or just a tarball) for the next handler. The cost
  is repo size; the benefit is reproducibility across upstream churn.
  Until vendored, the dispatch prompt for any session that touches
  the Dockerfile MUST verify the upstream URL still resolves before
  declaring "no Dockerfile change needed."
- **Companion to:** Pattern 1 (source-build via pinned-SHA git clone —
  this is the risk side of that pattern); Rule #8 (rebuild discipline
  — source-build rebuilds are slower and have more failure modes);
  Rule #19 (evidence-first — verify the URL resolves before trusting
  the cached Dockerfile).

### 3. Research-doc CLI flag transcription drift

The QNX research doc was written 2026-05-07 morning; the implementation
session ran 2026-05-07 afternoon. Even within the same day, transcribing
flags from the research doc into the worker without re-checking the
README at the pinned SHA introduces a drift risk: the doc author may
have summarised flags, used an older revision, or made a typo that
nobody caught. The dispatch prompt's verification step ("verify the
actual ifsdump CLI flags by reading the repo's README at the pinned
SHA before hardcoding `--list` and `-x`") is the mitigation.

- **What was done:** The archon's worker implementation pulled flags
  from the upstream README at the pinned SHA, not from the research
  doc. Post-build smoke (`ifsdump -h`) confirmed the 12 documented
  flags matched what the worker expected.
- **Failure mode (when verification skipped):** Worker hardcodes
  `--list` from the doc; real binary uses `-l`; subprocess returns
  rc=2 with "unknown option"; mock tests pass cleanly because they
  mocked the subprocess; live canary would catch it but is skipped
  due to no corpus → bug ships, surfaces only when a real .ifs hits
  the worker.
- **How to avoid (durable discipline):** Generalised Rule #6: for
  ANY external CLI tool, the source-of-truth for flags is the
  binary at the pinned SHA, not any intermediate documentation about
  it. Even your own research doc from earlier that day. `<binary> -h`
  in-container after the Dockerfile builds is the cheap canary.
- **Companion to:** Rule #6 (verify CLI flags on version upgrade);
  Rule #17 (silent-CLI-exit canary — same shape: trust the binary's
  actual behavior over any documentation about it).

### 4. Capability-bump sequencing within the handler group

The 6-commit handler shape places the capability bump (`3f03ccc`)
AFTER strategy registration (`e5bbefd`). Between those two commits,
the strategy table maps QNX_IFS → unpack_qnx_ifs but the capability
map still claims NONE. If a developer checks out `e5bbefd` exactly,
they see an inconsistent state: dispatch routes to a real handler,
but the user-facing capability says "not supported."

- **What was done:** The window is small (one commit, milliseconds in
  practice). The capability-map alignment invariant test
  (`test_capability_notes_only_for_partial_or_none`) catches the
  invariant violation but ONLY when run between commits — full
  pytest runs at the END of the group pass cleanly because the
  capability bump landed before the test gate.
- **Failure mode (when sequencing bends):** Bisect lands on `e5bbefd`,
  pytest fails the alignment test, bisect reports "this commit broke
  the test" when it actually didn't break anything — the alignment
  was always intended to land in the next commit. Bisect debugging
  noise.
- **How to avoid (durable discipline):** Alternative shape: ship the
  capability bump as part of the registration commit (single atomic
  cut-over per Pattern 5 — same effect as the prior session's
  4-commit shape). Trade-off: harder to revert capability claim
  independently of registration. Current shape preferred for
  revertability; the bisect-noise risk is acknowledged.
- **Companion to:** Rule #25 (per-sub-task commits — the trade-off is
  inherent: more commits = more revertability but more transient
  intermediate states); Rule #27 (N additive + 1 cut-over —
  capability bump COULD be folded into cut-over for handlers where
  bisect noise is more costly than independent revertability).

## Anti-pattern Avoided (would-have-been-incident)

### 5. The 4 proprietary QNX dumpers — `$QNXLicenseC$` header

The prior session's research doc evaluated 5 candidate tools.
4 carried the openqnx 2007 proprietary `$QNXLicenseC$` header:
`ttepatti/dumpifs-linux`, `askac/dumpifs`, `ReverseEngDotDev/dump_hbcifs`,
and the QNX SDP `dumpifs` itself. ANY of these would have given
broader format coverage (HBCIFS-wrapped automotive firmware, etc.)
than `jtang613/qnx_dumpers` — a naive "pick the most-featured tool"
heuristic would have selected one of them. The dispatch prompt's
Hard Constraints section explicitly enumerated all 4 as "DO NOT USE"
with the header citation, blocking the substitution.

- **What was avoided:** Shipping a Wairz container with code derived
  from openqnx 2007 sources, which would have contaminated the
  project's MIT license posture and been irreversible without a
  license re-evaluation across every downstream user.
- **Failure mode (without the explicit "DO NOT USE" enumeration):** An
  archon dispatch tasked with "ship a QNX handler" reads the research
  doc, weighs format coverage vs license, optimises for coverage,
  picks a proprietary tool, ships it. The license violation surfaces
  weeks later when someone audits the Dockerfile.
- **How to avoid (durable discipline):** For ANY format whose research
  doc names disqualified tools, the implementation dispatch prompt
  MUST list those tools BY NAME with the disqualifying-header citation
  in a Hard Constraints section. "Use the recommended tool" is
  insufficient — the archon needs the explicit deny-list.
- **Companion to:** Pattern 2 (license-conservative tool selection
  from a Decision Matrix — this is the risk that pattern guards
  against); Rule #19 (evidence-first — the `$QNXLicenseC$` marker
  IS the disqualifying evidence, citable verbatim).

## Cross-Reference

- Patterns file: `.planning/knowledge/session-2026-05-07-qnx-handler-patterns.md`
- Prior session anti-patterns: `.planning/knowledge/session-2026-05-07-extraction-pipeline-antipatterns.md`
- Research doc: `.planning/knowledge/qnx-ifs-extraction-research-2026-05-07.md`
  (Decision Matrix rows B/C/D enumerate the 4 disqualified tools)
