# Patterns: 2026-05-07 QNX_IFS PARTIAL handler

> Extracted: 2026-05-07
> Source: 6 commits between `4429f42` (baseline) and `ec687c3` (HEAD) on
> branch `clean-history`, pushed to origin. 1 archon dispatch, 0 reverts,
> 0 regressions, +9 mock tests + 1 skipped live canary. Phase 2 handler 5:
> QNX_IFS NONE → PARTIAL via `jtang613/qnx_dumpers/ifsdump` (MIT, pinned
> SHA `c621029e3495f3881407d6487735d44155c75f98`). Capability map advanced
> from 8/12 to 9/12 actively supported (75%). Follow-up corpus intake
> filed at `.planning/intake/qnx-ifs-test-corpus-2026-05-07.md`.

## Successful Patterns

### 1. Source-build dependency via pinned-SHA git clone (first non-apt-get handler)

QNX_IFS is the first Phase 2 handler whose tool wasn't available via
`apt-get install`. Prior handlers used Debian-packaged binaries
(7z, wimtools); QNX required cloning a GitHub repo and building C source.
The Dockerfile pattern: resolve `git ls-remote https://github.com/<repo>
HEAD` at dispatch time, hardcode the resolved SHA in the Dockerfile,
`git clone` + `git checkout <SHA>` + `make` + `cp` the binary to
`/usr/local/bin/`, then clean up the clone dir and apt cache.

- **Description:** apt-get tools come with Debian's stability backing
  (versioning, security backports, deterministic builds). Source-build
  tools have NONE of that — pinning the upstream SHA is the only
  mitigation against an upstream license flip, file rename, or
  build-system regression breaking the Wairz Dockerfile silently.
- **Where applied:** Commit `5be1fff` (Dockerfile clone + checkout +
  build of `jtang613/qnx_dumpers/ifsdump` with build-essential +
  zlib1g-dev + liblzo2-dev + libucl-dev).
- **Mechanical detection / how to apply next time:** When the format's
  research doc recommends a non-Debian-packaged tool, the Dockerfile
  diff MUST contain (a) `git clone <url>`, (b) `git checkout <hex SHA>`
  on the next line (NOT a tag, NOT `master`, NOT `HEAD`), (c) explicit
  apt-get build deps in the same RUN layer, (d) cleanup of the clone
  dir at the end. The pinned SHA goes in a comment one line above the
  clone with a citation to the research doc that justified the tool
  choice.
- **Companion to:** Rule #19 (evidence-first — the research doc IS the
  evidence the tool is the right pick); Rule #6 (verify CLI flags
  against the pinned SHA's README, not against the research doc which
  can drift); Rule #8 (backend+worker rebuild discipline — source-build
  Dockerfiles are heavier than apt-get layers; expect 5-7 min vs 3 min).

### 2. License-conservative tool selection from a research-doc Decision Matrix

The QNX research at `.planning/knowledge/qnx-ifs-extraction-research-2026-05-07.md`
evaluated 5 candidate tools. 4 carried the openqnx 2007 proprietary
`$QNXLicenseC$` header (`ttepatti/dumpifs-linux`, `askac/dumpifs`,
`ReverseEngDotDev/dump_hbcifs`, plus the QNX SDP `dumpifs` itself).
1 was MIT-licensed clean-room (`jtang613/qnx_dumpers`). The Dockerfile
ships ONLY the MIT tool. The proprietary candidates are explicitly
listed as "DO NOT USE" in the dispatch prompt's Hard Constraints.

- **Description:** When a research doc enumerates ≥3 tool candidates,
  one Decision Matrix row's License column dominates ALL other rows'
  feature comparisons. Better format coverage in a proprietary-licensed
  tool is irrelevant — that tool cannot ship in an open-source
  container without re-licensing the project. The dispatch prompt
  must explicitly enumerate the unusable tools by name to prevent the
  archon from "discovering" them mid-build and substituting silently.
- **Where applied:** Commit `5be1fff` shipped only `jtang613/qnx_dumpers`;
  the dispatch prompt's Hard Constraints listed the 4 proprietary tools
  by name with the `$QNXLicenseC$` citation. Capability claim is PARTIAL
  (not FULL) precisely because the chosen tool's format coverage is
  narrower than the proprietary alternatives'.
- **Mechanical detection / how to apply next time:** Any research doc
  with a Decision Matrix gets a "DO NOT USE" enumeration in the
  implementation dispatch prompt. Cite the proprietary header marker
  string verbatim (`$QNXLicenseC$`). Hard-fail on attempt to clone the
  blocked repos.
- **Companion to:** Rule #19 (evidence-first — the research doc's
  license analysis IS the evidence); the openqnx 2007 header marker is
  itself a Rule-31-style canary (a single grep for the marker confirms
  proprietary status).

### 3. PARTIAL-with-soft-fail-degrade as the default for narrow-coverage tools

`ifsdump` handles standard QNX .ifs but is not known to handle
HBCIFS-wrapped automotive variants (BMW HU NBT EVO, Harman/Becker).
The worker runs `ifsdump --list <ifs>` first (30s timeout) for a
readability probe; on any non-zero exit OR timeout in EITHER phase,
it degrades to `unpack_no_handler` semantics: `success=False`,
`error="QNX IFS extraction failed (exit=N)"`, `unpack_log` carries
the actual stderr AND a workaround pointer to host-side QNX SDP
`dumpifs` (which Wairz cannot bundle per the QNX Free Non-Commercial
license). Hard-failing the whole firmware unpack would discard
everything else the pipeline had extracted.

- **Description:** Soft-fail to no_handler shape is the default for
  PARTIAL handlers. The capability claim PARTIAL (not FULL) is the
  user-facing signal that some inputs may not work; the worker's
  graceful degradation is the runtime backstop when one of those inputs
  hits.
- **Where applied:** Commit `3b4f165` — `unpack_qnx_ifs.py` returns
  the no_handler shape on FileNotFoundError, asyncio.TimeoutError, and
  rc≠0 from either phase; commit `934ee77` tests cover all 5 failure
  modes plus the success path.
- **Mechanical detection / how to apply next time:** Every PARTIAL
  handler gets unit tests for: binary-missing, list-timeout,
  list-rc≠0, extract-timeout, extract-rc≠0, success-path. The
  rc≠0 test is the value-flow gate per Rule #35b — verify the returned
  shape matches `unpack_no_handler` exactly (same field names, same
  None values for file_count/listing).
- **Companion to:** Rule #29 (subprocess timeout discipline — explicit
  timeouts on both phases, asymmetric: 30s probe / 3600s extract);
  Rule #35b (mock-only tests verify dispatch shape; live canaries
  verify value flow).

### 4. Capability claim conservatism via "no public corpus" gate

Despite passing 9 mock tests cleanly, QNX_IFS shipped at PARTIAL (not
FULL) because no public test corpus exists to round-trip a real .ifs
file through the worker. The live canary
`test_unpack_qnx_ifs_live_canary_real_ifs` is `pytest.skip(...)`-marked
with a reason citing the corpus follow-up intake. The intake
(`qnx-ifs-test-corpus-2026-05-07.md`) ranks 6 sourcing options by
license clarity. Promotion PARTIAL→FULL waits on a fixture landing.

- **Description:** Mock-test coverage doesn't promote a handler to
  FULL. Real-input coverage does. PARTIAL is the honest signal when
  no real-input verification is possible at ship time. The
  follow-up intake is the discipline that prevents PARTIAL becoming
  permanent.
- **Where applied:** Commit `3f03ccc` set `EXTRACTION_CAPABILITY[QNX_IFS]
  = PARTIAL` and KEPT `CAPABILITY_NOTES[QNX_IFS]` (FULL formats drop the
  notes per the `test_capability_notes_only_for_partial_or_none`
  invariant); commit `ec687c3` filed the corpus intake.
- **Mechanical detection / how to apply next time:** Any handler whose
  test file contains a `pytest.skip(reason="No <X> corpus available")`
  MUST ship at PARTIAL with a CAPABILITY_NOTES entry. The intake-filing
  commit is the closing commit of the handler group; without it, the
  PARTIAL claim has no path forward.
- **Companion to:** Rule #35b (live canaries are required for value
  flow — when value flow can't be verified, capability must reflect
  that); the `test_capability_notes_only_for_partial_or_none` invariant
  enforces the FULL/PARTIAL/NONE classification at the test layer.

### 5. Per-handler 6-commit shape (Dockerfile + worker + register + capability + tests + intake)

The prior session established a 4-commit (5 with Dockerfile) per-handler
shape; QNX_IFS extends it to 6 by adding the corpus follow-up intake as
its own commit. Each commit is an independently-revertable slice with
its own acceptance grep or smoke check.

| Commit | Subject (verbatim from history) |
|---|---|
| `5be1fff` | chore(backend): build jtang613/qnx_dumpers ifsdump in container |
| `3b4f165` | feat(workers): QNX IFS unpack worker via ifsdump |
| `e5bbefd` | feat(extraction): register QNX_IFS strategy |
| `3f03ccc` | feat(format_detection): bump QNX_IFS capability NONE->PARTIAL |
| `934ee77` | test(unpack_qnx_ifs): subprocess + soft-fail discipline + skip-on-no-corpus canary |
| `ec687c3` | docs(intake): file QNX IFS test corpus follow-up for Phase 2 handler 5 live canary |

- **Description:** Bisect-clean across all 6 commits. Reverting commit
  N rolls back exactly the slice that commit shipped, no more. The
  intake commit is light (one markdown file) but durable — it captures
  the gap that PARTIAL-shipping creates and gives a future session a
  clear starting point.
- **Where applied:** This session's full handler group, `4429f42..ec687c3`.
- **Mechanical detection / how to apply next time:** When the corpus
  is unavailable at ship time, expect 6 commits. When the corpus IS
  available (typical for Phase 1 handlers with public test images),
  expect 4-5 (no separate intake commit; the live canary lights up
  in the test commit).
- **Companion to:** Rule #25 (per-sub-task commits); the prior
  session's `session-2026-05-07-extraction-pipeline-patterns.md`
  pattern #2 (4-commit per-handler shape — this is the
  corpus-deferred extension).

### 6. CLI flag verification against the pinned SHA's README, not the research doc

The dispatch prompt explicitly required: "Verify the actual ifsdump
CLI flags by reading the repo's README at the pinned SHA before
hardcoding `--list` and `-x`." Research docs are written at a moment
in time; even with a pinned SHA, the research doc's flag transcription
may have drifted between the doc's authoring and the implementation
session. The README at the pinned SHA is the canonical source of
truth for that exact code revision.

- **Description:** Rule #6 generalised from "verify CLI flags when
  upgrading versions" to "verify CLI flags against the source-of-truth
  for the version YOU are pinning, not against any intermediate
  document about it." The pinned SHA's README is THE source of truth.
- **Where applied:** Commit `3b4f165`'s worker uses the verified flag
  set; the archon report confirmed `ifsdump -h` runs cleanly in-container
  and lists 12 documented flags matching upstream README at the pinned SHA.
- **Mechanical detection / how to apply next time:** Before hardcoding
  any flag from a research doc, `git show <pinned-SHA>:README.md` (or
  the equivalent `git ls-tree` + `git show`) and grep for the flag
  string. Mismatch → use the README's flag and update the research
  doc in-band.
- **Companion to:** Rule #6 (CLI flag verification on version upgrade);
  Rule #19 (evidence-first); Rule #31 (broad-grep before trusting
  scope counts — same shape: trust the canonical source over the
  intermediate summary).

## Key Decisions Made

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| `jtang613/qnx_dumpers` (MIT) over 4 proprietary alternatives | Only candidate without `$QNXLicenseC$` openqnx 2007 header; only one shippable in OSS container | Capability claim PARTIAL (not FULL) reflects narrower format coverage but legally-clean shipping |
| Pinned upstream SHA (`c621029e`) over branch tracking | Upstream license can flip silently; pinned SHA freezes the snapshot we audited | Future bumps require deliberate review; license surprise mitigated |
| PARTIAL ship + corpus follow-up intake over deferring all QNX work | Mock-test coverage already proves dispatch + soft-fail; real-input verification is a separate gate | 9/12 catalogue (75%) supported now; live canary path is a clear future step |
| Soft-fail-degrade over hard-fail on tool failure | Hard-fail discards the whole firmware unpack; soft-fail preserves what other handlers extracted | Worker shape mirrors `unpack_no_handler` on failure; user sees the workaround pointer |
| 6-commit shape (added intake commit) over 5 | Corpus intake is genuinely independently-verifiable per Rule #25 | Bisect-clean; intake's path is durable independently of the worker code |

## Cross-Reference

- Prior session patterns: `.planning/knowledge/session-2026-05-07-extraction-pipeline-patterns.md`
  (Phase 1 dispatch infra + Phase 2 handlers 1-3: ISO/WIM/Windows installer ISO)
- Research doc: `.planning/knowledge/qnx-ifs-extraction-research-2026-05-07.md`
  (Decision Matrix, license analysis, mitigations)
- Follow-up intake: `.planning/intake/qnx-ifs-test-corpus-2026-05-07.md`
  (6 sourcing options, license-clarity ranking, PARTIAL→FULL gate)
- Strategic roadmap: `.planning/intake/multi-os-firmware-extractor-roadmap-2026-05-07.md`
  (next NONE: ACRONIS_BACKUP)
