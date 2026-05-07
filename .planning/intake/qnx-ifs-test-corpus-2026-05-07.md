---
title: "Source QNX IFS test corpus for live canary"
status: pending
priority: normal
target: backend/tests/fixtures/qnx_ifs/
discovered: 2026-05-07
type: test-fixture
session: 2026-05-07-handler-5
last_attempt: 2026-05-07
last_attempt_session: stream-gamma-fleet-wave1
---

## Context

Phase 2 handler 5 (QNX IFS extraction via jtang613/qnx_dumpers
ifsdump) shipped 2026-05-07 in commits `5be1fff..934ee77` on
`clean-history` with capability `PARTIAL` and a complete soft-fail
mock-test suite (9 mock tests + 1 skipped live canary). The live
canary is **skipped** because no public QNX IFS test corpus was
identified during the handler-build session.

This is a Rule #35b coverage gap — mock tests verify "the contract
we wrote", a live canary verifies "the contract ifsdump actually
has against real-world IFS variants". The gap is documented and
acceptable for ship (PARTIAL capability already telegraphs unverified
breadth) but should be closed when a fixture is available.

## Acceptance criteria

- A `.ifs` fixture committed under `backend/tests/fixtures/qnx_ifs/`
  whose round-trip through `ifsdump --list` and
  `ifsdump -d <dir> --extract <ifs>` returns exit 0 in both phases
  AND produces at least one extracted file.
- The skip marker on
  `test_unpack_qnx_ifs_live_canary_real_ifs` in
  `backend/tests/test_unpack_qnx_ifs.py` removed.
- The body of the live-canary test implemented per the docstring
  outline (read fixture, call worker, assert success + extracted-file
  set + log markers).
- Targeted pytest `tests/test_unpack_qnx_ifs.py` shows 10/10 passing
  (was 9 passed + 1 skipped).
- Capability claim review: if the live canary passes cleanly on ≥3
  distinct IFS variants from the corpus, consider promoting QNX_IFS
  to `FULL` in `backend/app/services/format_detection.py` and updating
  `CAPABILITY_NOTES`.

## Sourcing attempt log (2026-05-07, stream-gamma)

Comprehensive sweep of every option from the original priority list
plus several adjacent paths. **Conclusion: no committable fixture
sourced.** All paths blocked on license posture.

### Option 4 — OpenQNX archive corpus → NEGATIVE

`vocho/openqnx` `trunk/utils/m/mkxfs/dumpifs/` contains only
`Makefile`, `dumpifs.c`, `module.tmpl`, and empty platform-specific
build dirs (`linux/`, `nto/`, `solaris/`, `win32/`). **No `test/`
subdirectory**, no `.ifs` fixtures. The intake's "trunk/utils/m/mkxfs/
dumpifs/test/" claim was incorrect. Verified via `gh api "repos/vocho/
openqnx/contents/trunk/utils/m/mkxfs/dumpifs"` 2026-05-07.

Additionally, `dumpifs.c` carries the proprietary `$QNXLicenseC$`
header verbatim, so even if a test corpus existed under that tree
it would inherit the same restrictive license.

### Option 6 — jtang613/qnx_dumpers fixture → NEGATIVE

Repo top-level: `.gitignore`, `Makefile`, `README.md`,
`class_diagram.mermaid`, `efsdump.c`, `ifsdump.c`. **No fixture
files, no `test/` directory.** Issue tracker has 0 issues (state=all).
README has no test-corpus links. Per Hard Constraints in the dispatch
prompt, did NOT open an issue against the upstream repo.

Verified via `gh api "repos/jtang613/qnx_dumpers/git/trees/master?
recursive=1"` and `gh api "repos/jtang613/qnx_dumpers/issues?state=all"`
2026-05-07.

### Option 5 — Build with mkifs from QNX SDP → BLOCKED

`mkifs` is NOT available in the backend container; QNX SDP is NOT
installed on the deployment host (`which mkifs` → empty; `/opt/qnx*`
and `~/qnx*` do not exist). Standing up a QNX SDP requires accepting
the Free Non-Commercial license whose redistribution terms forbid
publishing fixture artifacts in a public repo / Docker image regardless
of how the IFS was built. Even a "we built this from open-source
inputs ourselves" stance doesn't help: the IFS necessarily contains
the QNX startup header and bootstrap glue, both of which are QNX
runtime-licensed components.

The community port `bigunclemax/mkxfs` (9 stars, last update
2026-04-25) is forked from openqnx and **its `dumpifs/dumpifs.c`
carries the proprietary `$QNXLicenseC$` header verbatim** (verified
2026-05-07). Same legal blocker — using mkxfs to build a fixture
locally would be permissible for personal RE work but the resulting
binary would carry QNX runtime components, and the build tool itself
cannot be vendored into wairz's image.

### Options 1+2 — BMW HU NBT EVO / Audi MMI samples → DEFERRED (legal)

Per intake hard constraints, did NOT search for or download
forum-hosted automotive head-unit firmware. Those dumps carry no
clear license posture and risk inheriting BMW/Audi/Harman copyright
on top of QNX runtime licensing — strictly worse than option 3.

### Option 3 — Public QNX SDP demo IFS → BLOCKED (academic-only)

`varghes/Raspberry-QNX/working_image/ifs-bcm2835.bin` (44.5 MB)
appears in a public Apache-2.0-licensed repo, **and round-trips
cleanly through ifsdump** (verified 2026-05-07: list exit=0, extract
exit=0, **190 extracted files** under `bin/`, `etc/`, `lib/`,
`proc/`, `usr/` — mature Linux-style rootfs from QNX Neutrino 6.5.0
SP1 BSP for the BCM2835).

**However**, the upstream README explicitly says: *"Source code is
distributed under Apache License, and final QNX Image distribution
requires run time license for each system. Contact QNX."* The
binary IFS is NOT covered by Apache 2.0; it requires a separate QNX
runtime license. Web search confirms: *"the Raspberry QNX Image
file (ifs-bcm2835.bin) is provided strictly for academic use, and
final QNX Image distribution requires a run time license for each
system."*

Per intake hard constraint ("DO NOT commit any firmware blob without
a clear license posture"), did NOT commit this file. Test fixture
was downloaded to `/tmp/test-ifs.bin` for round-trip verification
only, then deleted.

The official QNX Quick Start Target Image at
`gitlab.com/qnx/quick-start-images/raspberry-pi-qnx-8.0-quick-start-image`
ships under the QNX Free Non-Commercial license whose redistribution
terms forbid public-repo / Docker image inclusion (per research doc
section Q3). Confirmed not viable.

### Adjacent search — NetherlandsForensicInstitute/qnxmount → NEGATIVE

25-star repo (most popular QNX forensics project on GitHub).
`tests/` directory contains `qnx6/`, `qnx_efs/`, `qnx_etfs/`
fixtures — **but no `qnx_ifs/`**. The IFS format is genuinely
underrepresented even in academic forensics tooling. Confirmed
2026-05-07.

### Adjacent search — gvergine/ifsx → NEGATIVE

QNX IFS Extract / Repack tool (Java/Gradle). 0 stars, no LICENSE
file, no fixtures committed. The `testing/docker/Dockerfile`
expects a user-provided `~/qnx-build/image.ifs` — i.e. the upstream
test approach is also "build your own with QNX SDP locally."

### Adjacent search — RozikSv/dumpifs-qnx → NEGATIVE

Single Windows binary `dumpifs-qnx.exe` + a `proto/` directory
containing only `update_metadata.proto`. No fixtures, no LICENSE.
0 stars.

### Adjacent search — unblob qnx_deflate test fixtures → NEGATIVE (wrong format)

`onekey-sec/unblob/tests/integration/compression/qnx_deflate/`
contains `lorem_ipsum.deflated` and `lorem_ipsum_ulc.deflated`
(129 bytes each) — these are bare LZO/UCL compression streams
beginning with `iwlyfmbp` magic, NOT IFS images with the
`eb7eff7e` startup-header magic. They would not pass the IFS
format-detection check at `format_detection.py:211`. Useful as
Rule #6 reference for the LZO/UCL block format but not a fixture
candidate for the live canary.

## Concrete next-action recommendation

The most promising remaining path is **direct outreach to the QNX
community** asking for a permissively-licensed IFS test fixture.
Two specific options the user could authorise:

1. **File a friendly issue at `jtang613/qnx_dumpers`** asking the
   author whether they have a small synthetic IFS (built with their
   own toolchain or a permissive subset) that they'd be willing to
   license under MIT alongside the source. The author is active
   (commits in 2025) and the test corpus would benefit upstream too.
2. **Ask in the QNX Software Reverse Engineering community channels**
   (the OSDev forum, the active QNX Discord referenced in
   `qnx.com/products/everywhere`, the r/QNX subreddit) for an
   academic-only minimal IFS that someone has built and is willing
   to license under MIT for downstream redistribution.

Both options require external messaging and are out of scope for
autonomous agents per the dispatch prompt's "do not open issues or
send external messages without explicit user permission" hard
constraint. **Decision needed from the user**: do either of these
fit Wairz's external-comms policy?

If yes → user files the request, and the next agent dispatch can
land the fixture once a response arrives. If no → the live canary
stays skipped indefinitely and the PARTIAL capability claim is
the durable answer.

## Re-open trigger

Any of:
- A wairz user uploads a QNX IFS that ifsdump fails to extract
  (look for `unpack_log` containing `QNX IFS extraction failed`
  in production data) — a real production failure IS a corpus.
- A public QNX IFS test corpus is published upstream (e.g. unblob
  ships their private QNX IFS handler with fixtures).
- jtang613/qnx_dumpers grows a `test/` directory.
- BlackBerry releases QNX SDP demo IFS images under a redistribution-
  permissive license.
- User authorises one of the outreach actions above and gets a
  positive response.

## Cross-references

- `.planning/knowledge/qnx-ifs-extraction-research-2026-05-07.md` —
  research doc with full Decision Matrix and license analysis.
- `.planning/knowledge/session-2026-05-07-extraction-pipeline-patterns.md` —
  patterns extracted from the prior 4-handler shipping session.
- `backend/app/workers/unpack_qnx_ifs.py` — the worker module.
- `backend/tests/test_unpack_qnx_ifs.py:test_unpack_qnx_ifs_live_canary_real_ifs` —
  the skip marker to remove.
