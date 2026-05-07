---
title: "Source QNX IFS test corpus for live canary"
status: pending
priority: normal
target: backend/tests/fixtures/qnx_ifs/
discovered: 2026-05-07
type: test-fixture
session: 2026-05-07-handler-5
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

## Sourcing options (in suggested priority order)

1. **BMW HU NBT EVO sample.** The HAKSTUFF blog walkthrough referenced
   in the research doc explicitly extracts a BMW IFS via
   `dumpifs-folderized.sh`. Real BMW HU firmware images circulate on
   automotive RE forums (BimmerForums, BimmerFest); finding a sample
   with a known-public license posture is the gating step.
2. **Audi A5/S5 MMI ifs-root.ifs.** The a5oc.com forum thread
   (cited in the research doc) describes manually extracting the
   ifs-root.ifs from MMI head units. Same caveat re. license posture.
3. **Public QNX SDP demo images.** QNX has historically shipped demo
   IFS images with the SDP (e.g. `aarch64le-ifs.bin` from the QNX
   8.0 SDP demos). Under the Free Non-Commercial license the SDP
   itself is not redistributable, but a USER-built IFS from
   `mkifs` against an open-source demo template MAY be — verify.
4. **OpenQNX archives.** `vocho/openqnx` (the 2007 source release
   mirror) ships a small selftest corpus under
   `trunk/utils/m/mkxfs/dumpifs/test/` — verify license; even if the
   source files are unredistributable, the test IFS images may be
   under a clearer posture.
5. **Build our own.** Use `mkifs` from a downloaded QNX SDP (Free
   Non-Commercial) with a hand-authored mkifs build script + a tiny
   busybox-style binary. This is the cleanest legal posture (we
   produce the IFS from scratch using a tool we're licensed to use)
   but requires standing up the QNX SDP build environment.
6. **Ask jtang613 directly.** Open an issue against jtang613/qnx_dumpers
   asking whether the author has a small test fixture they're
   willing to license under the same MIT terms as the source.

## Re-open trigger

Any of:
- A wairz user uploads a QNX IFS that ifsdump fails to extract
  (look for `unpack_log` containing `QNX IFS extraction failed`
  in production data) — a real production failure IS a corpus.
- A public QNX IFS test corpus is published upstream (e.g. unblob
  ships their private QNX IFS handler).
- Phase 3 cycle picks up this intake explicitly.

## Cross-references

- `.planning/knowledge/qnx-ifs-extraction-research-2026-05-07.md` —
  research doc with full Decision Matrix and license analysis.
- `.planning/knowledge/session-2026-05-07-extraction-pipeline-patterns.md` —
  patterns extracted from the prior 4-handler shipping session.
- `backend/app/workers/unpack_qnx_ifs.py` — the worker module.
- `backend/tests/test_unpack_qnx_ifs.py:test_unpack_qnx_ifs_live_canary_real_ifs` —
  the skip marker to remove.
