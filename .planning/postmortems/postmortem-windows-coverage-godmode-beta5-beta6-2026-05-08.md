# Postmortem: windows-coverage-godmode β.5 + β.6 (Phase β.5 ARM64EC/X arch_view; β.6 RICH header decoder)

> Date: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Duration: ~2 hours (single session, two sub-tasks)
> Outcome: completed (β.5 + β.6 sub-tasks; campaign as a whole still IN PROGRESS — β.7+ remain)

## Summary

Shipped two consecutive Phase β sub-tasks: β.5 added `format_detection.detect_pe_arch_view` (lief-backed ARM64EC/ARM64X bimorphic detector) plumbed through `AuthenticodeVerdict.arch_view` onto `WindowsPESignature.arch_view` JSONB; β.6 added `rich_header_service.decode_rich_header` (pefile-backed Microsoft RICH header parser) plumbed through `AuthenticodeVerdict.rich_header_json` onto `WindowsPESignature.rich_header_json` JSONB. Two clean Rule #25 commits (a5ec238, 5246b85), zero reverts, zero rework cycles, 244 new/updated tests passing.

## What Broke

### 1. lief predicate location surprise

- **What happened:** Initial probe `hasattr(lief.PE, 'is_arm64ec')` returned `False` — the predicate isn't on the `lief.PE` class. The second probe revealed it's an instance attribute on `lief.PE.Binary` (i.e. accessed via `binary.is_arm64x` after `lief.PE.parse()`).
- **Caught by:** Iterative REPL probing in the running container before any code was written.
- **Cost:** ~1 minute (one extra probe round-trip). Zero impact on commits.
- **Fix:** Second probe ran `dir(lief.PE.Binary)` filtered for `'arm64'` — found `is_arm64ec`, `is_arm64x` immediately. Implementation went on the parsed binary, not the class.
- **Infrastructure created:** None needed — the existing wairz pattern of REPL-validating persona-brief library claims (Pattern #7 from this campaign's patterns doc) covers this. The session did exactly what the pattern prescribes.

### 2. Pre-existing α.3 test failure surfaced under β.5 validation

- **What happened:** Targeted pytest run for β.5 caught one failing test — `test_capability_notes_only_for_partial_or_none` — because `WINDOWS_DRIVER_PACKAGE` carries an operator-hint capability note despite `capability=FULL`.
- **Caught by:** β.5's targeted pytest run picked it up as part of `test_format_detection.py`. Stash + re-run on pre-β.5 source confirmed it pre-existed (commit α.3 / 49e5b6b).
- **Cost:** ~3 minutes verifying it was pre-existing rather than introduced. Zero impact on β.5/β.6 commits — the failure was scoped out.
- **Fix:** Documented in β.5 commit message as out of scope; flagged in handoff as a follow-up cleanup. No source change in this session.
- **Infrastructure created:** None this session — but the failure is now visible in two postmortem references and should be cleaned up in a future α-cleanup commit (either fix the test's assumption or move the capability mapping to PARTIAL+note-allowed).

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|----------------|-------|------------------|
| Rule #4 / `test_verdict_maps_to_windows_pe_signature_columns` drift-detector | Required updating `direct_mapped` set when adding `arch_view` (β.5) and again when adding `rich_header_json` (β.6) | 2 | Silent drift between dataclass + ORM column would have shipped; β.7 background runner would have constructed `WindowsPESignature(**asdict(verdict))` and either dropped fields or raised `TypeError` at runtime |
| Rule #11 import smoke (post-`docker cp`) | Green both phases | 2 | Zero catches this session, but the discipline ran cleanly — would have caught any module-scope `NameError` from the new imports (`detect_pe_arch_view`, `decode_rich_header`) |
| Rule #35a real-exit-code pattern (`cmd; rc=$?` not `cmd \| tail`) | Used cleanly throughout β.5 + β.6 | 4+ | Pipe-induced false `exit=0` would have masked a pytest failure; the validation rounds reported the actual pytest exit code (1 for the pre-existing α.3 failure, 0 for β.6's clean run) |
| Rule #30 lazy-import discipline | Applied to lief in `detect_pe_arch_view` and pefile in `decode_rich_header` (both lazy-imported inside the function) | 2 | Format_detection's hot path (called on every upload) would have eagerly loaded ~50 MB of lief + ~10 MB of pefile on every upload; deferred to β.4-style worker invocation only |
| Rule #25 per-sub-task commits | β.5 and β.6 each shipped as one focused commit | 2 | Bundled "feat(β): all of arch_view + RICH" would have been a single 12-file revert surface; per-sub-task commits keep `git revert <sha>` clean per the campaign's "Pattern #8" |

## Scope Analysis

- **Planned (β.5):** "`from app.services.format_detection import ...; lief.is_arm64ec / is_arm64x` predicates produce `arch_view` JSONB on the `windows_pe_signatures` row" (user prompt verbatim).
- **Planned (β.6):** Implicit ("yes proceed" with the recommendation that β.6 = RICH header decoder, similar size and shape to β.5).
- **Built (β.5):** `detect_pe_arch_view` + `AuthenticodeVerdict.arch_view` plumbing + JSONB normalizer triplet + drift-detector update + 30 new tests. Exactly to plan.
- **Built (β.6):** `rich_header_service.decode_rich_header` + `AuthenticodeVerdict.rich_header_json` plumbing + JSONB normalizer triplet + drift-detector update + 30+ new tests. Exactly to plan, mirroring the β.5 shape.
- **Drift:** none. Both sub-tasks landed precisely to spec.

## Patterns

- **β.5 set the template, β.6 reused it.** The shape — `<service>.<entry_function>(path) -> dict | None`, plumbed through `AuthenticodeVerdict.<field>`, normalized via `_normalize_<table>_<column>` + `_stamp_<table>_<column>`, drift-detected via the existing `test_verdict_maps_to_windows_pe_signature_columns` — was identical across both sub-tasks. β.6 was visibly faster to implement (single read-PRD pass + direct mirror of β.5's structure). The "intake-as-recipe" property of the campaign PRD is paying real productivity dividends.
- **Lazy-import discipline applied uniformly.** lief (β.5) and pefile (β.6) both imported inside the function body, both with the same `# noqa: PLC0415 — see docstring.` comment style. Format_detection's `detect_format()` hot path is now provably lief- and pefile-free.
- **Three-way independent parser pattern.** AuthenticodeVerdict now composes verdicts from THREE independent parsers — signify (chain), lief (arch), pefile (RICH). Each parser's failure mode is independent; one failing doesn't compromise the other two. The `_attached_when_*_fails` test family (4 tests across β.5 + β.6) verifies this discipline.
- **Sanity-bound parsing.** β.6's `_MAX_ENTRIES = 1000` cap on RICH header entries is the kind of bound that's cheap to add at write time and hard to retrofit. Phase γ/δ writers that introduce new JSONB sub-keys with iterated entries should follow this template.

## Recommendations

1. **Fix the pre-existing α.3 test inconsistency** in a follow-up commit: either remove `WINDOWS_DRIVER_PACKAGE` from `CAPABILITY_NOTES`, or relax `test_capability_notes_only_for_partial_or_none` to permit operator-hint notes on FULL-capability formats. Single-line change; was visible to β.5/β.6 validation but out of scope.
2. **Promote the "service + verdict-field + normalizer triplet + drift-detector" shape** to a `.mex/patterns/add-pe-verdict-field.md` recipe — β.7 (DBX matcher) and any future β/γ/δ verdict extensions will benefit from the explicit template. β.5 + β.6 are now two repetitions; one more (β.7) and we have a durable Rule of Three.
3. **Background runner (β.7+) should consume the verdict structurally**, not field-by-field. The drift-detector pattern only catches MISSING fields; constructing `WindowsPESignature(**{k: v for k, v in asdict(verdict).items() if k in {direct_mapped}})` keeps the boundary loose. β.8 should explicitly use this shape.
4. **Consider a Phase β recap commit before β.13 cut-over** that lists the 8 verdict-derivable columns (signed, chain_status, signer_subject, signer_issuer, leaf_serial, sig_hash_algo, tsa_authority, signed_at, chain_json, arch_view, rich_header_json — ten now) and verifies they all map cleanly. The drift-detector covers the dataclass↔model side, but there's no coverage of dataclass↔dict-key side after `asdict()`.

## Numbers

| Metric | Value |
|--------|-------|
| Sub-tasks planned (this session) | 2 (β.5, β.6) |
| Sub-tasks completed | 2 |
| Commits | 2 (a5ec238, 5246b85) |
| Files added | 2 (rich_header_service.py, test_rich_header_service.py) |
| Files modified | 4 each commit (3 unique source + 1 unique test, plus 1 shared each) |
| Total LOC delta | +1359 / -3 |
| Tests added/updated | 60+ (30 β.5 + 30+ β.6) |
| Failing tests | 1 (pre-existing α.3, out of scope) |
| Reverts | 0 |
| Rework cycles | 0 |
| Circuit breaker trips | 0 (none recorded in telemetry for this session) |
| Quality gate blocks | 0 |
| Anti-pattern warnings | 0 |
| Rule #11 import smoke runs | 2 (both green) |
| Rule #25 commits | 2 (one per sub-task) |
| Rule #30 lazy-import applications | 2 (lief, pefile) |
| Rule #35a `cmd; rc=$?` patterns | 4+ |
| Rule #35c JSONB normalizer triplets added | 2 (arch_view, rich_header_json) |

---HANDOFF---
- Postmortem: windows-coverage-godmode β.5 + β.6
- Document: .planning/postmortems/postmortem-windows-coverage-godmode-beta5-beta6-2026-05-08.md
- Failures documented: 2 (1 minor library-API surprise; 1 pre-existing α.3 inconsistency surfaced)
- Safety catches: 5 (drift-detector x2, Rule #11 import smoke, Rule #35a exit-code, Rule #30 lazy-import, Rule #25 per-sub-task commits)
- Recommendations: 4
---
