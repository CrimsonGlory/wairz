# Patterns: Windows-Coverage God-Mode β.5 + β.6 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta5-beta6-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: a5ec238 (β.5), 5246b85 (β.6)
> Status: 2 sub-tasks completed; campaign as a whole IN PROGRESS (β.7+ remain)

This is an incremental extraction layered on top of the prior pair
(`windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md`). Patterns
already captured there are not re-stated; this file captures only the
β.5/β.6-delta learnings.

## Successful Patterns

### 1. Three-way independent parser composition inside one verdict

- **Description:** `AuthenticodeVerdict` now carries data from THREE
  independent parsers — signify (chain validation), lief (ARM64EC/X
  detection), pefile (RICH header). Each call runs separately
  (`detect_pe_arch_view(p)`, `decode_rich_header(p)`, `AuthenticodeFile.from_stream(fh)`),
  and each parser's failure is caught independently. The verdict
  always ships with whatever data each parser produced; one failing
  doesn't compromise the other two.
- **Evidence:** β.5 (a5ec238) added `arch_view` plumbing through 4
  paths in `verify_pe_file` (success, OSError, generic Exception,
  inner verdict assembly). β.6 (5246b85) repeated the exact same
  4-path plumbing for `rich_header_json`. The four `_attached_when_*_fails`
  tests verify that signify failures don't lose arch_view / rich_header.
- **Applies when:** Any verdict-style service that composes multiple
  independent parsers. The mechanical rule: each parser is called
  with its own try/except, results are stored in local variables BEFORE
  the next parser runs, and every error-path return constructor
  receives the local variables explicitly. No shortcut — the inner
  verdict's "happy path" mutates a verdict instance whereas the error
  paths construct one fresh; both must populate every parser-derived
  field. The drift-detector test (`test_verdict_maps_to_<table>_columns`)
  enforces no field is silently dropped.

### 2. Verdict-field mirror discipline pays double-dividends on the second application

- **Description:** β.5 set the template — service module
  (`detect_pe_arch_view` in format_detection.py, `decode_rich_header`
  in rich_header_service.py) returning `dict | None`, plumbed through
  `AuthenticodeVerdict.<field>`, normalized via Rule #35c triplet,
  drift-detected via the existing `test_verdict_maps_to_<table>_columns`.
  β.6 mirrored the shape verbatim — same try/except plumbing across
  the same four code paths in `verify_pe_file`, same JSONB normalizer
  template (canonical → identity, None → None, wrong-typed → None,
  empty → None on stamp), same drift-detector update.
- **Evidence:** β.5 commit shipped 156 LOC of new format_detection
  code + 60 LOC of normalizer + 216 LOC of tests. β.6 shipped 170
  LOC of rich_header_service + 65 LOC of normalizer + 269 LOC of
  tests — visible time savings on β.6 because the structure was
  copy-and-modify, no architectural decisions left to make. Zero
  reverts, zero rework cycles across both sub-tasks.
- **Applies when:** Adding the Nth sub-task in a campaign whose first
  N-1 sub-tasks established a clear template. The signal is "this
  sub-task is structurally identical to the previous one" — at that
  point, copy the template wholesale, then only the data shapes (which
  parser, which JSONB sub-key, which test names) change. Rule #25
  per-sub-task commits keep each repetition independently revertable
  even when the structures rhyme.

### 3. Sanity-bounded iteration on writer-side for new JSONB sub-keys

- **Description:** β.6's `_MAX_ENTRIES = 1000` cap on RICH header
  entries — a malformed PE whose XOR'd values stream walks off into
  garbage could in principle produce arbitrary entry counts; the cap
  bounds JSONB row size at write time before bad data persists. The
  bound is documented inline ("largest legitimate Microsoft binary
  carries ~80 RICH entries; 1000 is well above any plausible
  legitimate maximum"). Verified by an explicit
  `test_decode_entries_clamped_to_max` test asserting the cap holds
  under 4× input.
- **Evidence:** β.6 commit `5246b85`,
  `backend/app/services/rich_header_service.py:62` plus the matching
  test in `test_rich_header_service.py`.
- **Applies when:** Any new JSONB writer that iterates an
  externally-controlled sequence. The mechanical question is
  "what's the largest legitimate value the upstream parser produces,
  and what happens if a malformed input pushes past it?". An
  empirical cap (5-10× the largest known legitimate count) plus a
  test asserting the cap holds is a 5-line addition that prevents
  unbounded JSONB growth + a class of degraded-row attacks. Companion
  to Rule #35c's normaliser discipline — the normaliser is the
  read-side gate, the cap is the write-side gate.

### 4. REPL-validation pattern's second instance — predicate location

- **Description:** Pattern #7 from the prior knowledge file (Empirical
  REPL-validation of persona-brief library claims) reproduced in β.5
  with a tighter loop: the user's prompt said
  `lief.is_arm64ec / is_arm64x predicates` — the implication was that
  the predicates live on the `lief.PE` class. First REPL probe
  (`hasattr(lief.PE, 'is_arm64ec')`) returned False; second probe
  (`dir(lief.PE.Binary)`) found them as instance attributes. Total
  recovery time ~1 minute; if the implementation had been written
  to the prompt's literal shape, the failure would have surfaced at
  test time as `AttributeError` and triggered a rework cycle.
- **Evidence:** β.5 session transcript — two consecutive
  `docker compose exec ... python -c` probes before the implementation
  was written.
- **Applies when:** Any time a prompt or persona brief asserts a
  specific API shape (function, attribute, class location) for an
  external library. The 1-minute REPL probe before coding is dramatically
  cheaper than `AttributeError` at test time. Generalises to
  prompt-given API claims, not just persona briefs — even a user-supplied
  description benefits from empirical validation against the running
  container's installed version.

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | Plumb arch_view + rich_header_json through AuthenticodeVerdict rather than separate verdicts | The WindowsPESignature model docstring already groups Authenticode + RICH + DBX + ARM-arch as "per-PE record"; one verdict object is the natural abstraction; the cost of growing the dataclass is bounded by the drift-detector | Both β.5 and β.6 shipped cleanly with zero rework; verdict now has 3-parser composition (signify + lief + pefile) |
| 2 | β.6 hash_md5 falls back to manual MD5 if pefile.get_rich_header_hash() raises | pefile's hash method has minor version-to-version variability; the cluster fingerprint is non-cryptographic so MD5 is fine; the fallback ensures the hash is always populated | Test `test_decode_rich_header_falls_back_when_pefile_hash_unavailable` proves the fallback works; ships green |
| 3 | ARM64X precedence over ARM64EC in `detect_pe_arch_view` | An ARM64X binary's machine type can be reported as ARM64EC depending on which loader half is preferred; the predicate is authoritative; bimorphic surface is the durable signal | Test `test_detect_pe_arch_view_arm64x_takes_precedence_over_arm64ec` enforces; β.5 ships green |
| 4 | β.6 _MAX_ENTRIES = 1000 cap on RICH entries | Largest legitimate Microsoft binary has ~80 entries; 1000 is well above any plausible legitimate count; explicit cap protects JSONB row size from malformed PE inputs | β.6 ships with explicit clamp test; cap is documented inline |
| 5 | β.6 lazy-import pefile inside `decode_rich_header` (Rule #30) | format_detection's `detect_format()` hot path runs on every upload and must stay cheap; pefile is a moderate-cost import; only the worker-container Authenticode path needs it | Confirmed: format_detection module imports remain stdlib-only |
| 6 | Skip a quality-rule addition for the verdict-field-mirror pattern | The `test_verdict_maps_to_<table>_columns` drift-detector test is already enforcing the discipline; a regex-based harness rule would be either too vague or too narrow; the runtime test catches every drift case | No new harness rule from β.5+β.6; existing drift-detector + Rule #4 cover the surface |
