# Anti-patterns: Windows-Coverage God-Mode β.5 + β.6 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta5-beta6-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`

This is an incremental extraction layered on
`windows-coverage-godmode-2026-05-07-antipatterns.md` (the prior
α-phase + β.1-β.4 anti-patterns). Patterns already captured there are
not re-stated; this file captures only the β.5/β.6-delta failures.

## Failed Patterns

### 1. Trusting the prompt's literal API shape without REPL validation — second instance

- **What was done:** β.5 prompt asserted "`lief.is_arm64ec / is_arm64x`
  predicates produce `arch_view` JSONB". The literal reading suggested
  the predicates live on the `lief` module or `lief.PE` class. First
  REPL probe (`hasattr(lief.PE, 'is_arm64ec')`) returned False —
  predicates are NOT class-level static methods or module attributes.
- **Failure mode:** lief 0.17.x exposes `is_arm64ec` and `is_arm64x` as
  INSTANCE properties on `lief.PE.Binary` — set at PE-parse time based
  on machine type and CHPE-metadata presence. Coding to the literal
  prompt would have produced `AttributeError: type object 'PE' has no
  attribute 'is_arm64ec'` at test time, requiring rework.
- **Evidence:** β.5 session transcript shows the first probe explicitly
  catching the surprise, second probe locating the correct attribute
  path. Recovery time <1 minute.
- **How to avoid:** This is a fresh instance of the pattern already
  captured (Pattern #7, prior knowledge file: empirical REPL-validation
  of persona-brief library claims). Generalised: ANY API claim in any
  upstream artifact (prompt, persona brief, blog post, doc string,
  recent SO answer) gets a 1-minute REPL probe BEFORE the
  implementation is written. The cost is microscopic; the prevented
  rework is multi-minute. The prior captured pattern was about persona
  briefs; β.5 demonstrated the same pattern applies to user prompts.

### 2. Pre-existing α.3 inconsistency surfaced during validation but not addressed

- **What was done:** β.5's targeted pytest run included
  `test_format_detection.py` because that's the file the new function
  lives in. The run reported one pre-existing failure:
  `test_capability_notes_only_for_partial_or_none` — it asserts that
  `CAPABILITY_NOTES` only carries text for PARTIAL/NONE-capability
  formats, but `WINDOWS_DRIVER_PACKAGE` (capability=FULL) carries an
  operator-hint note about reclassification. Stash + replay on
  pre-β.5 source confirmed this pre-exists from α.3 (commit 49e5b6b).
- **Failure mode:** The failure isn't β.5's bug to fix, but it's now
  an actively-failing test in the suite — every future β/γ/δ targeted
  run that touches `test_format_detection.py` will see one red entry
  and have to mentally tag "pre-existing, not me". That's cognitive
  toll on every future change in the file.
- **Evidence:** β.5 commit message explicitly notes the failure as
  out-of-scope. Stash-replay validated.
- **How to avoid:** When a "pre-existing failing test" surfaces during
  validation, two clean responses: (a) fix it as a separate pre-commit
  in the same session if cheap (single-line change here — relax the
  test, OR switch WINDOWS_DRIVER_PACKAGE to PARTIAL+note-allowed); (b)
  if non-trivial, file an explicit `.planning/intake/<slug>.md` cleanup
  item in the SAME commit so the cognitive toll has a documented end
  date. β.5 did neither — the postmortem's Recommendation #1 documents
  it but no intake item was filed. Filing the intake is cheaper than
  re-explaining "yes this is pre-existing" on every future targeted
  run.

## Notes — failures considered but not captured

- **3-parser plumbing redundancy.** `verify_pe_file` now has FOUR
  return paths (success, OSError, generic Exception, inner verdict
  assembly), each populating `arch_view` AND `rich_header_json` AND
  the standard chain fields explicitly. β.7 will add a fourth parser
  (DBX matcher) and the fourth-path manual replication will cost
  ~12 lines. This is on the verge of becoming an anti-pattern (DRY
  violation), but isn't there yet — the structural redundancy is
  bounded (parser count is small) and the alternative (a builder
  pattern or pre-flight aggregator) costs more in indirection than
  the redundancy costs in line count. Watch for β.7 to push it over
  the line; promote to anti-pattern if it does.

- **JSONB normalizer test parametrize duplication.** β.5 + β.6's
  normalizer tests have nearly identical structure (same parametrize
  shape, same idempotent + stamp assertions). Could be extracted to
  a parametrized fixture shape that takes the
  `(normalize_fn, stamp_fn, schema_version_const, canonical_example)`
  tuple. Not yet — the explicit shape is more readable than the
  parametrized version, and the cost of the duplication is ~30 lines
  per new sub-key. If Phase γ/δ add 4+ more JSONB sub-keys, revisit.
