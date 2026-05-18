---
name: cross-stack-alignment-test
description: Write a single-file regression canary asserting N source-of-truth surfaces enforce the same conceptual contract via their idiomatic shapes. Pairs with CLAUDE.md Rule #25 single-slice exception #2 (cross-stack-alignment commit shape) — durable Rule-of-Nine beyond debate.
triggers:
  - "cross-stack alignment"
  - "source-of-truth drift"
  - "alignment test"
  - "N surfaces same contract"
  - "pairwise agreement test"
  - "Rule #25 cross-stack"
edges:
  - target: context/conventions.md
    condition: to read the Verify Checklist's Rule #21 + Rule #25 + Rule #46 entries before authoring
  - target: patterns/INDEX.md
    condition: as the index that routes here from "alignment test" trigger words
last_updated: 2026-05-18
---

# Cross-Stack Alignment Test

## Context

When **two or more source-of-truth surfaces** (a DB CHECK constraint + a Pydantic
`Literal` + a frontend `Record<UnionType, Config>` map; a curated-tier
narrowing-field allowlist + a banner-pin family-only gate at a different layer;
a parser's exposed tuple + a loader's private allowlist) **enforce the same
conceptual contract**, silent drift between them is a known recurring failure
mode in wairz. CLAUDE.md Learned Rule #25 single-slice exception #2 codifies
the *commit-shape* for landing such changes; this recipe codifies the *test
shape* that catches drift after the surfaces are aligned.

The discipline is Rule-of-Nine durable beyond debate (see Evidence section
below). Cost per surface alignment: ~1 hour to author the test; ~0 maintenance.
Value: refactor signals surface as load-bearing CI failures instead of silent
production-output bugs.

## When to use

Trigger this recipe when **any** of the following is true:

- A new feature requires landing the same enum / allowlist / contract across
  ≥2 layers (e.g. extending a `FindingSource` `Literal` PLUS a DB CHECK PLUS a
  frontend config map — the canonical Rule-of-Eight β.12a..ζ.3.C shape).
- An existing gate has drifted between layers (e.g. one layer rejects entries
  the other accepts — typical post-refactor symptom) and you want a regression
  canary against re-drift.
- A reviewer has flagged a "double-source" risk where two in-tree constants
  represent the same logical concept and a runtime-derived single source isn't
  cheap (e.g. circular-import blocking lazy import; cross-domain coupling
  that defeats the unification benefit).

The discipline is REQUIRED — not optional — for any narrowing-field allowlist
or finding-source allowlist that crosses backend ↔ frontend OR curated-tier ↔
banner-pin-tier boundaries.

## Shape — five mandatory test parts

```python
# 1. Paired rejection — each layer rejects its dialect of the antipattern
def test_<layer1>_rejects_<antipattern>() -> None:
    """Layer 1 — synthesize the conceptual antipattern in L1's dialect; assert reject."""
    ...

def test_<layer2>_rejects_<antipattern>() -> None:
    """Layer 2 — synthesize same antipattern in L2's dialect; assert reject."""
    ...

# 2. Paired acceptance — each narrowing dimension in each layer's allowlist accepts
@pytest.mark.parametrize("narrowing_field,narrowing_value", [<L1 fields>])
def test_<layer1>_accepts_each_narrowing_field(...) -> None: ...

@pytest.mark.parametrize("narrowing_field,narrowing_value", [<L2 fields>])
def test_<layer2>_accepts_each_narrowing_condition(...) -> None: ...

# 3. Size-lock — both allowlists at their CURRENT documented sizes (drift = test edit)
def test_<layer1>_narrowing_field_count_documented() -> None:
    assert len(<L1_allowlist>) == <N1>, "L1 allowlist size changed; update test + postmortem"
    assert set(<L1_allowlist>) == {<expected fields>}, "L1 field set changed; update test"

def test_<layer2>_narrowing_condition_count_documented() -> None:
    assert len(<L2_allowlist>) == <N2>, "L2 allowlist size changed; update test + postmortem"

# 4. Cross-layer alignment proper — antipattern in BOTH dialects; both reject
def test_cross_layer_both_reject_same_conceptual_antipattern() -> None:
    """The alignment test core: BOTH layers reject the SAME conceptual antipattern
    via their idiomatic shapes. Asymmetry in reject mode (WARN+skip vs raise) is
    intentional — assert via each layer's own shape, NOT a forced common mode."""
    ...

# 5. META-CANARY (Rule #46) — confirm the gate's diagnostic output is actually emitted
def test_alignment_gate_canary_synthesizes_a_real_rejection() -> None:
    """Rule #46 META-CANARY: synthesize a CLEARLY-bad entry; confirm the gate's
    WARN/error contains the diagnostic substring operators rely on. Without this,
    a future refactor could silently weaken the synthesized antipattern so that the
    rejection tests above pass without exercising the rejection path."""
    ...
```

## Asymmetry tolerance — design principle, not a bug

Each layer's reject **mode** is its idiomatic shape:

- The curated-tier YAML loader runs against a long YAML; per-entry errors must
  NOT gate every CVE match. Reject mode = **WARN + skip the entry**.
- The BT banner-pin loader runs against a shorter pin set; fail-loud is
  acceptable. Reject mode = **raise ValueError**.

The asymmetry is **the mode, not the contract**. Both reject the conceptual
antipattern. The test asserts via each layer's idiomatic shape:

- `with _caplog_at(L1_LOGGER) as records: ...; assert any("antipattern-name" in r.message for r in records)` for the WARN-mode layer.
- `with pytest.raises(ValueError, match=r"<expected message>"): ...` for the raise-mode layer.

A name-equality assertion across dialects (e.g. asserting both allowlists
literally contain the string `"chipset_regex"`) would be a **false alignment**
— the dialects are intentionally different (regex-flavor strings vs
frozenset/regex/int conditions). The test asserts **SHAPE-equivalence**, not
name-equality.

Document this asymmetry in the test module docstring so a future reader doesn't
"normalise" it into a brittle common-mode assertion.

## Worked example — `d641f28` (F-FORENSIC-10 alignment, 2026-05-15 evening)

**Surfaces:**
- L1 = `cve_matcher._KNOWN_FIRMWARE_NARROWING_FIELDS` — 4 regex-flavor narrowing
  fields (`chipset_regex`, `category_regex`, `version_regex`, `vendor_regex`).
  Reject mode: **WARN + skip** at `_parse_known_firmware_data`.
- L2 = `patterns_loader._parse_banner_cve_pin` family-only check — 6
  frozenset/regex/int conditions (`codename_in`, `chipset_target_in`,
  `banner_match`, `build_date_before`, `build_id_lt`, `signed_eq`). Reject mode:
  **raise ValueError** at `patterns_loader.py:1034-1051`.

**Conceptual contract enforced by both:** "family / identity alone is insufficient
to attribute a CVE — at least one narrowing dimension MUST be present."

**Test file:** `backend/tests/test_forensic10_alignment.py` (in `d641f28`).
- 7 declared tests; 16 cases via parametrize over the 4+6 narrowing dimensions.
- Module docstring documents asymmetry as intentional.
- META-CANARY asserts the L1 WARN message contains the rejected entry name
  AND all 4 narrowing-field names — without that META-CANARY, a future
  refactor could silently weaken the WARN diagnostic without test detection.

**Read it.** When authoring a new alignment test, read `d641f28`'s test file
end-to-end as the working reference. The module docstring's asymmetry
commentary is part of the recipe.

## Two commit shapes — pick the right one

**Shape 1 — multi-surface change in ONE atomic commit (Rule #25 single-slice exception #2).**
When the change ADDS a new entry / extends an enum / lands a new contract
across N surfaces simultaneously, ALL N surfaces + the alignment test land
in ONE commit. Splitting leaves the alignment test RED between commits and
breaks bisect-clean lanes. Per CLAUDE.md Rule #25 single-slice exception #2
worked examples (Rule-of-Eight Windows-coverage chain, 2026-05-06..05-10).

**Shape 2 — alignment regression canary on EXISTING surfaces.**
When all N surfaces already exist (e.g. after a multi-session evolution where
each layer's gate landed independently), just commit the test as a regression
canary. The test alone protects against future drift. The 9th instance —
`d641f28` (F-FORENSIC-10 evening session) — is the first explicit Shape-2
case in wairz. Commit type prefix `test(<scope>):` rather than `feat(<scope>):`.

**Mechanical decision:** is the alignment test landing alongside a NEW surface
or new entries to an existing surface? Shape 1. Otherwise Shape 2.

## Steps

1. **Identify the surfaces.** Grep for the conceptual contract across the
   backend + frontend. Run twice with progressively broader patterns per
   Rule #31 width-canary — the first count is often an under-count.

2. **Codify per-layer narrowing/condition allowlist.** Each layer should
   either expose an explicit `_<LAYER>_NARROWING_FIELDS` tuple/frozenset OR
   the gate's reject logic should be `inspect.getsource`-able for a
   parametrize fixture. Explicit export is the durable shape (Reviewer A A2
   `evening:RvwA-A2`); inspect.getsource is fragile under Cython /
   AST-rewriting / frozen-wheel transforms and should be flagged for
   follow-up.

3. **Write paired-rejection tests (one per layer).** Each synthesizes its
   layer's dialect of the conceptual antipattern + asserts the gate rejects.
   Use the WARN-mode layer's idiomatic shape (`_caplog_at(<logger>) as records`
   + assert message contains entry name) OR the raise-mode layer's shape
   (`with pytest.raises(ValueError, match=...)`). Do NOT force a common mode.

4. **Write paired-acceptance tests (one per layer, parametrized).** Each
   accepts each narrowing dimension as a separate parametrize case (cleanly
   surfaces "L1 dropped narrowing-field X" or "L2 dropped condition Y" as
   per-case test failures).

5. **Write size-lock test.** Pins both allowlists' current documented
   sizes. A future expansion (e.g. adding `path_regex` to L1) is a
   deliberate cross-stack discipline change — should require updating BOTH
   this test AND the alignment commentary in the postmortem. The size-lock
   catches accidental allowlist drift that silently widens (or narrows) the
   gate without operator visibility.

6. **Write cross-layer alignment proper.** Synthesize the conceptual
   antipattern in BOTH dialects in ONE test; assert BOTH gates reject via
   their idiomatic shapes. This is the alignment-test core — the failure
   mode "one layer accepts what the other rejects" surfaces here.

7. **Write Rule #46 META-CANARY.** Synthesize a CLEARLY-bad entry; assert
   the gate's WARN/error contains the diagnostic substring operators rely
   on (e.g. rejected entry name + enumeration of accepted narrowing fields).
   Without this canary, a future refactor could silently drop the
   diagnostic without the rejection tests catching it.

8. **Document asymmetry in the module docstring.** Lead with the conceptual
   contract; enumerate each layer's reject mode + why it's idiomatic; note
   that name-equality across dialects would be a false alignment.

## Verify

- [ ] N surfaces identified via width-canary grep (Rule #31).
- [ ] Each layer has an explicit `_<LAYER>_NARROWING_FIELDS` constant OR a
  documented `inspect.getsource` follow-up (Reviewer A A2 shape) flagged in
  ADAPTIVE_BACKLOG.md if not yet promoted.
- [ ] Paired rejection tests pass for each layer.
- [ ] Paired acceptance tests pass for each narrowing dimension in each
  layer (one parametrize case per dimension).
- [ ] Size-lock test pins current documented sizes.
- [ ] Cross-layer alignment test synthesizes the conceptual antipattern in
  BOTH dialects + both reject.
- [ ] Rule #46 META-CANARY confirms the gate's diagnostic substring.
- [ ] Module docstring documents asymmetry as intentional.
- [ ] If Shape 1 (multi-surface change in one commit): commit message cites
  Rule #25 single-slice exception #2 + lists all surfaces touched.
- [ ] If Shape 2 (regression canary only): commit type prefix is
  `test(<scope>):`; commit message cites the rule-of-N evidence chain.

## Gotchas

- **Forcing a common reject mode.** Don't refactor a WARN-skip layer to
  raise so the test "looks symmetrical". The asymmetry is intentional;
  unifying reject modes breaks operator UX (long YAML with one bad entry
  must not gate every CVE match).
- **Name-equality across dialects.** Don't assert `"chipset_regex" in
  L2_allowlist`. L1 and L2 may legitimately use different vocabulary; the
  contract is SHAPE-equivalence, not name-equality.
- **inspect.getsource fragility.** Source-text-grep via
  `inspect.getsource(gate_function)` is fragile under Cython compilation /
  AST rewriting / frozen-wheel transforms (Reviewer A A2 `evening:RvwA-A2`).
  Prefer an explicit exported allowlist constant; flag the
  inspect.getsource path for follow-up if unavoidable today.
- **No META-CANARY.** Without Rule #46 META-CANARY, a future refactor can
  silently weaken the synthesized antipattern (e.g. accidentally include a
  narrowing field) so the rejection tests pass without exercising the
  rejection path. Rule #17 silent-success failure mode at the test layer.
- **Bundling Shape 2 into a feat commit.** Use `test(<scope>):` commit type
  for Shape 2 (regression canary on existing surfaces); don't mis-prefix
  as `feat` (the surfaces aren't new).

## Rule-of-Nine evidence — durable beyond debate

| # | Commit | Surfaces | Shape | Notes |
|---|--------|----------|-------|-------|
| 1 | `7079b4d` (2026-05-06) | DB CHECK + TS union + FE config-object | 1 | `FindingSource` baseline; original cross-stack alignment landing. |
| 2 | `ee2abd9` β.12a (2026-05-08) | DB CHECK + TS union + FE config-object | 1 | Windows authenticode + dbx_revoked. |
| 3 | `f70c2e1` γ.7 | DB CHECK + TS union + FE config-object | 1 | Windows registry_persistence + inf + driver_imports. |
| 4 | `20ea228` δ.8 | DB CHECK + TS union + FE config-object | 1 | Windows r2r_stomp + il_capa. |
| 5 | `5466644` ε.1.b.4 | DB CHECK + TS union + FE config-object | 1 | Windows sysmon + logon_success + logon_failure. |
| 6 | `da71afa` ζ.1 | DB CHECK + TS union + FE config-object | 1 | Windows amcache_install. |
| 7 | `a6be708` ζ.2.C | DB CHECK + TS union + FE config-object | 1 | Windows prefetch_execution. |
| 8 | `04a3c55` ζ.3.C | DB CHECK + TS union + FE config-object | 1 | Windows srum_network_activity + srum_application_runtime. |
| 9 | `d641f28` (2026-05-15 evening) | L1 curated-tier `_KNOWN_FIRMWARE_NARROWING_FIELDS` + L2 BT-banner `_parse_banner_cve_pin` family-only check | 2 | **F-FORENSIC-10 alignment canary — canonical Shape-2 instance**. First explicit add-test-only commit for existing-surface alignment. |

The Rule-of-Eight baseline (Shape 1) is the foundation; the 9th instance
(Shape 2) generalises the pattern to "regression canary on existing
surfaces" so future Shape-2 cases (e.g. legacy gates that drifted before
the discipline was named) have a documented path to add a canary without
re-shipping the surfaces themselves.

## Update Scaffold

- [ ] If adding a 10th+ instance to the evidence chain, append a row above
  AND extend CLAUDE.md Learned Rule #25 single-slice exception #2 in the
  same commit per Rule #21 sync discipline.
- [ ] If a new gotcha surfaces, append it to the Gotchas section.
- [ ] If a new commit shape (beyond Shape 1 + Shape 2) emerges, document
  the decision criteria here AND propagate to CLAUDE.md.
