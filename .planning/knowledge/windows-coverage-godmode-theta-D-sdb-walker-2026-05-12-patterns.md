# Patterns — windows-coverage-godmode θ.D SDB walker (2026-05-12)

Patterns extracted from the Phase θ.D session (~35 min single-sub-agent dispatch from Archon harness, 6 commits to main, 97 tier-1 tests, 0 reverts). θ.D is the FIFTH and FINAL stream of the θ campaign, closing 5-of-5 walkers matching η's precedent.

## P1 — Single-sub-agent dispatch + precedent reuse compounds to Rule-of-Five speedup

θ.A took ~2.5h. θ.B took ~1.5h. θ.C took ~1h. θ.E took ~40 min. **θ.D took ~35 min** despite including a SIXTH sub-task (vendor on top of the 5 layers).

| Application | Stream | Wall time | Δ from prior |
|---|---|---:|---:|
| 1 | θ.A BCD | ~2.5h | (baseline) |
| 2 | θ.B WMI | ~1.5h | −40% |
| 3 | θ.C ESP | ~1h | −33% |
| 4 | θ.E MBR/VBR | ~40 min | −33% |
| 5 | θ.D SDB | ~35 min | −12% |

**Pattern P1 is now Rule-of-Five.** The fifth application is faster than the fourth; the speedup compounds because each successive walker can mechanically copy-translate from the most-recent precedent.

**Natural bound for Pattern P1 measurement: ~30 min per stream.** Below this threshold the wall time is dominated by network + CI latency (~5-10 min per push for Lint completion), not by agent design effort. Further applications will likely cluster around 25-35 min.

**Mechanical preconditions for Rule-of-Five speedup:**
- Precedent shipped within the same session (working memory hot; file paths fresh).
- Single-sub-agent dispatch (no cross-stream communication overhead).
- Per-piece direct-push cadence (Pattern P5) maximises CI confidence per-commit.
- Test infrastructure (`make_live_db`, fixture builders) reused verbatim.

**Promotion candidate:** if a SIXTH walker stream ships within 30 min of agent-wall, Pattern P1 can be re-titled "Rule-of-Six precedent-reuse speedup with natural 25-35 min floor."

## P2 — Integration-only streams absorb sub-tasks — Rule-of-Three

θ.C's θ.C.E absorbed. θ.E's θ.E.E absorbed. **θ.D's θ.D.E.wiring also absorbed.** Same shape: walker triplet's outer wrapper calls the emit hook inline AND the cross-stack alignment commit ships the emit method itself.

**Mechanical rule for future walker streams:** if the walker triplet's wiring is INLINE in the run/auto wrappers AND the cross-stack alignment commit ships the emit METHOD, then a separate "wire emit" sub-task is functionally a no-op and should be absorbed.

**Validation across 3 streams:**
- θ.C.E absorbed → 5 commits shipped instead of 6.
- θ.E.E absorbed → 5 commits shipped instead of 6.
- θ.D.E.wiring absorbed → 6 commits shipped instead of 7 (θ.D had a vendor sub-task adding one).

**Pattern P2 is now Rule-of-Three — durable beyond debate.** Future walker streams should default to absorbing the wiring sub-task unless there's a specific reason to ship it separately (e.g. operator-triggered emit-only refresh without a re-walk).

## P3 — Clean-room vendor rewrite for upstream-with-heavyweight-deps (Rule-of-One, promote pending)

θ.B's PyWMIPersistenceFinder was vendored **VERBATIM** because upstream was pure stdlib (text parsing + regex matching).

**θ.D's python_sdb was vendored CLEAN-ROOM** because upstream depends on `vivisect-vstruct-wb==1.0.3` (heavyweight Vivisect reverse-engineering binary-parser fork). The vendor implements the same format from upstream's reverse-engineered documentation only, using only stdlib (`struct`, `dataclasses`).

**Decision made by probing `requirements.txt` via WebFetch BEFORE drafting.** Discovered the heavyweight transitive dep; clean-room rewrite avoided pulling 1+ MB of transitive deps into the worker container.

### Conditions for verbatim vendor (θ.B precedent)
- Upstream is pure stdlib.
- The parser logic is the value-add (e.g. regex patterns, dict-building heuristics).
- The library's code is small (<500 LOC) and self-contained.

### Conditions for clean-room rewrite (θ.D precedent)
- Upstream depends on a heavyweight transitive dep that would bloat the worker container.
- The upstream library's VALUE-ADD is the binary-format DOCUMENTATION (constants, signatures, layout) rather than complex parser logic.
- The parser logic can be re-implemented in <500 LOC of stdlib.
- The constants are PROTOCOL-LEVEL (TAG IDs, magic bytes) rather than copyrightable expression.

**Pattern P3 promotion to Rule-of-Two pending** — the binary outcome (verbatim vs clean-room) depends on probing upstream's `requirements.txt` FIRST. The discipline is durable; the next vendor sub-task should probe requirements.txt before deciding shape.

### Reference shape — clean-room vendor with Apache 2.0 source

```
backend/third_party/<pkg>/
├── __init__.py            # ~700 LOC stdlib-only parser using struct + dataclasses
├── LICENSE                # Verbatim copy of upstream's LICENSE
├── ATTRIBUTION.md         # Rule #37 — source URL + commit SHA + license + scope
                           #   + adaptations log + Rule #36 grep audit
                           #   + re-sync recipe
```

ATTRIBUTION.md MUST document:
1. Source URL + master SHA at vendoring time.
2. License of upstream (verbatim copy of LICENSE file).
3. Scope of vendoring (what's vendored vs what's NOT — explicitly cite any transitive deps that AREN'T vendored).
4. Why clean-room (heavyweight transitive dep, GPL contamination risk, etc.).
5. Adaptations log (line-by-line summary of how the wairz vendor differs from upstream).
6. Rule #36 grep audit showing ZERO forbidden execution primitives.
7. Re-sync recipe for future updates.

## P4 — Rule #25 single-slice exception #2 cross-stack alignment is Rule-of-Eighteen

θ.D.E extended `ck_findings_source` + `WindowsFindingSource` Literal + frontend `FindingSource` union + frontend `FINDING_SOURCE_CONFIG` + classifier + emit hook + 3 new source values in ONE atomic commit. `test_finding_source_alignment.py` + a dedicated `test_finding_source_alignment_includes_sdb_sources` enforced pairwise agreement immediately.

**Rule-of-Eighteen now** (7079b4d → ee2abd9 β.12a → f70c2e1 γ.7 → 20ea228 δ.8 → 5466644 ε.1.b.4 → da71afa ζ.1 → a6be708 ζ.2.C → 04a3c55 ζ.3.C → ac98e55 η.E → e149dcf η.B.D → fd7cd23 η.C.D → 66bd8d6 η.A.D → η.D.D → a4d5f45 θ.A.D → 383ffe9 θ.B.E → c0d5795 θ.C.D → f0544f2 θ.E.D → THIS θ.D.E).

**Beyond-debate** — pattern shipped 18 times across 6 weeks without a single divergence. The single-commit shape is the default for any cross-stack alignment change.

## P5 — Rule #39 inner/outer/safe runner triplet is Rule-of-Thirteen

θ.D.D extends the chain: γ.4 → δ.5 → ε.1.b.3 → ζ.2.B → ζ.3.B → η.B.C → η.C.C → η.A.C → θ.A.C → θ.B.D → θ.C.C → θ.E.C → θ.D.D.

**Beyond-debate** — the triplet is the CANONICAL wave-1 shape for any new walker in wairz. The next walker should default to the triplet without further consideration.

## P6 — Cross-firmware fingerprint aggregation completes Windows persistence coverage (Rule-of-Five)

| Tool | Stream | Source table | Aggregation surface |
|---|---|---|---|
| `lookup_bcd_chain` | θ.A | WindowsBcdEntry | BCD store entries (boot config DB) |
| `lookup_wmi_persistence` | θ.B | WindowsWmiEvent | WMI FilterToConsumerBinding |
| `lookup_esp_chain` | θ.C | WindowsEspEntry | UEFI .efi PE32+ files |
| `lookup_mbr_vbr_sector` | θ.E | WindowsMbrVbrSector | BIOS / legacy boot sectors |
| **`lookup_sdb_shim`** | **θ.D** | **WindowsSdbEntry** | **Application Compatibility Shim DB** |

**5 cross-firmware aggregation MCP tools spanning the entire Windows persistence chain.** Operator workflow: combine all 5 lookups to correlate multi-stage adversary campaigns across the corpus (a BCD-modified bootkit + an MBR-resident bootloader + a custom .efi shim + a WMI subscription + a custom .sdb shim all carrying the same campaign fingerprint).

**This is unique to wairz vs EZTools / flare-wmi / volatility / ANSSI bootcode_parser** — those tools analyse single firmware; wairz aggregates across the corpus.

## P7 — Test fixture builders mirror the precedent's _make_X pattern

Each walker test file ships a `_make_X(firmware_id, *, ...)` fixture builder that constructs a representative row with sensible defaults + keyword-arg overrides for the specific test case. Mirrors:

- `test_mbr_vbr_models.py::_make_firmware` + `_make_sector`
- `test_windows_mbr_vbr_tools.py::_make_sector`
- **`test_sdb_models.py::_make_firmware`** (this stream)
- **`test_windows_sdb_tools.py::_make_entry`** (this stream)

The pattern is durable. New walker streams should ship a `_make_X` builder in BOTH the model-test file AND the MCP-tool-test file. Defaults should be sensible (e.g. shim_class="Custom", sdb_kind="custom") so tests can override only the field being exercised.

## P8 — θ campaign completion — 5-of-5 walker streams matching η's precedent

η shipped 5 streams (A MFT + B Scheduled Tasks + C LNK + D BYOVD + E PowerShell). **θ shipped 5 streams (A BCD + B WMI + C ESP + E MBR/VBR + D SDB).**

Together they cover:
- **η = file-system / execution-history persistence** (Persona-E forensic timeline).
- **θ = boot-chain + lateral persistence + shim** (T1542.003 Pre-OS Boot + T1547 Boot/Logon Autostart + T1546.011 Application Shimming).

wairz now provides static-analysis coverage for **every major Windows persistence vector** reachable in a firmware extract. The next campaign (ι) can pivot to a different problem domain.
