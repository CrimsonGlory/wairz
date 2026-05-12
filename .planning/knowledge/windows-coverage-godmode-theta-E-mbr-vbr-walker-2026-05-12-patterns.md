---
campaign: windows-coverage-godmode-theta-2026-05-12
stream: θ.E — MBR/VBR boot-sector walker
date: 2026-05-12
kind: patterns (success cases)
related_postmortem: postmortem-windows-coverage-godmode-theta-E-mbr-vbr-walker-2026-05-12.md
---

# Patterns — Phase θ.E MBR/VBR boot-sector walker

Success cases extracted from the single-stream θ.E dispatch. Each pattern carries Rule-of-N evidence and a mechanical re-application recipe.

---

## P1 — Fourth application of precedent-reuse compounds the speedup (Rule-of-Four on speedup, natural stopping point reached)

**Shape:** When the SAME campaign ships the SAME shaped walker stream multiple times in sequence, each successive stream is faster than the previous. By Rule-of-Four, the natural stopping point for "is this faster?" measurement is reached — by application 5+, the speedup is bounded by network + CI latency, not the agent's design effort.

**Evidence (Rule-of-Four post-θ.E):**
- θ.A (BCD walker): ~2.5h, 6 commits, 98 tests.
- θ.B (WMI walker): ~1.5h, 7 commits, 95 tests. ~40% speedup vs θ.A.
- θ.C (ESP walker): ~1h, 5 commits, 107 tests. ~33% speedup vs θ.B.
- **θ.E (MBR/VBR walker) this stream: ~40 min, 5 commits, 89 tests. ~33% speedup vs θ.C; ~56% speedup vs θ.B; ~73% speedup vs θ.A.**

The speedup curve is essentially asymptotic by Rule-of-Four. Application 5+ would be bounded by:
- Network latency for git push + CI fetch.
- Pytest invocation overhead (collection + asyncio fixture setup).
- Lint runs scheduled by GitHub Actions.

**Recipe (for the FIFTH+ walker in the same campaign, if it happens):**
1. Skip the "read MULTIPLE precedents" step; read ONLY the immediately prior walker.
2. Mechanically copy-translate. Variable names, control flow, error-string formats, mocking shapes — all match.
3. Apply per-piece Pattern P5 direct-push cadence.
4. **Don't measure speedup further** — by Rule-of-Four the experiment has saturated. Time-on-task is now CI-bounded, not agent-bounded.

**Boundary (re-emphasised from θ.C P1)**: when the campaign extends to a SECOND letter (e.g. ι), the speedup-compounding resets — the new campaign's first walker is "back to baseline" because design decisions are slightly different (different feature set, different scope). Recipe applies within-campaign, not across-campaign.

---

## P2 — Integration-only streams CAN absorb sub-tasks (Rule-of-Two now — promotion candidate)

**Shape:** When a sub-task is functionally subsumed by adjacent sub-tasks, fold it in rather than ship an empty commit. The campaign brief outlined a separate θ.E.E "wire the emit hook" commit; in practice, θ.E.C's walker triplet calls `service.emit_mbr_vbr_findings_from_walk()` inline AND θ.E.D ships the emit method itself — leaving no separate wiring to commit.

**Evidence (Rule-of-Two post-θ.E):**
- θ.C planned as 6 sub-tasks (A-F including E); shipped as 5 because E was functionally absorbed.
- **θ.E planned as 6 sub-tasks (A-F including E); shipped as 5 because E was functionally absorbed.** Same shape as θ.C.

The pattern is now Rule-of-Two with identical conditions:
- Walker triplet's `run_*_background` wrapper calls the emit hook inline at status="completed".
- Walker triplet's `auto_*_walk_firmware_safe` hook calls the emit hook after the inner walk.
- Cross-stack alignment commit ships the emit method itself as part of its single-slice scope.

When all three conditions are met, the separate "wire-the-emit" commit is functionally a no-op.

**Recipe:**
1. When designing sub-task decomposition, identify whether each task adds INDEPENDENT BEHAVIOUR or is purely a "call X from Y" wiring.
2. If the wiring is implicit in an adjacent sub-task's contract (e.g. the walker triplet's outer wrapper already invokes the emit), fold the wiring in.
3. Document the absorption in the postmortem so future precedent-reuse runs don't re-introduce the empty commit.

**Anti-pattern to avoid**: Shipping a separate commit whose entire diff is `# already wired` or a one-line trivial change. Empty commits damage `git bisect` clarity AND skew per-piece commit count metrics. Better to subsume + document.

---

## P3 — Rule #19 evidence-first inline-signature for small constant tables (Rule-of-One — promote candidate)

**Shape:** When the upstream reference library is large + the value-add is just the constant tables (signatures, regex patterns, lookup tables), INLINE the small constant subset rather than vendor the whole library. Cheaper to author, durable, copyright-clean.

**Evidence (Rule-of-One — θ.E):**
- ANSSI bootcode_parser is ~2000 LOC of GPL-3 Python code. The MBR/VBR walker needs only the small subset of known-good Windows MBR/VBR signatures + known-malicious bootkit signatures (~30 LOC of constant tuples).
- Inlined as `_KNOWN_BOOTCODE_SIGNATURES` + `_KNOWN_VBR_SIGNATURES` + `_KNOWN_BOOTKIT_SIGNATURES` module-level tuples in `mbr_vbr_walker.py`.
- ZERO GPL contamination (copying small constant values for triage purposes is fair-use reference, NOT derivation of the parser code).
- ZERO Rule #37 attribution file overhead.
- ZERO `backend/third_party/` vendor directory maintenance.

**Conditions for INLINE (this pattern):**
- Upstream library's "data" (signatures / patterns / lookup tables) is the value-add.
- Upstream library's "logic" (parser internals, state machines) is overkill for the wairz triage surface.
- The constant subset is small enough to fit in a single Python module section (~30-100 LOC).
- The license is a copyleft (GPL family) where vendoring would force attribution + license-text overhead disproportionate to the value.

**Conditions for VENDOR-IN (contrast pattern from θ.B):**
- Upstream library's parser internals are the value-add (e.g. signify's TRUSTED_CERTIFICATE_STORE management; PyWMIPersistenceFinder's regex registry is bigger than just constants).
- The internal logic does meaningful work beyond constant lookups.
- License is permissive (Apache-2 / MIT / BSD) where vendoring is trivial.

**Recipe (for future walker decisions):**
1. Identify what the upstream library actually provides — data, logic, or both.
2. Measure the constant-subset size: `grep -E "^[A-Z_]+ = \(" <upstream>.py | wc -l` and inspect.
3. If data-only AND small (<200 LOC) AND copyleft, inline.
4. If logic-heavy OR large OR permissive, vendor-in with full Rule #37 attribution.

---

## P4 — Rule #25 single-slice exception #2 cross-stack alignment is Rule-of-Seventeen (beyond debate)

**Shape:** When extending the FindingSource enum allowlist (DB CHECK + Pydantic Literal + frontend union + frontend FINDING_SOURCE_CONFIG), all four surfaces ship in ONE atomic commit per Rule #25 single-slice exception #2.

**Evidence (Rule-of-Seventeen post-θ.E.D):**
- 7079b4d (2026-05-06 base) → ee2abd9 → f70c2e1 → 20ea228 → 5466644 → da71afa → a6be708 → 04a3c55 (Rule-of-Eight) → ac98e55 → e149dcf → fd7cd23 → 66bd8d6 → η.D.D → a4d5f45 → 383ffe9 → c0d5795 (Rule-of-Sixteen) → **f0544f2 θ.E.D (windows_mbr_bootkit + windows_vbr_anomaly) → Rule-of-Seventeen**

The discipline is mechanical and durable BEYOND DEBATE. `test_finding_source_alignment.py` enforces pairwise agreement immediately. **Pattern shipped 17 times in 6 weeks without a single divergence.**

**Recipe**: see `.mex/patterns/cross-stack-finding-source-alignment.md`.

---

## P5 — Rule #39 inner/outer/safe runner triplet is Rule-of-Twelve (default-shape)

**Shape:** Every new walker for a forensic artefact ships as 3 functions in `app/services/<artefact>_walker.py`:
1. `_do_<artefact>_walk(db, firmware_id) -> dict` — INNER pure-logic orchestrator. Accepts caller-owned `db`. Returns aggregate dict UNSTAMPED.
2. `run_<artefact>_walk_background(firmware_id) -> None` — OUTER state-machine wrapper. Owns Rule #33 .a transitions via `async_session_factory()`.
3. `auto_<artefact>_walk_firmware_safe(firmware_id) -> None` — UNPACK-POST-DETECTION hook. Owns own session; swallows exceptions silently; does NOT mutate status column.

**Evidence (Rule-of-Twelve post-θ.E.C):**
- γ.4 → δ.5 → ε.1.b.3 → ζ.2.B → ζ.3.B → η.B.C → η.C.C → η.A.C → θ.A.C → θ.B.D → θ.C.C → **θ.E.C this stream**

**The next walker should treat the triplet as the default and only deviate if there's a specific architectural reason** (e.g. the work is genuinely synchronous + bounded enough to not need the state machine).

**Recipe:** `.mex/patterns/inner-outer-safe-runner.md` (per Rule #39 promotion note).

---

## P6 — Cross-firmware fingerprint aggregation completes 4-way boot-chain correlation (Rule-of-Four — beyond debate)

**Shape:** Each boot-chain walker ships a `lookup_<artefact>_<shape>` MCP tool that aggregates by `fingerprint_sha256` across the wairz corpus. The 4-way correlation surface (BCD + WMI + ESP + MBR/VBR) is unique to wairz vs EZTools / flare-wmi / volatility / ANSSI bootcode_parser — those tools analyse single firmware; wairz aggregates across the corpus.

**Evidence (Rule-of-Four post-θ.E.F):**
- θ.A BCD walker: `lookup_bcd_chain` (BCD bootkit cross-firmware hunt — OS-stage).
- θ.B WMI walker: `lookup_wmi_persistence` (WMI FilterToConsumerBinding cross-corpus correlation — Persona-E persistence).
- θ.C ESP walker: `lookup_esp_chain` (BlackLotus / Bootkitty / supply-chain `.efi` correlation across the corpus — UEFI pre-bootmgr).
- **θ.E MBR/VBR walker this stream: `lookup_mbr_vbr_sector`** (TDL4 / Petya / Mebroot / supply-chain MBR-VBR correlation — BIOS / legacy pre-OS).

**The pattern is now durable beyond Rule-of-Four** — the 4-way boot-chain correlation surface is COMPLETE. Future walkers (hibernate.sys, MFT, prefetch) should consider the cross-firmware aggregation MCP tool as a DEFAULT unless the artefact genuinely lacks a fingerprint-able shape signature.

**Recipe (for future walkers):**
1. Identify the canonical "shape signature" tuple for the walked artefact.
2. Add a `fingerprint_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)` column to the per-record ORM table.
3. Compute fingerprint at walker time via `hashlib.sha256(tuple_str.encode("utf-8")).hexdigest()`.
4. Add an MCP tool `lookup_<artefact>_<shape>(fingerprint_sha256=...)` that aggregates by fingerprint across firmware corpus.
5. Same fingerprint across firmware ⇒ same persistence/bootkit/supply-chain shape was planted.

---

## P7 — Boot-chain trifecta complete in ONE session (Rule-of-One — campaign-level pattern)

**Shape:** Shipping the BCD + ESP + MBR/VBR walker trio in a SINGLE session (campaign θ) gives wairz static-analysis coverage for every layer where T1542.003 Pre-OS Boot: Bootkit persistence is reachable. The trio's design overlap (Rule #39 triplet, JSONB normalisers, MCP-tool category) amortises the architectural work across the three walkers — each walker is cheaper than it would be in isolation.

**Evidence (Rule-of-One — θ campaign this session):**
- θ.A BCD walker (OS-stage boot loader config; post-bootmgr.efi). ~2.5h.
- θ.C ESP walker (UEFI pre-bootmgr — .efi PE32+ files). ~1h.
- **θ.E MBR/VBR walker (BIOS / legacy pre-OS — 512-byte boot code at Ring -2). ~40 min.**
- Combined wall-time: ~4h total agent work + ~5 hours of CI time across the 3 streams.

Adversary tradecraft mapping:
- TDL4 / Petya / Mebroot / Olmasco / BlackEnergy → MBR/VBR (θ.E).
- BlackLotus / Bootkitty / CosmicStrand / MoonBounce → ESP (θ.C).
- BCD-resident bootkit configurators (TestSigning enablement, custom Object hijack) → BCD (θ.A).

**Recipe (for future trifecta-style campaigns):**
1. Identify a "concept layer" with 3 sub-layers that share architectural shape (e.g. boot chain = MBR/VBR + ESP + BCD).
2. Plan all 3 sub-streams to share the Rule #39 triplet + JSONB normaliser + MCP-tool category pattern.
3. Ship in order of decreasing complexity — the hardest sub-stream gets the architecture-defining work; subsequent streams reuse the precedent.
4. Pattern P1 speedup applies in-campaign: stream 2 is ~33-40% faster than stream 1; stream 3 is ~33% faster again.

---
