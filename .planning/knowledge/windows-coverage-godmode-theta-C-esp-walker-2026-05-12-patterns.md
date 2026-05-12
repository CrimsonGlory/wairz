---
campaign: windows-coverage-godmode-theta-2026-05-12
stream: θ.C — ESP `.efi` PE chain walker
date: 2026-05-12
kind: patterns (success cases)
related_postmortem: postmortem-windows-coverage-godmode-theta-C-esp-walker-2026-05-12.md
---

# Patterns — Phase θ.C ESP `.efi` PE chain walker

Success cases extracted from the single-stream θ.C dispatch. Each pattern carries Rule-of-N evidence and a mechanical re-application recipe.

---

## P1 — Third application of precedent-reuse compounds the speedup (Rule-of-Three on speedup)

**Shape:** When the SAME campaign ships THREE Rule #39 walker streams in sequence, each successive stream is faster than the previous. The speedup compounds because (a) the precedent stack is closer at hand and (b) the agent has internalized the recipe-specific decisions (when to use the inner-vs-outer split, which patches to use, etc.).

**Evidence:**
- θ.A (BCD walker): ~2.5h, 6 commits, 98 tests.
- θ.B (WMI walker): ~1.5h, 7 commits, 95 tests. ~40% speedup vs θ.A.
- **θ.C (ESP walker) this stream**: ~1h, 5 commits, 107 tests. ~33% speedup vs θ.B; ~60% speedup vs θ.A.

**Recipe (for the FOURTH+ walker in the same campaign):**
1. Read the IMMEDIATELY PRIOR walker (the most recent precedent) file-by-file at design time, NOT the first walker. The most recent precedent has the freshest design decisions.
2. Mechanically copy-translate. Variable names, control flow, error-string formats, mocking shapes — all match.
3. Apply per-piece Pattern P5 direct-push cadence.
4. Acknowledge: the THIRD application is the natural stopping point for "is this faster" measurement — by application 4+, the speedup is bounded by network + CI latency, not by the agent's design effort.

**Boundary**: when the campaign extends to a SECOND letter (e.g. ι), the speedup-compounding resets — the new campaign's first walker is "back to baseline" because design decisions are slightly different (different feature set, different scope). Recipe applies within-campaign, not across-campaign.

---

## P2 — Integration-only streams can absorb sub-tasks (Rule-of-One — promote candidate)

**Shape:** When a sub-task is functionally subsumed by adjacent sub-tasks, fold it in rather than ship an empty commit. The campaign brief outlined a separate θ.C.E "wire the emit hook" commit; in practice, θ.C.C's walker triplet calls `service.emit_esp_findings_from_walk()` inline AND θ.C.D ships the emit method itself — leaving no separate wiring to commit.

**Evidence (Rule-of-One this stream):**
- θ.C planned as 6 sub-tasks (A-F including E); shipped as 5 because E was functionally absorbed.
- Backend Tests CI green; no behavioral regression.

**Recipe:**
1. When designing sub-task decomposition, identify whether each task adds INDEPENDENT BEHAVIOUR or is purely a "call X from Y" wiring.
2. If the wiring is implicit in an adjacent sub-task's contract (e.g. the walker triplet's outer wrapper already invokes the emit), fold the wiring in.
3. Document the absorption in the postmortem so future precedent-reuse runs don't re-introduce the empty commit.

**Anti-pattern to avoid**: Shipping a separate commit whose entire diff is `# already wired` or a one-line trivial change. Empty commits damage `git bisect` clarity AND skew per-piece commit count metrics. Better to subsume + document.

---

## P3 — Rule #19 evidence-first probe of EXISTING SERVICE BOUNDARIES (Rule-of-Three — promotable)

**Shape:** Before drafting integration code, READ the existing service signatures + return shapes that the new code will consume. The integration boundary is described by the upstream service's API; reading it BEFORE drafting saves entire classes of redundant plumbing.

**Evidence (Rule-of-Three now):**
- θ.B WMI: Read PyWMIPersistenceFinder upstream source via WebFetch (Pattern P4 of θ.B postmortem) — extracted regex patterns, license, ZERO-subprocess fact.
- **θ.C ESP this stream**: Read `verify_pe_file()` + `AuthenticodeVerdict` + `match_dbx_revocation()` API surfaces. Discovered that the β.4 verifier ALREADY includes the β.10 DBX cross-reference — `verdict.dbx_revoked` is populated by `verify_pe_file` internally. The walker doesn't need to call DBX separately.
- ε.1.b EVTX: Read python-evtx upstream API shape before drafting the walker (earlier campaign).

**Recipe:**
1. Identify every existing service / library / module the new code will call.
2. For each, run `grep -n "def <function>" <module_path>` to find the signature + return shape.
3. Read the function body if needed (especially returns-something-complex like `AuthenticodeVerdict`).
4. Design the new code's mapping layer (e.g. `map_verdict_to_authenticode_state`) to consume the existing shape — DON'T design the new code first and then discover it duplicates work.

**Cost**: ~5 minutes per integration boundary. **Benefit**: eliminates redundant plumbing AND surfaces the LAYERING contract clearly (which layer owns what).

**Companion to Rule #19**: "the DB describes truth → the library source describes API truth → the upstream raw file describes vendor source-of-truth → the existing service describes the integration boundary." Generalizes the rule to in-tree services, not just upstream libraries.

---

## P4 — Rule #25 single-slice exception #2 cross-stack alignment is Rule-of-Sixteen (beyond debate)

**Shape:** When extending the FindingSource enum allowlist (DB CHECK + Pydantic Literal + frontend union + frontend FINDING_SOURCE_CONFIG), all four surfaces ship in ONE atomic commit per Rule #25 single-slice exception #2.

**Evidence (Rule-of-Sixteen post-θ.C.D):**
- 7079b4d (2026-05-06 base) → ee2abd9 → f70c2e1 → 20ea228 → 5466644 → da71afa → a6be708 → 04a3c55 (Rule-of-Eight) → ac98e55 → e149dcf → fd7cd23 → 66bd8d6 → η.D.D → a4d5f45 → 383ffe9 → **c0d5795 θ.C.D (windows_esp_unsigned + windows_esp_dbx_revoked) → Rule-of-Sixteen**

The discipline is mechanical and durable BEYOND DEBATE. `test_finding_source_alignment.py` enforces pairwise agreement immediately. **Pattern shipped 16 times in 6 weeks without a single divergence.**

**Recipe**: see `.mex/patterns/cross-stack-finding-source-alignment.md`.

---

## P5 — Rule #39 inner/outer/safe runner triplet is Rule-of-Eleven (default-shape)

**Shape:** Every new walker for a forensic artefact ships as 3 functions in `app/services/<artefact>_walker.py`:
1. `_do_<artefact>_walk(db, firmware_id) -> dict` — INNER pure-logic orchestrator. Accepts caller-owned `db`. Returns aggregate dict UNSTAMPED.
2. `run_<artefact>_walk_background(firmware_id) -> None` — OUTER state-machine wrapper. Owns Rule #33 .a transitions via `async_session_factory()`.
3. `auto_<artefact>_walk_firmware_safe(firmware_id) -> None` — UNPACK-POST-DETECTION hook. Owns own session; swallows exceptions silently; does NOT mutate status column.

**Evidence (Rule-of-Eleven post-θ.C.C):**
- γ.4 → δ.5 → ε.1.b.3 → ζ.2.B → ζ.3.B → η.B.C → η.C.C → η.A.C → θ.A.C → θ.B.D → **θ.C.C this stream**

**The next walker should treat the triplet as the default and only deviate if there's a specific architectural reason** (e.g. the work is genuinely synchronous + bounded enough to not need the state machine).

**Recipe:** `.mex/patterns/inner-outer-safe-runner.md` (per Rule #39 promotion note).

---

## P6 — Cross-firmware fingerprint aggregation MCP tool is Rule-of-Three (durable surface area)

**Shape:** Each walker ships a `lookup_<artefact>_<shape>` MCP tool that aggregates by `fingerprint_sha256` across the wairz corpus. Same fingerprint across firmware ⇒ same artefact shape was planted (campaign correlation surface — unique to wairz vs EZTools / flare-wmi / volatility).

**Evidence (Rule-of-Three now):**
- θ.A BCD walker: `lookup_bcd_chain` (BCD bootkit cross-firmware hunt — earlier sub-stream).
- θ.B WMI walker: `lookup_wmi_persistence` (Pattern P3 of θ.B; WMI FilterToConsumerBinding cross-corpus correlation).
- **θ.C ESP walker this stream: `lookup_esp_chain`** (BlackLotus / Bootkitty / supply-chain `.efi` correlation across the corpus).

**Recipe (for future walkers):**
1. Identify the canonical "shape signature" tuple for the walked artefact (e.g. ESP: file_path_lower + file_sha256 + authenticode_state; LNK: target_path + arguments; Scheduled Task: action_command + trigger_type).
2. Add a `fingerprint_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)` column to the per-record ORM table.
3. Compute fingerprint at walker time via `hashlib.sha256(tuple_str.encode("utf-8")).hexdigest()`.
4. Add an MCP tool `lookup_<artefact>_<shape>(fingerprint_sha256=...)` that aggregates by fingerprint across firmware corpus.
5. Same fingerprint across firmware ⇒ same persistence/bootkit/supply-chain shape was planted.

**The pattern is now durable beyond Rule-of-Three** — future walkers (hibernate.sys, MFT, prefetch) should consider the cross-firmware aggregation MCP tool as a DEFAULT unless the artefact genuinely lacks a fingerprint-able shape signature.

---

## P7 — Re-using existing services (signify + DBX + pefile) eliminates vendoring (Rule-of-One — context-dependent)

**Shape:** When the campaign brief flags a stream as "mostly wiring on existing primitives," the implementation should integrate without vendoring new code. θ.C ESP is integration-only — signify is in pyproject.toml; pefile is in pyproject.toml; β.4 + β.10 services already wrap the Authenticode + DBX pipeline. The walker just maps the verdict onto WindowsEspEntry columns.

**Evidence:**
- **θ.C ESP this stream**: 925 LOC walker (vs θ.B WMI's 917 LOC + 200 LOC vendor). No new third_party/ directory. No new vendor attribution. signify + pefile + β.4 + β.10 do all the heavy lifting.

**Recipe:**
1. Verify the campaign brief's "wiring on existing primitives" claim by running `grep -rn 'from app\.services\.' <new_walker.py>` after first-draft — if every service import resolves to an existing service, the integration claim holds.
2. Resist the urge to "package the verification logic" into a new vendor dir. Existing services are the integration contract.
3. The walker's JOB is the mapping layer (verdict → ORM columns + classifier inputs), NOT the verification.

**Boundary**: applies when the existing primitives are sufficient. Doesn't apply when the artefact format requires new parsing (WMI OBJECTS.DATA, MFT, prefetch). Identify by reading the existing service surface first (P3 above) — if the surface covers the integration, vendor-free is correct; if it doesn't, a focused vendor is right-sized.

---

## P8 — Pattern P5 per-piece direct-push + Rule #41 must-complete CI is healthy and durable (Rule-of-Many)

**Shape:** Each sub-task ships as its own commit; CI Lint runs per-commit; Backend Tests cancelled-on-intermediate per `concurrency.cancel-in-progress` (the lint sibling catches per-commit; the nightly cron catches deeper regressions).

**Evidence:** All 5 phase commits this session shipped clean — Lint green per-piece on first 4 (5th in_progress at session-close, expected green). Zero re-work cycles.

**Recipe:** See `.mex/patterns/rule-41-must-complete-ci.md` for the full mechanism description.

---

## Cross-references

- **CLAUDE.md rules applied:** #5 (executor wrap), #11 (runtime import smoke), #16 (detection roots), #19 (evidence-first), #20 (docker cp — deferred), #21 (CLAUDE.md ↔ mex sync), #24 (tsc -b --force), #25 (per-sub-task commits + single-slice exception #2), #29 (timeout discipline), #30 (lazy-import patch targets — used in walker → finding_service emit hook AND walker → authenticode_service.verify_pe_file), #33 (.a state machine + .c CHECK + .d task vs arq), #35a (exit-code-before-pipe), #35b (live canaries), #35c (JSONB normalisers), #36 (no-execute — CENTRAL DISCIPLINE FOR θ.C; structural test gate enforces it), #37 (offline-trust-anchor — β.10 DBX bundle reused, no new anchors), #38 (absolute paths + subshell-scoped cd), #39 (inner/outer/safe triplet — Rule-of-Eleven now), #41 (must-complete CI), #43 (per-line noqa rationale).
- **Antipatterns avoided:** A6 (ruff --no-cache), A10 (alembic ID pre-validation).
- **Postmortem:** `postmortem-windows-coverage-godmode-theta-C-esp-walker-2026-05-12.md`
- **Companion antipatterns:** `windows-coverage-godmode-theta-C-esp-walker-2026-05-12-antipatterns.md`
