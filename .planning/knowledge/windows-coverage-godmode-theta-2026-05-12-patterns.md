# Patterns: Windows-Coverage God-Mode Phase θ (boot-chain + lateral + shim)

> Extracted: 2026-05-12
> Campaign: `.planning/campaigns/completed/windows-coverage-godmode-theta-2026-05-12.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-theta-2026-05-12.md`
> Per-stream files (10): `.planning/knowledge/windows-coverage-godmode-theta-{A,B,C,D,E}-*-{patterns,antipatterns}.md`

## Successful Patterns (cross-stream, campaign-level)

### 1. Single-sub-agent + precedent file-by-file reuse (Pattern P1 — Rule-of-Five)

- **Description:** For each horizontal-expansion stream (θ.A through θ.E), dispatch ONE general-purpose sub-agent with: (a) the campaign brief reference, (b) the most-recent stream postmortem as just-shipped precedent, (c) the closest η-precedent file paths (e.g. `mft_walker.py`) for shape-by-shape reuse, (d) a per-sub-task ladder mapped to Rule #25 per-piece commits, (e) explicit end conditions. Sub-agent works ~25-30 min agent-wall floor (bounded below by CI latency at ~3-4 min CI wait per stream × ~7 pushes per stream).
- **Evidence:** θ.A 38m → θ.B 34m → θ.C 26m → θ.E 25m → θ.D 30m agent-wall (`duration_ms` from task-notification, NOT sub-agent self-reported strings — see antipattern A2). Total agent work ~153 min; total wall ~240 min including verification overhead. Compared to brief estimate (4-6h θ.A + 6-8h θ.B + 2-4h θ.C + 2-3h θ.E + 5-7h θ.D = 19-28h naive sum) — actual was 8-12× faster than the brief's aggregate.
- **Applies when:** A walker-stream-shape precedent exists in-tree (Rule #39 inner/outer/safe triplet + Rule #25 per-sub-task ladder + Rule #33 .a state machine + JSONB normaliser per Rule #35c). FIRST application of a new stream-shape sets the precedent; THIRD+ application saturates the speedup.

### 2. Integration-only sub-task absorption (Pattern P2 — Rule-of-Two)

- **Description:** When a stream's `.E` sub-task ("wire finding emit into auto_<op>_walk_firmware_safe") is trivially-invokable from the walker triplet that already exists in the prior `.C` commit, AND the emit method itself ships in `.D` (cross-stack alignment), the separate `.E` "wiring" commit becomes empty — absorb it into `.C` + `.D`. Result: 5-sub-task ladder collapses into 4 commits.
- **Evidence:** θ.C.E absorbed into θ.C.C + θ.C.D (commit `c0d5795`); θ.E.E absorbed into θ.E.C + θ.E.D (commits `1b9627f` + `f0544f2`). Both sub-agents independently arrived at this shape based on the prior stream's postmortem.
- **Applies when:** The walker triplet's inner runner directly invokes the emit helper inline AND the cross-stack alignment commit (`.D`) ships the emit helper itself. Mechanical detection: the proposed `.E` commit would contain ZERO lines of new logic — only a `git mv`-style move or test addition.

### 3. Vendor-in decision tree: verbatim fork vs clean-room rewrite (Pattern P3 — Rule-of-Two)

- **Description:** When a stream needs a 3p parser library (Rule #36 no-execute discipline), two shapes apply:
  - **Verbatim fork:** if upstream is (a) pure-stdlib OR (b) has only well-maintained transitive deps AND (c) is small enough to vendor entirely (<300 LOC). Shape: `cp` upstream source verbatim into `backend/third_party/<name>/`, add LICENSE + ATTRIBUTION.md citing upstream URL + commit SHA + license + Rule #36 no-execute scope clause.
  - **Clean-room rewrite:** if upstream's only transitive dep is a heavyweight unmaintained 3p library (e.g. `vivisect-vstruct-wb`), OR if upstream license requires verbatim retention but the format spec is public + small. Shape: implement from format spec (Microsoft docs / Geoff Chappell / vendor specs); cite influence in ATTRIBUTION.md as "format-spec-driven; influenced by <upstream>"; reproduce TAG-IDs + type-bit masks as protocol-level constants under fair-use reference.
- **Evidence:**
  - θ.B `7c581b1` PyWMIPersistenceFinder VERBATIM fork from David Pany's WMI_Forensics (MIT, ~200 LOC, no transitive deps).
  - θ.D `7c581b1` python-sdb CLEAN-ROOM rewrite from williballenthin/python-sdb (Apache 2.0, would have pulled vivisect-vstruct-wb 5y-stale transitive dep). ~700 LOC pure-stdlib parser.
- **Applies when:** Stream needs to parse a binary format Microsoft/vendor documents publicly. Decision criterion: `pip show <upstream>; ec=$?; grep -E "Requires:" <output>` — if any required dep is itself unmaintained-5y+, prefer clean-room.

### 4. Rule #25 single-slice exception #2 cross-stack alignment (Pattern P4 — Rule-of-Eighteen campaign-progression)

- **Description:** Multi-surface alignment commits (DB CHECK constraint + FE `FindingSource` union + FE `FINDING_SOURCE_CONFIG` map) MUST ship in ONE commit. `test_finding_source_alignment.py` enforces strict pairwise agreement; splitting leaves the test RED between commits and breaks bisect-clean lanes.
- **Evidence (campaign-progression count):** Pre-θ Rule-of-Sixteen. θ session added: `a4d5f45` (θ.A.D) + `383ffe9` (θ.B.E) + `c0d5795` (θ.C.D) + `f0544f2` (θ.E.D) + `66cd1bf` (θ.D.E) = +5 worked examples → **Rule-of-Eighteen** (visible: 2 of θ's 5 were "extension only, no new pattern" thus already accounted; the durable count is the 16 historical + 2 new pattern-extensions = Rule-of-Eighteen).
- **Applies when:** Adding any new `WindowsFindingSource` value(s). The narrow Literal at the helper boundary (per Rule #33 .c subtlety) + DB CHECK constraint + FE union + FE config bundle in one commit.

### 5. Rule #39 inner/outer/safe runner triplet (Pattern P5 — Rule-of-Thirteen campaign-progression)

- **Description:** Every walker stream authors three functions: `_do_<op>_walk(db, fw_id) -> dict` (inner pure-logic, takes `db` from caller, returns aggregate UNSTAMPED), `run_<op>_walk_background(fw_id)` (outer Rule #33 .a state machine with own `async_session_factory()`, owns 5-state transitions, outer guard catches anything), `auto_<op>_walk_firmware_safe(fw_id)` (unpack hook, swallows exceptions silently, leaves status `idle` for manual re-trigger).
- **Evidence (campaign-progression count):** Pre-θ Rule-of-Eight. θ session added: θ.A.C → θ.B.D → θ.C.C → θ.E.C → θ.D.D = +5 worked examples → **Rule-of-Thirteen**.
- **Applies when:** Any new background runner that owns a Rule #33 .a state machine on `firmware.<col>_walk_status`. Tier-1 tests MUST call the INNER runner with a `make_live_db()`-provided session (NOT the outer wrapper — that opens its own session and fails on dev-host with `socket.gaierror`).

### 6. Cross-firmware fingerprint aggregation MCP tool (Pattern P6 — Rule-of-Five)

- **Description:** Every new walker stream's MCP category includes ONE cross-firmware aggregation tool: `lookup_<entity>_<facet>(fingerprint: str) -> list[FirmwareMatch]`. Takes a hash/GUID/name; returns matching rows across the entire firmware corpus. This is the wairz-unique capability vs EZTools (per-firmware only), flare-wmi (single-platform), CHIPSEC (UEFI-only), Volatility (memory-only).
- **Evidence (campaign-progression count):** Pre-θ Rule-of-Zero. θ session added: `lookup_bcd_chain` (θ.A.F) → `lookup_wmi_persistence` (θ.B.G) → `lookup_esp_chain` (θ.C.F) → `lookup_mbr_vbr_sector` (θ.E.F) → `lookup_sdb_shim` (θ.D.F) = **Rule-of-Five**. Boot-chain 4-way correlation surface (BCD + ESP + MBR/VBR + SDB) operational.
- **Applies when:** New walker stream produces per-firmware rows with stable fingerprints (sha256, GUID, structured name). The aggregator filters by `fingerprint = ?` across all firmware rows; the unique-to-wairz value emerges from corpus-wide queries.

### 7. Trust-but-verify orchestrator gate (Pattern P7 — Rule-of-Five campaign-progression)

- **Description:** After each sub-agent returns its summary, orchestrator runs ~7 verification commands: `git log --oneline --grep='Phase θ.<x>' | wc -l`, `test -f <expected file>`, `wc -l <walker.py>`, `find ... grep registry.register | awk` (MCP count), `pytest <new tests>; ec=$?`, `npx tsc -b --force; ec=$?`, `ruff check --no-cache .; ec=$?`. Sub-agent self-reports are claims, not evidence (per Agent tool docstring).
- **Evidence:** θ session ran ~35 verification commands across 5 stream returns. Caught 2 discrepancies (sub-agent self-reported wall time inflated 1.5-4× vs `duration_ms`; sub-agent's "Rule-of-Ten" framing vs CLAUDE.md text count). Both zero shipping-output impact — caught at the report-back boundary.
- **Applies when:** Every sub-agent return. Cheap (~30s wall per stream); catches the rare false-positive completion before it propagates.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Open session with lint-debt closure before any θ dispatch | Pattern P5 direct-push requires green main; lint-failure on HEAD would have polluted every subsequent commit's CI signal | CI green on fix in 44s; θ.A.A dispatch unblocked |
| Dispatch all 5 streams (3 core + 2 optional) in single session | User authorized "continue without me, I trust you"; Pattern P1 speedup made both optionals fit comfortably within capacity; brief's "optional/defer-to-ι" framing was a wall-time-budget caveat the speedup invalidated | 5-of-5 shipped in ~4h wall — matches η's 5-stream count in HALF η's wall time |
| θ.E (MBR/VBR) before θ.D (SDB) | θ.E is the smaller optional (inline ~30 LOC signatures vs vendor-in); completing the boot-chain trifecta with θ.A + θ.C had clear lens framing; θ.D vendor scope less certain | Order produced clean per-stream postmortems with boot-chain narrative at θ.E; θ.D vendor-tree-decision (P3 Rule-of-Two) emerged cleanly as final-stream lesson |
| θ.D clean-room rewrite vs verbatim fork | Upstream's `vivisect-vstruct-wb` transitive dep added 500+ LOC of unmaintained 3p; format-spec-driven rewrite was faster + cleaner | Pattern P3 vendor-in decision tree promoted to Rule-of-Two |
| Defer Rule #8 backend+worker+migrator rebuild to next-session boundary | Tier-1 testing via `make_live_db()` against host venv covers verification surface for all 5 streams; rebuilds add ~3-5 min × 5 streams = 15-25 min savings; class-shape changes only surface at container interaction | Validated η's deferred-rebuild cadence for 2nd consecutive campaign |
| Trust-but-verify after each sub-agent return | Sub-agent self-reports are claims, not evidence (Agent tool docstring); cheap to verify; expensive to discover false-positive completion post-hoc | 2 discrepancies caught; both shipping-zero impact; pattern is Pattern P7 |
