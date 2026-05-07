# Patterns: Phase 2 Test Coverage Backfill — Router Half (Waves 1-5)

> Extracted: 2026-05-07
> Campaign: .planning/campaigns/phase-2-test-coverage-routers-services-2026-05-06.md
> Postmortem: not found (campaign mid-flight; extracted at "router half complete" milestone)
> Scope: 21 router test files + 5 service test files = 30 commits, 301 cases, 1 production bug fixed, 1 shim hardening

## Successful Patterns

### 1. Per-file commit (Rule #25 in practice)
- **Description:** Each test file ships as its own commit with the form `test(<module>): <summary> (N cases, +M LOC)`. Bug fixes uncovered during testing ship as their OWN commit BEFORE the test that depends on them. Infrastructure changes (e.g. `_live_db.py` shim hardening at commit `080c10d`) ship as their own commit BEFORE the test that depends on them.
- **Evidence:** 30 commits across 5 waves, all bisect-clean. The `apk_scan` production bug fix at commit `4a6357f` was independently revertable without losing the test commit `fdd549f`. The `_live_db.py` shim hardening at `080c10d` was independently revertable from the fuzzing test at `2febcc0`.
- **Applies when:** any multi-file backfill where individual files are independently revertable. The discipline pays off when one file surfaces a problem that needs separate triage.

### 2. Cross-project security-boundary canary
- **Description:** When a router has `<X>.project_id != project_id → 404`, write a Rule #35b live canary that uses TWO real Project rows + a real `<X>` row in project A; request via project B's URL → assert 404. Mock tests with arbitrary UUIDs trivially match; real-DB canary catches a comparison-operator flip (`==` → `!=`).
- **Evidence:** Used in `test_emulation_router.py`, `test_comparison_router.py`, `test_cra_compliance_router.py`, `test_findings_router.py`, `test_documents_router.py`, `test_compliance_router.py`. The pattern recurs because the wairz routers use this idiom across 6+ endpoints.
- **Applies when:** any router that fetches a row by ID and then filters by project_id post-hoc.

### 3. F-A-06 confidence-bypass backstop
- **Description:** When a router OR service constructs a Finding directly (NOT via FindingService.create), assert the explicit `confidence="medium"` (or whatever literal) round-trips through DB SELECT. Mock tests that assert `db.add.call_count == 1` cannot fail on a constructor that silently drops the kwarg.
- **Evidence:** `test_attack_surface_router.py` canary (line 160 of attack_surface.py); `test_apk_scan_router.py` canary on `_persist_rest_manifest_findings`; `test_assessment_service.py` canary on `_create_finding`. All assert `confidence` field round-trips.
- **Applies when:** any code path that builds a Finding (or other ORM row with explicit literal-typed kwargs) and persists it. Audit-2026-05-04 cited 5 such sites; 4 now backstopped through Wave 3.

### 4. `tests/_live_db.py` shim hardening
- **Description:** Render JSONB / ARRAY as TEXT (not JSON) in SQLite DDL + pass a tolerant `json_deserializer` to the engine. Eliminates the SQLite-dialect-level JSON processor's double-decode against bare-string `server_default="'[]'"` columns.
- **Evidence:** Commit `080c10d`. Validated against 276 tests in 15.68s — no regressions. Closes a future-tax flagged in `0c71262` (Wave 1 system_emulation_service workaround). Subsequent Wave 2 fuzzing_service test (`2febcc0`) uses the hardened shim with no per-test workaround.
- **Applies when:** any test that needs to write JSONB rows through `make_live_db()` AND the model uses bare-string SQL DEFAULT (`server_default="'[]'"` or `"'{}'"`). The shim is the durable fix; per-test `port_forwards=[]` workarounds are now unnecessary.

### 5. Live canary discipline for non-persistent routers
- **Description:** When a router doesn't persist (e.g. SSE event streamer, file streamer), the "value-flow contract" canary becomes "what does the SUBSCRIBE call hit" or "what bytes flow through the response stream" — the equivalent of Rule #35b for non-DB surfaces.
- **Evidence:** `test_events_router.py` asserts `pubsub.subscribed_channels` contains exactly the requested-AND-valid types (NOT all 6 valid types when only 2 are requested). `test_files_router.py` asserts `/download` streams exact bytes through real FileService.
- **Applies when:** routers that don't write to DB but DO have value-flow contracts (channel selection, byte streaming, header construction).

### 6. Schema-check before authoring tests
- **Description:** Before writing test request payloads, grep the actual schema file (`backend/app/schemas/`) for field names. Several tests in this campaign initially failed with 422 because the test draft assumed Docker-SDK or generic field names that didn't match the wairz-specific Pydantic schema.
- **Evidence:** PortForward (`host`/`guest` not `host_port`/`container_port`), KernelResponse (`file_size`/`uploaded_at` not `size_bytes`), FindingStatus (`open/confirmed/false_positive/fixed` not `resolved`), DeviceBridgeStatus (`connected`/`bridge_host` not `reachable`/`host`). Each gotcha cost ~1 round-trip; total recovery time ~10 minutes across 5 incidents.
- **Applies when:** authoring any router test that constructs a request body. Cheaper than failing at runtime.

### 7. Wave cadence with explicit pause
- **Description:** 5 files per wave + explicit pause for user review. The pause is a real budget gate, not a formality — it forces the user to confirm direction before the next batch ships.
- **Evidence:** 5 waves shipped on schedule (Wave 5 had 6 files because the small-router count was 6; user opted to push through). User explicitly approved each wave-restart with "continue fully!"
- **Applies when:** large mechanical backfills where the cost of a wrong-direction batch is high. Don't bundle 30 commits into one go without checkpoints.

### 8. Sequential in-place commits over parallel worktrees
- **Description:** When test files are independent (each writes only `backend/tests/test_<X>.py`), serial in-place commits avoid Rule #23 worktree complexity AND give the test author full container access for Rule #11 smoke runs.
- **Evidence:** 30 commits across 5 waves, zero cross-stream sweeps, zero worktree setup overhead. The author benefits from `docker cp + pytest` round-trips inside the same container the rest of the test suite uses.
- **Applies when:** N independent files writing to disjoint paths AND the per-file iteration is fast (<1 minute end-to-end). Worktrees pay off when files share dependencies or per-iteration cost is high.

### 9. Inverse-Rule-30 generalisation (consumer-module patch for module-scope imports)
- **Description:** Standard Rule #30 says: when a third-party symbol is LAZY-imported inside a function body, patch the SOURCE module (not the consumer) — because the consumer module never bound the symbol at module scope. The INVERSE shape applies when the third-party symbol is imported at MODULE scope in the consumer service: patches MUST hit the CONSUMER module, not the source. Mechanical check: `grep -n "^from <lib>\|^import <lib>" backend/app/services/<X>_service.py` — top-level match ⇒ consumer-module patch; indented (function-body) match ⇒ source-module patch (Rule #30).
- **Evidence:** Wave 6 distribution across 5 service tests was 3 inverse + 2 source = 5/5 services covered. Reference exemplars: `test_assessment_service.py:200` (Wave 1 — original inverse instance); `test_pcap_analysis_service.py` includes a dedicated `TestRule30InverseConsumerPatch` class proving the consumer-module patch is the correct target.
- **Applies when:** writing any mock-patch test against a service. Decide patch target by `grep`-ing the import style FIRST; both shapes occur in wairz and choosing wrong produces a silent no-op patch (mock never fires, real symbol runs against fake inputs).

### 10. Real-binary canary > synthetic-byte canary
- **Description:** For services wrapping binary parsers (LIEF, pyelftools, pefile, capstone), use a REAL binary already present in the test container (`/bin/ls` is guaranteed x86_64 PIE ELF with libselinux/libcap/libc deps + `/lib64/ld-linux-x86-64.so.2` interpreter) rather than building synthetic ELF/PE bytes. Synthetic fixtures pass the magic-byte classifier but fail every downstream value-flow assertion because the parser rejects malformed program/section headers and returns raw ints instead of proper enums.
- **Evidence:** `test_binary_analysis_service.py::TestAnalyzeBinaryLive::test_real_x86_64_elf_classified_correctly`. Cost: zero (binary already in container). Benefit: every architecture/endianness/bits assertion fires correctly because LIEF returns proper `lief.ELF.ARCH` enum values, so the arch-map lookup succeeds.
- **Applies when:** any service test that asserts on parsed-binary attributes (architecture, endianness, bits, imports, sections). If the test fails with `None` on a "happy path" arch assertion, the fixture is probably synthetic — switch to a real binary.

### 11. Autouse-prime fixture for module-level lazy-init state
- **Description:** When production code lazy-populates module-level dicts via a `_loaded` sentinel (e.g. `_ensure_lief()` populates `_LIEF_ELF_ARCH_MAP` on first call), tests that legitimately reset that sentinel to exercise the short-circuit branch leave the maps EMPTY for subsequent tests in the same session — silent value-flow regressions in any later `analyze_binary` call. Solution: an autouse fixture that resets the sentinel + clears the maps + force-runs the populator before EACH test.
- **Evidence:** `test_binary_analysis_service.py:160` `_prime_lief_maps` fixture. Eliminates cross-test state leakage from the lazy-init short-circuit test without sacrificing the short-circuit-branch coverage.
- **Applies when:** any service uses module-level lazy-init dicts/maps gated by a `_loaded`/`_initialized` sentinel AND the test suite needs to exercise BOTH the populated and unpopulated branches. The autouse fixture is cheaper and more durable than per-test setup/teardown.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Wave shape = 5 files | Matches Phase 1 cadence; user-paused review between waves | 30 commits across 5 waves; clean handoff |
| Serial commits, NOT worktrees | Files are independent; Rule #23 worktree overhead unjustified | Zero cross-stream sweeps |
| Skip `emulation_constants.py` | Pure constants module (153 LOC port lists) — no service surface | Documented in campaign Decision Log; correct triage |
| Per-file commit (Rule #25) | Independent revertability; bisect-clean history | Bug fix `4a6357f` cleanly separable from test `fdd549f` |
| `_live_db.py` shim hardening as separate commit | Test that depended on it (`2febcc0`) was independently revertable; shim itself was infrastructure | Validated against 276 tests; no regressions |
| PATCH happy-path canary on Project intentionally omitted | aiosqlite + `onupdate=func.now()` triggers refresh that needs greenlet context test client doesn't provide; production runs PostgreSQL | 5 cases shipped (vs 6 planned); 404 boundary still covered |
| Inverse Rule #30 documented | Module-imported symbol → patch CONSUMER module; lazy-imported → patch SOURCE | Both shapes now have explicit reference in test_assessment_service.py + test_androguard_service.py |
| Cross-project boundary canary as recurring pattern | 3 of 5 Wave 3 files + 4 of 5 Wave 4 files use the same shape | Generalized into the SUCCESSFUL-PATTERNS section here |
