# Opening Actions Baseline — 2026-05-21

## Rule #8 rebuild
`docker compose up -d --build backend worker migrator` — completed exit 0.

Container state post-rebuild:
- wairz-backend-1: Up 3 min (healthy)
- wairz-worker-1: Up 3 min (healthy)
- wairz-postgres-1: Up 2 weeks (healthy)
- wairz-redis-1: Up 2 weeks (healthy)
- wairz-frontend-1: Up 2 days (NOT rebuilt — image is 2 days old; flagged for Scout D stale-bundle audit per `auto-frontend-rebuild-not-restart` harness rule)

## Rule #20 caveat
Tests are excluded from the production image via `backend/.dockerignore` (`tests/` line). The user-supplied spec command `pytest tests/test_*.py` would silently exit 0 with "no tests ran" — a Rule #17 / Rule #35a-pipe-style silent-success trap. Applied Rule #20 `docker cp backend/tests wairz-backend-1:/app/tests` to get the suite running.

## Spec drift
- `tests/test_sbom_service.py` (named in user spec) does NOT exist. It was absorbed by the Phase 5 SBOM split (Rule #27, session 7e8dd7c3 2026-04-22). Current SBOM-adjacent test files:
  - `test_sbom_router.py` ✓ (cited)
  - `test_vulnerability_service.py` (substituted for test_sbom_service.py)
  - `test_finding_service.py`
  - `test_finding_service_pe_emit.py` ✓ (cited)
  - `test_hardware_firmware_cve_matcher.py` ✓ (cited)
  - `test_hardware_firmware_router.py` ✓ (cited)
- Re-ran with the corrected file list.

## Pytest baseline (192 tests collected, 6.03s wall)

**Result:** 180 passed / 12 FAILED / 0 skipped

**All 12 failures share root cause:**
```
sqlalchemy.exc.NoReferencedTableError: Foreign key associated with column
'volatility_injection_records.memory_image_id' could not find table
'memory_dump_image' with which to generate a foreign key to target column 'id'
```

Failing tests (all `LiveCanary` class — Rule #35b live-canary discipline):
- `test_sbom_router.py::TestSbomGeneratePersistenceLiveCanary::test_generate_persists_components_with_correct_fields`
- `test_sbom_router.py::TestVulnScanStatusLiveCanary::test_components_with_vuln_counts_subquery_filtered_by_firmware`
- `test_sbom_router.py::TestVulnScanStatusLiveCanary::test_status_field_round_trips_through_live_db`
- `test_vulnerability_service.py::TestCreateFindingsFromVulnsLiveCanary::test_persists_finding_with_confidence_and_linked_fields`
- `test_vulnerability_service.py::TestCreateFindingsFromVulnsLiveCanary::test_no_finding_created_when_only_low_severity`
- `test_vulnerability_service.py::TestBuildSummaryLive::test_summary_groups_by_severity`
- `test_hardware_firmware_router.py::TestPeSignaturesLiveCanary::test_list_and_get_pe_signature_round_trip`
- `test_hardware_firmware_router.py::TestPeSignaturesLiveCanary::test_get_signature_belonging_to_other_firmware_returns_404`
- `test_finding_service_pe_emit.py::test_emit_persists_authenticode_finding_with_full_columns`
- `test_finding_service_pe_emit.py::test_emit_persists_two_findings_for_double_bad_pe`
- `test_finding_service_pe_emit.py::test_emit_persists_zero_rows_for_clean_pe`
- `test_finding_service_pe_emit.py::test_emit_with_unknown_signed_persists_medium_authenticode_finding`

## Significance for the investigation

This is a **second-order finding**: the live-canary test coverage for SBOM + vuln-scan + finding emit is **currently broken** because `make_live_db()` can't instantiate metadata due to the FK breakage. Mock-based dispatch tests pass (Rule #35b weak-shape), but value-flow validation against a real ORM is impossible to run today. **Any regression in SBOM persistence would silently slip past CI** because the live-canary tests fail at metadata-load time, not at assertion time.

Cross-ref: ADAPTIVE_BACKLOG `morning:RvwC-make_live_db-FK` MEDIUM — originally noted as "3 tests in `test_sbom_router.py` blocked + likely more"; actual count today is **12 across 4 test files**. The "likely more" half of the original observation is confirmed.

## Action items surfaced (for Wave-2 / fix synthesis)

1. **Whatever the operator's primary regression is, the live-canary test layer is structurally unable to detect it today.** Fix order should be: (a) unblock `make_live_db()` FK, (b) re-run live canaries, (c) only then trust the test layer as a regression gate.
2. The `volatility_injection_records → memory_dump_image` FK references the wrong table name. The actual table is likely `memory_dump_images` (plural) or the model was renamed. Either side of the FK declaration is wrong.
3. The 180 passing mock-based tests provide ZERO assurance that SBOM persistence, vuln-scan persistence, or finding-emit value-flow are healthy. They only assure dispatch-shape.

---

Wave-1 + Wave-2 deep-research dispatch follows. Live-DB probe (Scout C) does the actual ground-truth; this opening baseline scopes the test-layer blind spot.
