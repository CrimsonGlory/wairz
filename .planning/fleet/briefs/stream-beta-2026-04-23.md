# Stream β brief — Hardware/Firmware cluster (2026-04-23)
Agent: fleet-backend-pytest-unstable-2026-04-23-w1-a2
Branch: feat/stream-beta-pytest-2026-04-23 (merged as 50d1bc1)
Commits: 7 | Files green: 5 | Tests passing: 236 | Skipped: 0
Pattern: per-stream subdir /app/tests-beta (no lock fallback needed)
Service changes: backend/app/services/manifest_checks/components.py — added intent:// to _SENSITIVE_SCHEMES (MANIFEST-017, CWE-926) — additive dict entry, class shape unchanged
Key findings:
- APIKeyASGIMiddleware enforces auth when settings.api_key truthy; container runs with API_KEY=dev-test-key-wairz-b1; any AsyncClient fixture needs X-API-Key header
- Rule #1 security invariant test_symlink_to_outside_is_rejected preserved — fix was test-side (missing header), product realpath-rejection logic untouched
- mtk_lk parser dropped partition_size emission; test assertions must match new layout/file_info_offset contract
- Bytecode test had AnalyzeAPK patch at service module but source is androguard.misc; fix target = source module for lazy imports
