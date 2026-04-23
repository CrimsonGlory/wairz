# Stream γ brief — Data/Emulation cluster (2026-04-23)
Agent: fleet-backend-pytest-unstable-2026-04-23-w1-a3
Branch: feat/stream-gamma-pytest-2026-04-23 (merged as c53800c)
Commits: 6 | Files green: 5 | Tests passing: 163 | Xfailed: 1
Pattern: fallback canonical /app/tests/ + file lock (per-stream subdir broke test_scan_harness cross-imports)
Service changes: none (edited backend/tests/harness/orchestrator.py which is test infra)
Key findings:
- Pre-flight hypothesis CONFIRMED: test_cache_module.py had 2 test bugs (AsyncMock hasattr auto-create + SQLAlchemy UUID hex literal). _cache.py service is Rule #3-compliant.
- scan_harness orchestrator patches app.services.androguard_service.APK; APK is lazy-imported so patch target should be androguard.core.apk.APK (same defect as α)
- fixture_def={} triggered orchestrator.should_skip short-circuit, bypassing scanner patches — minimal fixture must be non-empty
- Zip-bomb entry-count pre-flight check was aspirational (not implemented); marked @pytest.mark.xfail(strict=True) to lock the gap
- APIKeyASGIMiddleware monkey-patching via autouse fixture is the standard disable pattern — gets applied BEFORE the ASGI app instantiation
