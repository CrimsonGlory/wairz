# Anti-patterns: Autopilot models drift Family B + opportunistic quick-wins (M-9 + M-6) — 2026-05-05

> Extracted: 2026-05-05
> Campaign: ad-hoc autopilot pass (no campaign file)
> Companion to: `autopilot-models-drift-2026-05-05-patterns.md`

## Failed Patterns

### 1. Marking an intake "SHIPPED" when only 3/4 acceptance items are committed

- **What was done:** A prior autopilot session this morning edited 4 timestamp columns for Family A (the timezone=True drift). The intake's progress section recorded "Family A — SHIPPED" with all 4 columns listed. But `git log --since="2026-05-05 00:00" -- backend/app/models/hardware_firmware.py` returns empty — the hardware_firmware_blobs.created_at edit was made on disk and verified-via-runtime-smoke (`column.type.timezone == True`) but NEVER staged or committed. The intake's "SHIPPED" claim was incorrect: 3/4 of the work was committed, 1/4 was working-tree-only.
- **Failure mode:** The Family B autogen-empty assertion this session would silently rely on the uncommitted Family A change. Any future `git checkout HEAD~ && docker build` would surface a tz drift on hardware_firmware_blobs.created_at — making this session's "drift fully closed" claim wrong on a clean checkout.
- **Evidence:** `git status --short backend/app/models/` after Family B closure showed `M backend/app/models/hardware_firmware.py`. Mtime check (`stat -c '%y'` → 06:52:49 today) confirms it was edited this morning before the autopilot session that marked Family A shipped.
- **How to avoid:** When marking an intake "SHIPPED" in its progress section, don't rely on memory or post-edit "I think I committed that" — explicitly run `git status` AND `git log --since=<intake-open-time> -- <touched-files>` to confirm every claimed-shipped change is in HEAD. The runtime smoke (`column.type.timezone == True`) proves the EDIT works; only `git log` proves the COMMIT exists. Both are required; neither substitutes for the other.

### 2. Backend container's system `python` lacks project deps

- **What was done:** `docker compose exec -T backend python -c "from app.config import get_settings"` — failed with `ModuleNotFoundError: No module named 'pydantic_settings'`.
- **Failure mode:** The backend image's system Python (`/usr/local/bin/python`) doesn't have project deps installed — the `uv`-managed venv at `/app/.venv/` does. Running bare `python` finds the system interpreter, not the venv.
- **Evidence:** Re-running with `/app/.venv/bin/python` succeeded immediately.
- **How to avoid:** Inside the backend container, ALWAYS use `/app/.venv/bin/python`, `/app/.venv/bin/alembic`, `/app/.venv/bin/pytest` (where present). Never bare `python`. Same convention as the `docker compose exec -T -w /app -e PYTHONPATH=/app backend /app/.venv/bin/alembic ...` shape used everywhere else in this codebase.

### 3. Backend image doesn't ship pytest or the tests directory

- **What was done:** Tried `docker cp /home/dustin/code/wairz/backend/tests wairz-backend-1:/tmp/tests && docker compose exec -T backend /app/.venv/bin/pytest /tmp/tests/test_yara_service.py` — failed with `OCI runtime exec failed: ... pytest: stat /app/.venv/bin/pytest: no such file or directory`.
- **Failure mode:** The runtime backend image (built from `Dockerfile`, not `Dockerfile.ci`) excludes test runners and the tests directory. This is intentional (smaller production image, no test surface in production) but means M-6's natural verification path (run pytest) doesn't work without spinning up the CI image.
- **Evidence:** `docker compose exec backend ls /app/.venv/bin | grep pytest` returned no match. `/app/tests` directory absent.
- **How to avoid:** For test verification in this codebase, two options: (a) `Dockerfile.ci` build (heavier, ~30 s+); (b) direct `python -c` execution of the test logic for trivial verifies. This session used (b) for M-6: copied the env-override + cache_clear logic into a one-shot script that proves the same behavior as the test would. Document the path used in the commit body so future readers know what was actually verified.

### 4. Naively trusting an audit summary's "fix recommendation" without reading the discovery file

- **What was done:** M-9's audit summary said "CORS over-permissive — default to localhost-only". Looked like a one-line `allow_origins` change.
- **Failure mode:** Reading `backend/app/main.py:90-94` showed CORS WAS already localhost-only by default. Acting on the summary alone would have been a no-op edit. The discovery file (`audit-stream-b-routers-2026-05-04.md` F-B-10) had the actual finding: wildcard `allow_methods=["*"]` + wildcard `allow_headers=["*"]` + `allow_credentials=True`.
- **Evidence:** Discovery file's recommendation: "restrict allow_methods to the actual verbs in use (GET, POST, PATCH, PUT, DELETE) and allow_headers to the explicit list (Content-Type, X-API-Key, Authorization)". Final shipped change was tighter still: dropped Authorization since the codebase grep showed no Authorization header in use.
- **How to avoid:** Treat audit summaries as triage signal, not direction. Always read the cited discovery file before editing. The summary line compresses; the discovery file has the evidence and the actual recommendation. Cost of reading the discovery: 30 s. Cost of shipping a wrong "fix": one wasted commit + a follow-up correction.

### 5. Per-edit autogen migrations accumulate as alembic revisions if not deleted

- **What was done:** Each per-edit `alembic revision --autogenerate -m "drift check post X fix"` writes a new revision file under `/app/alembic/versions/<hash>_<name>.py`. Six edits ⇒ six accumulating revision files, each with a `revises` chain that would break if not cleaned.
- **Failure mode:** If left in place, the next real migration (post-session) would chain off whichever throwaway was most recent, polluting the migration tree. Worse, if alembic head sees multiple branches (one per throwaway), `alembic upgrade head` would refuse with "Multiple head revisions".
- **Evidence:** Each per-edit verification included an immediate `docker compose exec -T backend rm /app/alembic/versions/<hash>_*.py` after reading the autogen output. Final `alembic current` returned a single head matching pre-session state.
- **How to avoid:** When using `alembic revision --autogenerate` for verification (not for shipping), delete the generated file IMMEDIATELY after reading the output. Single-step: `rm /app/alembic/versions/<hash>_*.py`. Don't batch the cleanup; if the session crashes mid-sweep, the throwaways need to be hunted down later.

## Cross-cutting Lesson

This session validated the discipline that **a self-reported "SHIPPED" status in an intake file is not authoritative — git log is.** Earlier autopilot sessions wrote progress markers ("✅ shipped", "Family A SHIPPED") that turned out to mean "I edited this and ran a smoke test." The actual durability check is `git log` + `git status`. Future autopilot/archon/marshal closures should:

1. Run `git status --short` before claiming closure.
2. Run `git log --since=<intake-open> -- <touched-files>` to enumerate shipped commits.
3. Treat any `M`/`??` matches against the touched-files set as a closure gap, not a tolerable side effect.
4. Either commit the gap as part of the same closure (this session's choice for `0803eaf`) or push it back to a follow-up intake with an explicit handoff.

Companion to Rule #31 (re-grep with broader pattern before trusting "N hits") generalised to commit-tree state: re-check git status before trusting "scope X closed."
