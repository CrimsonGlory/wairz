# Patterns: Autopilot models drift Family B + opportunistic quick-wins (M-9 + M-6) — 2026-05-05

> Extracted: 2026-05-05
> Campaign: ad-hoc autopilot pass (no campaign file — closed `audit-models-orm-vs-db-schema-drift-2026-05-05` intake + 2 quick-wins)
> Postmortem: none
> Commits: `f5c0824` `04c8be1` `cb83774` `7f65908` `8fba6f7` `49d9d8f` `f95fc53` `faa1c70` `79281b8` `77e5030` `0803eaf` (11 commits)

## Successful Patterns

### 1. Per-edit autogen verification (no restart) localises which edit closed which drift entry

- **Description:** When closing index/UC drift across N tables, run `docker cp <model.py> <container>:<path>` and then `alembic revision --autogenerate -m "drift check post X fix"` between EACH per-table model edit. The autogen output reduces visibly with each fix — emulation_sessions edit dropped 4 lines from the autogen output (idx_emulation_project, idx_emulation_status, ix_emulation_sessions_container_id, ix_emulation_sessions_project_id), sbom edit dropped 5 (idx_sbom_firmware, uq_sbom_components_firmware_name_version_cpe, ix_sbom_components_firmware_id, ix_sbom_vulnerabilities_blob_id), etc. Every commit message can claim "after this change, autogen no longer reports {specific entries}" with evidence.
- **Evidence:** Commits `f5c0824`..`49d9d8f` each ran an intermediate autogen producing decreasing drift counts (12 → 8 → 8 → 2 → 1 → 0). Final empty `pass`/`pass` migration verified twice (once at end of Family B, once after Family A residual `0803eaf`).
- **Applies when:** N-table mechanical model edits where autogen is the acceptance gate. Cost per verification: ~5 s. Total cost: ~30 s for 6 verifications. Worth it for clean commit attribution.

### 2. `docker cp` + `alembic exec` is enough for autogen — no restart between edits

- **Description:** Rule #20's "class-shape change requires restart" applies to the LIVE uvicorn process holding cached ORM class instances in memory. Alembic runs in a fresh Python process invoked via `docker compose exec`, so it imports the modified models cleanly each time. Skipping the restart between per-table edits saves ~25 s × 6 = ~2.5 min over a 6-edit sweep. Restart only needed at the END of the stream (Rule #8 backend+worker rebuild for durability across the next session).
- **Evidence:** All 6 per-table fixes verified via `docker cp <model.py> wairz-backend-1:/app/app/models/<file>` followed by `docker compose exec -T -w /app -e PYTHONPATH=/app backend /app/.venv/bin/alembic revision --autogenerate ...`. Single `docker compose up -d --build backend worker` at the end re-validated against the rebuilt image.
- **Applies when:** Per-table model edits where the only verification needed is alembic autogen (or any Python-script verification that runs in a fresh process). Does NOT apply when the verification needs the live uvicorn process to see the change (e.g. live HTTP smoke against a running endpoint that uses the model — that DOES need the restart per Rule #20).

### 3. Final empty-autogen check after `docker compose up -d --build backend worker` catches uncommitted-but-on-disk scope gaps

- **Description:** Per-edit autogen verification uses `docker cp` (host file → container's running fs) which lets the autogen see ANY edited file, including ones not yet `git add`'d. The final acceptance check rebuilds the image FROM the host filesystem (which IS the git working tree) — but that's still NOT the committed tree. The catch is: `docker build` reads the working tree, not HEAD. So an edited-but-uncommitted file gets baked into the rebuild. To prove the scope is genuinely closed against HEAD, after the per-edit sweep AND the rebuild, do `git status` to enumerate any `M`'s — those are uncommitted files the autogen-empty assertion is implicitly riding on. This session caught `backend/app/models/hardware_firmware.py` modified-but-uncommitted (the prior autopilot's claimed-shipped Family A residual). Without that catch, a future `git checkout HEAD~ && docker build && alembic revision --autogenerate` would surface a tz drift on hardware_firmware_blobs.created_at.
- **Evidence:** `git status --short` after the Family B closure showed `M backend/app/models/hardware_firmware.py`. `git log --since="2026-05-05 00:00" -- backend/app/models/hardware_firmware.py` returned empty (no commits today touching it). The Family A intake claimed "SHIPPED" but `git log` told the truth: 3/4 timestamp columns were committed, the 4th was on disk only. Closing commit `0803eaf` honestly captured the gap.
- **Applies when:** Any intake closure whose acceptance check runs against the WORKING TREE (rebuild + verify, lint + verify, typecheck + verify). The acceptance check proves the working tree passes; only `git status` proves what's committed. The gap matters whenever a future session might re-rebuild from `git clean -fdx && git checkout HEAD`.

### 4. Read the discovery file before "fixing" the audit recommendation

- **Description:** M-9 ("CORS over-permissive") with the surface-level recommendation "default to localhost-only" looked like a one-line config change. But reading `backend/app/main.py:90-94` showed CORS WAS already localhost-only by default — `cors_origins=""` env var falls back to `["http://localhost:3000", "http://127.0.0.1:3000"]`. The actual issue (per discovery file `audit-stream-b-routers-2026-05-04.md` F-B-10) was wildcard `allow_methods=["*"]` + wildcard `allow_headers=["*"]` combined with `allow_credentials=True`. Reading the discovery file BEFORE editing prevented a wasted "fix" of a non-issue and pointed at the real change (narrow methods to actual verbs, narrow headers to actual sent values).
- **Evidence:** Commit `faa1c70` body documents the actual change (allow_methods → 5 explicit verbs grep'd from `@router\.*` decorators; allow_headers → `["Content-Type", "X-API-Key"]` grep'd from frontend axios usage). Curl preflight against running backend confirmed the narrowed lists.
- **Applies when:** Any audit recommendation that sounds like a one-liner — read the underlying discovery file first to confirm what the discovery actually flagged. Audit summary lines compress; discovery files have the evidence.

### 5. Live preflight curl as the M-9 equivalent of a live canary (Rule #35b for HTTP behaviour)

- **Description:** For HTTP middleware changes (CORS, rate limiting, auth), config-string verification is insufficient — Rule #35b's mock-vs-canary distinction maps directly: editing the source proves "the config was set"; curling preflight proves "the browser will see the narrowed value." `curl -X OPTIONS -H "Origin: http://localhost:3000" -H "Access-Control-Request-Method: GET" -H "Access-Control-Request-Headers: X-API-Key,Content-Type" http://localhost:8000/api/v1/health -i` returns the actual `access-control-allow-methods` / `access-control-allow-headers` Starlette will send to a real browser. The response showed Starlette auto-includes safelist headers (Accept, Accept-Language, Content-Language) — would not have been visible from the source-edit alone.
- **Evidence:** Commit `faa1c70` body includes the curl invocation and full response. The Starlette safelist behavior matters for documenting "what the wire actually says" — relevant to anyone debugging a future "header X blocked" report.
- **Applies when:** Any middleware behavior change (CORS, rate limit, auth, headers, redirects). Source-edit proves "I set X"; live curl proves "the wire reflects X". Cost: ~10 s. Catches Starlette/FastAPI's defaults injection.

### 6. Env override + `cache_clear()` is the durable mock pattern for `@lru_cache`'d settings (Rule #20)

- **Description:** When a test needs a specific Settings field value, `monkeypatch.setattr(get_settings(), "field", value)` mutates the cached singleton. If the test fails between the mutation and pytest's restore-on-teardown, the next test in the same process sees the mutated value. Even if teardown fires reliably, the mutation bypasses pydantic-settings validation (e.g. invalid types accepted silently). The durable pattern: `monkeypatch.setenv("FIELD_NAME", "value"); get_settings.cache_clear()` in a try/finally that re-clears on exit. The next `get_settings()` call re-instantiates Settings via env-var lookup — clean state, validation enforced, no leak.
- **Evidence:** Commit `79281b8` swapped `test_yara_service.py::test_raises_on_empty_rules_dir` from setattr-on-cached-instance to env+cache_clear. Verified the env override propagates and the ValueError fires correctly via direct Python (backend image doesn't ship pytest).
- **Applies when:** Any test that needs a non-default Settings value, in a codebase with `@lru_cache` on `get_settings()`. Pydantic-settings reads env vars at instantiation, so the env override naturally respects validation rules. The try/finally with `cache_clear()` on both ends ensures clean state regardless of test outcome.

### 7. Width-canary discipline at intake-closure time (Rule #31 applied to commit-tree state)

- **Description:** Rule #31 (re-grep with broader pattern before trusting "N hits") usually applies to source code searches, but it generalises to ANY claim of "scope X is closed." When closing the models-drift intake, the natural close-gate is "autogen is empty." But "autogen is empty against the working tree" ≠ "autogen will be empty against any future clean checkout of HEAD." The width-canary at closure: `git status --short backend/app/models/` showed an `M` for hardware_firmware.py. That one-second check caught the Family A residual that would have surfaced as drift on a future fresh clone.
- **Evidence:** This session: `git status` after Family B sign-off → `M backend/app/models/hardware_firmware.py` → committed as `0803eaf` "Family A residual" with body documenting the implicit-dependency rationale.
- **Applies when:** Any intake closure where the acceptance check runs against the working tree. The closure-time `git status` check is the cheap canary that distinguishes "I made it work" from "the work is durable in git."

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Per-table commits for Family B (6 commits) | Rule #25 (≥3 independently-verifiable sub-tasks); intake explicitly requested per-table; bisect cleanliness | 6 clean commits, autogen-empty at end |
| `docker cp` + alembic exec without restart between per-table edits | Rule #20: alembic runs in fresh Python process, doesn't see cached class state. Saves ~25 s × 6 ≈ 2.5 min | Verified per-edit; final rebuild caught durability |
| Commit Family A's hardware_firmware.py residual as part of this session (`0803eaf`) | Empty-autogen sign-off implicitly depended on it; closing scope honestly | Shipped; future-clean-rebuild produces empty autogen |
| For uart_sessions.firmware_id: drop `index=True` (DB has no index) instead of migration | Intake guidance "match what the DB already has"; uart_sessions row count is small; FK lookup cost negligible | DB-tracks-model resolution; clean intake closure |
| For sbom_components.firmware_id: drop `index=True` AND add explicit `Index("idx_sbom_firmware", ...)` | DB has `idx_sbom_firmware`, not the SA-default `ix_sbom_components_firmware_id`. Naming conflict resolution per intake guidance | Final autogen-empty includes sbom_components |
| Narrow CORS to actually-used verbs (5) and headers (2) — narrower than the audit's recommendation | Codebase grep showed no Authorization header in use, only X-API-Key. Tighter is better when the change is verifiable. | M-9 shipped narrower; preflight curl confirmed |
| Env+`cache_clear()` for yara test instead of setattr on cached Settings (M-6) | Rule #20 anti-pattern: mutating cached singleton. Env+cache_clear is durable + validated by pydantic. | M-6 robust to mid-test failures |
| Skip backend pytest run; use direct python -c for M-6 verification | Backend image doesn't ship pytest or tests/ directory; CI image (`Dockerfile.ci`) would have them but startup cost is high for one-test verify | Direct python -c proved the test logic; full suite deferred to CI |

## Quality Rule Candidates

None reach high enough confidence for harness.json:

- **`monkeypatch.setattr(get_settings()`-on-cached-Settings** (M-6 antipattern) — the actual pattern was `real_settings = get_settings(); monkeypatch.setattr(real_settings, ...)` which a single-line regex won't catch. Multi-line state-flow detection isn't viable in the harness.json regex shape. Rule #20 in CLAUDE.md and the M-6 commit message capture the discipline durably.
- **Bare `python` (no /app/.venv/bin/) inside `docker compose exec backend`** — would catch `docker compose exec backend python ...` failure-to-find-deps. But it would false-positive on legitimate `docker compose exec backend python ...` for sibling system-python tooling. Skip.
- **Per-edit autogen + final rebuild discipline** — not a regex-detectable pattern. Captures as a successful pattern in this file instead.
