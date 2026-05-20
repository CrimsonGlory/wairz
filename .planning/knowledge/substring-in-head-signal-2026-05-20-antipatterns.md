# Anti-patterns: substring_in_head signal kind (P3.x — 2026-05-20)

> Extracted: 2026-05-20
> Campaign: (no campaign file — direct-shipped per Rule #25 per-piece cadence)
> Postmortem: .planning/postmortems/postmortem-substring-in-head-signal-2026-05-20.md
> Commits: dcebd1c..7216d47

## Failed Patterns

### 1. Editing source files DURING a parallel `docker compose up -d --build` snapshot window
- **What was done:** Started the Rule #8 rebuild in the background (~6 min duration compiling C extensions for pyesedb), then edited 4 source files in parallel during the build window: `app/schemas/file_format.py`, `app/services/file_format_catalog/resolver.py`, `app/services/format_detection.py`, and the `windows_installer_iso.yaml`.
- **Failure mode:** BuildKit's `COPY . .` layer snapshotted at some moment during the build. Only edits made BEFORE the snapshot moment landed in the image — for this session, only the schema edit. The resolver + format_detection + YAML edits made AFTER the snapshot did NOT land. Symptom: `docker compose exec -T backend grep -c "substring_in_head" /app/app/services/file_format_catalog/resolver.py` returned 0 despite the host file containing 4 matches. Live canary would have produced subtle wrong behaviour (catalog can't resolve via new evaluator → falls back to bridge → no schema extension visible).
- **Evidence:** Postmortem What Broke #1; container mtimes for resolver.py / format_detection.py show 2026-05-20 01:25:34 UTC (well before my 15:36 UTC edits), confirming the COPY snapshot included an older version.
- **How to avoid:** Sequential ordering — either (a) wait for the rebuild to complete BEFORE editing; (b) edit-first / rebuild-after (P3.2 used this); or (c) accept the parallel snapshot risk + verify with `docker compose exec backend grep -c <token> <file>` per edited file + `docker cp` the missing ones + `docker compose restart` for class-shape changes. Path (c) saves ~5 min idle time but costs ~3 min recovery if mis-snapshotted.

### 2. `docker compose exec backend uv run python tests/fixtures/.../_GENERATE.py` for fixture regeneration
- **What was done:** Initial attempt to regenerate the corpus fixture inside the running backend container via `docker compose exec -T -w /app backend uv run python tests/fixtures/format_parity_corpus/_GENERATE.py`.
- **Failure mode:** Failed with `can't open file '/app/tests/fixtures/format_parity_corpus/_GENERATE.py': [Errno 2] No such file or directory`. The production image's `.dockerignore` excludes `tests/` (commit `b9f438f`, 2026-04-18), so the file is genuinely absent.
- **Evidence:** Postmortem What Broke #2; `backend/.dockerignore` line `tests/`; `docker compose exec backend ls /app/tests` returns "No such file or directory".
- **How to avoid:** Always run dev-only scripts (fixture generators, ad-hoc analysis, etc.) on the HOST via `cd backend && uv run python <path>`. The host's `backend/.venv` has the same `uv.lock`-resolved deps as the container. NEVER use `docker compose exec` for tests/, alembic/versions/, .ruff_cache/, .planning/, docs/, *.md, .citadel/, or .claude/ paths — all are .dockerignore'd.

### 3. Trusting "phantom-green" pytest output from a stale container
- **What was done:** At session-open, ran `docker compose exec -T -w /app backend uv run pytest tests/test_file_format_catalog.py ...` against the still-running "Up 15 hours" backend container — got `223 passed in 4.11s`. After the Rule #8 rebuild, the SAME invocation against the SAME path returned `ERROR: file or directory not found: tests/test_file_format_catalog.py`.
- **Failure mode:** Logically impossible if `.dockerignore` was respected in both builds, BUT the earlier output was real (pytest ran + produced output). Possible explanation: the previous "Up 15 hours" backend container was built from a state where `.dockerignore` didn't exclude tests/ (developer override, partial rebuild, hand-staged `.dockerignore` removal). Trusting an out-of-band 223-passed signal would have masked a real .dockerignore exclusion of tests/.
- **Evidence:** Postmortem What Broke #3; baseline run output (223 passed in 4.11s) vs post-rebuild run (`ERROR: file or directory not found`).
- **How to avoid:** Treat HOST pytest as the canonical test execution surface for wairz. `docker compose exec backend pytest tests/...` is opportunistic and may produce phantom-green results when the container's image diverges from `.dockerignore`. Use `cd backend && uv run pytest tests/...` instead — it reads the LIVE source files directly with no caching ambiguity.

### 4. Adding a Pydantic model with quoted forward reference WITHOUT `from __future__ import annotations`
- **What was done:** Authored `class SubstringInHeadConstraint(BaseModel): ... @model_validator def _check_needles(self) -> "SubstringInHeadConstraint": ...` with a QUOTED forward reference in the return annotation (necessary because the class is being defined when `_check_needles` is parsed — `SubstringInHeadConstraint` doesn't exist in the namespace yet).
- **Failure mode:** ruff UP037 fires on the quoted annotation, suggesting "Remove quotes from type annotation". Mechanically correct — `from __future__ import annotations` at the top of the file would make ALL annotations strings and the explicit quote becomes redundant. WITHOUT that future-import, removing the quotes raises `NameError` at function definition time. 8 pre-existing UP037s in the file follow the SAME quoted-forward-reference shape, indicating the file lives without the future-import.
- **Evidence:** Ruff output during validation; 8 pre-existing UP037 instances + 1 new = 9 total in `app/schemas/file_format.py`.
- **How to avoid:** When adding a new Pydantic model + model_validator to `file_format.py`, follow the existing project convention (quoted forward reference) — NOT ruff's UP037 suggestion. The UP037 cleanup is a SEPARATE refactor (one-line `from __future__ import annotations` at top of file). Don't try to fix one UP037 without fixing all 9, OR add `from __future__ import annotations` while NOT touching anything else — both are out-of-scope for a schema extension commit per Rule #25 minimum-scope.

### 5. Including SHA placeholder `<sha>` in same commit as the artefact it references
- **What was done:** Commit `dcebd1c` bundled the source change + ADAPTIVE_BACKLOG.md row that referenced `<sha>` as a placeholder (because the commit SHA didn't exist until the commit landed).
- **Failure mode:** Required a follow-up commit (`52bce07`) to pin the actual SHA. The backlog row was momentarily inconsistent between the artefact-creation commit + the SHA-pin commit.
- **Evidence:** Commit chain: `dcebd1c` (source + backlog row with `<sha>`) → `52bce07` (SHA fixup).
- **How to avoid:** Two cleaner alternatives: (a) Use a 2-commit shape — Commit A ships the source + tests; Commit B updates ADAPTIVE_BACKLOG.md referencing commit A's SHA (cleanest; matches the prior session's Rule #21 closure pattern from `e7824cf`). (b) Use a Git filter or `git commit --amend` to fix up the placeholder before the SHA-pin commit is needed (less clean; loses the audit trail). Path (a) preferred for any session shipping source + backlog sync.
