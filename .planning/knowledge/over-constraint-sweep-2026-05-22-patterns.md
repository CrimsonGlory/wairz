# Patterns — Over-Constraint Sweep 2026-05-22

> Source: `.planning/postmortems/postmortem-over-constraint-sweep-2026-05-22.md`
> Date: 2026-05-22
> Outcome: 5 shipping commits + 1 housekeeping, ~3.5 hours

## Pattern #1 — Wave-1 single-axis scouts are sufficient for ad-hoc "find me X" audits

**Context.** The Rule #52 worked examples mandate Wave-1 + Wave-2 cross-feature critique for closed-grammar EXTENSIONS (file-format YAML registry, ICS protocol catalog) because Wave-1 single-axis scouts architecturally CAN'T surface cross-feature attacks. But ad-hoc "find me every instance of X" audits — where X is a single conceptual dimension applied across the codebase — are well-served by Wave-1 alone.

**Shape.** When the user's prompt is "find every place we have X" or "audit Y across the codebase" or "where are we doing W badly":

1. Decompose X / Y / W into 3-5 SUB-DIMENSIONS that span the surface area without overlap.
2. Launch 3-5 parallel research scouts, one per dimension, each with a tight ~300-500 word brief + a structured output format.
3. After scouts return, synthesize directly (no Wave-2 critique scouts needed) — present findings + prioritized fix sequence.
4. Ship per Rule #25 per-piece, validating each commit independently.

**Why no Wave-2.** Ad-hoc audits don't have inter-feature interactions to attack — every finding is independent. Wave-2 cross-feature critique adds noise (scouts invent connections that don't exist) without surfacing new attacks.

**Evidence.** Over-constraint sweep 2026-05-22: 4 Wave-1 scouts (rate-limit decorators / frontend timeouts+polling / resource ceilings / code-level caps) returned 50+ findings. Synthesis took 1 round-trip. 5-commit fix sequence shipped per Rule #25 in ~3 hours. Zero rework. No Wave-2 needed.

**Anti-pattern (when to USE Wave-2).** Wave-2 cross-feature critique IS necessary when:
- The dimension being audited is a closed-grammar extension (Rule #52 territory)
- The audit involves multi-source-of-truth alignment (DB CHECK ↔ Pydantic ↔ frontend Config)
- The audit produces a NEW abstraction that downstream code will depend on

For "find me X" where X is a single dimension applied across an existing codebase, single-axis Wave-1 is the right scope.

**Recipe.** When the user says "deep research and deep review all the places we have over-constrained" (or analogous "find every X" prompt):
1. Identify the AXES of X (rate-limit / timeout / resource / code-cap = 4 axes for this sweep).
2. Brief one scout per axis. Each brief includes: the rule that governs that axis, precise paths to investigate, the format of the report, severity classification criteria.
3. Run scouts in parallel.
4. Synthesize within ~1500 words. Group findings by severity (HIGH actively-blocks / MEDIUM bites-on-large-input / LOW defensive).
5. Prioritize commits by USER-FACING IMPACT first, RISK-COMPENSATION second, INTERNAL CONSISTENCY third.

## Pattern #2 — Rule #15 family confirmation: any new `String(N≤512)` column carrying paths/titles/identifiers should default to `String(1024)`+ minimum

**Context.** CLAUDE.md Rule #15 originally codified the `analysis_cache.operation` 100→512 widening. This sweep added 3 more instances (Finding.title 512→1024, Finding.file_path 512→2048, sbom.purl 512→1024). Rule-of-Three+ now exists.

**Shape.** Mechanical rule: when adding a NEW SQLAlchemy column declared `String(N)` where N ≤ 512 AND the column semantically carries:
- Paths (Windows long-paths can exceed 512 in WinSxS / nested Maven shaded jars)
- Titles (CRA / compliance / windows / ICS titles include OEM model + CWE list + check description)
- Identifiers (CPE / purl with classifier metadata)
- Banners (firmware build banners with timestamp + builder + branch)

Default the column to `String(1024)` minimum. For path-bearing columns, prefer `String(2048)` (Windows long-paths) or `String(4096)` (deeply-nested filesystem paths). Validate against the wairz reference set (Win11 ISO firmware, Medtronic ILLUMISITE, Yocto rootfs) at design time.

**Why.** The widening cost is zero — PostgreSQL `ALTER COLUMN ... TYPE VARCHAR(N)` with larger N is metadata-only (no table rewrite). The contraction cost is HIGH — a silently-truncated value loses operator visibility (Finding.title cuts off CWE evidence; Finding.file_path cuts off the path the operator needs to investigate).

**Evidence.** Rule-of-Three+ instances:
- `analysis_cache.operation` 100→512 (2026-04, Rule #15 original)
- `windows_mft_record.full_path` String(4096) (already wide at model authoring)
- `windows_lnk_record.target_path` String(2048) (already wide)
- `Finding.title` 512→1024 (this sweep, 2026-05-22)
- `Finding.file_path` 512→2048 (this sweep, 2026-05-22)
- `sbom.purl` 512→1024 (this sweep, 2026-05-22)

**Recipe.** When authoring a new model:
1. List every `String(N)` column.
2. For each, ask: "could this value carry a path / title / identifier on real-world firmware?"
3. If yes AND N ≤ 512: set to 1024 minimum (or 2048 for paths).
4. If unsure: query the reference firmware set to measure actual values via `SELECT MAX(LENGTH(<col>)) FROM <table>`.

## Pattern #3 — Per-commit `docker cp + restart` validates without Rule #8 rebuild overhead

**Context.** Rule #8 mandates `docker compose up -d --build backend worker migrator` after any Dockerfile or alembic change. But INTRA-SESSION iteration (5 commits over 3 hours) would burn ~15 minutes on rebuilds if applied per commit. Rule #20 codified `docker cp + restart` as the fast-iteration alternative.

**Shape.** For each per-piece commit during a sweep:
1. Edit files locally (Edit tool).
2. Test via host venv if applicable (`(cd backend && .venv/bin/pytest ...)`).
3. `docker cp <file> wairz-<service>-1:/app/<path>` for each changed file affecting a service.
4. `docker compose restart <service>` if the change is module-scope (constants, class shape).
5. Runtime smoke: `docker compose exec -T -w /app -e PYTHONPATH=/app <service> /app/.venv/bin/python -c "<import + check>"`.
6. Commit.

**End of session:** ONE Rule #8 full rebuild (`docker compose up -d --build backend worker migrator`) bakes the changes into the image. The `docker cp + restart` cycles during the session are VALIDATION ONLY — they're lost if the operator force-recreates a container.

**Evidence.** 5 commits × ~30s validation cycle = ~2.5 min of validation. Full rebuild × 5 = ~15 min. 6× speedup on validation alone.

**Recipe.** Pair with the `git commit` step: every per-piece commit includes a `docker cp ... && docker compose restart ... && runtime smoke` as its validation step. The final commit (housekeeping / postmortem) is followed by the ONE Rule #8 full rebuild.

## Pattern #4 — Live nginx config inspection via `docker compose exec frontend cat /etc/nginx/conf.d/default.conf` is the canonical way to verify nginx env substitution

**Context.** wairz frontend uses nginx-unprivileged's template feature — files in `/etc/nginx/templates/*.template` are envsubst'd at container START into `/etc/nginx/conf.d/`. The substitution is invisible at the source layer (template is `client_max_body_size ${MAX_UPLOAD_SIZE_MB}M`; the actual served config depends on the container's env at start time).

**Shape.** When debugging an nginx-served behavior that depends on an env var:
1. Read the live config: `docker compose exec -T frontend cat /etc/nginx/conf.d/default.conf`.
2. Read the env in the container: `docker compose exec -T frontend printenv <VAR>`.
3. Compare: live config should reflect the env's value via envsubst.
4. If mismatched, the container needs `docker compose up -d --force-recreate frontend` to re-run envsubst with the current env.

**Evidence.** Session 2026-05-22 first-five-minutes diagnosis: nginx logs showed 413 rejections; live config showed `client_max_body_size 2048M`; `.env` declared `MAX_UPLOAD_SIZE_MB=20480`. The mismatch IS the diagnosis.

**Recipe.** Add this to the "frontend debugging" checklist: when nginx behavior surprises you, inspect the LIVE rendered config, not the template source.
