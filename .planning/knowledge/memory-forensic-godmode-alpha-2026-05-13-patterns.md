# Patterns: λ memory-forensic-godmode α (session 1)

> Extracted: 2026-05-13
> Campaign: ``.planning/intake/memory-forensic-godmode-alpha-kickoff-2026-05-12.md``
> Postmortem: ``.planning/postmortems/postmortem-memory-forensic-godmode-alpha-session-1-2026-05-13.md``
> Scout reports: ``.planning/research/memory-forensic-godmode-alpha-2026-05-13/``

## Successful Patterns

### 1. 3-scout research-fleet → synthesize → ship-per-piece (Rule-of-Three)

- **Description:** Dispatch 3 parallel research agents on
  decomposed-but-related questions; consolidate findings into a
  short synthesis brief that locks decisions BEFORE any code ships;
  then execute per-piece commits referencing the brief.
- **Evidence:** Vol3 library probe + ISF bundle dry-run + plugin
  taxonomy scouts ran in 5-7 min each in parallel; synthesis brief
  locked subprocess-over-Python-API, GitHub-release-over-Apache-mirror,
  ~885 MiB bundle size, quarterly refresh cadence, ``windows.malware.*``
  paths for the injection walker — all decisions made BEFORE λ.α.A
  shipped. Three streams shipped in close succession with no mid-stream
  "should we?" stalls.
- **Applies when:** Any "broad-research-driven implementation" directive
  where the scope is well-defined but the answers aren't yet known.
  Especially good when external library / format / API knowledge is
  on the critical path.
- **Promotion:** Third validated instance per user-memory log
  (``feedback_do_them_all_pattern.md``); this session pushes it from
  Rule-of-Two to Rule-of-Three. Durable.

### 2. Synthesis brief locks decisions before implementation

- **Description:** Write a short (~1 page) decision-lock document that
  consolidates scout findings into a numbered decision list +
  risk-surface section + a "first-session deliverables" section. Code
  references the brief for any decision question that arises.
- **Evidence:**
  ``.planning/research/memory-forensic-godmode-alpha-2026-05-13/synthesis.md``
  — 1 page, 6 sections (decisions / risks / streams 1-4 / deferrals /
  spillover / reference card). Eliminated mid-stream stalls.
- **Applies when:** After parallel research; before any commit. Always.

### 3. Rule #39 inner/outer/safe triplet — Rule-of-Six

- **Description:** New walker = three async functions: inner (pure
  logic with caller-owned db), outer (state machine with own session),
  safe (unpack hook with own session that swallows exceptions and
  doesn't mutate status).
- **Evidence:** λ.α.B's memory_image_enumerator.py is the sixth
  application of the pattern (γ.4 + δ.5 + ε.1.b.3 + ζ.2.B + ζ.3.B +
  λ.α.B). The shape is so well-understood that authoring took ~30
  minutes including the test gate.
- **Applies when:** Any new walker / artefact-enumerator added to the
  walker registry. CLAUDE.md Rule #39 codifies the pattern.

### 4. Rule #47 mechanical application — Rule-of-Two

- **Description:** When a state-machine refactor decouples an OLD
  invariant from a NEW one, every consumer of the OLD invariant must
  be migrated OR have its assertion updated to discriminate on the
  TRUE intent rather than the (now-broken) proxy.
- **Evidence:** The walker-bridge wire-in (``5f3d195``) set
  ``firmware.extracted_path`` unconditionally for generic-ZIP
  extractions, decoupling "extracted_path set" from "rootfs classified".
  ``test_zip_of_fat_image_does_not_shortcut`` had asserted
  ``extracted_path is None`` as a proxy for "rootfs shortcut didn't
  fire". Fix: discriminate on ``unpack_log`` marker (the message the
  rootfs shortcut writes) — captures the TRUE invariant. Commit
  ``7438520``.
- **Applies when:** Any state-machine / invariant refactor. Companion
  to Rule #47 codification incident itself (which was the FIRST
  application — Rule-of-One). This is the SECOND mechanical
  application; Rule #47 is now Rule-of-Two.

### 5. P1 (single-sub-agent + precedent reuse) for one-off scripts

- **Description:** When writing a one-off operational script
  (backfill, audit, migration), find the closest existing precedent
  in ``backend/scripts/``, mirror its argparse / outer-loop /
  per-row session pattern. Saves debugging time + cargo-cult risk.
- **Evidence:** ``backend/scripts/backfill_walker_results_2026_05_13.py``
  closely mirrors ``backfill_detection.py`` (Phase 4 of
  feature-extraction-integrity, 2026-04-26). Reused dataclass shape,
  per-firmware session pattern, ``_emit_row`` style. Smoke-tested in
  one pass; full sweep ran clean (15 rows, 0 errored, +315 stamps).
- **Applies when:** Any new ``backend/scripts/`` file.

### 6. Rule #19 evidence-first applied to spec-derived counts

- **Description:** When a spec / intake says "N rows match condition
  X", QUERY the DB FIRST and verify the count before writing code
  that processes them. Spec drift is a real source of "code shipped,
  did nothing" outcomes.
- **Evidence:** The session resume said "Pre-existing rows uploaded
  between 847eae9 (~6 days ago) and 5f3d195 have NULL extracted_path
  and zero walker results." The DB query returned 0 rows matching
  ``upload_stage='ready' AND extracted_path IS NULL``. Widening the
  criteria (Rule #31 width-canary) surfaced 16 rows with NULL
  walker results but populated extracted_path — different shape than
  spec described. Code shipped against the actual condition, not the
  spec.
- **Applies when:** Any "backfill the legacy rows" / "migrate the
  old data" / "fix the broken column" task. Rule #19 explicitly
  generalises to this.

### 7. Boundary commit pause for CI completion (Rule #41 mitigation)

- **Description:** When shipping per-piece commits in close
  succession on a branch with ``concurrency: cancel-in-progress``,
  intermediate Backend Tests get cancelled. Pause AT the boundary
  commit to let CI complete before opening the postmortem +
  knowledge extract.
- **Evidence:** 5 commits shipped this session before the postmortem;
  Backend Tests on ``8ed2d48`` + ``d357938`` cancelled when later
  commits landed. λ.α.C (``ef14bb5``) was the first non-cancelled
  Backend Tests run after the test fix. Paused before the postmortem
  commit and confirmed Lint + Backend Tests on the boundary completed.
- **Applies when:** Every per-piece commit run of length ≥3.
  Rule #41 codifies this; this session is the second mechanical
  application.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Pin ``volatility3==2.28.0[full]`` | Scout 1: 2.28.0 (2026-04-30) fixes both prior 3.12 bugs; [full] needed for pycryptodome → 13 plugins | Locked in λ.α.C; Dockerfile gate ships it |
| Subprocess invocation over Python API | Scout 1: Rule #29 timeout via ``proc.kill()`` only works with subprocess; Python API has no cooperative cancellation; process isolation reclaims 500 MB-2 GB caches | Locked; vol3_runner.py (λ.α.D) will subprocess |
| GitHub release source over Apache mirror | Scout 2: ``volatility3-test-data v0.0.1`` release on GitHub is current; ``downloads.volatilityfoundation.org`` is stale (last refresh 2024-11) | Locked; backend/vol3-symbols/SHA256SUMS.url points to GitHub |
| ``--offline`` flag mandatory | Scout 1 + Scout 2: without ``--offline`` vol3 reaches out to msdl.microsoft.com + downloads.volatilityfoundation.org; defeats Rule #37 | Documented; vol3_runner (λ.α.D) MUST pass ``--offline`` |
| ``windows.malware.*`` paths for injection walker | Scout 3: top-level wrappers deprecated, removal scheduled 2026-06-07 | Documented for λ.γ implementation |
| Defer credentials family beyond λ.δ | Scout 3 + Rule #45: hashdump/lsadump/cachedump are credential extraction, need Rule #45 sign-off | Locked; documented in synthesis brief |
| Defer λ.α.D to next session | Context budget: ~400 LOC + Rule #29 timeout + Rule #36 argv check + tests + synthetic memory image | Documented as session-1 follow-up #1 |
| ``ARG INCLUDE_VOL3=0`` default (opt-in) | Image-size budget: +~924 MiB compressed; mirrors ``INCLUDE_DOTNET=0`` precedent | Locked in λ.α.C |
| ``memory_dump_walk_*`` columns mirror prefetch precedent | 5 columns + DB CHECK + JSONB result; consistent shape across all walkers | Locked in λ.α.B migration |
| Single-commit bundle for migration + ORM + service + walker_registry | Rule #25 + tightly-coupled multi-layer change; bisect-clean as one revertable unit | Worked; λ.α.B shipped as one 5-file commit |
