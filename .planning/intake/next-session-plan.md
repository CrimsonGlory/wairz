---
title: "Wairz session-pickup pointer"
status: reference
type: reference
priority: low
---

> **DO NOT use this file as actionable intake.**
>
> Three staleness-warning iterations (2026-04-21, 2026-04-22, 2026-05-12)
> proved that the historical body content was being mined as work-items
> regardless of the warning.  The body has been replaced with this thin
> pointer (2026-05-11, postmortem-followup Rec #4 closure).
>
> Canonical sources for picking up work, in priority order:
>
> 1. **`.planning/intake/*.md`** (siblings of this file) — open intakes.
>    Each has frontmatter + scope; treat as authoritative for what's
>    pending.  Resolved items live in `.planning/intake/resolved/`.
> 2. **`.planning/campaigns/*.md`** (excluding `completed/`) — active
>    multi-session campaigns with explicit phase letters and end
>    conditions.
> 3. **`.planning/postmortems/*-followup-*.md`** — most-recent
>    postmortem-followup file's "Recommendations" section is the
>    freshest list of follow-ups from the last completed work.
> 4. **`CLAUDE.md`** — operating rules #1-#43 (always load).
> 5. **`.mex/ROUTER.md`** — task-routing table when starting a specific
>    task; pairs with `.mex/patterns/INDEX.md`.
>
> The historical "Wairz Master Plan" body that previously lived here
> has been removed.  Its content was a snapshot in time (2026-04-01,
> last refreshed 2026-04-18) that drifted out of agreement with the
> codebase as work shipped without back-edits.  Per Rule #19
> (evidence-first), the canonical sources above describe truth; this
> file no longer attempts to summarize them.
>
> See `git log -- .planning/intake/next-session-plan.md` for prior
> revisions if archaeology is needed.
