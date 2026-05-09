# Antipatterns — Windows-Coverage God-Mode ζ + Lint Cleanup (2026-05-10)

## A1: Trusting `tail -N` exit code (sub-case of Rule #35a)

**Failure shape:** `cmd | tail -N; echo "exit=$?"` reports `tail`'s exit,
not `cmd`'s. The Bash tool does NOT enable `set -o pipefail` by default.
This was originally Rule #35a from session 2026-05-04; this campaign
re-confirmed via routine lint runs.

**Mitigation:** capture exit code BEFORE the pipe. `cmd; ec=$?` or
`cmd > /tmp/out; ec=$?; tail /tmp/out`. For ad-hoc pipeline use:
`set -o pipefail` explicit, or `${PIPESTATUS[0]}` after the pipe.

**Recurrence:** zero this campaign — discipline held throughout. The
mitigation is now mechanical habit, not deliberate vigilance.

## A2: Removing a suppression without measuring the residue

**Failure shape:** lifting `S314` from `pyproject.toml` ruff `ignore`
without first migrating the call sites. CI immediately fails on the
first push. Cost: a CI cycle (~3 min) wasted; recovery via revert or
follow-up commit.

**Mitigation (this campaign):** the discipline of "fix BEFORE remove
suppression" — apply the source-level fix, run `ruff check --no-cache .
--select <code>` to confirm zero hits, THEN remove the suppression.
Verified for all 5 ruff codes closed (S314, F601, F811, E741, F402).
Zero CI failures attributable to suppression removal this campaign.

**Generalisation:** "remove the suppression LAST" — same discipline as
Rule #19 evidence-first applied to lint cleanup.

## A3: Trusting "drop-in API compatible" without probing

**Failure shape:** defusedxml is ALMOST drop-in compatible with
`xml.etree.ElementTree`, but `Element` is NOT re-exported. Code that
naively swaps `import xml.etree.ElementTree as ET` →
`import defusedxml.ElementTree as ET` and then uses `ET.Element` for
type annotations gets `AttributeError: module 'defusedxml.ElementTree'
has no attribute 'Element'` at import time.

**Mitigation:** Rule #19 evidence-first probe before committing to a
swap pattern. Cost: ~30 seconds (`python -c "import defusedxml...
print(dir(...))"`). Surfaced this campaign at edit time, not at CI time.

**Cross-cutting lesson:** "drop-in compatible" claims in library docs
mean "the API for the canonical use case is identical." Edge-case API
surfaces (type re-exports, exception class identity, attribute
visibility on internal classes) often diverge silently. Always probe
the specific API surfaces YOUR code uses before swapping.

## A4: Bandit's blacklist coarse-grained on type-only imports

**Failure shape:** removing B405 from bandit `[tool.bandit] skips`
after the S314 call-site swap caused bandit to flag the residual
`import xml.etree.ElementTree as ET` (type-only, used only for
annotations and exception handling). Bandit does not have a "type-only
import" exemption.

**Mitigation:** keep B405 in skips with refined rationale. The CALL-SITE
signal that actually matters is B314 (the parsing operation); that's
been removed. B405 (the import itself) is a known coarse-grained
limitation; suppression is appropriate.

**Generalisation:** when a security tool's blacklist is coarse-grained,
prefer the call-site rule over the import-site rule. Document the
distinction in the skip rationale so the next session understands
why the import-site skip is intentional.

## A5: Container-vs-host environment drift on test runners

**Failure shape:** `docker compose exec backend pytest` failed with
`No module named pytest` — the production backend image does not bundle
pytest. Tests run via `uv run pytest` on the host, not inside the
container.

**Mitigation:** distinguish "smoke test" (runs in-container, validates
imports) from "test run" (runs on host via uv, validates behavior).
The former goes in the validation section as a `docker compose exec`;
the latter goes as `( cd backend && uv run pytest ... )`.

**Cost this campaign:** ~1 minute of confusion before re-routing to
host uv. Discipline is durable now.

## A6: Stale ruff cache permission tarpit

**Failure shape:** `backend/.ruff_cache/` is owned by root (legacy
container running as root). `uv run ruff check .` fails:
`Failed to initialize cache at /home/dustin/code/wairz/backend/.ruff_cache:
Permission denied (os error 13)`.

**Mitigation (this campaign):** add `--no-cache` to every ruff invocation
during the session. Cost: ~1 second per run (cache benefit is small
for whole-tree checks). Long-term fix is a startup hook to chown the
cache directory back to the user; deferred (low value, low cost).

**Generalisation:** when a tool's cache is in a shared bind-mounted
directory, expect ownership drift between host and container. The
durable fix is `--no-cache` until someone reaches for sudo.

## A7: Adding a Python dep without updating uv.lock

**Failure shape:** adding `defusedxml>=0.7.1` to `pyproject.toml`
dependencies but forgetting to run `uv lock` (or equivalent) leaves
`uv.lock` out of sync. CI / fresh install `uv sync` fails because the
lock doesn't have an entry for the new package.

**Mitigation (this campaign):** `uv run` operations during validation
auto-resolved + auto-installed defusedxml AND auto-updated `uv.lock`,
which got picked up by `git status` and was staged for the B.3 commit.
Worked accidentally; the discipline should be explicit `uv sync` or
`uv lock` after dependency edits.

**Generalisation:** any `pyproject.toml` `dependencies` edit MUST be
paired with a lock-file update in the same commit. CI smoke would
catch this; locally, `git diff --stat` after `uv run` confirms the
auto-update happened.

## A8: Cross-session campaign-file staleness

**Failure shape:** the prior session's continuation prompt warned that
the campaign file's "Active Context" section was stale (git log was
authoritative). The new session followed that guidance; if it had
trusted the campaign file's "Continuation State" alone, it would have
re-done the ζ.2.A migration that already shipped.

**Mitigation:** continuation prompts that span sessions MUST cite
"git log is authoritative; campaign file is a planning artefact, not
a state record." Fresh session bootstraps from `git log --oneline -15
origin/main` first, campaign file second, lint triage third. Order
matters.

**Generalisation:** the campaign file is forward-looking (decision log,
phase plan, telemetry); it is NOT a substitute for git log + actual
filesystem state. Treat it as the diary, not the inventory.

## A9: Pattern #6 numbered-Rule promotion deferred too long

**Failure shape:** Rule-of-Four for "lower-bound count assertions for
growing collections" was reached in this campaign but not promoted to a
numbered Rule yet. Each new MCP tool category will trigger another
relaxation; we're spending ~5 minutes per occurrence relaxing tests
without consolidating the principle.

**Mitigation (this campaign):** explicitly noted promotion candidate
in the postmortem (next campaign that ships an MCP tool category
triggers the promotion).

**Generalisation:** when a pattern is at Rule-of-Three+ AND each new
occurrence carries a small consistent cost (here: 5 min), promote on
the next occurrence. Rule-of-Five is not a hard threshold — Rule-of-
Three for cheap-to-verify mechanical patterns is sufficient.
