---
name: lint
description: >-
  Runs every check the GitHub Actions "Lint" workflow runs (Ruff, Bandit,
  the custom async-subprocess gate, ESLint, TypeScript), matching
  .github/workflows/lint.yml exactly. Use after any change to backend/ or
  frontend/ source, before considering the change done or handing off.
---

# Lint — full local CI parity

Runs the same checks as `.github/workflows/lint.yml`'s four jobs
(`lint-backend`, `lint-frontend`, `typecheck-frontend`, and the custom
async-subprocess gate baked into `lint-backend`), so a failure here is a
failure in CI too. Prefer this over guessing which subset of checks is
"probably fine" — it costs under a minute and catches the exact things CI
will flag on push.

## When to run

- After any edit under `backend/` or `frontend/`, before reporting the
  change complete (CLAUDE.md "Standing Operating Principles" → Agent Work
  Loop step 7, and the Required Validation Commands section, both point
  here).
- Before creating a commit that touches backend or frontend source.
- Before telling the user a fix is "done" — a change isn't done until this
  passes or every failure has been triaged as a known, documented
  exception.

## Steps

Run from the repo root. Adjust the `cd` targets if invoked from elsewhere.

### 1. Backend — Ruff

```bash
cd backend
ruff check .
```

If `ruff` isn't installed, either `pip install ruff` into whatever
environment CLAUDE.md's project conventions call for, or use a throwaway
venv:

```bash
python3 -m venv /tmp/lintvenv && /tmp/lintvenv/bin/pip install --quiet ruff bandit
/tmp/lintvenv/bin/ruff check backend/
```

Ruff auto-fixable findings can be closed immediately with
`ruff check . --fix`. For `ASYNC109` / `ASYNC230` / `ASYNC240` / other
non-auto-fixable findings, follow CLAUDE.md Rule #43's noqa-with-rationale
convention — do not blanket-suppress the rule in `pyproject.toml`.

### 2. Backend — Bandit

```bash
cd backend
bandit -r app/ -c pyproject.toml
```

Findings that are genuine false positives (e.g. a documented, non-secret
`chmod`) get a `# noqa: <CODE> -- <rationale>  # nosec <CODE>` comment pair
— note bandit and ruff each require their own directive to be the FIRST
token in their own `#` comment; a single combined comment satisfies neither
tool's parser. Two separate `#` comments on the same line work for both.

### 3. Backend — async-subprocess gate

```bash
cd backend
python3 scripts/lint_async_subprocess.py app/
```

Guards CLAUDE.md Rule #5: no sync `subprocess.*` call inside an `async def`
body. Fix by switching to `asyncio.create_subprocess_exec` (preferred for
fire-and-forget detached workers) or wrapping the sync call with
`await loop.run_in_executor(None, sync_fn, *args)`.

### 4. Frontend — ESLint

```bash
cd frontend
npm ci   # only if node_modules is missing or package-lock.json changed
npm run lint
```

`npm run lint` is `eslint .` with no `--max-warnings`, so only errors (not
warnings) fail this step — matches CI. Several rules are deliberately
downgraded to `warn` in `eslint.config.js` as pre-existing tech debt; don't
"fix" those unless the user asks.

### 5. Frontend — TypeScript

```bash
cd frontend
npx tsc -b --force
```

**Never use `tsc --noEmit`** — `frontend/tsconfig.json` uses `"files": []`
+ project references, so `--noEmit` silently no-ops without descending
into the referenced projects (CLAUDE.md Rule #24, a Rule #17 silent-exit
instance). `-b --force` is the only invocation that actually type-checks
everything.

Once per session, canary the gate before trusting a clean run:

```bash
cd frontend
echo 'const x: number = "nope"; export default x;' > src/__canary.ts
npx tsc -b --force; echo "canary_exit=$?"   # must be non-zero
rm src/__canary.ts
```

If the canary passes silently, the gate isn't actually checking — stop and
investigate before trusting any other "0 errors" result this session.

## On failure

- Fix genuine bugs at the root cause; don't silence real findings.
- For findings that are false positives given the surrounding code, use
  the per-line `noqa`/`nosec` conventions above — never widen a
  project-level ignore list to unblock a single call site (CLAUDE.md
  `[tool.ruff.lint] ignore` and `[tool.bandit] skips` already carry an
  explicit paper trail for every existing entry; match that discipline).
- Report exactly which check failed and why before claiming the lint pass
  succeeded — "I ran lint" is not the same claim as "lint passed."
