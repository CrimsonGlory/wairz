---
title: "Security: Fix Double-Shell Injection in Fuzzing Service"
status: completed
priority: critical
target: backend/app/services/fuzzing_service.py
completed_at: 2026-04-19
completed_in: session 69f004fe phase 1
shipped_commits:
  - e443def  # fix(security): eliminate double-shell injection at 4 sites in services
closed_by: wave3-stream-gamma (Rule-19 status-bump)
---

## Problem

`backend/app/services/fuzzing_service.py:532-535`:

```python
container.exec_run([
    "sh", "-c",
    f"nohup sh -c '{afl_cmd}' > /opt/fuzzing/afl.log 2>&1 & echo $! > /opt/fuzzing/afl.pid"
])
```

The outer `sh -c` contains `'{afl_cmd}'` wrapped in single quotes. `afl_cmd` is built at `:488-528` via f-string concatenation from shlex-quoted values. **`shlex.quote` targets ONE shell level.** If any quoted value contains `'`, the outer single-quote wrapper breaks and arbitrary commands execute inside the fuzzing container.

Attack vector: `campaign.binary_path` originates from user input, is persisted to DB, and flows into `afl_cmd` construction. A crafted binary path with a single quote escapes the outer quoting.

Same pattern in `fuzzing_service.py:827-844` (`triage_crash` with `timeout 30 sh -c '...'`).

Similar but less exploitable pattern in `emulation_service.py:1383` (user's explicit exec intent — by design), but the `session.binary_path` at that site is also un-quoted before interpolation — container-local impact.

## Impact

Blast radius is scoped to the fuzzing container (resource-limited, `network_mode="none"`). But:
- Attacker who controls `campaign.binary_path` (user input, DB-stored) runs arbitrary commands in a container that has read-write access to `/data/fuzzing` shared volume
- Can tamper with other campaigns' crash artifacts and AFL state on the same shared volume
- Can pivot through the compose bridge network

## Approach

**Collapse to a single shell level. Write the command to a file and exec the file.**

Replace the `nohup sh -c '{afl_cmd}'` pattern:

```python
# Write the command script to a file inside the container
run_script = f"/opt/fuzzing/run.sh"
container.exec_run([
    "sh", "-c",
    f"cat > {run_script}"
], stdin=True, socket=True)
# ...write afl_cmd bytes to stdin...

# Then exec it without shell interpolation
container.exec_run([
    "sh", "-c",
    f"nohup sh {run_script} > /opt/fuzzing/afl.log 2>&1 & echo $! > /opt/fuzzing/afl.pid"
])
```

Better: use `container.put_archive()` to write the script, then `container.exec_run(["sh", "/opt/fuzzing/run.sh"])`.

**For `triage_crash` at :827:** same pattern — write the triage command to a file, exec the file.

**For `emulation_service.py:1383`:** apply `shlex.quote(session.binary_path)` to the interpolation.

**Add a linter rule.** In `backend/pyproject.toml` `[tool.ruff.lint]`, consider extending the existing S-rule set, and add a project-specific grep check in CI for the pattern `sh", "-c",\s*f"`.

## Files

- `backend/app/services/fuzzing_service.py` (lines 488-535, 780-844)
- `backend/app/services/emulation_service.py` (line 1383 — apply shlex.quote)
- `.github/workflows/lint.yml` (add grep for `sh", "-c",\s*f"` as a CI check)

## Acceptance Criteria

- [ ] A test campaign with `binary_path = "/tmp/evil'; touch /tmp/pwned; #.bin"` does not create `/tmp/pwned` inside the fuzzing container
- [ ] Existing fuzzing E2E test (`backend/tests/test_fuzzing_sanitization.py`) still passes
- [ ] `grep -rn 'sh", "-c",\s*f"' backend/app/services/` returns zero matches
- [ ] CI check fails if the pattern is re-introduced

## Risks

- Writing to the container filesystem adds a step; if the container is killed between write and exec the script leaks — use `mktemp -p /opt/fuzzing` with a campaign-scoped name and clean up in `stop_session`
- `put_archive` requires a tar stream — use `io.BytesIO` + `tarfile` to construct in memory

## References

- Security review C3
- CLAUDE.md learned rule `auto-review-no-shell-interpolation` — this is that class of bug
