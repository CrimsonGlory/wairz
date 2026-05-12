---
campaign: windows-coverage-godmode-theta-2026-05-12
stream: θ.E — MBR/VBR boot-sector walker
date: 2026-05-12
kind: antipatterns (what broke + how to avoid)
related_postmortem: postmortem-windows-coverage-godmode-theta-E-mbr-vbr-walker-2026-05-12.md
---

# Antipatterns — Phase θ.E MBR/VBR boot-sector walker

Failure cases extracted from the single-stream θ.E dispatch. Each antipattern carries Rule-of-N evidence + mitigation recipe.

---

## A1 — get_detection_roots returns multi-root tuple in tempdir-based tier-1 tests (Rule-of-Three now — promotion ready)

**Shape:** Tier-1 walker tests using `tempfile.TemporaryDirectory` + `firmware.extracted_path = td` see `get_detection_roots()` return `[td, '/tmp']` (the firmware's tmp dir AND its parent). The walker then scans BOTH directories, picking up unrelated test artefacts from sibling sessions in `/tmp` and inflating the `images_scanned` / `efi_files_scanned` / `bcd_stores_scanned` count.

**Evidence (Rule-of-Three now — promotion ready):**
- BCD walker tests (θ.A) — historical precedent, fixed via `@patch("app.services.bcd_walker.get_detection_roots", _fake_roots)`.
- ESP walker tests (θ.C postmortem #1) — fixed via same patch pattern; documented in θ.C postmortem.
- **MBR/VBR walker tests (θ.E this stream)** — `test_do_mbr_vbr_walk_no_disk_images` failed with `assert 6 == 0` (6 disk images from prior test sessions in /tmp). Fixed via same patch pattern; documented in test docstring as a θ.C postmortem #1 reference.

**Mitigation (durable now — Rule-of-Three is the promotion gate):**
Every tier-1 walker test that uses `tempfile.TemporaryDirectory` + `firmware.extracted_path = td` MUST patch `get_detection_roots` to return a single-root list:

```python
async def _fake_roots(firmware, *, db=None, use_cache=True):
    return [td]

with patch(
    "app.services.<artefact>_walker.get_detection_roots",
    _fake_roots,
):
    result = await _do_<artefact>_walk(db, firmware.id)
```

**Promote to CLAUDE.md candidate**: Rule #44 (or extension to Rule #16) — "Tier-1 walker tests against tempdir firmware fixtures MUST patch get_detection_roots to a single-root list. The default multi-root behavior cross-contaminates with sibling tmpdirs."

---

## A2 — Pipe-induced silent exit on canary check (Rule #35a recurrence — Rule-of-Many)

**Shape:** Running `npx tsc -b --force 2>&1 | tail -5; echo "exit=$?"` returns the exit code of the LAST pipe command (`tail`), NOT the first (`tsc`). When tsc exits non-zero (the canary expectation), the pipe + tail returns 0, MASKING the failure.

**Evidence (recurrence — already documented in CLAUDE.md Rule #35a):**
- θ.E session: initial canary run printed type error AND `exit=0` together. The exit code was meaningless because `tail` always exits 0 when it has input.

**Mitigation (durable per Rule #35a):**
Always capture exit codes WITHOUT pipes when the exit code is the success-criterion:
```bash
# WRONG — pipe-induced silent exit
npx tsc -b --force 2>&1 | tail -5; echo "exit=$?"

# RIGHT — capture exit before pipe
npx tsc -b --force; ec=$?; echo "real-exit=$ec"
```

OR if you must pipe for output trimming:
```bash
set -o pipefail
npx tsc -b --force 2>&1 | tail -5; echo "real-exit=${PIPESTATUS[0]}"
```

**Already in CLAUDE.md** as Rule #35a — no promotion needed; mention in postmortem for completeness (Rule-of-Many recurrence — the pipe issue has bitten every Rule #24 canary run that didn't apply the discipline).

---

## A3 — ToolRegistry has no `list_tools()` method (test-shape error — Rule-of-One)

**Shape:** When writing a registration-shape test for a new MCP tool category, the natural copy-translate from ESP precedent included `registry.list_tools()` — but `ToolRegistry` exposes `_tools: dict[str, ToolDefinition]` directly without a `list_tools()` method.

**Evidence (Rule-of-One — θ.E this stream):**
- `test_register_windows_mbr_vbr_tools_registers_two` initially called `list(registry.list_tools())`.
- AttributeError caught at test runtime.
- Fixed via `set(registry._tools.keys())` — direct access pattern consistent with internal usage (`subset()`, `get_anthropic_tools()` both read `self._tools` directly).

**Mitigation:**
Before writing a registration-shape test, read the ToolRegistry source:
```bash
grep -n 'def \|self\._\|self\.tools' backend/app/ai/tool_registry.py
```
Use `set(registry._tools.keys())` for "what tools were registered" assertions.

**Don't promote** — this is a minor test-shape error from incorrect precedent assumption. The ESP test precedent had a different (working) shape that didn't use list_tools(); the bug was a transcription error from a different test file, not a systemic issue.

---

## Net summary

**3 antipatterns caught + recovered in ~40 min agent-time.** All 3 are well-understood + mitigated:

- **A1** (get_detection_roots multi-root): Rule-of-Three — promotion-ready as CLAUDE.md Rule extension.
- **A2** (pipe-induced silent exit): Rule-of-Many — already CLAUDE.md Rule #35a; recurrence reminder.
- **A3** (ToolRegistry list_tools): Rule-of-One — minor; no promotion needed.

**Recovery time:**
- A1: ~30 seconds (apply patch pattern from precedent).
- A2: ~10 seconds (re-run without pipe).
- A3: ~10 seconds (switch to direct `_tools.keys()` access).

**Total recovery cost:** ~50 seconds out of ~40 min total session — under 3% of total time. The Rule #35b live-canary discipline + Rule #24 canary + Rule #35a pipe discipline all caught their respective issues at the cheapest possible moment.

---
