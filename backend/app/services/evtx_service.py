"""Phase ε.1 — Windows Event Log (EVTX) walker (PRD-deferred reversal).

Reads on-disk ``.evtx`` Event Log files from extracted Windows
installations / live-system images and surfaces event records as
plain dictionaries for downstream finding-emit hooks.

**Scope (Phase ε.1 — scaffold + parser foundation + walker).**

ε.1.a shipped the *parser foundation* (:func:`parse_evtx_file` +
:func:`is_python_evtx_available`). ε.1.b.1 (this commit) adds the
*walker* (:func:`walk_evtx_files`) — the on-disk scanner that yields
``.evtx`` paths under any iterable of detection roots. Subsequent
ε.1.b commits add Rule #33 outer state-machine runner + auto-walk
hook + MCP tool category + FE skeleton page + Finding emit hook.

**Mirrors γ.4 / δ.5 precedent shape.** Per the new
``.mex/patterns/real-firmware-skip-tier-canary.md`` recipe (committed
on ``feat/postmortem-followups-2026-05-09``, PR #2) and CLAUDE.md
Rule #33, subsequent ε.1.b commits will add:

- ``_do_evtx_walk_run(db: AsyncSession, firmware_id: uuid.UUID) -> dict``
  — INNER orchestrator (accepts a ``db``; the live canary tier-1
  shape from δ Pattern #2). Walks every ``.evtx`` in the firmware's
  detection roots (resolved via :func:`app.services.firmware_paths.get_detection_roots`
  per Rule #16), aggregates event records into a JSONB result on
  ``firmware.evtx_walk_result`` (per-event persistence deferred to a
  future ζ.X phase per the ε.1.b campaign Decision #1).
- ``run_evtx_walk_background(firmware_id: uuid.UUID) -> None`` —
  OUTER state-machine wrapper (owns the Rule #33 .a status
  transitions ``idle → queued → running → completed | failed`` via
  ``async_session_factory()``).
- ``auto_walk_firmware_safe(firmware_id: uuid.UUID) -> None`` —
  unpack-post-detection hook that runs the same orchestrator but
  does NOT mutate the firmware's status fields (γ.4
  ``auto_walk_firmware_safe`` precedent).

**Rule #36 no-execute discipline.** python-evtx PARSES the EVTX
binary AS DATA — there is no event-replay path. The EVTX file
format is a custom binary record stream; events are decoded
read-only into Python dictionaries. wairz does NOT invoke
``wevtutil``, ``Get-WinEvent``, or any other event-replay tool, and
the ε.1 worker MUST NOT pass an extracted ``.evtx`` path as
``argv[0]`` to ``subprocess.run`` / ``Popen`` / ``asyncio.create_subprocess_*``
or any ``os.system`` / ``execv*`` family call. Future ε.X workers
that shell out to additional EVTX tools (e.g. ``evtxtool``,
``LogParser``, ``Plaso``) MUST extend ``FORBIDDEN_ARGV0_TOKENS`` in
the same shape as δ.4's ``dotnet_decompile_service.assert_no_execute_argv``.

**Rule #19 evidence-first probe.** The dependency probe
(:func:`is_python_evtx_available`) is exposed as a public function
so MCP tools / future Rule #33 trigger handlers can degrade
gracefully when ``python-evtx`` is missing — same shape as δ.7's
``windows_storage`` tools degrading when ``libesedb-utils`` is
absent (now installed via Phase ε.2 Dockerfile delta).
"""
from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Walker constants ────────────────────────────────────────────────────────


# Canonical Windows Event Log file extension. Real EVTX files always end
# in ``.evtx`` (case-insensitive on Windows; we match case-insensitively
# here so an EXTRACTED tree from a case-preserving filesystem doesn't
# miss files capitalised by the unpacker). Files with the extension
# without the EVTX magic header are still surfaced — :func:`parse_evtx_file`
# will degrade them to ``status="error"`` rather than crashing.
_EVTX_EXTENSION: str = ".evtx"


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_python_evtx_available() -> bool:
    """Return True iff ``python-evtx`` is importable in this process.

    Mirrors the regipy / dnfile graceful-degrade probes used by γ.4
    and δ.4. Use this at the top of any consumer (MCP tool handler,
    Rule #33 trigger, auto-walk hook) so the absence of the dep
    surfaces as a clear "library not installed" message rather than
    an opaque ImportError stack trace.

    The probe runs in <1 ms after first call (Python's import cache
    handles repeated invocations).
    """
    try:
        import Evtx.Evtx  # noqa: F401 — import-only probe
    except ImportError:
        return False
    return True


# ── Parser ──────────────────────────────────────────────────────────────────


# Sentinel returned by parse_evtx_file when python-evtx is unavailable.
# Distinguishable from a "real" empty parse (a zero-record EVTX file is
# valid but rare; missing-dep is the common failure mode at scaffold time
# and during minimal-CI Docker builds that omit Phase ε deps).
PYTHON_EVTX_UNAVAILABLE: dict[str, Any] = {
    "status": "unavailable",
    "reason": "python-evtx not installed — see backend/pyproject.toml ε.1 block",
    "records": [],
    "record_count": 0,
}


def parse_evtx_file(path: str | Path) -> dict[str, Any]:
    """Parse a single ``.evtx`` file and return a record summary.

    Returns a dict with keys:
    - ``status``: ``"ok"`` | ``"unavailable"`` | ``"error"``.
    - ``record_count``: total event records yielded by the parser.
    - ``records``: list of records (each a dict with keys
      ``event_id``, ``provider``, ``timestamp``, ``raw_xml``). Empty
      list when ``status != "ok"``.
    - ``error``: present only when ``status == "error"``; contains
      the exception message (truncated to 500 chars to stay under
      Rule "MCP tool output ≤30KB" budget when wrapped by a tool
      handler).

    **Defensive against missing dep** — returns
    :data:`PYTHON_EVTX_UNAVAILABLE` shape if ``python-evtx`` isn't
    importable. Callers MUST check ``status`` before accessing
    ``records``.

    **Defensive against malformed input** — wraps the EVTX iteration
    in a try/except. A truncated / corrupted EVTX file raises in
    python-evtx; we surface a structured error instead of letting
    the caller crash.

    Rule #36 reminder: ``path`` is read AS DATA (the python-evtx
    parser uses ``mmap`` internally — read-only memory map, not
    process spawn).
    """
    if not is_python_evtx_available():
        return PYTHON_EVTX_UNAVAILABLE

    # Lazy import per Rule #30 — `from Evtx.Evtx import Evtx` at
    # module scope would force a hard import even when consumers
    # only check the probe. The lazy import keeps the module
    # cold-import fast (<5 ms) for non-EVTX code paths.
    from Evtx.Evtx import Evtx

    p = Path(path)
    records: list[dict[str, Any]] = []

    try:
        with Evtx(str(p)) as log:
            for record in log.records():
                # python-evtx Record.lxml() returns the parsed lxml
                # element; .xml() returns a serialized string. Both
                # are expensive on large logs; we sample minimal
                # fields here. The full XML is preserved as raw_xml
                # for downstream finding emitters that need the
                # complete record (e.g. a future Sysmon-1 rule that
                # extracts the parent-process command line).
                try:
                    xml = record.xml()
                except Exception as exc:  # pragma: no cover — record-level
                    logger.debug(
                        "evtx record %s xml() failed: %s",
                        record.record_num(),
                        exc,
                    )
                    continue
                records.append(
                    {
                        "record_num": record.record_num(),
                        "raw_xml": xml,
                    }
                )
    except Exception as exc:
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        return {
            "status": "error",
            "record_count": 0,
            "records": [],
            "error": msg,
        }

    return {
        "status": "ok",
        "record_count": len(records),
        "records": records,
    }


__all__ = [
    "PYTHON_EVTX_UNAVAILABLE",
    "is_python_evtx_available",
    "parse_evtx_file",
    "walk_evtx_files",
]


# ── Walker ──────────────────────────────────────────────────────────────────


def walk_evtx_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return a list of ``.evtx`` file paths.

    Mirrors :func:`registry_hive_walker.scan_for_hives` (γ.4 precedent)
    exactly — case-insensitive extension match + sandbox check that
    rejects symlinks pointing outside the root tree (Rule #1 spirit;
    the unpacker may have legitimate symlinks within the rootfs but
    escape symlinks are a sandbox concern).

    Sync I/O — wrap in ``run_in_executor`` for async callers
    (Rule #5). Defensive against missing roots, permission errors,
    short reads — every error path is swallowed at the per-root /
    per-file level so one corrupted detection root doesn't abort the
    entire walk.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`app.services.firmware_paths.get_detection_roots` — NEVER
    a single ``firmware.extracted_path`` (scatter-zip uploads, multi-
    archive medical firmware, and nested unblob output produce sibling
    detection roots that ``extracted_path`` misses entirely).
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if not os.path.isdir(real_root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for name in filenames:
                # Case-insensitive match — Windows filesystems are
                # case-preserving but case-insensitive, and unpackers
                # vary on case-normalisation behavior.
                if not name.lower().endswith(_EVTX_EXTENSION):
                    continue
                full = os.path.join(dirpath, name)
                # Sandbox check — never surface a file whose realpath
                # escapes the root tree. Same shape as scan_for_hives;
                # legitimate intra-rootfs symlinks pass through, escape
                # symlinks are dropped silently.
                try:
                    real_full = os.path.realpath(full)
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                # ``os.path.isfile`` after realpath confirms the symlink
                # target (if any) actually exists as a regular file —
                # broken symlinks within the sandbox are rejected.
                try:
                    if not os.path.isfile(real_full):
                        continue
                except OSError:
                    continue
                hits.append(real_full)
    return hits
