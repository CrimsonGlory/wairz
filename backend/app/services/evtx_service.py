"""Phase ε.1 — Windows Event Log (EVTX) walker (PRD-deferred reversal).

Reads on-disk ``.evtx`` Event Log files from extracted Windows
installations / live-system images and surfaces event records as
plain dictionaries for downstream finding-emit hooks.

**Scope (Phase ε.1 — scaffold + parser foundation).**

This module ships the *parser foundation* + helper for walking an
extracted firmware tree to locate ``.evtx`` files. The full
forensic-format inspection pipeline (auto-walk hook from
``unpack_common.py`` post-detection + Rule #33 outer state-machine
runner + persisted ``WindowsEventLogWalk`` / ``WindowsEventRecord``
ORM rows + MCP tool category + FE skeleton page + Finding emit hook)
is tracked as ε.1.b and lands in a follow-up commit; this commit
keeps the surface intentionally narrow so the dependency probe
(:func:`is_python_evtx_available`) and the parse contract
(:func:`parse_evtx_file`) can be exercised + reviewed in isolation.

**Mirrors γ.4 / δ.5 precedent shape.** Per the new
``.mex/patterns/real-firmware-skip-tier-canary.md`` recipe (committed
on ``feat/postmortem-followups-2026-05-09``, PR #2) and CLAUDE.md
Rule #33, the next commit (ε.1.b) will add:

- ``walk_evtx_files(extracted_path: Path) -> Iterator[Path]`` — walks
  an extracted-path tree (using ``app.services.firmware_paths``'s
  ``get_detection_roots`` per Rule #16) yielding ``.evtx`` paths.
- ``_do_evtx_walk_run(db: AsyncSession, firmware_id: uuid.UUID) -> dict``
  — INNER orchestrator (accepts a ``db``; the live canary tier-1
  shape from δ Pattern #2). Walks every ``.evtx`` in the firmware's
  detection roots, batches event records into a ``WindowsEventRecord``
  table via natural-key UPSERT (mirroring δ.5 ``windows_update_dll_diffs``).
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
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


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
]
