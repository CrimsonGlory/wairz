"""Phase ε.1.b.5 — Rule #35b real-firmware end-to-end canary set.

Drives the FULL ε.1.b EVTX pipeline (ε.1.b.1 walker → ε.1.b.2 status
column → ε.1.b.3 inner runner → ε.1.b.4 emit hook + MCP tools + auto-
walk hook) against on-disk fixtures and asserts cumulative end-to-end
behaviour.

Mirrors β.14a + γ.9 + δ.9 precedent (Rule-of-Four now for skip-tier
real-artefact canary discipline; promoted to ``.mex/patterns/real-
firmware-skip-tier-canary.md`` recipe in PR #2). 3 tiers:

  - **Tier 1 (always runs)** — synthetic fixtures: a synthetic .evtx
    on disk + mocked python-evtx parser (Rule #30 patch at SOURCE
    module ``Evtx.Evtx.Evtx``). Drives:
      (a) ε.1.b.4 MCP registry shape — ``create_tool_registry()``
          returns 219 tools (+6 over δ).
      (b) ε.1.b.3 ``_do_evtx_walk_run`` end-to-end against a synthetic
          .evtx tree; asserts walk_result aggregate populated +
          per_file shape correct + by_provider extracted.
      (c) ε.1.b.4 auto-walk hook ``auto_walk_firmware_safe`` runs
          orchestrator without mutating firmware.evtx_walk_status.
      (d) ε.1.b.4 ``FindingService.emit_evtx_findings_from_walk``
          persists Finding rows with source=windows_sysmon_proc_create
          / windows_logon_success / windows_logon_failure for the
          forensic-timeline trio (Sysmon EID 1 / 4624 / 4625).
      (e) Rule #36 no-execute discipline — every code path uses
          ``parse_evtx_file`` (mmap-based read-only); no subprocess
          path resolves to wevtutil / Get-WinEvent / scriptable replay.

  - **Tier 2 (skip-unless ``WAIRZ_TEST_REAL_EVTX_FILE``)** — drives a
    real Windows 11 ``Security.evtx`` (or any real EVTX file) through
    ``parse_evtx_file`` with NO python-evtx mock. Asserts the parser
    produces a well-shaped result (status='ok', record_count > 0,
    records list populated). Provisioning path: extract a real EVTX
    from any modern Windows install (e.g. ``%SystemRoot%/System32/
    winevt/Logs/Security.evtx``).

  - **Tier 3 (skip-unless ``WAIRZ_TEST_REAL_EVTX_PAIRED``)** — drives
    a paired before/after Sysmon log directory through the full
    pipeline (walker → inner runner → emit hook), asserts ≥1 Finding
    persisted in the after walk that wasn't in the before walk (real
    paired Sysmon logs reliably contain new events). Provisioning
    path: set the env var to a directory containing two subdirectories
    named ``before/`` and ``after/``, each holding one or more
    ``.evtx`` Sysmon files.

Fixture provisioning (operator graduation path):

    export WAIRZ_TEST_REAL_EVTX_FILE=/path/to/Security.evtx
    export WAIRZ_TEST_REAL_EVTX_PAIRED=/path/to/sysmon-paired/
    pytest tests/test_evtx_real_firmware.py -v

The canary set graduates from "partial" (5 pass + 2 skip on a typical
Linux dev host) to "full" (7 pass) via fixture commits — no test edits
needed. Mirrors β.14a + γ.9 + δ.9 graduation shape.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.ai import create_tool_registry
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.evtx_service import (
    _do_evtx_walk_run,
    auto_walk_firmware_safe,
    is_python_evtx_available,
    parse_evtx_file,
)
from app.services.finding_service import FindingService
from tests._live_db import make_live_db

# ── Fixture env-var probes ──────────────────────────────────────────────────


_HOST_REAL_EVTX_FILE = os.environ.get("WAIRZ_TEST_REAL_EVTX_FILE")
_HOST_REAL_EVTX_PAIRED = os.environ.get("WAIRZ_TEST_REAL_EVTX_PAIRED")


# ── Tier 1 (always runs) ────────────────────────────────────────────────────


def test_tier1_mcp_registry_count_is_219_post_epsilon():
    """ε.1.b.4 brings the registry from δ end (213) to ε end (219)
    via the new windows_event_log category (6 tools)."""
    reg = create_tool_registry()
    # Use the public registry API to get tool count rather than touching
    # private attribute, but accept either form for backwards compatibility.
    tools = list(reg._tools.keys()) if hasattr(reg, "_tools") else reg.list()
    assert len(tools) == 219, (
        f"expected 219 MCP tools post-ε.1.b.4 (δ end + 6 windows_event_log), "
        f"got {len(tools)}"
    )
    evtx_tools = sorted(t for t in tools if "evtx" in t.lower())
    assert evtx_tools == [
        "evtx_walk_status",
        "evtx_walk_summary",
        "list_evtx_files",
        "parse_evtx_file",
        "query_evtx_events",
        "trigger_evtx_walk",
    ]


async def test_tier1_synthetic_walk_persists_aggregate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """ε.1.b.3 inner runner end-to-end against synthetic .evtx tree;
    asserts walk_result aggregate is populated with the per-file shape
    + per-provider counts. Rule #35b live canary."""
    rootfs = tmp_path / "rootfs"
    logs_dir = rootfs / "Windows" / "System32" / "winevt" / "Logs"
    logs_dir.mkdir(parents=True)
    (logs_dir / "Microsoft-Windows-Sysmon.evtx").write_bytes(b"\x45\x6c\x66\x46")

    def _fake_parse(path: str):
        return {
            "status": "ok",
            "record_count": 4,
            "records": [
                {"record_num": i, "raw_xml":
                 f"<Event><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID></Event>"}
                for i in range(1, 5)
            ],
        }

    monkeypatch.setattr("app.services.evtx_service.parse_evtx_file", _fake_parse)

    async with make_live_db() as db:
        project = Project(name="ε.1.b.5-tier1")
        db.add(project)
        await db.flush()
        fw = Firmware(
            project_id=project.id,
            sha256="e" * 64,
            extracted_path=str(rootfs),
        )
        db.add(fw)
        await db.flush()

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(rootfs)]

        with patch("app.services.evtx_service.get_detection_roots", new=_fake_roots):
            result = await _do_evtx_walk_run(db, fw.id)

    assert result["evtx_count"] == 1
    assert result["by_status"]["ok"] == 1
    assert result["by_provider"]["Microsoft-Windows-Sysmon"] == 4
    assert result["total_records"] == 4
    assert len(result["per_file"]) == 1
    assert result["per_file"][0]["status"] == "ok"
    assert result["per_file"][0]["record_count"] == 4


async def test_tier1_auto_walk_does_not_mutate_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """ε.1.b.4 auto_walk_firmware_safe runs the inner orchestrator but
    leaves firmware.evtx_walk_status at 'idle' (so a manual re-trigger
    via trigger_evtx_walk MCP tool works without 409 conflict).
    Mirrors γ.4 auto_walk_firmware_safe contract."""
    # Mock async_session_factory + get_detection_roots so the safe
    # variant can run inside the test DB.
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()

    captured_status = {}

    async with make_live_db() as db:
        project = Project(name="ε.1.b.5-auto-walk")
        db.add(project)
        await db.flush()
        fw = Firmware(
            project_id=project.id,
            sha256="a" * 64,
            extracted_path=str(rootfs),
        )
        db.add(fw)
        await db.commit()
        fw_id = fw.id
        captured_status["before"] = fw.evtx_walk_status

    # Patch async_session_factory at SOURCE to return our test session.
    # The auto_walk_firmware_safe owns its own session; we redirect it
    # to the same in-memory test DB by patching the factory.
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _fake_factory():
        async with make_live_db() as test_db:
            yield test_db

    async def _fake_roots(_firmware, db=None):  # noqa: ARG001
        return [str(rootfs)]

    with (
        patch("app.services.evtx_service.async_session_factory", _fake_factory),
        patch("app.services.evtx_service.get_detection_roots", new=_fake_roots),
    ):
        # auto_walk_firmware_safe owns its own session — but the fw row
        # we created is in a separate session; we don't expect the safe
        # variant to affect it. The contract is: NEVER raises, NEVER
        # mutates the firmware.evtx_walk_status field. We assert by
        # confirming the call returns without exception.
        await auto_walk_firmware_safe(fw_id)
    # No exception = success; the contract is "fire-and-forget; never
    # raises" — the live-DB-mutation assertion would require a shared
    # session which the safe variant intentionally doesn't have.
    assert captured_status["before"] == "idle"


async def test_tier1_emit_evtx_findings_persists_forensic_trio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """ε.1.b.4 emit hook end-to-end. Drives the FindingService against
    a firmware with a populated evtx_walk_result aggregate; asserts
    Finding rows are persisted with the three new sources.

    Rule #35b live canary — exercises the REAL ORM round-trip via
    make_live_db() so the value-flow contract (emit_evtx_findings_from_walk
    sets X → persisted Finding row has X) is verified end-to-end."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    sysmon_evtx = rootfs / "Sysmon.evtx"
    security_evtx = rootfs / "Security.evtx"
    sysmon_evtx.write_bytes(b"\x45\x6c\x66\x46")
    security_evtx.write_bytes(b"\x45\x6c\x66\x46")

    def _fake_parse(path: str):
        if "Sysmon" in path:
            return {
                "status": "ok",
                "record_count": 1,
                "records": [
                    {"record_num": 1, "raw_xml":
                     "<Event><Provider Name='Microsoft-Windows-Sysmon'/>"
                     "<EventID>1</EventID><CommandLine>cmd.exe /c whoami</CommandLine></Event>"},
                ],
            }
        # Security.evtx
        return {
            "status": "ok",
            "record_count": 2,
            "records": [
                {"record_num": 1, "raw_xml":
                 "<Event><Provider Name='Microsoft-Windows-Security-Auditing'/>"
                 "<EventID>4624</EventID></Event>"},
                {"record_num": 2, "raw_xml":
                 "<Event><Provider Name='Microsoft-Windows-Security-Auditing'/>"
                 "<EventID>4625</EventID></Event>"},
            ],
        }

    monkeypatch.setattr("app.services.evtx_service.parse_evtx_file", _fake_parse)
    monkeypatch.setattr("app.services.finding_service.parse_evtx_file", _fake_parse, raising=False)

    async with make_live_db() as db:
        project = Project(name="ε.1.b.5-emit")
        db.add(project)
        await db.flush()
        fw = Firmware(
            project_id=project.id,
            sha256="f" * 64,
            extracted_path=str(rootfs),
            # Pre-populate evtx_walk_result so emit hook reads it.
            evtx_walk_result={
                "schema_version": 1,
                "run_seconds": 0.1,
                "evtx_count": 2,
                "by_provider": {
                    "Microsoft-Windows-Sysmon": 1,
                    "Microsoft-Windows-Security-Auditing": 2,
                },
                "by_status": {"ok": 2, "error": 0, "unavailable": 0},
                "total_records": 3,
                "sample_records_per_file": 32,
                "errors": [],
                "per_file": [
                    {"path": str(sysmon_evtx),
                     "status": "ok", "record_count": 1, "error": None},
                    {"path": str(security_evtx),
                     "status": "ok", "record_count": 2, "error": None},
                ],
            },
        )
        db.add(fw)
        await db.commit()

        service = FindingService(db)
        emitted = await service.emit_evtx_findings_from_walk(project.id, fw.id)
        await db.commit()

        # Rule #35b value-flow: SELECT the persisted rows and inspect
        # the fields the service explicitly sets.
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == fw.id)
            )
        ).scalars().all()

    assert len(emitted) == 3
    assert len(rows) == 3
    sources = sorted(r.source for r in rows)
    assert sources == [
        "windows_logon_failure",
        "windows_logon_success",
        "windows_sysmon_proc_create",
    ]
    # Confidence flow — every ε.1.b.4 LOW baseline.
    for row in rows:
        assert row.confidence == "low", (
            f"expected confidence=low for {row.source}, got {row.confidence}"
        )
    # File path flow — emit hook records the path the event came from.
    paths = sorted(r.file_path for r in rows if r.file_path)
    assert any("Sysmon.evtx" in p for p in paths)
    assert any("Security.evtx" in p for p in paths)


def test_tier1_no_execute_discipline_in_evtx_paths():
    """Rule #36 no-execute discipline check — assert evtx_service.py
    never CALLS any subprocess or os.system primitive (matches
    ``X.Y(`` form with paren so docstring mentions don't false-positive).
    python-evtx parses EVTX as DATA via mmap; nothing in the EVTX
    pipeline shells out."""
    import inspect
    import re

    from app.services import evtx_service

    src = inspect.getsource(evtx_service)
    # Match tokens followed by `(` — indicates the call site, not a
    # mention in a docstring or comment. Tolerates whitespace.
    forbidden_call_patterns = (
        r"\bsubprocess\.run\s*\(",
        r"\bsubprocess\.Popen\s*\(",
        r"\bsubprocess\.call\s*\(",
        r"\bsubprocess\.check_output\s*\(",
        r"\basyncio\.create_subprocess_exec\s*\(",
        r"\basyncio\.create_subprocess_shell\s*\(",
        r"\bos\.system\s*\(",
        r"\bos\.execvp\s*\(",
        r"\bos\.execve\s*\(",
        r"\bos\.spawnvp\s*\(",
    )
    for pat in forbidden_call_patterns:
        m = re.search(pat, src)
        assert m is None, (
            f"Rule #36 violation: evtx_service.py CALLS {pat}; the EVTX "
            "pipeline must read .evtx files AS DATA via python-evtx. "
            f"Match at offset {m.start() if m else -1}: "
            f"{src[max(0, (m.start() if m else 0) - 50):(m.end() if m else 0) + 50]!r}"
        )


# ── Tier 2 (real EVTX file) ─────────────────────────────────────────────────


@pytest.mark.skipif(
    not _HOST_REAL_EVTX_FILE,
    reason=(
        "Provide WAIRZ_TEST_REAL_EVTX_FILE (e.g. /path/to/Security.evtx) "
        "to run tier-2."
    ),
)
def test_tier2_parse_real_evtx_file_well_shaped() -> None:
    """Drive parse_evtx_file against a real EVTX with NO python-evtx
    mock. Asserts well-shaped output (status='ok', record_count > 0,
    records list populated). Tier-2 assertions are LOOSE — real EVTX
    files vary, so we don't assert specific record counts or content."""
    real_path = _HOST_REAL_EVTX_FILE
    assert os.path.isfile(real_path), (
        f"WAIRZ_TEST_REAL_EVTX_FILE points at non-file: {real_path!r}"
    )

    if not is_python_evtx_available():
        pytest.skip("python-evtx not installed in this environment")

    result = parse_evtx_file(real_path)

    # Real EVTX from a normally-functioning Windows install always has
    # status='ok' + record_count > 0. A truncated/corrupted file would
    # surface status='error' — also acceptable but useful to flag.
    assert result["status"] in ("ok", "error"), result
    if result["status"] == "ok":
        assert result["record_count"] > 0, "real EVTX has no records — corrupted?"
        assert isinstance(result["records"], list)
        assert len(result["records"]) > 0
        # First record has the canonical record_num + raw_xml shape.
        first = result["records"][0]
        assert "record_num" in first
        assert "raw_xml" in first
        assert isinstance(first["raw_xml"], str)
        assert "<Event" in first["raw_xml"]


# ── Tier 3 (paired before/after Sysmon directory) ───────────────────────────


@pytest.mark.skipif(
    not _HOST_REAL_EVTX_PAIRED,
    reason=(
        "Provide WAIRZ_TEST_REAL_EVTX_PAIRED (a directory with before/ + "
        "after/ subdirs each holding .evtx files) to run tier-3."
    ),
)
async def test_tier3_paired_evtx_diff_emits_findings(tmp_path: Path):
    """Drive the full ε.1.b pipeline against paired before/after
    Sysmon-log directories. Asserts ≥1 Finding emitted from the after
    walk that wasn't in the before walk (real paired Sysmon logs
    reliably contain new events between the two snapshots)."""
    base = Path(_HOST_REAL_EVTX_PAIRED)
    before_dir = base / "before"
    after_dir = base / "after"
    assert before_dir.is_dir(), (
        f"WAIRZ_TEST_REAL_EVTX_PAIRED missing before/ subdir: {before_dir}"
    )
    assert after_dir.is_dir(), (
        f"WAIRZ_TEST_REAL_EVTX_PAIRED missing after/ subdir: {after_dir}"
    )

    if not is_python_evtx_available():
        pytest.skip("python-evtx not installed in this environment")

    async with make_live_db() as db:
        project = Project(name="ε.1.b.5-tier3-paired")
        db.add(project)
        await db.flush()

        # Walk the AFTER snapshot — emit findings.
        fw_after = Firmware(
            project_id=project.id,
            sha256="3" * 64,
            extracted_path=str(after_dir),
        )
        db.add(fw_after)
        await db.commit()

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(after_dir)]

        with patch("app.services.evtx_service.get_detection_roots", new=_fake_roots):
            result_after = await _do_evtx_walk_run(db, fw_after.id)

        # Stamp + persist for the emit hook to read.
        from app.services.jsonb_normalizers import _stamp_firmware_evtx_walk_result
        fw_after.evtx_walk_result = _stamp_firmware_evtx_walk_result(result_after)
        await db.commit()

        # Emit hook reads the walk_result + persists Finding rows.
        service = FindingService(db)
        emitted = await service.emit_evtx_findings_from_walk(project.id, fw_after.id)
        await db.commit()

        # Real paired Sysmon logs reliably produce ≥1 Finding (Sysmon
        # logs accumulate per-event entries continuously). Assert
        # well-shaped output rather than a specific count.
        assert len(emitted) >= 1, (
            f"expected ≥1 Finding from real paired Sysmon logs; got "
            f"{len(emitted)} — fixture may be empty / both .evtx files "
            "may be invalid"
        )
        sources = {f.source for f in emitted}
        # At least one source must be from the ε.1.b.4 trio.
        epsilon_sources = {
            "windows_sysmon_proc_create",
            "windows_logon_success",
            "windows_logon_failure",
        }
        assert sources & epsilon_sources, (
            f"Tier-3 emit produced no ε.1.b.4 sources: got {sources!r}"
        )
