"""Phase ε.1 — Tier-1 unit tests for the EVTX parser scaffold + walker
+ inner runner (Rule #35b live canary).

Mirrors the new ``.mex/patterns/real-firmware-skip-tier-canary.md``
recipe (committed on ``feat/postmortem-followups-2026-05-09`` /
PR #2) — tier-1 always runs against synthetic / on-disk fixtures with
the third-party lib unavailable OR present-but-given-bad-input. The
tier-2/3 real-firmware canaries (a real Windows 11 ``Security.evtx``
+ a paired before/after Sysmon log) live in
``test_evtx_real_firmware.py`` (ε.1.b.5) per the recipe's per-test-file
discipline.

Rule #19 evidence-first probe codified as a test:
:func:`test_is_python_evtx_available_probe_is_callable` exercises
the probe regardless of whether python-evtx is actually installed.

Rule #36 no-execute reminder: tests read EVTX paths as DATA. No
subprocess invocation against EVTX files at any point in this file.
"""
from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from app.models.firmware import Firmware
from app.models.project import Project
from app.services.evtx_service import (
    PYTHON_EVTX_UNAVAILABLE,
    _do_evtx_walk_run,
    is_python_evtx_available,
    parse_evtx_file,
    walk_evtx_files,
)
from tests._live_db import make_live_db

# ── Tier 1 (always runs) ────────────────────────────────────────────────────


def test_is_python_evtx_available_probe_is_callable() -> None:
    """Rule #19 dependency probe exists and returns a bool.

    Does NOT assert the value (the probe's correctness depends on
    whether python-evtx is installed in the test runtime — host
    pytest may have it OR not depending on environment). The
    contract is just "the function exists, returns bool, doesn't
    raise".
    """
    result = is_python_evtx_available()
    assert isinstance(result, bool)


def test_parse_evtx_file_unavailable_short_circuits_when_python_evtx_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When python-evtx isn't importable, parse_evtx_file returns the
    canonical PYTHON_EVTX_UNAVAILABLE sentinel WITHOUT touching the
    file path. This is the graceful-degrade path used by MCP tools /
    future Rule #33 triggers when the dep is missing in a minimal-CI
    Docker build.
    """
    # Mock the probe to report unavailable regardless of host state.
    monkeypatch.setattr(
        "app.services.evtx_service.is_python_evtx_available",
        lambda: False,
    )
    result = parse_evtx_file("/nonexistent/path.evtx")
    assert result == PYTHON_EVTX_UNAVAILABLE
    assert result["status"] == "unavailable"
    assert result["records"] == []


def test_parse_evtx_file_handles_missing_file_gracefully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When python-evtx IS available but the path doesn't exist, the
    parser's Evtx() open raises — parse_evtx_file should surface a
    structured error response, not propagate the exception.

    Mocks Evtx() to simulate the not-found error path so this test
    runs deterministically regardless of host python-evtx state.
    """
    monkeypatch.setattr(
        "app.services.evtx_service.is_python_evtx_available",
        lambda: True,
    )

    class _FakeEvtx:
        def __init__(self, *args, **kwargs):
            raise FileNotFoundError("fake evtx not found")

        def __enter__(self):  # pragma: no cover — never reached
            return self

        def __exit__(self, *exc):  # pragma: no cover
            return False

    with patch("Evtx.Evtx.Evtx", _FakeEvtx):
        result = parse_evtx_file("/definitely/not/a/file.evtx")

    assert result["status"] == "error"
    assert result["record_count"] == 0
    assert result["records"] == []
    assert "fake evtx not found" in result["error"]


def test_parse_evtx_file_returns_records_on_synthetic_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drive the happy-path parse contract end-to-end against a
    mocked Evtx() that yields 2 synthetic records. Verifies the
    parser surfaces ``status="ok"`` + populated ``records`` list +
    correct ``record_count``.
    """
    monkeypatch.setattr(
        "app.services.evtx_service.is_python_evtx_available",
        lambda: True,
    )

    class _FakeRecord:
        def __init__(self, num: int, xml: str):
            self._num = num
            self._xml = xml

        def record_num(self) -> int:
            return self._num

        def xml(self) -> str:
            return self._xml

    class _FakeEvtxLog:
        def records(self):
            yield _FakeRecord(1, "<Event>EID=4624</Event>")
            yield _FakeRecord(2, "<Event>EID=4625</Event>")

    class _FakeEvtx:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return _FakeEvtxLog()

        def __exit__(self, *exc):
            return False

    with patch("Evtx.Evtx.Evtx", _FakeEvtx):
        with tempfile.NamedTemporaryFile(suffix=".evtx") as tmp:
            tmp.write(b"\x45\x6c\x66\x46\x69\x6c\x65")  # ElfFile EVTX magic
            tmp.flush()
            result = parse_evtx_file(tmp.name)

    assert result["status"] == "ok"
    assert result["record_count"] == 2
    assert len(result["records"]) == 2
    assert result["records"][0]["record_num"] == 1
    assert "EID=4624" in result["records"][0]["raw_xml"]
    assert result["records"][1]["record_num"] == 2
    assert "EID=4625" in result["records"][1]["raw_xml"]


def test_parse_evtx_file_truncates_long_error_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Error messages > 500 chars are truncated with ``"..."`` suffix
    to keep MCP tool wrappers under the 30KB output budget."""
    monkeypatch.setattr(
        "app.services.evtx_service.is_python_evtx_available",
        lambda: True,
    )

    long_msg = "x" * 1000

    class _FakeEvtx:
        def __init__(self, *args, **kwargs):
            raise RuntimeError(long_msg)

        def __enter__(self):  # pragma: no cover
            return self

        def __exit__(self, *exc):  # pragma: no cover
            return False

    with patch("Evtx.Evtx.Evtx", _FakeEvtx):
        result = parse_evtx_file("/whatever.evtx")

    assert result["status"] == "error"
    assert len(result["error"]) <= 503  # 500 + "..."
    assert result["error"].endswith("...")


# ── Tier 1 (always runs) — walker (ε.1.b.1) ─────────────────────────────────


def test_walk_evtx_files_yields_extension_matches(tmp_path: Path) -> None:
    """walk_evtx_files surfaces every ``.evtx`` file under any root.

    Creates a synthetic on-disk tree with mixed file extensions and
    asserts the walker returns only the EVTX-extension files. Mirrors
    the γ.4 ``scan_for_hives`` test shape.
    """
    root = tmp_path / "rootfs"
    (root / "Windows" / "System32" / "winevt" / "Logs").mkdir(
        parents=True, exist_ok=True
    )
    # Three .evtx (Security, Sysmon, Application — canonical Windows EVTX
    # locations). Different cases to verify case-insensitive match.
    (root / "Windows/System32/winevt/Logs/Security.evtx").write_bytes(
        b"\x45\x6c\x66\x46\x69\x6c\x65"  # ElfFile EVTX magic, not validated here
    )
    (root / "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon.EVTX").write_bytes(
        b"\x45\x6c\x66\x46"
    )
    (root / "Windows/System32/winevt/Logs/Application.evtx").write_bytes(b"")
    # Decoy files that MUST NOT be matched.
    (root / "Windows/System32/winevt/Logs/Application.txt").write_text("noise")
    (root / "Windows/System32/winevt/Logs/Security.evtx.bak").write_text("backup")

    hits = walk_evtx_files([str(root)])
    names = sorted(os.path.basename(h) for h in hits)
    assert names == ["Application.evtx", "Microsoft-Windows-Sysmon.EVTX", "Security.evtx"]


def test_walk_evtx_files_skips_non_evtx_extensions(tmp_path: Path) -> None:
    """Files whose name doesn't end in ``.evtx`` (case-insensitive) are
    not surfaced — including ``.evt`` (legacy XP/2003 format),
    ``.evtx.bak``, ``.evtx.gz``, and arbitrary text files."""
    root = tmp_path / "rootfs"
    root.mkdir()
    for fn in ("legacy.evt", "rotated.evtx.bak", "compressed.evtx.gz", "log.txt"):
        (root / fn).write_bytes(b"x")

    hits = walk_evtx_files([str(root)])
    assert hits == []


def test_walk_evtx_files_skips_symlinks_pointing_outside_root(
    tmp_path: Path,
) -> None:
    """Sandbox check — a symlink inside the root that points OUTSIDE
    the root tree must be rejected. Same shape as
    :func:`registry_hive_walker.scan_for_hives` (Rule #1 spirit)."""
    root = tmp_path / "rootfs"
    root.mkdir()
    outside = tmp_path / "outside.evtx"
    outside.write_bytes(b"sneaky")

    sneaky_link = root / "sneaky.evtx"
    try:
        sneaky_link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover — symlink-unsupported FS
        pytest.skip("symlinks not supported on this filesystem")

    # Add a legitimate intra-root file too — it MUST still be returned.
    inside = root / "real.evtx"
    inside.write_bytes(b"")

    hits = walk_evtx_files([str(root)])
    names = sorted(os.path.basename(h) for h in hits)
    assert names == ["real.evtx"]


def test_walk_evtx_files_returns_empty_for_missing_root() -> None:
    """A nonexistent / inaccessible root path returns empty. The
    walker never raises on missing input — defensive boundary per the
    γ.4 ``scan_for_hives`` precedent so one bad root doesn't abort
    the entire multi-root walk."""
    hits = walk_evtx_files(["/definitely/does/not/exist"])
    assert hits == []


def test_walk_evtx_files_handles_multiple_roots(tmp_path: Path) -> None:
    """Multi-root walk surfaces files from every root passed in (Rule
    #16 detection-roots discipline — scatter-zip / multi-partition
    firmware produces sibling detection roots all of which must be
    walked)."""
    root_a = tmp_path / "rootfs_a"
    root_b = tmp_path / "rootfs_b"
    root_a.mkdir()
    root_b.mkdir()
    (root_a / "a.evtx").write_bytes(b"")
    (root_b / "b.evtx").write_bytes(b"")

    hits = walk_evtx_files([str(root_a), str(root_b)])
    names = sorted(os.path.basename(h) for h in hits)
    assert names == ["a.evtx", "b.evtx"]


# ── Tier 1 (always runs) — _do_evtx_walk_run inner runner (ε.1.b.3) ─────────
#
# Live canary per Rule #35b — drives the inner runner against the real
# ORM with synthetic on-disk EVTX fixtures + mocked python-evtx parser.
# The outer state-machine wrapper ``run_evtx_walk_background`` is NOT
# tested here because it uses ``async_session_factory()`` which resolves
# the ``postgres`` Docker hostname; host pytest can't reach it. The inner
# runner accepts a ``db`` directly so it's exercisable under
# ``make_live_db()`` (δ Pattern #2 inner-vs-outer split).


async def _seed_firmware(db, *, extracted_path: str) -> uuid.UUID:
    """Create a Project + Firmware row pointing at extracted_path."""
    project = Project(name="ε-test")
    db.add(project)
    await db.flush()

    firmware = Firmware(
        project_id=project.id,
        sha256="0" * 64,
        extracted_path=extracted_path,
    )
    db.add(firmware)
    await db.flush()
    return firmware.id


async def test_do_evtx_walk_run_returns_empty_when_no_evtx_files(
    tmp_path: Path,
) -> None:
    """A firmware with no .evtx files in any detection root produces
    the canonical empty aggregate (evtx_count=0, all status counters
    at 0). Same shape as registry_hive_walker's _empty_walk_result."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()

    async with make_live_db() as db:
        firmware_id = await _seed_firmware(db, extracted_path=str(rootfs))
        await db.commit()

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(rootfs)]

        with patch("app.services.evtx_service.get_detection_roots", new=_fake_roots):
            result = await _do_evtx_walk_run(db, firmware_id)

    assert result["evtx_count"] == 0
    assert result["by_status"] == {"ok": 0, "error": 0, "unavailable": 0}
    assert result["total_records"] == 0
    assert result["per_file"] == []


async def test_do_evtx_walk_run_aggregates_per_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drive the inner runner end-to-end against synthetic .evtx
    fixtures. Asserts:

    - aggregate.evtx_count == files found
    - aggregate.by_status counts
    - aggregate.by_provider extracted from sample-record XML
    - aggregate.total_records summed
    - aggregate.per_file shape

    Rule #35b live canary — exercises the REAL ORM round-trip via
    make_live_db() so the value-flow contract (runner sets X →
    aggregate has X) is verified end-to-end (mock-only would miss
    the F-A-06-shape constructor-args-vs-persisted-fields class).
    """
    rootfs = tmp_path / "rootfs"
    logs_dir = rootfs / "Windows" / "System32" / "winevt" / "Logs"
    logs_dir.mkdir(parents=True)
    sysmon_path = logs_dir / "Microsoft-Windows-Sysmon.evtx"
    security_path = logs_dir / "Security.evtx"
    sysmon_path.write_bytes(b"\x45\x6c\x66\x46")  # not validated
    security_path.write_bytes(b"\x45\x6c\x66\x46")

    # Mock parse_evtx_file at the SOURCE module per Rule #30 — patch
    # the symbol used by _do_evtx_walk_run via its run_in_executor
    # wrapper. Each call gets a different return based on path.
    def _fake_parse(path: str):
        if "Sysmon" in path:
            return {
                "status": "ok",
                "record_count": 3,
                "records": [
                    {"record_num": 1, "raw_xml":
                     "<Event><Provider Name='Microsoft-Windows-Sysmon'/></Event>"},
                    {"record_num": 2, "raw_xml":
                     "<Event><Provider Name='Microsoft-Windows-Sysmon'/></Event>"},
                    {"record_num": 3, "raw_xml":
                     "<Event><Provider Name='Microsoft-Windows-Sysmon'/></Event>"},
                ],
            }
        else:  # Security.evtx
            return {
                "status": "ok",
                "record_count": 2,
                "records": [
                    {"record_num": 1, "raw_xml":
                     "<Event><Provider Name='Microsoft-Windows-Security-Auditing'/></Event>"},
                    {"record_num": 2, "raw_xml":
                     "<Event><Provider Name='Microsoft-Windows-Security-Auditing'/></Event>"},
                ],
            }

    monkeypatch.setattr("app.services.evtx_service.parse_evtx_file", _fake_parse)

    async with make_live_db() as db:
        firmware_id = await _seed_firmware(db, extracted_path=str(rootfs))
        await db.commit()

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(rootfs)]

        with patch("app.services.evtx_service.get_detection_roots", new=_fake_roots):
            result = await _do_evtx_walk_run(db, firmware_id)

    # Aggregate shape — Rule #35b value-flow assertions, not just call shape.
    assert result["evtx_count"] == 2
    assert result["by_status"]["ok"] == 2
    assert result["by_status"]["error"] == 0
    assert result["by_status"]["unavailable"] == 0
    assert result["by_provider"]["Microsoft-Windows-Sysmon"] == 3
    assert result["by_provider"]["Microsoft-Windows-Security-Auditing"] == 2
    assert result["total_records"] == 5

    # Per-file shape.
    paths = sorted(entry["path"] for entry in result["per_file"])
    assert any(p.endswith("Microsoft-Windows-Sysmon.evtx") for p in paths)
    assert any(p.endswith("Security.evtx") for p in paths)
    statuses = {entry["status"] for entry in result["per_file"]}
    assert statuses == {"ok"}


async def test_do_evtx_walk_run_handles_parse_errors_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A corrupted .evtx that raises during parse is captured as
    status=error in the per-file list AND counted in by_status.error;
    the walk continues to subsequent files (defensive boundary per
    γ.4 precedent)."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "good.evtx").write_bytes(b"\x45\x6c\x66\x46")
    (rootfs / "bad.evtx").write_bytes(b"truncated")

    def _fake_parse(path: str):
        if "bad" in path:
            return {
                "status": "error",
                "record_count": 0,
                "records": [],
                "error": "synthetic parse failure",
            }
        return {
            "status": "ok",
            "record_count": 1,
            "records": [
                {"record_num": 1, "raw_xml":
                 "<Event><Provider Name='Microsoft-Windows-Eventlog'/></Event>"},
            ],
        }

    monkeypatch.setattr("app.services.evtx_service.parse_evtx_file", _fake_parse)

    async with make_live_db() as db:
        firmware_id = await _seed_firmware(db, extracted_path=str(rootfs))
        await db.commit()

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(rootfs)]

        with patch("app.services.evtx_service.get_detection_roots", new=_fake_roots):
            result = await _do_evtx_walk_run(db, firmware_id)

    assert result["evtx_count"] == 2
    assert result["by_status"]["ok"] == 1
    assert result["by_status"]["error"] == 1
    assert result["total_records"] == 1
    # The error path's per_file entry carries the error message.
    bad_entry = next(e for e in result["per_file"] if "bad.evtx" in e["path"])
    assert bad_entry["status"] == "error"
    assert "synthetic parse failure" in (bad_entry["error"] or "")


# ── Tier 2/3 (deferred to ε.1.b.5 — real-firmware canary set) ───────────────
#
# WAIRZ_TEST_REAL_EVTX_FILE / WAIRZ_TEST_REAL_EVTX_PAIRED env vars
# will graduate the canary set from N pass → (N+M) pass once ε.1.b.5
# lands the dedicated real-firmware test file. See the C.3 recipe at
# .mex/patterns/real-firmware-skip-tier-canary.md (PR #2) for the tier
# shape that file will follow.
