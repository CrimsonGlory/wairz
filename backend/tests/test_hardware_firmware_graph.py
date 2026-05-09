"""Unit tests for the Phase 3 driver <-> firmware graph builder.

Uses a mock ``AsyncSession`` pattern consistent with
``test_finding_service.py`` — no live database required.  The fake DB stubs
``execute`` to return pre-populated model rows, ``add`` / ``flush`` to be
no-ops that we assert on.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.finding import Finding
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.services.hardware_firmware.graph import (
    DriverFirmwareEdge,
    GraphResult,
    _resolve_firmware_name,
    _scan_vmlinux_firmware_strings,
    build_driver_firmware_graph,
)

# ---------------------------------------------------------------------------
# _resolve_firmware_name
# ---------------------------------------------------------------------------


class TestResolveFirmwareName:
    def test_exact_match(self) -> None:
        blob = MagicMock(spec=HardwareFirmwareBlob)
        fw_by_name = {"wcn6750.bin": [blob]}
        assert _resolve_firmware_name("wcn6750.bin", fw_by_name) == [blob]

    def test_basename_strip(self) -> None:
        blob = MagicMock(spec=HardwareFirmwareBlob)
        fw_by_name = {"wcn6750.bin": [blob]}
        # Reference from .modinfo can carry a directory prefix.
        assert _resolve_firmware_name("/lib/firmware/wcn6750.bin", fw_by_name) == [blob]
        assert _resolve_firmware_name("qca/wcn6750.bin", fw_by_name) == [blob]

    def test_case_insensitive(self) -> None:
        blob = MagicMock(spec=HardwareFirmwareBlob)
        fw_by_name = {"wcn6750.bin": [blob]}
        assert _resolve_firmware_name("WCN6750.BIN", fw_by_name) == [blob]

    def test_miss_returns_empty(self) -> None:
        blob = MagicMock(spec=HardwareFirmwareBlob)
        fw_by_name = {"wcn6750.bin": [blob]}
        assert _resolve_firmware_name("other.bin", fw_by_name) == []

    def test_empty_name_returns_empty(self) -> None:
        assert _resolve_firmware_name("", {}) == []
        assert _resolve_firmware_name("/", {}) == []


# ---------------------------------------------------------------------------
# _scan_vmlinux_firmware_strings
# ---------------------------------------------------------------------------


class TestScanVmlinuxStrings:
    def test_extracts_valid_firmware_paths(self, tmp_path: Path) -> None:
        vmlinux = tmp_path / "vmlinux"
        payload = (
            b"\x00\x00random garbage\x00"
            b"brcmfmac43430-sdio.bin\x00"
            b"more bytes\x00"
            b"qca/wcn6750.bin\x00"
        )
        vmlinux.write_bytes(payload)

        refs = _scan_vmlinux_firmware_strings(str(vmlinux))
        assert "brcmfmac43430-sdio.bin" in refs
        assert "qca/wcn6750.bin" in refs

    def test_rejects_double_dot_paths(self, tmp_path: Path) -> None:
        """Paths containing '..' are treated as debug/source artifacts."""
        vmlinux = tmp_path / "vmlinux_dotted"
        vmlinux.write_bytes(b"../somefile.bin\x00garbage..bin\x00good.bin\x00")

        refs = _scan_vmlinux_firmware_strings(str(vmlinux))
        assert "good.bin" in refs
        # Anything containing ".." in path or the specific pathological
        # 'garbage..bin' must not appear.
        for r in refs:
            assert ".." not in r

    def test_rejects_proc_and_windows_paths(self, tmp_path: Path) -> None:
        vmlinux = tmp_path / "vmlinux_odd"
        vmlinux.write_bytes(
            b"/proc/self/status.bin\x00"
            b"C:\\tmp\\fake.bin\x00"
            b"realfirmware.bin\x00"
        )
        refs = _scan_vmlinux_firmware_strings(str(vmlinux))
        assert "realfirmware.bin" in refs
        assert not any(r.startswith("/proc/") for r in refs)
        assert not any(r.startswith("C:") for r in refs)

    def test_respects_cap_on_distinct_refs(self, tmp_path: Path) -> None:
        """With 1000+ unique firmware strings we should stop at <= 500."""
        vmlinux = tmp_path / "vmlinux_big"
        # 1000 distinct firmware names, NUL-separated.
        payload = b"\x00".join(
            f"distinct_name_{i:04d}.bin".encode("ascii") for i in range(1000)
        )
        vmlinux.write_bytes(payload)

        refs = _scan_vmlinux_firmware_strings(str(vmlinux))
        assert len(refs) <= 500

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert _scan_vmlinux_firmware_strings(str(tmp_path / "nope")) == []


# ---------------------------------------------------------------------------
# build_driver_firmware_graph
# ---------------------------------------------------------------------------


def _make_blob(
    *,
    blob_path: str,
    fmt: str,
    metadata: dict | None = None,
) -> MagicMock:
    """Minimal HardwareFirmwareBlob mock that behaves like the ORM row.

    We use a MagicMock with the correct attributes so mutation in-place
    (``blob.driver_references = [...]``) is observable by assertions.
    """
    blob = MagicMock(spec=HardwareFirmwareBlob)
    blob.blob_path = blob_path
    blob.format = fmt
    blob.metadata_ = metadata or {}
    blob.driver_references = None
    return blob


def _make_firmware(
    *,
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    extracted_path: str | None = None,
    kernel_path: str | None = None,
) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = firmware_id
    fw.project_id = project_id
    fw.extracted_path = extracted_path
    fw.kernel_path = kernel_path
    return fw


def _mock_db_with_results(
    *,
    blobs: list,
    firmware: MagicMock | None,
    existing_finding_titles: list[str] | None = None,
) -> AsyncMock:
    """Produce an AsyncMock AsyncSession whose execute() returns the right rows.

    The graph builder issues three queries in order:

    1. ``select(HardwareFirmwareBlob).where(firmware_id == ...)``  -> blobs
    2. ``select(Firmware).where(Firmware.id == ...)``              -> firmware
    3. ``select(Finding.title).where(firmware_id == ..., source == ...)``
       -> list[tuple[title]]

    We attach a side_effect that yields results in that order.  Each call
    returns an object whose ``scalars()/all()`` / ``scalar_one_or_none()`` /
    ``all()`` methods match what the code under test asks for.
    """
    existing_finding_titles = existing_finding_titles or []

    blobs_result = MagicMock()
    blobs_result.scalars.return_value.all.return_value = blobs

    firmware_result = MagicMock()
    firmware_result.scalar_one_or_none.return_value = firmware

    findings_result = MagicMock()
    # build_driver_firmware_graph iterates over the result of .all() — each
    # row should be a single-tuple-like with .title in position 0.
    findings_result.all.return_value = [(t,) for t in existing_finding_titles]

    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.execute = AsyncMock(
        side_effect=[blobs_result, firmware_result, findings_result],
    )
    return db


@pytest.mark.asyncio
async def test_build_graph_empty_blobs_returns_empty_result() -> None:
    firmware_id = uuid.uuid4()
    db = _mock_db_with_results(blobs=[], firmware=None)
    # Short-circuit: no blobs -> no Firmware / Finding lookup needed.
    db.execute = AsyncMock(return_value=_empty_blob_result())

    result = await build_driver_firmware_graph(firmware_id, db)
    assert result.edges == []
    assert result.kmod_drivers == 0
    assert result.dtb_sources == 0
    assert result.unresolved_count == 0


def _empty_blob_result() -> MagicMock:
    mock = MagicMock()
    mock.scalars.return_value.all.return_value = []
    return mock


@pytest.mark.asyncio
async def test_build_graph_resolves_kmod_firmware_deps() -> None:
    project_id = uuid.uuid4()
    firmware_id = uuid.uuid4()

    ko_blob = _make_blob(
        blob_path="/vendor/lib/modules/wcn6750.ko",
        fmt="ko",
        metadata={"firmware_deps": ["wcn6750.bin", "wcn6750_nv.bin"]},
    )
    fw_blob = _make_blob(
        blob_path="/vendor/firmware/wcn6750.bin",
        fmt="fw_bcm",
    )
    nv_blob = _make_blob(
        blob_path="/vendor/firmware/wcn6750_nv.bin",
        fmt="raw_bin",
    )
    fw = _make_firmware(project_id=project_id, firmware_id=firmware_id)
    db = _mock_db_with_results(blobs=[ko_blob, fw_blob, nv_blob], firmware=fw)

    result = await build_driver_firmware_graph(firmware_id, db)

    assert result.kmod_drivers == 1
    assert result.dtb_sources == 0
    assert result.unresolved_count == 0
    # Two edges, both kmod_modinfo, both resolved.
    assert len(result.edges) == 2
    for e in result.edges:
        assert e.source == "kmod_modinfo"
        assert e.firmware_blob_path is not None
    # driver_references must be written back to the kmod row.
    assert ko_blob.driver_references == ["wcn6750.bin", "wcn6750_nv.bin"]
    # No Finding added for a fully-resolved graph.
    db.add.assert_not_called()
    db.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_build_graph_creates_missing_firmware_findings() -> None:
    project_id = uuid.uuid4()
    firmware_id = uuid.uuid4()

    ko_blob = _make_blob(
        blob_path="/vendor/lib/modules/wcn6750.ko",
        fmt="ko",
        metadata={"firmware_deps": ["absent1.bin", "absent2.bin"]},
    )
    fw = _make_firmware(project_id=project_id, firmware_id=firmware_id)
    db = _mock_db_with_results(blobs=[ko_blob], firmware=fw)

    result = await build_driver_firmware_graph(firmware_id, db)

    assert result.unresolved_count == 2
    assert len(result.edges) == 2
    for e in result.edges:
        assert e.firmware_blob_path is None
    # driver_references list must include both unresolved names.
    assert ko_blob.driver_references == ["absent1.bin", "absent2.bin"]
    # Two Finding rows added.
    assert db.add.call_count == 2
    added_findings = [call.args[0] for call in db.add.call_args_list]
    for f in added_findings:
        assert isinstance(f, Finding)
        assert f.source == "hardware_firmware_graph"
        assert f.severity == "medium"
        assert f.project_id == project_id
        assert f.firmware_id == firmware_id
        assert f.title.startswith("Missing firmware: ")


@pytest.mark.asyncio
async def test_build_graph_findings_dedup_on_second_run() -> None:
    """Running the graph twice must NOT create duplicate finding rows."""
    project_id = uuid.uuid4()
    firmware_id = uuid.uuid4()

    ko_blob = _make_blob(
        blob_path="/vendor/lib/modules/wifi.ko",
        fmt="ko",
        metadata={"firmware_deps": ["missing.bin"]},
    )
    fw = _make_firmware(project_id=project_id, firmware_id=firmware_id)

    # First run: no existing findings.
    db1 = _mock_db_with_results(blobs=[ko_blob], firmware=fw)
    r1 = await build_driver_firmware_graph(firmware_id, db1)
    assert r1.unresolved_count == 1
    assert db1.add.call_count == 1

    # Reset driver_references so the second run re-walks the same code paths.
    ko_blob.driver_references = None

    # Second run: existing finding already present.
    db2 = _mock_db_with_results(
        blobs=[ko_blob],
        firmware=fw,
        existing_finding_titles=["Missing firmware: missing.bin"],
    )
    r2 = await build_driver_firmware_graph(firmware_id, db2)
    assert r2.unresolved_count == 1
    # Dedup must short-circuit the add().
    db2.add.assert_not_called()


@pytest.mark.asyncio
async def test_build_graph_handles_dtb_firmware_names() -> None:
    project_id = uuid.uuid4()
    firmware_id = uuid.uuid4()

    dtb_blob = _make_blob(
        blob_path="/vendor/firmware/platform.dtb",
        fmt="dtb",
        metadata={"firmware_names": ["wcn6750.bin"]},
    )
    fw_blob = _make_blob(
        blob_path="/vendor/firmware/wcn6750.bin",
        fmt="fw_bcm",
    )
    fw = _make_firmware(project_id=project_id, firmware_id=firmware_id)
    db = _mock_db_with_results(blobs=[dtb_blob, fw_blob], firmware=fw)

    result = await build_driver_firmware_graph(firmware_id, db)
    assert result.dtb_sources == 1
    assert result.kmod_drivers == 0
    assert len(result.edges) == 1
    assert result.edges[0].source == "dtb_firmware_name"
    assert result.edges[0].firmware_blob_path is not None


@pytest.mark.asyncio
async def test_build_graph_skips_ko_without_firmware_deps() -> None:
    """kmod rows with empty firmware_deps must not count as drivers."""
    project_id = uuid.uuid4()
    firmware_id = uuid.uuid4()

    ko_blob = _make_blob(
        blob_path="/vendor/lib/modules/empty.ko",
        fmt="ko",
        metadata={"firmware_deps": []},
    )
    fw = _make_firmware(project_id=project_id, firmware_id=firmware_id)
    db = _mock_db_with_results(blobs=[ko_blob], firmware=fw)

    result = await build_driver_firmware_graph(firmware_id, db)
    assert result.kmod_drivers == 0
    assert result.edges == []
    # driver_references must NOT be set when there are no deps.
    assert ko_blob.driver_references is None


# ---------------------------------------------------------------------------
# GraphResult / DriverFirmwareEdge dataclasses
# ---------------------------------------------------------------------------


def test_dataclasses_are_importable() -> None:
    edge = DriverFirmwareEdge(
        driver_path="/a.ko", firmware_name="x.bin",
        firmware_blob_path=None, source="kmod_modinfo",
    )
    assert edge.driver_path == "/a.ko"
    res = GraphResult(edges=[edge], unresolved_count=1, kmod_drivers=1, dtb_sources=0)
    assert res.unresolved_count == 1
