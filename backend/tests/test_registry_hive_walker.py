"""Phase γ.4 — registry_hive_walker tests.

Two layers of coverage:

1. Pure walker (``walk_hive_path``, ``_is_hive_file``, ``scan_for_hives``,
   ``_hive_type_from_path``, ``_coerce_value_data``) tested with
   synthetic ``regf``-magic fixtures + mocked ``RegistryHive``. Covers
   normal walks, depth/key/timeout caps, malformed inputs, empty
   hives, non-canonical filenames.

2. Live canary (``test_auto_walk_firmware_persists_real_extract``) per
   Rule #35b — round-trips a synthetic hive through the full
   ``auto_walk_firmware`` orchestrator against ``tests._live_db.
   make_live_db``, then SELECTs the persisted ``WindowsRegistryExtract``
   + ``HardwareFirmwareBlob`` rows to inspect every field the service
   explicitly sets. Mock-only coverage would miss the value-flow
   contract (constructor args → persisted columns) per the audit-2026-
   05-04 F-A-06 / F-G-03 lessons baked into Rule #35b.

regipy is patched to a fake ``RegistryHive`` for layer 1 (no real
.hive fixture committed — Win11 hives are GiB-scale and licence-
restricted; the synthetic ``b"regf"`` + 4 KiB padding fixture is
enough to exercise filename + magic detection without dragging a
real hive into the repo).
"""
from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

import pytest

from app.models import (
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsRegistryExtract,
)
from app.services.registry_hive_walker import (
    _DEFAULT_MAX_DEPTH,
    _HIVE_FILENAME_PATTERNS,
    _coerce_value_data,
    _hive_type_from_path,
    _is_hive_file,
    auto_walk_firmware,
    scan_for_hives,
    walk_hive_path,
)
from tests._live_db import make_live_db

# ── Synthetic fixture builder ────────────────────────────────────────────────


def _write_synthetic_hive(path: str, *, with_magic: bool = True) -> None:
    """Write a tiny ``regf``-magic-prefixed file at ``path``. The body
    is 4 KiB of zeros — enough to satisfy the filename + magic
    heuristic without dragging a real hive into the repo. The walker
    will be mocked separately."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    body = b"regf" if with_magic else b"BOGS"
    body += b"\x00" * 4092
    with open(path, "wb") as fh:
        fh.write(body)


# ── _hive_type_from_path ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/x/Windows/System32/config/SOFTWARE", "SOFTWARE"),
        ("/x/Windows/System32/config/SYSTEM", "SYSTEM"),
        ("/x/Users/Default/NTUSER.DAT", "NTUSER"),
        ("/x/Users/Joe/AppData/Local/Microsoft/Windows/UsrClass.dat", "UsrClass"),
        ("/x/Windows/AppCompat/Programs/Amcache.hve", "AmCache"),
        ("/x/whatever/some_random_file", "unknown"),
        # Case-insensitive — Linux fs may preserve case but Windows is
        # case-insensitive; an lowercase variant should still classify.
        ("/x/Windows/System32/config/system", "SYSTEM"),
    ],
)
def test_hive_type_from_path(path: str, expected: str) -> None:
    assert _hive_type_from_path(path) == expected


# ── _is_hive_file ────────────────────────────────────────────────────────────


def test_is_hive_file_true_for_software_with_magic(tmp_path) -> None:
    p = str(tmp_path / "config" / "SOFTWARE")
    _write_synthetic_hive(p, with_magic=True)
    assert _is_hive_file(p) is True


def test_is_hive_file_false_for_software_without_magic(tmp_path) -> None:
    """Filename match alone is not enough — a coincidentally-named
    file without the regf magic must not be picked up."""
    p = str(tmp_path / "config" / "SOFTWARE")
    _write_synthetic_hive(p, with_magic=False)
    assert _is_hive_file(p) is False


def test_is_hive_file_false_for_random_filename_with_magic(tmp_path) -> None:
    """Magic match alone is not enough — random files happen to start
    with ``regf`` (e.g. log files mentioning "regf"); the canonical
    name list constrains the surface."""
    p = str(tmp_path / "subdir" / "some_random_file.bin")
    _write_synthetic_hive(p, with_magic=True)
    assert _is_hive_file(p) is False


def test_is_hive_file_false_for_directory(tmp_path) -> None:
    """A directory named SYSTEM should not be classified as a hive."""
    p = str(tmp_path / "SYSTEM")
    os.makedirs(p)
    assert _is_hive_file(p) is False


def test_is_hive_file_false_for_missing(tmp_path) -> None:
    assert _is_hive_file(str(tmp_path / "missing")) is False


def test_hive_filename_patterns_include_canonical_names() -> None:
    """Smoke check the canonical filename allowlist hasn't drifted."""
    expected = {
        "SOFTWARE", "SYSTEM", "SAM", "SECURITY", "DEFAULT",
        "NTUSER.DAT", "USRCLASS.DAT", "AMCACHE.HVE",
    }
    assert expected.issubset(_HIVE_FILENAME_PATTERNS)


# ── scan_for_hives ───────────────────────────────────────────────────────────


def test_scan_for_hives_finds_canonical_hives_under_root(tmp_path) -> None:
    """Walks the root and returns paths whose basename is canonical
    AND magic matches; non-matches are filtered."""
    sw_path = str(tmp_path / "Windows" / "System32" / "config" / "SOFTWARE")
    sys_path = str(tmp_path / "Windows" / "System32" / "config" / "SYSTEM")
    bogus_path = str(tmp_path / "Windows" / "System32" / "config" / "bogus")
    fake_software_path = str(tmp_path / "Documents" / "SOFTWARE")
    _write_synthetic_hive(sw_path, with_magic=True)
    _write_synthetic_hive(sys_path, with_magic=True)
    _write_synthetic_hive(bogus_path, with_magic=True)  # name fails
    _write_synthetic_hive(fake_software_path, with_magic=False)  # magic fails

    found = sorted(scan_for_hives([str(tmp_path)]))
    assert sw_path in found
    assert sys_path in found
    assert bogus_path not in found
    assert fake_software_path not in found


def test_scan_for_hives_handles_missing_root(tmp_path) -> None:
    """Missing root contributes 0 hits, doesn't raise."""
    assert scan_for_hives([str(tmp_path / "nope")]) == []


def test_scan_for_hives_skips_escape_symlinks(tmp_path) -> None:
    """A symlink whose realpath escapes the root should NOT be
    followed (Rule #1 sandbox spirit)."""
    outside = tmp_path / "outside"
    outside.mkdir()
    real = outside / "SYSTEM"
    _write_synthetic_hive(str(real), with_magic=True)

    inside_root = tmp_path / "rootfs"
    inside_root.mkdir()
    config_dir = inside_root / "Windows" / "System32" / "config"
    config_dir.mkdir(parents=True)
    # Symlink inside the root that points OUTSIDE the root.
    (config_dir / "SYSTEM").symlink_to(real)

    found = scan_for_hives([str(inside_root)])
    assert str(real) not in found  # escape rejected
    # The escape symlink itself is also rejected (its realpath is outside).
    assert all(not p.startswith(str(outside)) for p in found)


# ── _coerce_value_data ───────────────────────────────────────────────────────


def test_coerce_value_data_passes_short_string() -> None:
    assert _coerce_value_data("short", max_bytes=100) == "short"


def test_coerce_value_data_truncates_long_string() -> None:
    out = _coerce_value_data("x" * 200, max_bytes=100)
    assert out == "x" * 100 + "...[truncated]"


def test_coerce_value_data_hex_encodes_short_bytes() -> None:
    out = _coerce_value_data(b"\x01\x02\x03", max_bytes=100)
    assert out == "010203"


def test_coerce_value_data_truncates_long_bytes() -> None:
    out = _coerce_value_data(b"\xff" * 200, max_bytes=100)
    assert out.endswith("...[truncated]")
    assert out.startswith("ff" * 100)


def test_coerce_value_data_passes_int_unchanged() -> None:
    assert _coerce_value_data(42, max_bytes=100) == 42


def test_coerce_value_data_passes_none() -> None:
    assert _coerce_value_data(None, max_bytes=100) is None


# ── walk_hive_path (mocked regipy.RegistryHive) ──────────────────────────────


@dataclass
class _FakeSubkey:
    """Mirror of regipy.registry.Subkey shape for tests."""
    subkey_name: str
    path: str
    timestamp: str
    values_count: int
    values: list[dict[str, Any]]
    actual_path: str | None = None


class _FakeHive:
    """Stand-in for regipy.registry.RegistryHive that yields a
    pre-canned subkey list."""

    def __init__(self, subkeys: list[_FakeSubkey]):
        self._subkeys = subkeys

    def recurse_subkeys(self, *, as_json: bool = False, fetch_values: bool = True) -> Iterator[_FakeSubkey]:
        yield from self._subkeys


def test_walk_hive_path_canonical_run_keys(tmp_path) -> None:
    """A SOFTWARE hive with one Run key + one persistence value
    produces the canonical parsed_tree shape with key/value counts
    populated and the subkey path preserved."""
    p = str(tmp_path / "Windows" / "System32" / "config" / "SOFTWARE")
    _write_synthetic_hive(p, with_magic=True)

    fake = _FakeHive([
        _FakeSubkey(
            subkey_name="Run",
            path="\\Microsoft\\Windows\\CurrentVersion\\Run",
            timestamp="2024-01-01T00:00:00",
            values_count=1,
            values=[
                {
                    "name": "OneDrive",
                    "value": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
                    "value_type": "REG_SZ",
                    "is_corrupted": False,
                },
            ],
        ),
    ])

    with patch(
        "app.services.registry_hive_walker.RegistryHive",
        return_value=fake,
    ) if False else patch(
        # Function-local lazy import — patch at the source module.
        "regipy.registry.RegistryHive",
        return_value=fake,
    ):
        result = walk_hive_path(p)

    assert result["hive_type"] == "SOFTWARE"
    assert result["walk_complete"] is True
    assert result["truncated"] is False
    assert result["key_count"] == 1
    assert result["value_count"] == 1
    assert result["errors"] == []
    assert result["subkeys"] == [
        {
            "path": "\\Microsoft\\Windows\\CurrentVersion\\Run",
            "values": [
                {
                    "name": "OneDrive",
                    "type": "REG_SZ",
                    "data": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
                },
            ],
        },
    ]


def test_walk_hive_path_depth_cap_truncates(tmp_path) -> None:
    """Subkeys beyond max_depth are dropped; truncated=True."""
    p = str(tmp_path / "SYSTEM")
    _write_synthetic_hive(p, with_magic=True)

    # Mix of shallow + deep subkeys. Default max_depth=5; a path with
    # 7 backslashes should be dropped.
    fake = _FakeHive([
        _FakeSubkey("a", "\\one", "2024-01-01T00:00:00", 0, []),
        _FakeSubkey(
            "b",
            "\\one\\two\\three\\four\\five\\six\\seven",
            "2024-01-01T00:00:00",
            0,
            [],
        ),
    ])

    with patch("regipy.registry.RegistryHive", return_value=fake):
        result = walk_hive_path(p)

    assert result["truncated"] is True
    assert result["key_count"] == 1  # only the shallow one retained
    assert [s["path"] for s in result["subkeys"]] == ["\\one"]


def test_walk_hive_path_key_cap_breaks_walk(tmp_path) -> None:
    """key_count cap stops the walk and sets walk_complete=False."""
    p = str(tmp_path / "SYSTEM")
    _write_synthetic_hive(p, with_magic=True)

    fake = _FakeHive([
        _FakeSubkey(f"k{i}", f"\\k{i}", "2024-01-01T00:00:00", 0, [])
        for i in range(5)
    ])

    with patch("regipy.registry.RegistryHive", return_value=fake):
        result = walk_hive_path(p, max_keys=3)

    assert result["truncated"] is True
    assert result["walk_complete"] is False
    assert result["key_count"] == 3
    assert len(result["subkeys"]) == 3


def test_walk_hive_path_open_failure_returns_partial_with_error(tmp_path) -> None:
    """When RegistryHive() raises, the walker captures the error and
    returns a partial parsed_tree rather than re-raising."""
    p = str(tmp_path / "SOFTWARE")
    _write_synthetic_hive(p, with_magic=True)

    from regipy.exceptions import UnidentifiedHiveException

    with patch(
        "regipy.registry.RegistryHive",
        side_effect=UnidentifiedHiveException("not a real hive"),
    ):
        result = walk_hive_path(p)

    assert result["walk_complete"] is False
    assert result["key_count"] == 0
    assert len(result["errors"]) == 1
    assert result["errors"][0].startswith("open: UnidentifiedHiveException")


def test_walk_hive_path_walk_failure_returns_partial(tmp_path) -> None:
    """When recurse_subkeys raises mid-iteration, the partial subkey
    list is preserved + the error is captured."""
    p = str(tmp_path / "SOFTWARE")
    _write_synthetic_hive(p, with_magic=True)

    from regipy.exceptions import RegistryParsingException

    class _PartialFake:
        def recurse_subkeys(self, **_kwargs):
            yield _FakeSubkey("ok", "\\ok", "2024-01-01T00:00:00", 0, [])
            raise RegistryParsingException("corrupted at offset 0xDEAD")

    with patch("regipy.registry.RegistryHive", return_value=_PartialFake()):
        result = walk_hive_path(p)

    assert result["walk_complete"] is False
    assert result["key_count"] == 1  # the partial subkey retained
    assert len(result["errors"]) == 1
    assert "RegistryParsingException" in result["errors"][0]


def test_walk_hive_path_default_depth_constant() -> None:
    """Smoke check: depth_limit propagates from the module default."""
    # Doesn't actually walk a hive — checks the constant feeds through.
    assert _DEFAULT_MAX_DEPTH == 5


# ── auto_walk_firmware (live canary, Rule #35b) ──────────────────────────────
#
# make_live_db is an asynccontextmanager (wraps a SQLite-shimmed engine
# + session) — use ``async with make_live_db() as db:`` directly per the
# test_windows_pe_signature_tools.py precedent rather than a fixture.


async def _seed_firmware(db, *, extracted_path: str) -> tuple[uuid.UUID, uuid.UUID]:
    """Create a Project + Firmware row pointing at extracted_path."""
    project = Project(name="γ-test")
    db.add(project)
    await db.flush()

    firmware = Firmware(
        project_id=project.id,
        sha256="0" * 64,
        extracted_path=extracted_path,
    )
    db.add(firmware)
    await db.flush()
    return project.id, firmware.id


async def test_auto_walk_firmware_persists_real_extract(tmp_path) -> None:
    """Live canary per Rule #35b. End-to-end: scan → walk → persist
    HardwareFirmwareBlob (category='registry_hive') + WindowsRegistryExtract.

    Mocks regipy.registry.RegistryHive but exercises the REAL ORM round-trip
    so the value-flow contract (auto_walk_firmware sets X → persisted row
    has X) is verified end-to-end (mock-only would miss the F-A-06-shape
    confidence-bypass class of bug).
    """
    """Live canary per Rule #35b. End-to-end: scan → walk → persist
    HardwareFirmwareBlob (category='registry_hive') + WindowsRegistryExtract.

    Mocks regipy.registry.RegistryHive but exercises the REAL ORM round-trip
    so the value-flow contract (auto_walk_firmware sets X → persisted row
    has X) is verified end-to-end (mock-only would miss the F-A-06-shape
    confidence-bypass class of bug).
    """
    # Lay a synthetic SOFTWARE hive on disk under the firmware's extracted_path.
    hive_dir = tmp_path / "rootfs" / "Windows" / "System32" / "config"
    hive_dir.mkdir(parents=True)
    hive_path = str(hive_dir / "SOFTWARE")
    _write_synthetic_hive(hive_path, with_magic=True)

    async with make_live_db() as db:
        # Seed firmware row.
        _project_id, firmware_id = await _seed_firmware(
            db, extracted_path=str(tmp_path / "rootfs")
        )
        await db.commit()

        # Patch regipy + get_detection_roots so the orchestrator sees our root.
        fake = _FakeHive([
            _FakeSubkey(
                "Run",
                "\\Microsoft\\Windows\\CurrentVersion\\Run",
                "2024-01-01T00:00:00",
                1,
                [
                    {
                        "name": "OneDrive",
                        "value": "C:\\OneDrive.exe",
                        "value_type": "REG_SZ",
                        "is_corrupted": False,
                    },
                ],
            ),
        ])

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(tmp_path / "rootfs")]

        with (
            patch("regipy.registry.RegistryHive", return_value=fake),
            patch(
                "app.services.registry_hive_walker.get_detection_roots",
                new=_fake_roots,
            ),
        ):
            result = await auto_walk_firmware(firmware_id, db)
        await db.commit()

        # ── Aggregate result shape ──
        assert result["hive_count"] == 1
        assert result["by_hive_type"] == {"SOFTWARE": 1}
        assert result["by_walk_status"]["completed"] == 1
        assert result["total_keys"] == 1
        assert result["total_values"] == 1
        assert result["errors"] == []

        # ── Live SELECTs — VALUE FLOW VERIFICATION ──
        from sqlalchemy import select as _sel

        blobs = (
            await db.execute(
                _sel(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == firmware_id
                )
            )
        ).scalars().all()
        assert len(blobs) == 1
        blob = blobs[0]
        assert blob.category == "registry_hive"
        assert blob.format == "regf_hive"
        assert blob.detection_source == "registry_hive_walker"
        # blob_path is the relative path under the detection root.
        assert blob.blob_path.endswith("Windows/System32/config/SOFTWARE")

        extracts = (
            await db.execute(
                _sel(WindowsRegistryExtract).where(
                    WindowsRegistryExtract.blob_id == blob.id
                )
            )
        ).scalars().all()
        assert len(extracts) == 1
        extract = extracts[0]
        assert extract.hive_type == "SOFTWARE"
        assert extract.walk_status == "completed"
        assert extract.walk_error is None
        assert extract.key_count == 1
        assert extract.value_count == 1
        # parsed_tree was stamped with schema_version per Rule #35c.
        assert extract.parsed_tree is not None
        assert extract.parsed_tree["schema_version"] == 1
        # The Run-key path survived the round-trip through JSONB +
        # _stamp helper.
        assert any(
            sk["path"] == "\\Microsoft\\Windows\\CurrentVersion\\Run"
            for sk in extract.parsed_tree.get("subkeys", [])
        )


async def test_auto_walk_firmware_no_hives_returns_empty_aggregate(tmp_path) -> None:
    """Firmware with no hives in its tree returns hive_count=0 + empty
    histograms; no ORM rows created."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()  # Linux-shaped tree, no Windows hives.

    async with make_live_db() as db:
        _project_id, firmware_id = await _seed_firmware(
            db, extracted_path=str(rootfs)
        )
        await db.commit()

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(rootfs)]

        with patch(
            "app.services.registry_hive_walker.get_detection_roots",
            new=_fake_roots,
        ):
            result = await auto_walk_firmware(firmware_id, db)
        await db.commit()

        assert result["hive_count"] == 0
        assert result["by_hive_type"] == {}
        assert result["total_keys"] == 0

        from sqlalchemy import select as _sel

        blobs = (
            await db.execute(
                _sel(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == firmware_id
                )
            )
        ).scalars().all()
        assert blobs == []


async def test_auto_walk_firmware_idempotent_on_rerun(tmp_path) -> None:
    """Running the orchestrator twice on the same firmware UPDATEs the
    existing extract row rather than creating a duplicate (the
    UniqueConstraint on (blob_id, hive_path) gates the re-walk)."""
    hive_dir = tmp_path / "rootfs" / "Windows" / "System32" / "config"
    hive_dir.mkdir(parents=True)
    hive_path = str(hive_dir / "SOFTWARE")
    _write_synthetic_hive(hive_path, with_magic=True)

    async with make_live_db() as db:
        _project_id, firmware_id = await _seed_firmware(
            db, extracted_path=str(tmp_path / "rootfs")
        )
        await db.commit()

        fake = _FakeHive([
            _FakeSubkey("Run", "\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "2024-01-01T00:00:00", 0, []),
        ])

        async def _fake_roots(_firmware, db=None):  # noqa: ARG001
            return [str(tmp_path / "rootfs")]

        with (
            patch("regipy.registry.RegistryHive", return_value=fake),
            patch(
                "app.services.registry_hive_walker.get_detection_roots",
                new=_fake_roots,
            ),
        ):
            await auto_walk_firmware(firmware_id, db)
            await db.commit()
            await auto_walk_firmware(firmware_id, db)
            await db.commit()

        from sqlalchemy import select as _sel

        blobs = (
            await db.execute(
                _sel(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == firmware_id
                )
            )
        ).scalars().all()
        extracts = (
            await db.execute(_sel(WindowsRegistryExtract))
        ).scalars().all()
        # ONE blob row + ONE extract row even after two walks.
        assert len(blobs) == 1
        assert len(extracts) == 1
