"""Tests for the Phase θ.A.C Windows BCD store walker triplet.

Rule #35b live canary — exercises the inner orchestrator
(``_do_bcd_walk``) against a real test DB via ``make_live_db()``.

regipy requires a REGF-formatted file. Synthesizing one in-process
is heavy (the format has a 4 KB header + hbins + cell pointer
tracking). For tier-1 tests we mock ``regipy.registry.RegistryHive``
and feed it record-shaped fakes (Rule #30 — patch the source module,
not the service). The walker's per-entry extraction helpers,
aggregation math, anomaly classifier, and ORM persistence flow
exercise via these fakes; an integration-test extension against a
real BCD store is deferred to a follow-up.

Covers:
- Pure-function helpers (looks_like_regf / walk_bcd_stores /
  is_regipy_available).
- Element extraction (_safe_element_value / _safe_description_type /
  _parse_application_device_blob / coercion helpers).
- Anomaly classifier (is_microsoft_description /
  is_suspicious_bootloader_path / build_anomaly_flags).
- Inner orchestrator against a real test DB.
- Aggregate math (entries_walked / testsigning_count /
  suspicious_path_count).
- Caps (max_entries / max_custom_elements).
- Defensive boundaries (missing keys, parse failures, missing libs).
"""
from __future__ import annotations

import os
import tempfile
import uuid
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsBcdEntry
from app.services.bcd_walker import (
    ELEM_APPLICATION_DEVICE,
    ELEM_APPLICATION_PATH,
    ELEM_DEFAULT_OBJECT,
    ELEM_DESCRIPTION,
    ELEM_NO_INTEGRITY_CHECKS,
    ELEM_NX_POLICY,
    ELEM_TESTSIGNING,
    REGIPY_UNAVAILABLE,
    _coerce_bool,
    _coerce_custom_element_value,
    _coerce_int,
    _coerce_str,
    _do_bcd_walk,
    _extract_custom_elements,
    _extract_entry_fields,
    _parse_application_device_blob,
    _safe_description_type,
    _safe_element_value,
    build_anomaly_flags,
    is_microsoft_description,
    is_regipy_available,
    is_suspicious_bootloader_path,
    looks_like_regf,
    walk_bcd_stores,
)
from tests._live_db import make_live_db

# ── REGF magic / fixture helpers ─────────────────────────────────────────────


def _make_regf_magic() -> bytes:
    """Return a 4-byte REGF magic for looks_like_regf to recognise."""
    return b"regf"


@contextmanager
def _temp_bcd_store() -> str:
    """Yield a path to a temp file with REGF magic — for tests that
    need a passing magic check without needing a full BCD parse."""
    fd, path = tempfile.mkstemp(prefix="BCD_", dir=None)
    try:
        os.write(fd, _make_regf_magic())
        os.close(fd)
        # Rename to bare 'BCD' so walk_bcd_stores picks it up.
        bcd_path = os.path.join(os.path.dirname(path), "BCD")
        os.rename(path, bcd_path)
        yield bcd_path
    finally:
        try:
            os.unlink(bcd_path)
        except OSError:
            pass


# ── Mock helpers for regipy NKRecord-shaped fakes ────────────────────────────


def _make_fake_element_subkey(value):
    """Return a MagicMock that mimics a subkey under ``Elements`` —
    has a get_value('Element') method returning ``value``."""
    elem = MagicMock()
    elem.get_value.return_value = value
    return elem


def _make_fake_elements_key(elements: dict[int, object]):
    """Return a MagicMock that mimics the ``Elements`` subkey of a
    BCD object. ``elements`` maps int element-type to the element
    value the get_value('Element') call should return.

    Supports:
    - get_subkey('%08X' % type, raise_on_missing=False) → element subkey
    - iter_subkeys() → iterator of element subkeys named by hex type
    - subkey_count property
    """
    elements_key = MagicMock()
    elements_key.subkey_count = len(elements)

    def _get_subkey(name, raise_on_missing=False):
        # name is '%08X' rendered. Match by int.
        try:
            type_int = int(name, 16)
        except (TypeError, ValueError):
            return None
        if type_int in elements:
            return _make_fake_element_subkey(elements[type_int])
        return None

    elements_key.get_subkey.side_effect = _get_subkey

    def _iter_subkeys():
        for type_int, value in elements.items():
            sub = _make_fake_element_subkey(value)
            sub.name = f"{type_int:08X}"
            yield sub

    elements_key.iter_subkeys.side_effect = _iter_subkeys

    return elements_key


def _make_fake_description_key(type_value: int | None):
    """Return a MagicMock that mimics the ``Description`` subkey of a
    BCD object — has a get_value('Type') method returning ``type_value``."""
    desc = MagicMock()
    desc.get_value.return_value = type_value
    return desc


def _make_fake_bcd_object(
    *,
    guid: str,
    description_type: int | None = 0x10200003,
    last_modified: int = 132950000000000000,
    elements: dict[int, object] | None = None,
):
    """Build a fake BCD object NKRecord ready for the walker.

    Supports:
    - .name (the GUID)
    - .header.last_modified
    - .get_subkey('Description'/'Elements', raise_on_missing=False)
    """
    obj = MagicMock()
    obj.name = guid
    obj.header.last_modified = last_modified

    description_key = (
        _make_fake_description_key(description_type)
        if description_type is not None
        else None
    )
    elements_key = _make_fake_elements_key(elements or {})

    def _get_subkey(name, raise_on_missing=False):
        if name == "Description":
            return description_key
        if name == "Elements":
            return elements_key
        return None

    obj.get_subkey.side_effect = _get_subkey
    return obj


class _FakeHive:
    """Minimal RegistryHive stand-in. Supports
    ``hive.get_key('\\Objects')`` returning an objects_key whose
    iter_subkeys() yields the provided objects, AND default-boot
    GUID resolution via the bootmgr GUID lookup."""

    def __init__(self, objects: list, default_boot_guid: str | None = None):
        self._objects = objects
        self._default_boot_guid = default_boot_guid

    def get_key(self, path):
        if path != r"\Objects":
            return None

        # Build an objects_key that supports iter_subkeys() over the
        # provided objects AND get_subkey('{bootmgr-guid}') for the
        # default-boot lookup.
        objects_key = MagicMock()

        def _iter_subkeys():
            yield from self._objects

        objects_key.iter_subkeys.side_effect = _iter_subkeys

        def _get_subkey(name, raise_on_missing=False):
            # Look for the bootmgr object — well-known GUID.
            if (
                name == "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"
                and self._default_boot_guid is not None
            ):
                # Synthesize a bootmgr object with DefaultObject element.
                bootmgr_elements = {
                    ELEM_DEFAULT_OBJECT: self._default_boot_guid,
                }
                return _make_fake_bcd_object(
                    guid="{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
                    elements=bootmgr_elements,
                )
            return None

        objects_key.get_subkey.side_effect = _get_subkey
        return objects_key


def _patch_registry_hive(objects: list, default_boot_guid: str | None = None):
    """Patch regipy.registry.RegistryHive to return a _FakeHive."""
    fake = _FakeHive(objects, default_boot_guid=default_boot_guid)
    return patch(
        "regipy.registry.RegistryHive", return_value=fake
    )


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    """Centralised Firmware factory (mirror η.A.C pattern)."""
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── Helper-function tests ────────────────────────────────────────────────────


def test_is_regipy_available_true():
    """dep installed in dev venv."""
    assert is_regipy_available() is True


def test_looks_like_regf_with_magic():
    """Magic check passes on REGF magic."""
    with _temp_bcd_store() as path:
        assert looks_like_regf(path) is True


def test_looks_like_regf_with_zero_bytes():
    """Magic check fails on all-zero file."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fp:
        fp.write(b"\x00" * 512)
        path = fp.name
    try:
        assert looks_like_regf(path) is False
    finally:
        os.unlink(path)


def test_looks_like_regf_on_missing_file():
    """OSError → False (defensive boundary)."""
    assert looks_like_regf("/nonexistent/path/BCD") is False


def test_walk_bcd_stores_finds_bare_BCD_filename():
    """Walker enumerates files named exactly 'BCD' (case-insensitive)."""
    with tempfile.TemporaryDirectory() as root:
        # Create BCD candidates with different casings
        for name in ("BCD", "bcd"):
            d = os.path.join(root, f"sub_{name}")
            os.makedirs(d)
            with open(os.path.join(d, name), "wb") as fp:  # noqa: ASYNC230 — test fixture: seed BCD file candidates; sync open acceptable
                fp.write(b"\x00")
        # Non-candidate
        with open(os.path.join(root, "BCD.LOG"), "wb") as fp:  # noqa: ASYNC230 — test fixture: seed non-BCD file; sync open acceptable
            fp.write(b"hello")
        with open(os.path.join(root, "notes.txt"), "wb") as fp:  # noqa: ASYNC230 — test fixture: seed non-BCD file; sync open acceptable
            fp.write(b"hello")

        hits = walk_bcd_stores([root])
        # 2 BCD candidates (BCD + bcd); 0 non-candidates
        assert len(hits) == 2


def test_walk_bcd_stores_handles_missing_root_gracefully():
    """Non-existent detection root returns empty list, no raise."""
    hits = walk_bcd_stores(["/nonexistent/dir/path"])
    assert hits == []


def test_walk_bcd_stores_handles_mixed_roots():
    """One valid + one missing root: returns valid-root hits only."""
    with tempfile.TemporaryDirectory() as good_root:
        with open(os.path.join(good_root, "BCD"), "wb") as fp:  # noqa: ASYNC230 — test fixture: seed BCD file candidate; sync open acceptable
            fp.write(b"\x00")
        hits = walk_bcd_stores([good_root, "/missing"])
        assert len(hits) == 1


# ── Element value coercion tests ─────────────────────────────────────────────


def test_coerce_str_preserves_strings():
    assert _coerce_str("hello") == "hello"
    assert _coerce_str("padded\x00") == "padded"


def test_coerce_str_handles_bytes():
    """UTF-16 LE bytes decode."""
    # "BCD" in UTF-16 LE
    raw = "BCD".encode("utf-16-le")
    assert _coerce_str(raw) == "BCD"


def test_coerce_str_none():
    assert _coerce_str(None) is None


def test_coerce_bool_handles_byte_payloads():
    """BCD boolean elements typically arrive as \\x01 or \\x00 bytes."""
    assert _coerce_bool(b"\x01") is True
    assert _coerce_bool(b"\x00") is False
    assert _coerce_bool(True) is True
    assert _coerce_bool(False) is False
    assert _coerce_bool(1) is True
    assert _coerce_bool(0) is False
    assert _coerce_bool(None) is None
    assert _coerce_bool("Yes") is True
    assert _coerce_bool("no") is False


def test_coerce_int_handles_dword():
    """BCD DWORD elements may arrive as int or little-endian bytes."""
    assert _coerce_int(42) == 42
    assert _coerce_int(b"\x02\x00\x00\x00") == 2  # NxPolicy AlwaysOff
    assert _coerce_int(None) is None
    assert _coerce_int("0x10") == 16


def test_coerce_custom_element_handles_list():
    """DisplayOrder element 0x14000006 arrives as list of GUID strings."""
    out = _coerce_custom_element_value(["{guid-1}", "{guid-2}"])
    assert out == ["{guid-1}", "{guid-2}"]


def test_coerce_custom_element_handles_unprintable_bytes():
    """Unprintable bytes → hex rendering."""
    raw = b"\xff\xff\x00\x01"
    out = _coerce_custom_element_value(raw)
    assert isinstance(out, str)


def test_parse_application_device_blob_short():
    """Blob shorter than 72 bytes → (None, None)."""
    assert _parse_application_device_blob(b"") == (None, None)
    assert _parse_application_device_blob(b"\x00" * 10) == (None, None)


def test_parse_application_device_blob_canonical():
    """Canonical 72-byte ApplicationDevice blob yields both GUIDs."""
    # Build a synthetic blob with recognizable UUIDs at the right offsets
    blob = bytearray(72)
    partition_uuid = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
    disk_uuid = uuid.UUID("1b1de4d3-9ec8-4f00-86f3-d2e5e2e0e4f1")
    blob[32:48] = partition_uuid.bytes_le
    blob[56:72] = disk_uuid.bytes_le
    pg, dg = _parse_application_device_blob(bytes(blob))
    assert pg == "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"
    assert dg == "{1b1de4d3-9ec8-4f00-86f3-d2e5e2e0e4f1}"


# ── Anomaly classifier tests ─────────────────────────────────────────────────


def test_is_microsoft_description_recognises_windows():
    assert is_microsoft_description("Windows 10") is True
    assert is_microsoft_description("Windows Boot Manager") is True
    assert is_microsoft_description("Microsoft Windows Recovery Environment") is True
    assert is_microsoft_description("Memory Diagnostic") is True


def test_is_microsoft_description_rejects_third_party():
    assert is_microsoft_description("Ubuntu") is False
    assert is_microsoft_description("Adversary Bootkit") is False
    assert is_microsoft_description("") is False
    assert is_microsoft_description(None) is False


def test_is_suspicious_bootloader_path_recognises_known_good():
    """Known-good prefixes → not suspicious."""
    assert is_suspicious_bootloader_path("\\Windows\\System32\\winload.efi") is False
    assert is_suspicious_bootloader_path("\\Boot\\BCD") is False
    assert is_suspicious_bootloader_path("\\EFI\\Microsoft\\Boot\\bootmgfw.efi") is False
    # Case-insensitive
    assert is_suspicious_bootloader_path("\\windows\\system32\\winload.efi") is False


def test_is_suspicious_bootloader_path_flags_unknown():
    """Paths outside known-good prefixes are suspicious."""
    assert is_suspicious_bootloader_path("\\Users\\Public\\evil.efi") is True
    assert is_suspicious_bootloader_path("\\Tmp\\rootkit.bin") is True


def test_is_suspicious_bootloader_path_handles_null():
    """NULL path → not suspicious (some entries legitimately have no path)."""
    assert is_suspicious_bootloader_path(None) is False
    assert is_suspicious_bootloader_path("") is False


def test_build_anomaly_flags_full_clean():
    """A healthy bootloader entry produces all-False anomaly flags."""
    flags = build_anomaly_flags(
        description="Windows 10",
        image_path="\\Windows\\System32\\winload.efi",
        testsigning=False,
        no_integrity_checks=False,
        nx_policy=0,  # OptIn
        is_default_boot=True,
    )
    assert flags["suspicious_path"] is False
    assert flags["non_microsoft_description"] is False
    assert flags["testsigning_enabled"] is False
    assert flags["no_integrity_checks"] is False
    assert flags["nx_disabled"] is False
    assert flags["is_default_boot"] is True


def test_build_anomaly_flags_full_dirty():
    """A bootkit-shape entry raises all anomaly flags."""
    flags = build_anomaly_flags(
        description="Adversary Bootkit",
        image_path="\\Users\\Public\\evil.efi",
        testsigning=True,
        no_integrity_checks=True,
        nx_policy=2,  # AlwaysOff
        is_default_boot=False,
    )
    assert flags["suspicious_path"] is True
    assert flags["non_microsoft_description"] is True
    assert flags["testsigning_enabled"] is True
    assert flags["no_integrity_checks"] is True
    assert flags["nx_disabled"] is True
    assert flags["is_default_boot"] is False


# ── _extract_entry_fields tests ──────────────────────────────────────────────


def test_extract_entry_fields_full_complement():
    """An object with all canonical elements yields full fields."""
    # Build an ApplicationDevice blob.
    blob = bytearray(72)
    partition_uuid = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
    disk_uuid = uuid.UUID("1b1de4d3-9ec8-4f00-86f3-d2e5e2e0e4f1")
    blob[32:48] = partition_uuid.bytes_le
    blob[56:72] = disk_uuid.bytes_le

    obj = _make_fake_bcd_object(
        guid="{deadbeef-1234-5678-9abc-def012345678}",
        description_type=0x10200003,
        elements={
            ELEM_DESCRIPTION: "Windows 10",
            ELEM_APPLICATION_PATH: "\\Windows\\System32\\winload.efi",
            ELEM_APPLICATION_DEVICE: bytes(blob),
            ELEM_TESTSIGNING: b"\x00",
            ELEM_NO_INTEGRITY_CHECKS: b"\x00",
            ELEM_NX_POLICY: b"\x00\x00\x00\x00",
        },
    )
    fields = _extract_entry_fields(obj)
    assert fields["object_guid"] == "{deadbeef-1234-5678-9abc-def012345678}"
    assert fields["object_type"] == 0x10200003
    assert fields["description"] == "Windows 10"
    assert fields["image_path"] == "\\Windows\\System32\\winload.efi"
    assert fields["gpt_partition_guid"] == "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"
    assert fields["gpt_disk_guid"] == "{1b1de4d3-9ec8-4f00-86f3-d2e5e2e0e4f1}"
    assert fields["testsigning"] is False
    assert fields["no_integrity_checks"] is False
    assert fields["nx_policy"] == 0


def test_extract_entry_fields_minimal_object():
    """An object with no elements still yields object_guid."""
    obj = _make_fake_bcd_object(
        guid="{a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba}",
        description_type=None,
        elements={},
    )
    fields = _extract_entry_fields(obj)
    assert fields["object_guid"] == "{a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba}"
    assert fields["description"] is None
    assert fields["image_path"] is None


def test_extract_custom_elements_skips_flat_promoted():
    """Elements promoted to flat columns are NOT included in custom_elements."""
    obj = _make_fake_bcd_object(
        guid="{guid}",
        elements={
            ELEM_DESCRIPTION: "Windows",       # flat
            ELEM_APPLICATION_PATH: "\\path",   # flat
            0x14000006: ["{a}", "{b}"],        # NOT flat (DisplayOrder)
        },
    )
    custom = _extract_custom_elements(obj, max_elements=100)
    types = {e["element_type"] for e in custom}
    assert "0x14000006" in types
    assert "0x12000004" not in types  # Description is flat
    assert "0x12000002" not in types  # ApplicationPath is flat


# ── REGIPY_UNAVAILABLE shape ─────────────────────────────────────────────────


def test_regipy_unavailable_shape():
    """Module-level UNAVAILABLE constant carries the documented keys."""
    assert REGIPY_UNAVAILABLE["status"] == "unavailable"
    assert "not installed" in REGIPY_UNAVAILABLE["reason"]
    assert REGIPY_UNAVAILABLE["entries"] == 0


# ── _safe_element_value defensive boundaries ─────────────────────────────────


def test_safe_element_value_handles_missing_elements_key():
    """Object with no Elements subkey → returns None."""
    obj = MagicMock()
    obj.get_subkey.return_value = None
    assert _safe_element_value(obj, ELEM_DESCRIPTION) is None


def test_safe_element_value_handles_empty_elements_key():
    """Elements subkey present but empty → returns None."""
    obj = _make_fake_bcd_object(guid="{guid}", elements={})
    assert _safe_element_value(obj, ELEM_DESCRIPTION) is None


def test_safe_description_type_missing():
    """Object with no Description subkey → returns None."""
    obj = _make_fake_bcd_object(
        guid="{guid}", description_type=None, elements={}
    )
    assert _safe_description_type(obj) is None


# ── Inner orchestrator live-canary tests ─────────────────────────────────────


@pytest.mark.asyncio
async def test_do_bcd_walk_no_detection_roots():
    """No detection roots → empty result aggregate, no rows persisted."""
    async with make_live_db() as db:
        project = Project(name="θ.A.C empty roots")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-empty.bin", "e")
        db.add(firmware)
        await db.flush()

        with patch(
            "app.services.bcd_walker.get_detection_roots",
            return_value=[],
        ):
            result = await _do_bcd_walk(db, firmware.id)

        assert result["stores_scanned"] == 0
        assert result["entries_walked"] == 0
        assert result["entries_persisted"] == 0
        assert result["per_store"] == []


@pytest.mark.asyncio
async def test_do_bcd_walk_no_store_candidates():
    """Detection root exists but no BCD candidates → empty aggregate."""
    async with make_live_db() as db:
        project = Project(name="θ.A.C no candidates")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-noc.bin", "n")
        db.add(firmware)
        await db.flush()

        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "notes.txt"), "wb") as fp:  # noqa: ASYNC230 — test fixture: seed non-BCD file; sync open acceptable
                fp.write(b"hello")

            with patch(
                "app.services.bcd_walker.get_detection_roots",
                return_value=[root],
            ):
                result = await _do_bcd_walk(db, firmware.id)

        assert result["stores_scanned"] == 0


@pytest.mark.asyncio
async def test_do_bcd_walk_store_not_regf():
    """BCD candidate without REGF magic → status=not_regf."""
    async with make_live_db() as db:
        project = Project(name="θ.A.C not regf")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-notregf.bin", "x")
        db.add(firmware)
        await db.flush()

        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "BCD")
            with open(path, "wb") as fp:  # noqa: ASYNC230 — test fixture: seed non-REGF file; sync open acceptable
                fp.write(b"\x00" * 4096)  # No REGF magic

            with patch(
                "app.services.bcd_walker.get_detection_roots",
                return_value=[root],
            ):
                result = await _do_bcd_walk(db, firmware.id)

        assert result["stores_scanned"] == 1
        assert len(result["per_store"]) == 1
        assert result["per_store"][0]["status"] == "not_regf"


@pytest.mark.asyncio
async def test_do_bcd_walk_persists_entries_for_synthetic_store():
    """Valid REGF magic + mocked RegistryHive yielding 3 object fakes
    → 3 WindowsBcdEntry rows persisted."""
    async with make_live_db() as db:
        project = Project(name="θ.A.C live canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-real.bin", "r")
        db.add(firmware)
        await db.flush()

        # Build 3 boot entries:
        # - {bootmgr}: well-known, default boot lookup target
        # - default OS entry: clean Windows 10 image
        # - bootkit: testsigning enabled + suspicious path
        bootmgr_obj = _make_fake_bcd_object(
            guid="{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
            description_type=0x10100002,
            elements={
                ELEM_DESCRIPTION: "Windows Boot Manager",
                ELEM_APPLICATION_PATH: "\\bootmgr",
                ELEM_DEFAULT_OBJECT: "{12345678-1234-1234-1234-123456789abc}",
            },
        )

        win_obj = _make_fake_bcd_object(
            guid="{12345678-1234-1234-1234-123456789abc}",
            description_type=0x10200003,
            elements={
                ELEM_DESCRIPTION: "Windows 10",
                ELEM_APPLICATION_PATH: "\\Windows\\System32\\winload.efi",
                ELEM_TESTSIGNING: b"\x00",
                ELEM_NO_INTEGRITY_CHECKS: b"\x00",
                ELEM_NX_POLICY: b"\x00\x00\x00\x00",
            },
        )

        bootkit_obj = _make_fake_bcd_object(
            guid="{deadbeef-1234-5678-9abc-def012345678}",
            description_type=0x10200003,
            elements={
                ELEM_DESCRIPTION: "Adversary Bootkit",
                ELEM_APPLICATION_PATH: "\\Users\\Public\\evil.efi",
                ELEM_TESTSIGNING: b"\x01",
                ELEM_NO_INTEGRITY_CHECKS: b"\x01",
                ELEM_NX_POLICY: b"\x02\x00\x00\x00",  # AlwaysOff
            },
        )

        with tempfile.TemporaryDirectory() as root:
            store_path = os.path.join(root, "BCD")
            with open(store_path, "wb") as fp:  # noqa: ASYNC230 — test fixture: seed minimal REGF header for walker test; sync open acceptable
                fp.write(_make_regf_magic())

            with patch(
                "app.services.bcd_walker.get_detection_roots",
                return_value=[root],
            ), _patch_registry_hive(
                [bootmgr_obj, win_obj, bootkit_obj],
                default_boot_guid="{12345678-1234-1234-1234-123456789abc}",
            ):
                result = await _do_bcd_walk(db, firmware.id)

        await db.commit()

        # Aggregate counters
        assert result["stores_scanned"] == 1
        assert result["entries_walked"] == 3
        assert result["entries_persisted"] == 3
        # bootkit: testsigning + suspicious_path + non_microsoft + no_integrity + nx_disabled
        # bootmgr: ApplicationPath=\bootmgr is known-good
        # win: clean
        assert result["testsigning_count"] == 1  # bootkit only
        assert result["suspicious_path_count"] == 1  # bootkit only
        assert result["non_microsoft_description_count"] == 1  # bootkit only
        assert result["anomaly_total"] == 1  # bootkit fires multiple anomaly flags

        # Persisted rows
        rows = (
            await db.execute(
                select(WindowsBcdEntry).where(
                    WindowsBcdEntry.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 3

        guids = {r.object_guid for r in rows}
        assert "{9dea862c-5cdd-4e70-acc1-f32b344d4795}" in guids
        assert "{12345678-1234-1234-1234-123456789abc}" in guids
        assert "{deadbeef-1234-5678-9abc-def012345678}" in guids

        # Rule #35b live canary: confirm bootkit row's anomaly_flags
        # persist with full shape so the θ.A.D classifier can re-derive
        # the verdict from the row.
        bk_row = next(
            r for r in rows
            if r.object_guid == "{deadbeef-1234-5678-9abc-def012345678}"
        )
        assert bk_row.testsigning is True
        assert bk_row.no_integrity_checks is True
        assert bk_row.nx_policy == 2
        assert bk_row.anomaly_flags is not None
        assert bk_row.anomaly_flags["testsigning_enabled"] is True
        assert bk_row.anomaly_flags["suspicious_path"] is True
        assert bk_row.anomaly_flags["non_microsoft_description"] is True

        # Default-boot lookup wired correctly.
        win_row = next(
            r for r in rows
            if r.object_guid == "{12345678-1234-1234-1234-123456789abc}"
        )
        assert win_row.anomaly_flags["is_default_boot"] is True


@pytest.mark.asyncio
async def test_do_bcd_walk_caps_persisted_entries():
    """entries_walked > max_entries → caps entries_persisted but
    continues iterating for aggregate counters."""
    async with make_live_db() as db:
        project = Project(name="θ.A.C cap test")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-cap.bin", "c")
        db.add(firmware)
        await db.flush()

        # Build 6 minimal entries; cap walker at 3 persisted.
        entries = [
            _make_fake_bcd_object(
                guid=f"{{guid-cap-{i:08x}-0000-0000-0000-000000000000}}",
                elements={
                    ELEM_DESCRIPTION: f"Entry {i}",
                    ELEM_APPLICATION_PATH: f"\\Windows\\image{i}.efi",
                },
            )
            for i in range(6)
        ]

        with tempfile.TemporaryDirectory() as root:
            store_path = os.path.join(root, "BCD")
            with open(store_path, "wb") as fp:  # noqa: ASYNC230 — test fixture: seed minimal REGF header for walker test; sync open acceptable
                fp.write(_make_regf_magic())

            with patch(
                "app.services.bcd_walker.get_detection_roots",
                return_value=[root],
            ), _patch_registry_hive(entries):
                result = await _do_bcd_walk(db, firmware.id, max_entries=3)

        # Walked all 6, persisted only 3.
        assert result["entries_walked"] == 6
        assert result["entries_persisted"] == 3


@pytest.mark.asyncio
async def test_do_bcd_walk_handles_no_objects_key():
    """Hive without ``\\Objects`` key → status=error per-store."""
    async with make_live_db() as db:
        project = Project(name="θ.A.C no objects")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-noobj.bin", "o")
        db.add(firmware)
        await db.flush()

        # Build a hive that returns None for get_key('\\Objects').
        hive = MagicMock()
        hive.get_key.return_value = None

        with tempfile.TemporaryDirectory() as root:
            store_path = os.path.join(root, "BCD")
            with open(store_path, "wb") as fp:  # noqa: ASYNC230 — test fixture: seed minimal REGF header for walker test; sync open acceptable
                fp.write(_make_regf_magic())

            with patch(
                "app.services.bcd_walker.get_detection_roots",
                return_value=[root],
            ), patch(
                "regipy.registry.RegistryHive",
                return_value=hive,
            ):
                result = await _do_bcd_walk(db, firmware.id)

        await db.commit()
        assert result["stores_scanned"] == 1
        assert result["per_store"][0]["status"] == "error"
        assert "Objects" in (result["per_store"][0]["error"] or "")


@pytest.mark.asyncio
async def test_do_bcd_walk_handles_parser_exception():
    """RegistryHive constructor raising → status=error, walk continues."""
    async with make_live_db() as db:
        project = Project(name="θ.A.C parse error")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-perr.bin", "p")
        db.add(firmware)
        await db.flush()

        with tempfile.TemporaryDirectory() as root:
            store_path = os.path.join(root, "BCD")
            with open(store_path, "wb") as fp:  # noqa: ASYNC230 — test fixture: seed minimal REGF header for walker test; sync open acceptable
                fp.write(_make_regf_magic())

            with patch(
                "app.services.bcd_walker.get_detection_roots",
                return_value=[root],
            ), patch(
                "regipy.registry.RegistryHive",
                side_effect=Exception("synthetic parse fail"),
            ):
                result = await _do_bcd_walk(db, firmware.id)

        assert result["stores_scanned"] == 1
        assert result["per_store"][0]["status"] == "error"
        assert "synthetic" in (result["per_store"][0]["error"] or "")


@pytest.mark.asyncio
async def test_do_bcd_walk_skips_objects_with_no_guid():
    """An object whose .name is None / empty is skipped (no row written)."""
    async with make_live_db() as db:
        project = Project(name="θ.A.C no-guid skip")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-skip.bin", "k")
        db.add(firmware)
        await db.flush()

        # Build an object whose .name is empty
        bad_obj = _make_fake_bcd_object(guid="", elements={})
        good_obj = _make_fake_bcd_object(
            guid="{guid-good}",
            elements={ELEM_DESCRIPTION: "Windows"},
        )

        with tempfile.TemporaryDirectory() as root:
            store_path = os.path.join(root, "BCD")
            with open(store_path, "wb") as fp:  # noqa: ASYNC230 — test fixture: seed minimal REGF header for walker test; sync open acceptable
                fp.write(_make_regf_magic())

            with patch(
                "app.services.bcd_walker.get_detection_roots",
                return_value=[root],
            ), _patch_registry_hive([bad_obj, good_obj]):
                result = await _do_bcd_walk(db, firmware.id)

        # Both walked but only good is persisted (no_guid skipped).
        assert result["entries_walked"] == 2
        assert result["entries_persisted"] == 1
