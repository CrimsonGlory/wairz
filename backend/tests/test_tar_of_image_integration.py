"""Integration tests for tar/zip uploads that wrap raw filesystem images.

Guards the Eaton Network M3 regression end-to-end: a vendor tarball
containing ``{EULA, manifest.json, .data_img(FAT16)}`` must NOT be
silently classified as "rootfs" by the upload-time shortcut. It must
fall through to the terminal path so the user's ``POST /unpack`` call
eventually hands the file to unblob, which can extract the FAT16
filesystem.

Strategy:
    - Build a minimal FAT16 stub via ``_make_fat16_stub``.
    - Pack it into a real ``.tar`` or ``.zip`` alongside text metadata.
    - Invoke ``FirmwareService.create_firmware`` with a mock upload.
    - Assert ``unpack_log`` does NOT contain a rootfs-shortcut marker
      for the image case (Rule #47 — the walker-bridge fix in commit
      ``5f3d195`` decoupled ``extracted_path`` from rootfs classification
      so the old ``extracted_path is None`` proxy is no longer valid),
      AND ``unpack_log`` DOES contain a marker for the pure-rootfs-tar
      control case.

Scenarios:
    1. Tar-of-FAT-image (Eaton shape) → rootfs shortcut must NOT fire.
    2. Tar-of-pure-rootfs (ADB-dump shape with etc/, usr/, bin/)
       → rootfs shortcut fires + ``extracted_path`` set AND
       detection_roots populated (Rule #16).
    3. Zip-of-FAT-image (latent defect, parallel of #1) → rootfs
       shortcut must NOT fire.
"""
from __future__ import annotations

import io
import os
import tarfile
import uuid
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.firmware_service import FirmwareService


def _make_fat16_stub_bytes(size_kb: int = 8) -> bytes:
    buf = bytearray(size_kb * 1024)
    buf[54:62] = b"FAT16   "
    buf[510:512] = b"\x55\xaa"
    return bytes(buf)


def _make_rootfs_tar(path: Path) -> None:
    """Build a pure-rootfs tar: etc/ + usr/ + bin/ dirs + a couple files."""
    with tarfile.open(path, "w") as tf:
        # etc/ with one file
        etc_data = b"root:x:0:0::/:/bin/sh\n"
        ti = tarfile.TarInfo("etc/passwd")
        ti.size = len(etc_data)
        tf.addfile(ti, io.BytesIO(etc_data))
        # usr/ with one stub file
        stub_data = b"#!/bin/sh\n"
        ti2 = tarfile.TarInfo("usr/bin/true")
        ti2.size = len(stub_data)
        ti2.mode = 0o755
        tf.addfile(ti2, io.BytesIO(stub_data))
        # bin/ stub
        ti3 = tarfile.TarInfo("bin/sh")
        ti3.size = len(stub_data)
        ti3.mode = 0o755
        tf.addfile(ti3, io.BytesIO(stub_data))


def _make_tar_of_image(path: Path) -> None:
    """Build an Eaton-shape tar: EULA + manifest.json + .data_img(FAT16)."""
    fat_bytes = _make_fat16_stub_bytes()
    eula_bytes = b"END USER LICENSE AGREEMENT ... " * 16
    manifest_bytes = b'{"vendor": "TestVendor", "version": "1.0.0"}'

    with tarfile.open(path, "w") as tf:
        ti = tarfile.TarInfo("EULA")
        ti.size = len(eula_bytes)
        tf.addfile(ti, io.BytesIO(eula_bytes))
        ti2 = tarfile.TarInfo("manifest.json")
        ti2.size = len(manifest_bytes)
        tf.addfile(ti2, io.BytesIO(manifest_bytes))
        ti3 = tarfile.TarInfo(".data_img")
        ti3.size = len(fat_bytes)
        tf.addfile(ti3, io.BytesIO(fat_bytes))


def _make_zip_of_image(path: Path) -> None:
    """Zip variant of the above (Eaton-shape in a ZIP wrapper)."""
    fat_bytes = _make_fat16_stub_bytes()
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("EULA", b"LICENCE" * 32)
        zf.writestr("manifest.json", b'{"v":"1"}')
        zf.writestr("payload.img", fat_bytes)


def _mock_upload(path: Path, filename: str):
    """Build a FastAPI UploadFile-like mock that streams from a real file."""
    fake = MagicMock()
    fake.filename = filename
    fake.size = path.stat().st_size

    with open(path, "rb") as f:
        content = f.read()

    # read() returns progressively smaller chunks until empty
    offset = [0]

    async def _read(size: int = -1):
        if offset[0] >= len(content):
            return b""
        if size < 0:
            chunk = content[offset[0]:]
            offset[0] = len(content)
        else:
            chunk = content[offset[0]:offset[0] + size]
            offset[0] += len(chunk)
        return chunk

    fake.read = _read
    return fake


def _mock_db_no_duplicates() -> AsyncMock:
    """Build an ``AsyncSession``-shaped mock whose ``db.execute(...)``
    returns a result whose ``scalar_one_or_none()`` is ``None``.

    Required because ``FirmwareService.upload`` issues a same-content
    reupload guard (firmware_service.py:362-381 — ``SELECT Firmware.id
    WHERE project_id == ? AND sha256 == ?``) and a bare ``AsyncMock()``
    returns a non-None ``MagicMock`` from the chained ``.scalar_one_or_none()``,
    which the service interprets as "duplicate exists" → 409.
    """
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    no_match_result = MagicMock()
    no_match_result.scalar_one_or_none = MagicMock(return_value=None)
    db.execute = AsyncMock(return_value=no_match_result)
    return db


def _make_settings(storage_root: Path):
    s = MagicMock()
    s.storage_root = str(storage_root)
    s.max_upload_size_mb = 2048
    return s


# Substrings that ``firmware_service`` writes into ``firmware.unpack_log``
# when the upload-time rootfs shortcut classifies the upload as a rootfs.
# See ``firmware_service.py:603`` (tar shortcut) and ``:650`` (zip shortcut).
# The walker-bridge fix in commit 5f3d195 made ``extracted_path`` get set
# even for non-rootfs ZIPs (so walkers can fire over arbitrary extractions),
# so we discriminate on this log marker instead of on ``extracted_path``.
_ROOTFS_SHORTCUT_MARKERS = (
    "Rootfs ZIP detected",
    "Tarball detected; extracted directly as rootfs",
)


def _rootfs_shortcut_fired(firmware) -> bool:
    """True iff the upload-time rootfs auto-classifier fired."""
    log = firmware.unpack_log or ""
    return any(marker in log for marker in _ROOTFS_SHORTCUT_MARKERS)


@pytest.mark.asyncio
async def test_tar_of_fat_image_does_not_shortcut(tmp_path: Path):
    """Eaton-shape tar must fall through the shortcut — extracted_path None."""
    storage_root = tmp_path / "storage"
    storage_root.mkdir()
    tar_path = tmp_path / "vendor.tar"
    _make_tar_of_image(tar_path)

    db = _mock_db_no_duplicates()

    svc = FirmwareService(db)
    with patch("app.services.firmware_service.get_settings", return_value=_make_settings(storage_root)):
        upload = _mock_upload(tar_path, "vendor.tar")
        firmware = await svc.upload(
            project_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            file=upload,
        )

    # Eaton-shape: the rootfs auto-classifier must NOT have fired. Before
    # commit 5f3d195 the cleanest proxy was ``extracted_path is None``;
    # after the walker-bridge fix that proxy is no longer reliable because
    # the generic-fallback path also sets ``extracted_path`` so walkers
    # can fire. Use the unpack_log marker as the durable discriminator.
    assert not _rootfs_shortcut_fired(firmware), (
        f"tar containing a raw FS image was falsely classified as rootfs: "
        f"unpack_log={firmware.unpack_log!r}"
    )


@pytest.mark.asyncio
async def test_zip_of_fat_image_does_not_shortcut(tmp_path: Path):
    """Parallel case — zip-rootfs shortcut must also fall through."""
    storage_root = tmp_path / "storage"
    storage_root.mkdir()
    zip_path = tmp_path / "vendor.zip"
    _make_zip_of_image(zip_path)

    db = _mock_db_no_duplicates()

    svc = FirmwareService(db)
    with patch("app.services.firmware_service.get_settings", return_value=_make_settings(storage_root)):
        upload = _mock_upload(zip_path, "vendor.zip")
        firmware = await svc.upload(
            project_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            file=upload,
        )

    # Same Rule #47 discriminator as the tar variant — see the
    # ``test_tar_of_fat_image_does_not_shortcut`` comment for rationale.
    assert not _rootfs_shortcut_fired(firmware), (
        f"zip containing a raw FS image was falsely classified as rootfs: "
        f"unpack_log={firmware.unpack_log!r}"
    )


@pytest.mark.asyncio
async def test_pure_rootfs_tar_still_shortcuts_with_detection_roots(tmp_path: Path):
    """Control: ADB-dump shape still hits the shortcut AND gets detection_roots."""
    storage_root = tmp_path / "storage"
    storage_root.mkdir()
    tar_path = tmp_path / "device_dump.tar"
    _make_rootfs_tar(tar_path)

    db = _mock_db_no_duplicates()

    svc = FirmwareService(db)
    with patch("app.services.firmware_service.get_settings", return_value=_make_settings(storage_root)):
        upload = _mock_upload(tar_path, "device_dump.tar")
        firmware = await svc.upload(
            project_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            file=upload,
        )

    # Pure rootfs: the rootfs auto-classifier fires, extracted_path is set.
    # Check the unpack_log marker directly (post-Rule #47, ``extracted_path``
    # alone is no longer sufficient to prove the shortcut fired vs the
    # generic-ZIP fallback).
    assert _rootfs_shortcut_fired(firmware), (
        f"pure rootfs tar failed to classify via the shortcut: "
        f"unpack_log={firmware.unpack_log!r}"
    )
    assert firmware.extracted_path is not None, (
        "pure rootfs tar set unpack_log marker but extracted_path remained None"
    )
    # Rule #16: detection_roots must be populated inline.
    meta = firmware.device_metadata or {}
    roots = meta.get("detection_roots")
    assert isinstance(roots, list) and len(roots) >= 1, (
        f"detection_roots not populated on shortcut path: meta={meta!r}"
    )
    # Every root must be a string path that exists on disk.
    for r in roots:
        assert isinstance(r, str)
        assert os.path.isdir(r), f"detection_root does not exist: {r}"  # noqa: ASYNC240 — test assertion: verify every detection_root path exists on disk; sync stat acceptable
