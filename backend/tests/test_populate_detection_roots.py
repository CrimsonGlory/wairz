"""Contract tests for populate_detection_roots — the canonical
detection_roots writer shared by every extraction code path.

Guards the session b3a3b580 architectural robustness fix: before this
helper existed, three separate code paths hand-rolled the same
_compute_roots_sync + dedup-merge + _persist_roots sequence, and each
site had subtly different semantics (e.g. the .zip generic path
omitted detection_roots entirely; the vendor-decrypt merge dropped
the primary root). Consolidating to one writer eliminates that class
of divergence.

Scenarios:
    - Empty extracted_path → no-op, returns [].
    - Plain rootfs → roots include the extraction root.
    - Extra roots (vendor decrypt outputs) → merged dedup'd.
    - Extra root that duplicates primary root → dedup'd out.
    - Extra root that doesn't exist on disk → filtered.
    - Realpath dedup: symlinks pointing at the same realpath collapse.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from app.services.firmware_paths import populate_detection_roots


@dataclass
class _FakeFirmware:
    """Enough shape to satisfy the helper without touching the DB."""
    extracted_path: str | None = None
    device_metadata: dict | None = None


def test_no_extracted_path_returns_empty(tmp_path: Path) -> None:
    fw = _FakeFirmware(extracted_path=None)
    result = populate_detection_roots(fw)
    assert result == []
    assert fw.device_metadata is None  # untouched


def test_plain_rootfs_produces_root(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()
    (rootfs / "usr").mkdir()
    (rootfs / "bin").mkdir()
    fw = _FakeFirmware(extracted_path=str(rootfs))

    result = populate_detection_roots(fw)

    assert len(result) >= 1
    # device_metadata written
    assert fw.device_metadata is not None
    assert fw.device_metadata["detection_roots"] == result


def test_extra_roots_merged(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()
    (rootfs / "bin").mkdir()
    (rootfs / "usr").mkdir()
    decrypt1 = tmp_path / "payload_a.tar.xz_extract"
    decrypt1.mkdir()
    decrypt2 = tmp_path / "payload_b.tar.xz_extract"
    decrypt2.mkdir()
    fw = _FakeFirmware(extracted_path=str(rootfs))

    result = populate_detection_roots(
        fw,
        extra_roots=[str(decrypt1), str(decrypt2)],
    )

    realpaths = {os.path.realpath(r) for r in result}
    assert os.path.realpath(str(decrypt1)) in realpaths
    assert os.path.realpath(str(decrypt2)) in realpaths


def test_extra_root_duplicating_primary_is_deduped(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()
    (rootfs / "bin").mkdir()
    (rootfs / "usr").mkdir()
    fw = _FakeFirmware(extracted_path=str(rootfs))

    # Pass the same dir as an "extra" — should not appear twice.
    result = populate_detection_roots(
        fw,
        extra_roots=[str(rootfs)],
    )

    realpaths = [os.path.realpath(r) for r in result]
    assert realpaths.count(os.path.realpath(str(rootfs))) == 1


def test_nonexistent_extra_root_filtered(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()
    (rootfs / "bin").mkdir()
    (rootfs / "usr").mkdir()
    fw = _FakeFirmware(extracted_path=str(rootfs))

    result = populate_detection_roots(
        fw,
        extra_roots=[str(tmp_path / "does_not_exist")],
    )

    for r in result:
        assert os.path.isdir(r)


def test_realpath_dedup_via_symlink(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()
    (rootfs / "bin").mkdir()
    (rootfs / "usr").mkdir()
    decrypt = tmp_path / "payload.tar.xz_extract"
    decrypt.mkdir()
    decrypt_alias = tmp_path / "alias_to_payload"
    decrypt_alias.symlink_to(decrypt)
    fw = _FakeFirmware(extracted_path=str(rootfs))

    result = populate_detection_roots(
        fw,
        extra_roots=[str(decrypt), str(decrypt_alias)],
    )

    realpaths = [os.path.realpath(r) for r in result]
    # The realpath of both extras resolves to the same directory; should
    # appear only once in the final list.
    assert realpaths.count(os.path.realpath(str(decrypt))) == 1


def test_preserves_existing_device_metadata_keys(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()
    (rootfs / "bin").mkdir()
    (rootfs / "usr").mkdir()
    fw = _FakeFirmware(
        extracted_path=str(rootfs),
        device_metadata={
            "detection_audit": {"roots_count": 0, "blobs_detected": 0},
            "vendor_decryption": [{"archive": "x", "algorithm": "aes-128-cbc"}],
            "extraction_diagnostics": {"summary": "test"},
        },
    )

    populate_detection_roots(fw)

    # Every pre-existing key must survive the write.
    assert "detection_audit" in fw.device_metadata
    assert "vendor_decryption" in fw.device_metadata
    assert "extraction_diagnostics" in fw.device_metadata
    assert "detection_roots" in fw.device_metadata
