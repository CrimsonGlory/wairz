"""Tests for :class:`LooseDebStrategy`.

Constructs synthetic ``.deb`` archives via ``ar`` + ``tar`` (both
required to be on PATH inside the test environment — they ship with
debian-base / ubuntu-base / ``binutils`` packages and are present in
the wairz backend container).

Coverage:

1. **Happy path** — a minimal valid deb with a control file emits an
   ``IdentifiedComponent`` carrying the correct purl, supplier, arch,
   and ``loose_deb`` source.
2. **Rule #46 META-CANARY — corrupt deb** — a file with the right
   extension but no valid ar header is skipped silently (no crash, no
   component).
3. **Rule #46 META-CANARY — non-deb with .deb extension** — a plain
   text file ending in ``.deb`` is skipped without an exception.
4. **Registration smoke** — ``LooseDebStrategy`` appears in
   ``SbomService._STRATEGY_CLASSES``.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tarfile
import tempfile

import pytest

from app.services.sbom.constants import IdentifiedComponent  # noqa: F401 (re-export check)
from app.services.sbom.normalization import ComponentStore
from app.services.sbom.strategies.base import StrategyContext
from app.services.sbom.strategies.loose_deb_strategy import (
    _MAX_DEBS_PER_ROOT,
    LooseDebStrategy,
)

_AR_AVAILABLE = shutil.which("ar") is not None
_TAR_AVAILABLE = shutil.which("tar") is not None

pytestmark = pytest.mark.skipif(
    not (_AR_AVAILABLE and _TAR_AVAILABLE),
    reason="ar + tar required to build synthetic .deb archives",
)


def _build_minimal_deb(
    out_path: str,
    *,
    package: str = "test-pkg",
    version: str = "1.2.3",
    architecture: str = "arm64",
    maintainer: str = "Test Author <test@example.com>",
    section: str = "misc",
    homepage: str = "https://example.com",
    description: str = "A synthetic test package for LooseDebStrategy",
) -> None:
    """Construct a minimal but valid .deb at ``out_path``.

    Layout:
      - debian-binary (text "2.0\\n")
      - control.tar.gz containing ./control
      - data.tar.gz containing one empty file
    """
    workdir = tempfile.mkdtemp(prefix="loosedeb-builder-")
    try:
        # debian-binary
        db_path = os.path.join(workdir, "debian-binary")
        with open(db_path, "w") as f:
            f.write("2.0\n")

        # control.tar.gz with ./control
        control_body = (
            f"Package: {package}\n"
            f"Version: {version}\n"
            f"Architecture: {architecture}\n"
            f"Maintainer: {maintainer}\n"
            f"Section: {section}\n"
            f"Homepage: {homepage}\n"
            f"Description: {description}\n"
        ).encode()

        ct_path = os.path.join(workdir, "control.tar.gz")
        with tarfile.open(ct_path, mode="w:gz") as tf:
            info = tarfile.TarInfo(name="./control")
            info.size = len(control_body)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(control_body))

        # data.tar.gz with one empty file
        dt_path = os.path.join(workdir, "data.tar.gz")
        with tarfile.open(dt_path, mode="w:gz") as tf:
            info = tarfile.TarInfo(name="./usr/share/doc/test-pkg/EMPTY")
            info.size = 0
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(b""))

        # Assemble via ar
        # `ar rcs` creates a fresh archive in deterministic order.
        subprocess.run(
            ["ar", "rcs", out_path, db_path, ct_path, dt_path],
            check=True,
            capture_output=True,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_loose_deb_strategy_happy_path(tmp_path):
    """Strategy parses control file and emits a high-confidence component."""
    deb_path = tmp_path / "test-pkg_1.2.3_arm64.deb"
    _build_minimal_deb(
        str(deb_path),
        package="nvidia-l4t-core",
        version="32.3.1-20191209230245",
        architecture="arm64",
        maintainer="NVIDIA Corporation <linux-tegra-bugs@nvidia.com>",
        section="misc",
        homepage="https://developer.nvidia.com/linux-tegra",
        description="NVIDIA L4T core libraries for Jetson",
    )

    store = ComponentStore()
    ctx = StrategyContext(
        extracted_root=str(tmp_path),
        store=store,
        partition_name=None,
    )
    LooseDebStrategy().run(ctx)

    components = list(store.values())
    assert len(components) == 1
    comp = components[0]
    assert comp.name == "nvidia-l4t-core"
    assert comp.version == "32.3.1-20191209230245"
    assert comp.type == "application"
    assert comp.cpe is None  # enrichment happens later
    assert comp.purl == "pkg:deb/nvidia-l4t-core@32.3.1-20191209230245?arch=arm64"
    assert comp.supplier == "NVIDIA Corporation <linux-tegra-bugs@nvidia.com>"
    assert comp.detection_source == "loose_deb"
    assert comp.detection_confidence == "high"
    assert comp.file_paths == ["/test-pkg_1.2.3_arm64.deb"]
    assert comp.metadata["section"] == "misc"
    assert comp.metadata["homepage"] == "https://developer.nvidia.com/linux-tegra"
    assert "NVIDIA L4T core libraries" in comp.metadata["description"]
    assert comp.metadata["arch"] == "arm64"
    assert comp.metadata["source"] == "loose_deb"


def test_loose_deb_strategy_multi_deb(tmp_path):
    """Multiple debs in nested dirs all get emitted."""
    nested = tmp_path / "nv_tegra" / "l4t_deb_packages"
    nested.mkdir(parents=True)

    _build_minimal_deb(str(nested / "pkg-a_1.0_arm64.deb"), package="pkg-a", version="1.0")
    _build_minimal_deb(str(nested / "pkg-b_2.0_arm64.deb"), package="pkg-b", version="2.0")
    _build_minimal_deb(str(nested / "pkg-c_3.0_arm64.deb"), package="pkg-c", version="3.0")

    store = ComponentStore()
    ctx = StrategyContext(
        extracted_root=str(tmp_path),
        store=store,
        partition_name=None,
    )
    LooseDebStrategy().run(ctx)

    names = sorted(c.name for c in store.values())
    assert names == ["pkg-a", "pkg-b", "pkg-c"]
    # Relative paths anchored to extracted_root and prefixed with "/".
    for comp in store.values():
        assert comp.file_paths[0].startswith("/nv_tegra/l4t_deb_packages/")


def test_loose_deb_strategy_corrupt_deb_silent_skip(tmp_path):
    """Rule #46 META-CANARY: a corrupt .deb is skipped without crashing.

    Synthesizes a file with the .deb extension that is NOT a valid ar
    archive (just raw bytes). The strategy must not raise; the store
    must remain empty.
    """
    bad_path = tmp_path / "corrupt_1.0_arm64.deb"
    bad_path.write_bytes(b"\x00\x01\x02 NOT AN AR ARCHIVE \x03\x04\x05")

    store = ComponentStore()
    ctx = StrategyContext(
        extracted_root=str(tmp_path),
        store=store,
        partition_name=None,
    )
    # MUST NOT raise.
    LooseDebStrategy().run(ctx)
    assert len(store) == 0


def test_loose_deb_strategy_non_deb_with_deb_extension(tmp_path):
    """Rule #46 META-CANARY: plain-text file with .deb suffix is skipped."""
    fake_path = tmp_path / "readme_1.0_arm64.deb"
    fake_path.write_text(
        "This is a README that some misguided vendor renamed to .deb"
    )

    store = ComponentStore()
    ctx = StrategyContext(
        extracted_root=str(tmp_path),
        store=store,
        partition_name=None,
    )
    LooseDebStrategy().run(ctx)
    assert len(store) == 0


def test_loose_deb_strategy_ar_archive_without_control_tar(tmp_path):
    """Rule #46 META-CANARY: valid ar archive missing control.tar.* is skipped.

    Important: a hostile actor could ship an ar archive that LOOKS like
    a deb (has ``debian-binary``) but lacks the control tarball. The
    strategy must skip this without emitting a malformed component.
    """
    workdir = tmp_path / "_build"
    workdir.mkdir()

    db_path = workdir / "debian-binary"
    db_path.write_text("2.0\n")
    junk_path = workdir / "junk.bin"
    junk_path.write_bytes(b"not a control tarball")

    deb_path = tmp_path / "no-control_1.0_arm64.deb"
    subprocess.run(
        ["ar", "rcs", str(deb_path), str(db_path), str(junk_path)],
        check=True,
        capture_output=True,
    )

    store = ComponentStore()
    ctx = StrategyContext(
        extracted_root=str(tmp_path),
        store=store,
        partition_name=None,
    )
    LooseDebStrategy().run(ctx)
    assert len(store) == 0


def test_loose_deb_strategy_registered_in_service():
    """LooseDebStrategy is wired into SbomService._STRATEGY_CLASSES."""
    from app.services.sbom.service import SbomService

    assert LooseDebStrategy in SbomService._STRATEGY_CLASSES


def test_loose_deb_strategy_max_cap_constant_reasonable():
    """Sanity: the cap is well above typical BSP sizes (~21 for L4T)."""
    assert _MAX_DEBS_PER_ROOT >= 100
    assert _MAX_DEBS_PER_ROOT <= 100_000  # Defense against typos
