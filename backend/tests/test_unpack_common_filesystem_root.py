"""Regression tests for the marker-only ``find_filesystem_root_strict`` variant.

Locks in the SBOM completeness fix shipped at commit ``88b3826``
(2026-05-22): ``find_filesystem_root_strict`` returns ``None`` when no
Linux-rootfs markers are found instead of falling back to entry-count
guessing. The post-recursion re-probe site in
``firmware_service._post_process_pipeline`` then falls back to the
OUTER ``extraction_dir`` rather than relocating ``firmware.extracted_path``
to whichever deep blob subdir happens to have the most direct entries.

Original regression: NVIDIA Jetson L4T BSP firmware
(``live_base-2.14.4-rc.5238.tar.gz``, 2.5 GiB) extracted to a tree with
NO ``etc + bin/usr`` markers anywhere. The legacy ``find_filesystem_root``
entry-count fallback picked ``.../bootloader/`` (92 direct entries) as
``fs_root``; ``detection_roots`` then locked to that subtree and the
SBOM dropped from 28 components (May 15 sibling) to 1.

Scenarios covered:

a. ``find_filesystem_root_strict`` returns ``None`` on a tree with NO
   markers anywhere — the canonical L4T BSP shape.
b. ``find_filesystem_root_strict`` returns the marker dir even when a
   competing non-marker dir has 200× more entries (priority dominates
   entry count).
c. Full L4T BSP fixture (bootloader / kernel / nv_tegra / tools /
   source / rootfs/README.txt + a sibling tegraflash archive subdir)
   — strict variant returns ``None`` (no markers in EITHER container).
d. Non-strict ``find_filesystem_root`` on the SAME L4T BSP shape
   returns the entry-count winner — locks in the LEGACY behaviour
   (proves the strict variant is the post-recursion safety net, not
   a unilateral replacement).
e. Post-recursion fallback shape: when ``find_filesystem_root_strict``
   returns ``None``, the caller's
   ``fs_root = new_fs_root if new_fs_root is not None else extraction_dir``
   line resolves to the OUTER container — exercises the exact
   contract used in ``firmware_service.py`` lines 657-660.

Each primary test ships with a Rule #46 META-CANARY companion that
synthesises a positive case the gate MUST catch. Without the canary, a
silent regression (strict variant always returns ``None`` /
``find_filesystem_root`` always returns ``None`` on the L4T shape /
fallback never picks the outer dir) would leave the primary tests
passing on degenerate behaviour.

Rule mappings:
- Rule #46: META-CANARY pairings for every absence-asserting gate.
- Rule #19: evidence-first — fixtures mirror the actual L4T BSP shape
  documented in commit ``88b3826`` (10+ debs under
  ``nv_tegra/l4t_deb_packages``; bootloader dir with 92-ish entries;
  no rootfs markers).
- Rule #38: absolute paths throughout (`tmp_path` from pytest IS
  absolute).
- Rule #25: shipped as one commit per Rule #25 single-slice exception
  (the regression-canary file is a single atomic deliverable).
"""

from __future__ import annotations

import os
from pathlib import Path

from app.workers.unpack_common import (
    find_filesystem_root,
    find_filesystem_root_strict,
)


# ───────────────────────── Fixture builders ─────────────────────────


def _make_marker_rootfs(root: Path, *, extra_entries: int = 5) -> Path:
    """Create a Linux rootfs marker tree (etc/ + bin/) under ``root``.

    Returns the rootfs path. Used as the positive canary fixture for
    the marker-detection gate.
    """
    root.mkdir(parents=True, exist_ok=True)
    (root / "etc").mkdir()
    (root / "bin").mkdir()
    # Add some plausible files inside etc so it isn't structurally empty.
    (root / "etc" / "hostname").write_text("canary\n")
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (root / "bin" / "sh").write_bytes(b"\x7fELF stub")
    for i in range(extra_entries):
        (root / f"misc_{i}").mkdir()
    return root


def _make_l4t_bsp_layout(extraction_dir: Path) -> None:
    """Build a fixture tree mirroring the NVIDIA Jetson L4T BSP shape
    that surfaced the SBOM regression in commit ``88b3826``.

    Layout (a faithful reduction of the real
    ``live_base-2.14.4-rc.5238.tar.gz`` after the tarball-shortcut +
    nested recursion expansion):

        extraction_dir/L4T_BSP_SecureBoot.R32.3.1.tar.gz_extracted/
          bootloader/                  ← entry-count winner (~92 entries)
            t186ref/{BCT,p2771-0000/000,p2771-0000/500}/
            <86 stub files>
          kernel/dtb/                  ← kernel binaries, no rootfs
          nv_tegra/l4t_deb_packages/   ← 11 deb stubs (the real packages
                                        Syft mines for SBOM components)
          tools/                       ← ~3 deb stubs
          source/source.tar.bz2.stub
          rootfs/README.txt            ← placeholder file ONLY; no
                                        etc/+bin to qualify as rootfs

        extraction_dir/DS1.2-tegraflash.tar.gz_extracted/
          bootloader/, pkc/, rollback/, ds_bup/
    """
    extraction_dir.mkdir(parents=True, exist_ok=True)

    bsp = extraction_dir / "L4T_BSP_SecureBoot.R32.3.1.tar.gz_extracted"
    bsp.mkdir()

    # bootloader/ — 92 direct entries to mirror the real entry-count
    # winner. Mix of subdirs + stub files so the tree resembles a real
    # vendor bootloader bundle.
    bootloader = bsp / "bootloader"
    bootloader.mkdir()
    (bootloader / "t186ref").mkdir()
    (bootloader / "t186ref" / "BCT").mkdir()
    (bootloader / "t186ref" / "p2771-0000").mkdir()
    (bootloader / "t186ref" / "p2771-0000" / "000").mkdir()
    (bootloader / "t186ref" / "p2771-0000" / "500").mkdir()
    # Top up bootloader/ to ~92 direct entries with stub files.
    for i in range(87):
        (bootloader / f"stub_{i:03d}.bin").write_bytes(b"\x00" * 64)

    # kernel/dtb/ — kernel binaries; no rootfs structure.
    kernel = bsp / "kernel"
    (kernel / "dtb").mkdir(parents=True)
    (kernel / "dtb" / "tegra186-quill-p3310.dtb").write_bytes(b"\xd0\x0d\xfe\xed")
    (kernel / "Image").write_bytes(b"\x7fELF kernel stub")

    # nv_tegra/l4t_deb_packages/ — 11 deb stubs.
    debs = bsp / "nv_tegra" / "l4t_deb_packages"
    debs.mkdir(parents=True)
    for name in (
        "nvidia-l4t-bootloader_arm64.deb",
        "nvidia-l4t-core_arm64.deb",
        "nvidia-l4t-cuda_arm64.deb",
        "nvidia-l4t-firmware_arm64.deb",
        "nvidia-l4t-graphics-demos_arm64.deb",
        "nvidia-l4t-init_arm64.deb",
        "nvidia-l4t-kernel_arm64.deb",
        "nvidia-l4t-kernel-dtbs_arm64.deb",
        "nvidia-l4t-multimedia_arm64.deb",
        "nvidia-l4t-multimedia-utils_arm64.deb",
        "nvidia-l4t-tools_arm64.deb",
    ):
        (debs / name).write_bytes(b"!<arch>\n")  # deb is an ar archive

    # tools/ — small set of deb stubs.
    tools = bsp / "tools"
    tools.mkdir()
    for name in ("flash.sh", "tegraflash.py", "rcm_boot.py"):
        (tools / name).write_text("# stub\n")

    # source/ — source tarball placeholder.
    (bsp / "source").mkdir()
    (bsp / "source" / "source.tar.bz2.stub").write_bytes(b"BZh stub")

    # rootfs/ — has ONLY a README.txt placeholder; missing both
    # ``etc`` AND ``bin/usr`` so ``_has_linux_markers`` correctly
    # rejects it.
    (bsp / "rootfs").mkdir()
    (bsp / "rootfs" / "README.txt").write_text("Placeholder for L4T rootfs.\n")

    # Sibling archive: DS1 tegraflash bundle.
    sibling = extraction_dir / "DS1.2-tegraflash.tar.gz_extracted"
    sibling.mkdir()
    for sub in ("bootloader", "pkc", "rollback", "ds_bup"):
        (sibling / sub).mkdir()
        (sibling / sub / "data.bin").write_bytes(b"\x00" * 128)


# ───────────────────────── Test (a) + canary ─────────────────────────


def test_find_filesystem_root_strict_returns_none_on_no_markers(
    tmp_path: Path,
) -> None:
    """No Linux markers anywhere → strict variant returns ``None``.

    Fixture: three sibling subdirs (``tools/``, ``bootloader/``,
    ``kernel/dtb/``) — each populated but NONE with ``etc + bin/usr``.
    Locks the contract: strict variant MUST NOT fall back to
    entry-count guessing.
    """
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "flash.sh").write_text("# stub\n")
    (tmp_path / "tools" / "extra").mkdir()

    (tmp_path / "bootloader").mkdir()
    for i in range(30):
        (tmp_path / "bootloader" / f"blob_{i:02d}.bin").write_bytes(b"\x00")

    (tmp_path / "kernel").mkdir()
    (tmp_path / "kernel" / "dtb").mkdir()
    (tmp_path / "kernel" / "dtb" / "board.dtb").write_bytes(b"\xd0\x0d\xfe\xed")

    assert find_filesystem_root_strict(str(tmp_path)) is None


def test_find_filesystem_root_strict_canary_marker_dir_detected(
    tmp_path: Path,
) -> None:
    """META-CANARY for ``test_..._returns_none_on_no_markers``.

    Synthesises a fixture with a SINGLE marker dir
    (``/rootfs/{etc,bin}``). Without this canary, ``find_filesystem_root_strict``
    could be returning ``None`` for everything (silent failure) and the
    primary test would still pass. The canary proves the marker
    detection branch is live.
    """
    rootfs = tmp_path / "rootfs"
    _make_marker_rootfs(rootfs)

    result = find_filesystem_root_strict(str(tmp_path))
    assert result is not None, "strict variant failed to find marker rootfs"
    assert os.path.realpath(result) == os.path.realpath(str(rootfs))


# ───────────────────────── Test (b) + canary ─────────────────────────


def test_find_filesystem_root_strict_picks_priority_marker_over_entry_count(
    tmp_path: Path,
) -> None:
    """Marker priority dominates entry-count ranking.

    Fixture: ONE small marker rootfs (``rootfs_a/{etc,bin}``, ~5
    entries) plus ONE non-marker dir with 200 entries. The strict
    variant MUST return ``rootfs_a`` — entry-count is a tiebreaker
    only AFTER marker priority. The non-marker dir is invisible to the
    strict probe regardless of its size.
    """
    rootfs_a = tmp_path / "rootfs_a"
    _make_marker_rootfs(rootfs_a, extra_entries=0)

    fat = tmp_path / "fat_non_marker_dir"
    fat.mkdir()
    for i in range(200):
        (fat / f"entry_{i:03d}.bin").write_bytes(b"\x00")

    result = find_filesystem_root_strict(str(tmp_path))
    assert result is not None
    assert os.path.realpath(result) == os.path.realpath(str(rootfs_a))


def test_find_filesystem_root_strict_canary_picks_higher_priority_marker(
    tmp_path: Path,
) -> None:
    """META-CANARY for the priority-dominates test.

    Two marker dirs side-by-side: ``ext-root/{etc,bin}`` (priority
    name from ``_FS_ROOT_NAMES``, priority=10) AND
    ``randomname/{etc,bin}`` (no priority bonus, priority=0). The
    strict variant MUST pick ``ext-root`` even if both look identical
    in size. Without this canary, a regression that ignores the
    ``_FS_ROOT_NAMES`` bonus would still pass test (b) (the only
    marker-priority signal there is "has markers vs no markers").
    """
    priority_root = tmp_path / "ext-root"
    _make_marker_rootfs(priority_root, extra_entries=0)

    plain_root = tmp_path / "randomname"
    _make_marker_rootfs(plain_root, extra_entries=0)

    result = find_filesystem_root_strict(str(tmp_path))
    assert result is not None
    assert os.path.basename(result) == "ext-root", (
        f"expected priority-name 'ext-root' to win; got {result!r}"
    )


# ───────────────────────── Test (c) + canary ─────────────────────────


def test_find_filesystem_root_strict_l4t_bsp_shape(tmp_path: Path) -> None:
    """L4T BSP shape: no rootfs markers anywhere → strict returns ``None``.

    This is the exact regression case from commit ``88b3826``. The
    pre-fix ``find_filesystem_root`` entry-count fallback picked
    ``.../bootloader/`` (92 direct entries) as ``fs_root``,
    cascading into a 1-component SBOM. The strict variant correctly
    returns ``None`` so the post-recursion site in
    ``_post_process_pipeline`` can fall back to the outer
    ``extraction_dir`` and detection_roots can sweep every sibling
    archive subdir.
    """
    extracted = tmp_path / "extracted"
    _make_l4t_bsp_layout(extracted)

    assert find_filesystem_root_strict(str(extracted)) is None


def test_find_filesystem_root_strict_canary_l4t_with_rootfs_present(
    tmp_path: Path,
) -> None:
    """META-CANARY for the L4T BSP test.

    Same L4T BSP fixture PLUS a real rootfs (``ext-root/{etc,bin}``)
    grafted on as a sibling. The strict variant MUST return the
    grafted rootfs (mirrors the DS1 Moto ``super.img → ext4`` case
    that the commit message explicitly preserves). Without this
    canary, a regression where the strict variant returns ``None``
    for any complex tree (e.g. an over-eager early-return) would
    pass test (c) but break the DS1 Moto case.
    """
    extracted = tmp_path / "extracted"
    _make_l4t_bsp_layout(extracted)

    real_rootfs = extracted / "ext-root"
    _make_marker_rootfs(real_rootfs, extra_entries=2)

    result = find_filesystem_root_strict(str(extracted))
    assert result is not None
    assert os.path.realpath(result) == os.path.realpath(str(real_rootfs))


# ───────────────────────── Test (d) + canary ─────────────────────────


def test_find_filesystem_root_picks_entry_count_when_no_markers(
    tmp_path: Path,
) -> None:
    """Non-strict ``find_filesystem_root`` keeps the LEGACY entry-count
    behaviour on the L4T BSP shape — picks the entry-count winner
    (the bootloader/ subdir under L4T_BSP_…_extracted/).

    Locks in the pre-recursion compatibility: the legacy variant is
    still around for callers that want a best-effort guess; the
    strict variant is the post-recursion safety net. This test
    asserts the strict / non-strict CONTRAST stays meaningful (if
    both returned None, the strict variant would be a no-op
    upgrade).
    """
    extracted = tmp_path / "extracted"
    _make_l4t_bsp_layout(extracted)

    result = find_filesystem_root(str(extracted))
    # Legacy fallback picks the entry-count winner — should be
    # somewhere under the BSP tree's bootloader subdir (~92 entries).
    assert result is not None, (
        "non-strict variant unexpectedly returned None on L4T BSP shape; "
        "the entry-count fallback should still fire when no markers "
        "are present"
    )
    # The exact winner is the bootloader subdir (~92 direct entries)
    # — the dir name 'bootloader' anchors the regression: this is the
    # value the legacy fallback historically picked and the strict
    # variant + outer-fallback now correctly avoid.
    assert os.path.basename(result) == "bootloader", (
        f"expected legacy fallback to pick the 'bootloader' entry-count "
        f"winner; got {result!r}. If the layout fixture changed, "
        f"re-verify the 92-entry bootloader subdir is still the densest."
    )


def test_find_filesystem_root_canary_returns_marker_when_present(
    tmp_path: Path,
) -> None:
    """META-CANARY for the legacy-entry-count test.

    Pure rootfs fixture (only ``rootfs/{etc,bin}``, ~3 entries).
    Non-strict ``find_filesystem_root`` MUST return the rootfs (it
    delegates to ``find_filesystem_root_strict`` first). Without this
    canary, a regression where ``find_filesystem_root`` ALWAYS
    falls back to entry-count (skipping the strict-first delegation)
    would pass test (d) — the L4T fixture has no markers so the
    fallback DOES fire there legitimately; only the marker-present
    case distinguishes the two code paths.
    """
    rootfs = tmp_path / "rootfs"
    _make_marker_rootfs(rootfs, extra_entries=0)

    # Add a non-marker decoy with more entries to confirm the
    # marker path wins.
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    for i in range(50):
        (decoy / f"x_{i:02d}").write_text("")

    result = find_filesystem_root(str(tmp_path))
    assert result is not None
    assert os.path.realpath(result) == os.path.realpath(str(rootfs))


# ───────────────────────── Test (e) + canary ─────────────────────────


def test_post_recursion_fallback_to_extraction_dir(tmp_path: Path) -> None:
    """Post-recursion fallback contract: when ``find_filesystem_root_strict``
    returns ``None`` on a recursed L4T-shaped tree, the
    ``_post_process_pipeline`` site MUST resolve fs_root to the OUTER
    ``extraction_dir`` — never to a deep BSP subdir.

    Exercises the exact code shape from
    ``firmware_service.py:657-660``::

        new_fs_root = find_filesystem_root_strict(extraction_dir)
        fs_root = new_fs_root if new_fs_root is not None else extraction_dir

    The shape is deliberately tested as an inline expression (not by
    invoking the full async ``_post_process_pipeline`` with DB +
    firmware objects) — the contract being tested is the
    fallback-to-outer behaviour, not the surrounding state machine.
    Companion to Rule #46: the canary below verifies the inverse
    branch (strict returns a real rootfs → that rootfs wins).
    """
    extraction_dir = tmp_path / "extracted"
    _make_l4t_bsp_layout(extraction_dir)

    # Mirror lines 657-660 of firmware_service.py exactly.
    new_fs_root = find_filesystem_root_strict(str(extraction_dir))
    fs_root = new_fs_root if new_fs_root is not None else str(extraction_dir)

    # The strict probe MUST return None for the L4T shape (test (c)
    # asserts that directly); the fallback expression MUST then
    # resolve to the outer extraction_dir, NOT a buried bootloader
    # subdir.
    assert new_fs_root is None
    assert os.path.realpath(fs_root) == os.path.realpath(str(extraction_dir))
    # Defence in depth: explicitly reject the legacy mis-location.
    assert "bootloader" not in os.path.basename(fs_root), (
        f"fs_root resolved to {fs_root!r} — looks like the legacy "
        "entry-count winner leaked through. The post-recursion site "
        "must fall back to the outer extraction_dir."
    )


def test_post_recursion_canary_real_rootfs_wins_over_outer(
    tmp_path: Path,
) -> None:
    """META-CANARY for the post-recursion fallback test.

    Same L4T BSP shape PLUS a real rootfs (``ext-root/{etc,bin}``)
    grafted on. The fallback expression MUST resolve to the grafted
    rootfs, NOT the outer extraction_dir — this mirrors the DS1
    Moto ``super.img → ext4`` case that the commit message
    explicitly preserves ("If recursion exposed a real rootfs ...,
    the strict variant returns that").

    Without this canary, a regression where the fallback ALWAYS
    picks the outer extraction_dir would pass the primary test (the
    L4T fixture has no markers, so outer-fallback is correct there)
    while silently breaking the DS1 Moto path.
    """
    extraction_dir = tmp_path / "extracted"
    _make_l4t_bsp_layout(extraction_dir)
    real_rootfs = extraction_dir / "ext-root"
    _make_marker_rootfs(real_rootfs, extra_entries=2)

    new_fs_root = find_filesystem_root_strict(str(extraction_dir))
    fs_root = new_fs_root if new_fs_root is not None else str(extraction_dir)

    assert new_fs_root is not None
    assert os.path.realpath(fs_root) == os.path.realpath(str(real_rootfs))
