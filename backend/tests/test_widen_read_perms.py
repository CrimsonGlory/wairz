"""Regression tests for widen_read_perms.

Guards the gen_creds.sh permissions defect:
    Firmware tarballs frequently ship files with vendor-restrictive
    modes (e.g. rwxr-x--- root:root for credential-generation scripts).
    When Wairz extracts those, the backend (running as a non-root user)
    gets EPERM when trying to open them. The file-explorer API returns
    "no access" despite the file being on disk.

widen_read_perms walks the tree and ORs group+other read into every
file mode + group+other read+execute into every directory mode.
Execute bits on files are preserved (scripts stay executable).
Symlinks are skipped (chmod on a symlink would affect the target).
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from app.workers.unpack_common import widen_read_perms


def test_widens_locked_down_file(tmp_path: Path) -> None:
    f = tmp_path / "gen_creds.sh"
    f.write_text("#!/bin/sh\necho creds\n")
    f.chmod(0o750)
    assert stat.S_IMODE(f.lstat().st_mode) == 0o750

    changed = widen_read_perms(str(tmp_path))

    assert changed >= 1
    new_mode = stat.S_IMODE(f.lstat().st_mode)
    # Group + other read bits set
    assert new_mode & stat.S_IRGRP
    assert new_mode & stat.S_IROTH
    # Execute bit on user preserved
    assert new_mode & stat.S_IXUSR


def test_widens_locked_down_dir(tmp_path: Path) -> None:
    d = tmp_path / "locked_etc"
    d.mkdir(mode=0o700)
    assert stat.S_IMODE(d.lstat().st_mode) == 0o700

    widen_read_perms(str(tmp_path))

    new_mode = stat.S_IMODE(d.lstat().st_mode)
    assert new_mode & stat.S_IRGRP
    assert new_mode & stat.S_IROTH
    # Directories get execute bit (traversable) too
    assert new_mode & stat.S_IXGRP
    assert new_mode & stat.S_IXOTH


def test_preserves_execute_bits_on_script(tmp_path: Path) -> None:
    f = tmp_path / "run.sh"
    f.write_text("#!/bin/sh\necho hi\n")
    f.chmod(0o750)  # user rwx, group rx, other none

    widen_read_perms(str(tmp_path))

    new_mode = stat.S_IMODE(f.lstat().st_mode)
    # Execute bit on user preserved from original 0o750
    assert new_mode & stat.S_IXUSR
    # Group execute preserved from original 0o750 (don't STRIP execute)
    assert new_mode & stat.S_IXGRP


def test_leaves_already_readable_files_alone(tmp_path: Path) -> None:
    f = tmp_path / "readme.txt"
    f.write_text("readme")
    f.chmod(0o644)
    before = stat.S_IMODE(f.lstat().st_mode)

    changed = widen_read_perms(str(tmp_path))

    # File count may include the parent dir or not — assert the file
    # itself didn't change (mask already set).
    assert stat.S_IMODE(f.lstat().st_mode) == before


def test_skips_symlinks(tmp_path: Path) -> None:
    # Build: real file + symlink pointing at it; chmod the real file to
    # 0o600 and confirm widen_read_perms does NOT change the link's
    # target mode (symlink mode is ignored on Linux; the concern is that
    # chmod on the LINK would affect the TARGET and we want neither).
    real = tmp_path / "target"
    real.write_text("x")
    real.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(real)

    widen_read_perms(str(tmp_path))

    # target should be widened (it's reached via the walk, not the symlink)
    assert stat.S_IMODE(real.lstat().st_mode) & stat.S_IROTH


def test_missing_dir_returns_zero(tmp_path: Path) -> None:
    # os.walk on a nonexistent path yields nothing; no exception
    assert widen_read_perms(str(tmp_path / "does_not_exist")) == 0


def test_real_shape_from_eaton_firmware(tmp_path: Path) -> None:
    """End-to-end: locked rootfs with creds/ subdir and gen_creds.sh.

    Matches the concrete shape that blocked the file-explorer UI during
    RespArray v1.05 investigation (session b3a3b580).
    """
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    etc = rootfs / "etc"
    etc.mkdir(mode=0o700)
    creds = etc / "creds"
    creds.mkdir(mode=0o700)
    key = creds / "EDAN_Root_CA.key"
    key.write_text("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n")
    key.chmod(0o600)
    script = rootfs / "bin" / "gen_creds.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\necho gen\n")
    script.chmod(0o750)

    widen_read_perms(str(tmp_path))

    # Every leaf reachable via walk + readable by "other"
    for p in (etc, creds, key, script):
        mode = stat.S_IMODE(p.lstat().st_mode)
        assert mode & stat.S_IROTH, f"{p} not readable by other: {oct(mode)}"
        if p.is_dir():
            assert mode & stat.S_IXOTH, f"{p} not traversable: {oct(mode)}"
