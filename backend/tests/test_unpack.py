"""Unit tests for the firmware unpack pipeline (workers/unpack.py)."""
from __future__ import annotations

import os
from pathlib import Path

from app.workers.unpack import (
    _count_fs_markers,
    _has_linux_markers,
    find_filesystem_root,
)


def _make_dirs(base: Path, layout: dict) -> None:
    """Create a directory tree from a nested dict.

    Values that are dicts become directories with recursive contents; other
    values become empty files.
    """
    for name, contents in layout.items():
        path = base / name
        if isinstance(contents, dict):
            path.mkdir(parents=True, exist_ok=True)
            _make_dirs(path, contents)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"" if contents is None else contents)


class TestCountMarkers:
    def test_counts_standard_layout(self, tmp_path: Path):
        _make_dirs(tmp_path, {
            "bin": {}, "sbin": {}, "etc": {}, "lib": {}, "usr": {},
        })
        assert _count_fs_markers(str(tmp_path)) == 5

    def test_zero_for_empty(self, tmp_path: Path):
        assert _count_fs_markers(str(tmp_path)) == 0

    def test_zero_for_nonexistent(self, tmp_path: Path):
        assert _count_fs_markers(str(tmp_path / "missing")) == 0

    def test_recognises_embedded_init_dir(self, tmp_path: Path):
        # Wyze cameras use /init/ instead of /etc/.
        _make_dirs(tmp_path, {"bin": {}, "init": {}, "ko": {}, "lib": {}})
        assert _count_fs_markers(str(tmp_path)) == 4


class TestHasLinuxMarkers:
    def test_two_markers_qualifies(self, tmp_path: Path):
        _make_dirs(tmp_path, {"bin": {}, "lib": {}})
        assert _has_linux_markers(str(tmp_path))

    def test_one_marker_does_not_qualify(self, tmp_path: Path):
        _make_dirs(tmp_path, {"bin": {}})
        assert not _has_linux_markers(str(tmp_path))


class TestFindFilesystemRoot:
    def test_picks_named_root_over_deep_match(self, tmp_path: Path):
        # Regression: the Wyze Battery Cam Solar firmware has no /etc/, so the
        # old "etc + (usr|bin)" heuristic missed the actual rootfs and the
        # "largest dir" fallback picked bin/busybox/bin/ (~50 busybox symlinks)
        # instead. Verify we now pick the squashfs-root regardless.
        _make_dirs(tmp_path, {
            "_fw.bin.extracted": {
                "squashfs-root": {
                    "bin": {
                        "busybox": {
                            # 50 fake busybox symlinks
                            "bin": {f"sym{i}": None for i in range(50)},
                            "sbin": {f"s{i}": None for i in range(20)},
                        },
                        "dnsmasq": None,
                        "ppsapp": None,
                    },
                    "init": {"initrun.sh": None},
                    "ko": {"foo.ko": None},
                    "lib": {},
                },
                # Sibling: same squashfs re-extracted by binwalk -Me
                "raw.squashfs.extracted": {
                    "bin": {"busybox": {"bin": {f"sym{i}": None for i in range(50)}}},
                    "init": {}, "ko": {}, "lib": {},
                },
            },
        })

        result = find_filesystem_root(str(tmp_path))
        assert result is not None
        assert os.path.basename(result) == "squashfs-root"

    def test_picks_shallowest_marker_dir_when_no_named_root(self, tmp_path: Path):
        # If there's no *-root dir, pick the shallowest dir with enough markers,
        # not a deeply-nested one.
        _make_dirs(tmp_path, {
            "rootfs": {
                "bin": {}, "sbin": {}, "etc": {}, "lib": {},
                "usr": {
                    "bin": {"foo": None, "bar": None},
                    "lib": {"baz": None},
                },
            },
        })
        result = find_filesystem_root(str(tmp_path))
        assert result is not None
        assert os.path.basename(result) == "rootfs"

    def test_prefers_unnumbered_named_root(self, tmp_path: Path):
        # If both squashfs-root and squashfs-root-0 exist, the shallowest one
        # wins on depth tie-break; in practice they're at the same depth so
        # we tie-break on marker count then path order.
        _make_dirs(tmp_path, {
            "squashfs-root": {"bin": {}, "etc": {}, "lib": {}, "var": {}},
            "squashfs-root-0": {"bin": {}, "etc": {}},
        })
        result = find_filesystem_root(str(tmp_path))
        assert result is not None
        # squashfs-root has more markers, so it wins on the tie-break
        assert os.path.basename(result) == "squashfs-root"

    def test_returns_none_when_no_qualifying_dir(self, tmp_path: Path):
        # No fallback to "biggest directory" — we'd rather fail explicitly
        # than mount the wrong directory.
        _make_dirs(tmp_path, {
            "junk": {f"file{i}": None for i in range(100)},
            "more_junk": {f"x{i}": None for i in range(50)},
        })
        assert find_filesystem_root(str(tmp_path)) is None

    def test_does_not_descend_into_named_root(self, tmp_path: Path):
        # An ext-root nested inside a squashfs-root should not be picked over
        # the outer squashfs-root.
        _make_dirs(tmp_path, {
            "squashfs-root": {
                "bin": {}, "etc": {}, "lib": {}, "var": {},
                # Some weird vendor that ships an ext image inside its rootfs.
                "tmp": {"ext-root": {"bin": {}, "etc": {}, "lib": {}}},
            },
        })
        result = find_filesystem_root(str(tmp_path))
        assert result is not None
        assert os.path.basename(result) == "squashfs-root"
