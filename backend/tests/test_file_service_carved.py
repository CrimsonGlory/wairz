"""Unit tests for FileService — /_carved/ namespace.

Phase 1 carving sandbox surfaces agent-written outputs at /_carved/... so
the rest of wairz's read tools (read_file, extract_strings, decompile_function)
see them automatically. These tests verify that the path-resolution layer
honors the new namespace and rejects traversal attempts.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.services.file_service import FileService
from app.utils.sandbox import PathTraversalError


class TestCarvedResolve:
    def test_resolve_carved_root(self, tmp_path: Path):
        carved = tmp_path / "carved"
        carved.mkdir()
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        svc = FileService(str(rootfs), carved_path=str(carved))
        assert svc._resolve("/_carved") == str(carved)

    def test_resolve_carved_subpath(self, tmp_path: Path):
        carved = tmp_path / "carved"
        carved.mkdir()
        (carved / "foo.bin").write_bytes(b"\x00" * 16)
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        svc = FileService(str(rootfs), carved_path=str(carved))
        assert svc._resolve("/_carved/foo.bin") == str(carved / "foo.bin")

    def test_resolve_carved_works_without_extraction_dir(self, tmp_path: Path):
        # Even legacy-mode firmwares (no extraction_dir) should accept /_carved/.
        carved = tmp_path / "carved"
        carved.mkdir()
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        svc = FileService(str(rootfs), carved_path=str(carved))
        assert svc._resolve("/_carved") == str(carved)

    def test_resolve_carved_works_with_extraction_dir(self, tmp_path: Path):
        # Multi-namespace mode shouldn't shadow /_carved/.
        carved = tmp_path / "fw" / "carved"
        carved.mkdir(parents=True)
        rootfs = tmp_path / "fw" / "extracted" / "squashfs-root"
        rootfs.mkdir(parents=True)
        svc = FileService(
            str(rootfs),
            extraction_dir=str(rootfs.parent),
            carved_path=str(carved),
        )
        assert svc._resolve("/_carved") == str(carved)
        # And /rootfs/ still resolves to extracted_root
        assert svc._resolve("/rootfs") == str(rootfs)

    def test_resolve_carved_rejects_traversal(self, tmp_path: Path):
        carved = tmp_path / "carved"
        carved.mkdir()
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        svc = FileService(str(rootfs), carved_path=str(carved))
        with pytest.raises(PathTraversalError):
            svc._resolve("/_carved/../etc/passwd")

    def test_no_carved_path_falls_through(self, tmp_path: Path):
        # When carved_path is None (project never used the sandbox), the
        # /_carved/ prefix is treated as a regular subdirectory under
        # extracted_root. The path is well-formed (not a traversal) but
        # may not exist on disk — that's the expected fall-through.
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        svc = FileService(str(rootfs), carved_path=None)
        resolved = svc._resolve("/_carved/foo")
        assert resolved == str(rootfs / "_carved" / "foo")


class TestCarvedToVirtualPath:
    def test_carved_file_round_trips(self, tmp_path: Path):
        carved = tmp_path / "carved"
        carved.mkdir()
        (carved / "manifest.bin").write_bytes(b"\x00" * 4)
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        svc = FileService(str(rootfs), carved_path=str(carved))
        assert (
            svc.to_virtual_path(str(carved / "manifest.bin"))
            == "/_carved/manifest.bin"
        )

    def test_carved_root_round_trips(self, tmp_path: Path):
        carved = tmp_path / "carved"
        carved.mkdir()
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        svc = FileService(str(rootfs), carved_path=str(carved))
        assert svc.to_virtual_path(str(carved)) == "/_carved"

    def test_rootfs_paths_unchanged(self, tmp_path: Path):
        # Adding carved_path must not perturb existing rootfs round-trips.
        carved = tmp_path / "carved"
        carved.mkdir()
        rootfs = tmp_path / "rootfs"
        (rootfs / "bin").mkdir(parents=True)
        (rootfs / "bin" / "ls").write_bytes(b"\x7fELF")
        svc = FileService(str(rootfs), carved_path=str(carved))
        # legacy mode (no extraction_dir): rootfs file maps to /bin/ls
        assert svc.to_virtual_path(str(rootfs / "bin" / "ls")) == "/bin/ls"

    def test_outside_returns_none(self, tmp_path: Path):
        carved = tmp_path / "carved"
        carved.mkdir()
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        svc = FileService(str(rootfs), carved_path=str(carved))
        assert svc.to_virtual_path("/etc/passwd") is None


class TestCarvedTopLevelListing:
    def test_carved_appears_when_populated(self, tmp_path: Path):
        # Set up the extraction-dir-mode tree (rootfs nested + sibling files
        # at the extraction_dir level) plus a populated /_carved/.
        outer = tmp_path / "outer"
        squash = outer / "squashfs-root"
        squash.mkdir(parents=True)
        carved = tmp_path / "carved"
        carved.mkdir()
        (carved / "manifest.bin").write_bytes(b"\x00" * 16)
        svc = FileService(
            str(squash),
            extraction_dir=str(outer),
            carved_path=str(carved),
        )
        entries, _ = svc.list_directory("/")
        names = [e.name for e in entries]
        assert "_carved" in names
        assert "rootfs" in names

    def test_carved_hidden_when_empty(self, tmp_path: Path):
        outer = tmp_path / "outer"
        squash = outer / "squashfs-root"
        squash.mkdir(parents=True)
        carved = tmp_path / "carved"
        carved.mkdir()  # exists but empty
        svc = FileService(
            str(squash),
            extraction_dir=str(outer),
            carved_path=str(carved),
        )
        entries, _ = svc.list_directory("/")
        names = [e.name for e in entries]
        assert "_carved" not in names

    def test_carved_hidden_when_dir_missing(self, tmp_path: Path):
        outer = tmp_path / "outer"
        squash = outer / "squashfs-root"
        squash.mkdir(parents=True)
        carved = tmp_path / "no-such-dir"
        svc = FileService(
            str(squash),
            extraction_dir=str(outer),
            carved_path=str(carved),
        )
        entries, _ = svc.list_directory("/")
        names = [e.name for e in entries]
        assert "_carved" not in names
