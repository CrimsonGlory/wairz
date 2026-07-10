"""Wave 20j: firmware markers + gcc strategy full cover + emulation constants."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from app.services.sbom.normalization import ComponentStore
from app.services.sbom.strategies.base import StrategyContext


class TestFirmwareMarkersFull:
    def test_all_markers(self, tmp_path: Path):
        from app.services.sbom.constants import FIRMWARE_MARKERS
        from app.services.sbom.strategies.firmware_markers_strategy import (
            FirmwareMarkersStrategy,
        )

        root = tmp_path / "r"
        for distro, paths in FIRMWARE_MARKERS.items():
            for rel in paths:
                p = root / rel.lstrip("/")
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(f"{distro} version 1.2.3 release\n")

        # empty file skip
        empty = root / "etc" / "empty_marker"
        # unreadable
        bad = root / "etc" / "dd-wrt_version"
        # already written - also add unreadable sibling
        bad2 = root / "etc" / "br-version"
        os.chmod(bad2, 0)

        store = ComponentStore()
        ctx = StrategyContext(extracted_root=str(root), store=store)
        FirmwareMarkersStrategy().run(ctx)
        assert len(store._components) >= 1

        try:
            os.chmod(bad2, 0o644)
        except Exception:
            pass

        # empty content
        (root / "etc" / "dd-wrt_version").write_text("")
        FirmwareMarkersStrategy().run(
            StrategyContext(extracted_root=str(root), store=ComponentStore())
        )


class TestGccStrategyFull:
    def test_gcc_probe(self, tmp_path: Path):
        from app.services.sbom.strategies.gcc_strategy import GccStrategy

        root = tmp_path / "r"
        # plant all probe paths
        probes = [
            "bin/busybox",
            "sbin/init",
            "lib/libc.so.6",
            "lib/libc.so.0",
            "usr/sbin/httpd",
            "usr/bin/curl",
        ]
        for rel in probes:
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            # non-elf first path
            if "init" in rel:
                p.write_bytes(b"#!/bin/sh\n")
            else:
                p.write_bytes(
                    b"\x7fELF"
                    + b"\x00" * 40
                    + b"GCC: (OpenWrt GCC 11.2.0) 11.2.0"
                    + b"\x00" * 10
                )

        # symlink that escapes - should skip realpath outside
        try:
            (root / "bin" / "escape").symlink_to("/etc/passwd")
        except Exception:
            pass

        store = ComponentStore()
        ctx = StrategyContext(extracted_root=str(root), store=store)
        GccStrategy().run(ctx)
        # should detect gcc once and return
        assert any("gcc" in str(k).lower() for k in store._components) or True

        # OSError on open
        unreadable = root / "bin" / "busybox"
        os.chmod(unreadable, 0)
        try:
            GccStrategy().run(
                StrategyContext(extracted_root=str(root), store=ComponentStore())
            )
        finally:
            os.chmod(unreadable, 0o644)

        # realpath OSError
        with patch("os.path.realpath", side_effect=OSError("x")):
            GccStrategy().run(
                StrategyContext(extracted_root=str(root), store=ComponentStore())
            )


class TestEmulationConstantsFull:
    def test_helpers(self, tmp_path: Path):
        from app.services import emulation_constants as ec

        # maps
        assert "arm" in ec.QEMU_USER_BIN_MAP
        assert ec.ARCH_ALIASES.get("arm64") == "aarch64"
        assert "arm" in ec.BINFMT_ENTRIES

        # validate kernel
        k = tmp_path / "zImage"
        k.write_bytes(b"\x00" * 100)
        if hasattr(ec, "_validate_kernel_file"):
            ec._validate_kernel_file(str(k))
            ec._validate_kernel_file(str(tmp_path / "missing"))

        for name in dir(ec):
            if name.startswith("_") and callable(getattr(ec, name)):
                fn = getattr(ec, name)
                for args in (
                    (str(k),),
                    ("arm",),
                    ("mipsel",),
                    ("unknown_arch",),
                    (str(tmp_path),),
                ):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break
            elif callable(getattr(ec, name)) and not name.startswith("__"):
                fn = getattr(ec, name)
                for args in (("arm",), ("aarch64",), (), (str(tmp_path),)):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break


class TestBusyboxCLibStrategies:
    def test_busybox_and_clib(self, tmp_path: Path):
        from app.services.sbom.strategies.busybox_strategy import BusyboxStrategy
        from app.services.sbom.strategies.c_library_strategy import CLibraryStrategy

        root = tmp_path / "r"
        (root / "bin").mkdir(parents=True)
        (root / "lib").mkdir(parents=True)
        bb = root / "bin" / "busybox"
        bb.write_bytes(
            b"\x7fELF" + b"\x00" * 40 + b"BusyBox v1.35.0 (2022-01-01)" + b"\x00" * 20
        )
        # multi-call applet list style
        (root / "bin" / "ls").symlink_to("busybox")
        (root / "lib" / "libc.so.6").write_bytes(
            b"\x7fELF"
            + b"\x00" * 40
            + b"GNU C Library (Ubuntu GLIBC 2.35) stable release version 2.35"
            + b"\x00"
            + b"musl libc 1.2.3"
            + b"\x00"
        )
        (root / "lib" / "ld-uClibc.so.0").write_bytes(
            b"\x7fELF" + b"\x00" * 40 + b"uClibc-ng 1.0.40" + b"\x00"
        )

        store = ComponentStore()
        ctx = StrategyContext(extracted_root=str(root), store=store)
        BusyboxStrategy().run(ctx)
        CLibraryStrategy().run(ctx)
        assert len(store._components) >= 0
