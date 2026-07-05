"""Unit tests for SBOM service additions: vendor-layout busybox + .ko vermagic.

Covers Bug 5 (generate_sbom returned 0 components on the Wyze fixture). The
underlying issues were:
  1. BusyBox lives at /bin/busybox/bin/busybox in this firmware, not /bin/busybox.
  2. Kernel modules live in /ko/, not /lib/modules/<version>/, so the kernel
     version detector found nothing.
"""
from __future__ import annotations

from pathlib import Path

from app.services.sbom.service import SbomService


def _make_dirs(base: Path, layout: dict) -> None:
    for name, contents in layout.items():
        path = base / name
        if isinstance(contents, dict):
            path.mkdir(parents=True, exist_ok=True)
            _make_dirs(path, contents)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"" if contents is None else contents)


def _fake_elf_with_strings(strings: list[str], padding_before: int = 0) -> bytes:
    """Build an ELF-magic file with embedded strings.

    *padding_before* puts the first string deeper into the file. The default
    BusyBox binary in some firmware ships with the banner at offset 300K+, so
    the ELF header read limit (256KB) misses it — see _scan_busybox_at fix.
    """
    elf_header = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 56
    body = b"\x00" * padding_before
    body += b"\x00".join(s.encode() for s in strings) + b"\x00\x00"
    return elf_header + body + b"\x00" * 256


class TestBusyboxScan:
    def test_finds_busybox_at_standard_location(self, tmp_path: Path):
        _make_dirs(tmp_path, {
            "bin": {
                "busybox": _fake_elf_with_strings(["BusyBox v1.36.1 (built)"]),
            },
        })
        components = SbomService(str(tmp_path)).generate_sbom()
        assert any(c["name"] == "busybox" and c["version"] == "1.36.1" for c in components)

    def test_finds_busybox_at_wyze_nested_location(self, tmp_path: Path):
        # Regression: Wyze cameras ship busybox at /bin/busybox/bin/busybox
        # because /bin/busybox is a directory of installed symlink targets.
        _make_dirs(tmp_path, {
            "bin": {
                "busybox": {
                    "bin": {
                        "busybox": _fake_elf_with_strings(["BusyBox v1.22.1"]),
                    },
                },
            },
        })
        components = SbomService(str(tmp_path)).generate_sbom()
        assert any(c["name"] == "busybox" and c["version"] == "1.22.1" for c in components)

    def test_finds_busybox_with_banner_past_256kb(self, tmp_path: Path):
        # The BusyBox banner often lives in rodata past offset 0x40000. Make
        # sure the scanner reads enough of the file to catch it.
        _make_dirs(tmp_path, {
            "bin": {
                "busybox": _fake_elf_with_strings(
                    ["BusyBox v1.30.1"], padding_before=300 * 1024
                ),
            },
        })
        components = SbomService(str(tmp_path)).generate_sbom()
        assert any(c["name"] == "busybox" and c["version"] == "1.30.1" for c in components)

    def test_skips_oversized_busybox_candidate(self, tmp_path: Path):
        # 5MB candidate — outside the 4MB read cap. Don't crash; just skip.
        bin_path = tmp_path / "bin" / "busybox"
        bin_path.parent.mkdir()
        bin_path.write_bytes(b"\x7fELF" + b"\x00" * (5 * 1024 * 1024))

        components = SbomService(str(tmp_path)).generate_sbom()
        assert not any(c["name"] == "busybox" for c in components)


class TestKernelFromKoVermagic:
    def test_extracts_kernel_version_from_ko(self, tmp_path: Path):
        # Wyze keeps kernel modules in /ko/, not /lib/modules/<version>/.
        # vermagic= rodata in any .ko file gives us the kernel version.
        ko_data = (
            b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 100
            + b"\x00vermagic=3.10.14-Archon preempt mod_unload MIPS32_R1 32BIT \x00"
            + b"\x00" * 100
        )
        _make_dirs(tmp_path, {"ko": {"exfat.ko": ko_data}})

        components = SbomService(str(tmp_path)).generate_sbom()
        assert any(
            c["name"] == "linux-kernel"
            and c["version"] == "3.10.14"
            and c["detection_source"] == "kernel_vermagic"
            for c in components
        )

    def test_prefers_lib_modules_over_ko_vermagic(self, tmp_path: Path):
        # When both are present, the /lib/modules/<version>/ path is more
        # canonical. Don't double-emit.
        ko_data = b"\x7fELF" + b"\x00" * 100 + b"vermagic=4.4.0-stuff\x00"
        _make_dirs(tmp_path, {
            "lib": {"modules": {"5.10.0-arm64": {"kernel": {}}}},
            "ko": {"exfat.ko": ko_data},
        })
        components = SbomService(str(tmp_path)).generate_sbom()
        kernels = [c for c in components if c["name"] == "linux-kernel"]
        assert len(kernels) == 1
        assert kernels[0]["version"] == "5.10.0"
        assert kernels[0]["detection_source"] == "kernel_modules"

    def test_no_ko_no_kernel(self, tmp_path: Path):
        # _scan_from_vermagic also scans sibling dirs of extracted_root (for
        # Android partition splits); pytest's tmp_path fixture shares a common
        # parent across every test in the session, so using tmp_path directly
        # as extracted_root risks picking up a sibling test's .ko fixture
        # (e.g. test_extracts_kernel_version_from_ko's exfat.ko). Nest one
        # level deeper so this test has no siblings to leak from.
        root = tmp_path / "extracted"
        _make_dirs(root, {"bin": {}, "lib": {}})
        components = SbomService(str(root)).generate_sbom()
        assert not any(c["name"] == "linux-kernel" for c in components)
