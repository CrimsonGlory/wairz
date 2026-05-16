"""Tests for the NVIDIA Tegra content-evidence parser.

Covers each magic-byte dispatch path (ELF / FDT / Android boot.img /
Debian ar) plus the Rule #46 paired-canary (operator-renamed Tegra
ELF still classifies as vendor=nvidia via content evidence).

NVIDIA wrapper (mb1/tos) + BUP magic are deferred TBDs — no tests
yet; filename-pattern carries for those subsets until magic is
pinned from a live BSP install.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.services.hardware_firmware.parsers.base import ParsedBlob
from app.services.hardware_firmware.parsers.tegra_blob import (
    merge_tegra_evidence,
    parse_tegra_blob,
)


# ---------------------------------------------------------------------------
# Magic-byte constants for fixture synthesis. Pinned to actual values
# (Rule #19 evidence-first — magic bytes not guessed at).
# ---------------------------------------------------------------------------
_ELF_MAGIC = b"\x7fELF"
_FDT_MAGIC = b"\xd0\x0d\xfe\xed"
_ANDROID_BOOT_MAGIC = b"ANDROID!"
_DEB_AR_MAGIC = b"!<arch>\n"


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


def _write_elf_with_tegra_section(
    path: Path, soc_token: bytes = b"nvidia,tegra186",
) -> None:
    """Synthesize an ELF blob with Tegra section-name + .rodata SOC
    string evidence. Sufficient for the byte-scan to fire — does NOT
    need to be a valid ELF parseable by lief / pyelftools.
    """
    # ELF magic + minimal header padding + Tegra section name + SOC string.
    payload = bytearray()
    payload += _ELF_MAGIC  # offset 0
    payload += b"\x02\x01\x01\x00"  # EI_CLASS=64, EI_DATA=LE, EI_VERSION=1
    payload += b"\x00" * 8  # padding to e_ident[16]
    payload += struct.pack("<H", 2)  # e_type=ET_EXEC
    payload += struct.pack("<H", 0xB7)  # e_machine=EM_AARCH64
    payload += struct.pack("<I", 1)  # e_version
    payload += b"\x00" * 256  # arbitrary header area
    # The byte-scan looks for section names anywhere in the head;
    # putting them after the e_ident is fine.
    payload += b"\x00" * 1024
    payload += b".bpmp_fw\x00"  # Tegra section name
    payload += b"\x00" * 1024
    payload += b"T18x_BootStrap\x00"  # Tegra symbol prefix
    payload += b"\x00" * 1024
    payload += soc_token + b"\x00"  # .rodata SOC string
    payload += b"\x00" * 1024
    path.write_bytes(bytes(payload))


def _write_generic_arm_elf(path: Path) -> None:
    """ELF magic + no Tegra evidence — should return None."""
    payload = bytearray()
    payload += _ELF_MAGIC
    payload += b"\x02\x01\x01\x00"
    payload += b"\x00" * 8
    payload += struct.pack("<H", 2)
    payload += struct.pack("<H", 0xB7)  # AArch64
    payload += struct.pack("<I", 1)
    payload += b"\x00" * 4096  # generic body — no Tegra tokens anywhere
    # Include a non-Tegra section name to exercise the negative path.
    payload += b".text\x00.data\x00.bss\x00.rodata\x00"
    payload += b"\x00" * 4096
    path.write_bytes(bytes(payload))


def _write_fdt_with_tegra_compatible(
    path: Path, soc: str = "tegra194",
) -> None:
    """Synthesize an FDT blob with Tegra compatible/model strings.
    Sufficient for the byte-scan — not a valid FDT parseable by fdt lib.
    """
    payload = bytearray()
    payload += _FDT_MAGIC  # offset 0
    payload += b"\x00" * 8  # padding
    payload += f"nvidia,{soc}\x00".encode("ascii")
    payload += b"\x00" * 64
    payload += b"NVIDIA Jetson Xavier\x00"
    payload += b"\x00" * 1024
    path.write_bytes(bytes(payload))


def _write_generic_fdt(path: Path) -> None:
    """FDT magic + no Tegra evidence — should return None."""
    payload = bytearray()
    payload += _FDT_MAGIC
    payload += b"\x00" * 8
    payload += b"raspberrypi,4-model-b\x00"
    payload += b"\x00" * 64
    payload += b"Raspberry Pi 4 Model B\x00"
    payload += b"\x00" * 1024
    path.write_bytes(bytes(payload))


def _write_android_bootimg(path: Path, with_tegra_hint: bool = True) -> None:
    """Synthesize an Android boot.img with optional Tegra cmdline hint."""
    payload = bytearray()
    payload += _ANDROID_BOOT_MAGIC  # offset 0
    payload += b"\x00" * 56  # padding to offset 64 (cmdline region)
    if with_tegra_hint:
        cmdline = (
            b"androidboot.product=jetson-nano "
            b"androidboot.hardware=tegra210 "
            b"console=ttyS0,115200\x00"
        )
    else:
        cmdline = b"androidboot.product=oriole console=ttyS0\x00"  # Pixel 6
    payload += cmdline.ljust(512, b"\x00")
    payload += b"\x00" * 4096
    path.write_bytes(bytes(payload))


def _write_deb_ar(path: Path) -> None:
    """Minimal Debian ar archive — magic + arbitrary trailing bytes."""
    payload = _DEB_AR_MAGIC + b"\x00" * 256
    path.write_bytes(payload)


def _read_magic(path: Path) -> bytes:
    """Read first 64 bytes — matches what the detector hands the parser."""
    with open(path, "rb") as f:
        return f.read(64)


# ---------------------------------------------------------------------------
# ELF — positive + negative.
# ---------------------------------------------------------------------------


def test_elf_with_tegra_evidence_returns_nvidia_high(tmp_path: Path) -> None:
    """Canonical Tegra ELF with section name + symbol prefix +
    rodata SOC string → vendor=nvidia, confidence=high."""
    fixture = tmp_path / "bpmp_t186.bin"
    _write_elf_with_tegra_section(fixture, b"nvidia,tegra186")
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.vendor == "nvidia"
    assert result.chipset_target == "t186"
    assert result.metadata["tegra_blob"]["subset"] == "elf"
    assert result.metadata["tegra_blob"]["confidence"] == "high"
    evidence_kinds = {
        t["kind"] for t in result.metadata["tegra_blob"]["evidence_tokens"]
    }
    assert "section_name" in evidence_kinds
    assert "symbol_prefix" in evidence_kinds


def test_elf_with_only_rodata_soc_token_returns_medium(tmp_path: Path) -> None:
    """Operator stripped section names + symbols, but the .rodata
    SOC string remains → vendor=nvidia, confidence=medium."""
    fixture = tmp_path / "stripped.bin"
    payload = bytearray()
    payload += _ELF_MAGIC
    payload += b"\x02\x01\x01\x00" + b"\x00" * 8
    payload += struct.pack("<H", 2)
    payload += struct.pack("<H", 0xB7)
    payload += struct.pack("<I", 1)
    payload += b"\x00" * 2048
    payload += b"nvidia,tegra194\x00"  # ONLY rodata SOC string
    payload += b"\x00" * 2048
    fixture.write_bytes(bytes(payload))
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.vendor == "nvidia"
    assert result.chipset_target == "t194"
    assert result.metadata["tegra_blob"]["confidence"] == "medium"


def test_generic_arm_elf_returns_none(tmp_path: Path) -> None:
    """NEGATIVE — ELF without any Tegra evidence returns None
    (filename-stage decision stays authoritative)."""
    fixture = tmp_path / "generic.elf"
    _write_generic_arm_elf(fixture)
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is None


# ---------------------------------------------------------------------------
# FDT — positive + negative.
# ---------------------------------------------------------------------------


def test_fdt_with_tegra_compatible_returns_nvidia_high(
    tmp_path: Path,
) -> None:
    """Tegra DTB with nvidia,tegra* compatible + NVIDIA Jetson model
    → vendor=nvidia, confidence=high."""
    fixture = tmp_path / "tegra194-quill.dtb"
    _write_fdt_with_tegra_compatible(fixture, "tegra194")
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.vendor == "nvidia"
    assert result.chipset_target == "t194"
    assert result.metadata["tegra_blob"]["subset"] == "fdt"
    assert result.metadata["tegra_blob"]["confidence"] == "high"


def test_generic_fdt_returns_none(tmp_path: Path) -> None:
    """NEGATIVE — non-Tegra DTB (Raspberry Pi) returns None."""
    fixture = tmp_path / "rpi4.dtb"
    _write_generic_fdt(fixture)
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is None


# ---------------------------------------------------------------------------
# Android boot.img — positive + negative.
# ---------------------------------------------------------------------------


def test_android_bootimg_with_tegra_cmdline_returns_nvidia_medium(
    tmp_path: Path,
) -> None:
    """Android boot.img with Tegra cmdline hint → vendor=nvidia,
    confidence=medium (magic alone is Android-generic; medium with hint)."""
    fixture = tmp_path / "ds1-boot.img"
    _write_android_bootimg(fixture, with_tegra_hint=True)
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.vendor == "nvidia"
    assert result.metadata["tegra_blob"]["subset"] == "android_bootimg"
    assert result.metadata["tegra_blob"]["confidence"] == "medium"


def test_android_bootimg_from_non_jetson_returns_none(tmp_path: Path) -> None:
    """NEGATIVE — Android boot.img from a non-Jetson device (Pixel 6
    cmdline) returns None — refuses to fabricate Tegra attribution
    from Android-generic magic."""
    fixture = tmp_path / "pixel6-boot.img"
    _write_android_bootimg(fixture, with_tegra_hint=False)
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is None


# ---------------------------------------------------------------------------
# Debian ar (.deb).
# ---------------------------------------------------------------------------


def test_deb_ar_magic_returns_debian_medium(tmp_path: Path) -> None:
    """Debian .deb (ar archive) → vendor=debian / subset=deb_ar /
    medium confidence. Tegra-specific refinement happens inside the
    unpacked control archive."""
    fixture = tmp_path / "nvidia-l4t-bootloader_35.4.1_arm64.deb"
    _write_deb_ar(fixture)
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.vendor == "debian"
    assert result.metadata["tegra_blob"]["subset"] == "deb_ar"
    assert result.metadata["tegra_blob"]["confidence"] == "medium"


# ---------------------------------------------------------------------------
# Operator-renamed canary (Rule #46) — the load-bearing test.
# ---------------------------------------------------------------------------


def test_operator_renamed_tegra_elf_still_classifies_as_nvidia(
    tmp_path: Path,
) -> None:
    """LOAD-BEARING — a Tegra ELF blob renamed to something completely
    unrelated (``foo.bin``) STILL classifies as vendor=nvidia via
    content evidence. This is the adaptability test the user direction
    2026-05-18 specifically targets."""
    fixture = tmp_path / "foo.bin"
    _write_elf_with_tegra_section(fixture, b"nvidia,tegra234")
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.vendor == "nvidia"
    assert result.chipset_target == "t234"


# ---------------------------------------------------------------------------
# Negative magic — non-Tegra-eligible formats.
# ---------------------------------------------------------------------------


def test_non_tegra_magic_returns_none(tmp_path: Path) -> None:
    """Magic bytes that aren't ELF / FDT / ANDROID! / ar return None
    immediately — no file read attempted."""
    fixture = tmp_path / "random.bin"
    fixture.write_bytes(b"\xaa\xbb\xcc\xdd" + b"\x00" * 1024)
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is None


def test_empty_magic_returns_none(tmp_path: Path) -> None:
    """Empty magic bytes returns None (no IndexError)."""
    fixture = tmp_path / "empty.bin"
    fixture.write_bytes(b"")
    result = parse_tegra_blob(str(fixture), b"", 0)
    assert result is None


def test_short_magic_returns_none(tmp_path: Path) -> None:
    """Magic shorter than 4 bytes returns None."""
    fixture = tmp_path / "short.bin"
    fixture.write_bytes(b"AB")
    result = parse_tegra_blob(str(fixture), b"AB", 2)
    assert result is None


def test_parser_does_not_raise_on_unreadable_file(tmp_path: Path) -> None:
    """The parser contract: MUST NOT raise. A path that vanishes
    between detector-stage read and parser-stage read returns None."""
    fixture = tmp_path / "vanishing.elf"
    _write_elf_with_tegra_section(fixture)
    magic = _read_magic(fixture)
    fixture.unlink()  # delete before parse_tegra_blob reads the file

    result = parse_tegra_blob(str(fixture), magic, 4096)

    assert result is None


# ---------------------------------------------------------------------------
# merge_tegra_evidence — overlay onto existing ParsedBlob.
# ---------------------------------------------------------------------------


def test_merge_overrides_unknown_vendor_with_nvidia() -> None:
    """Tegra evidence overrides None vendor."""
    base = ParsedBlob(vendor=None, chipset_target=None, metadata={})
    overlay = ParsedBlob(
        vendor="nvidia",
        chipset_target="t186",
        metadata={"tegra_blob": {"subset": "elf"}},
    )
    merged = merge_tegra_evidence(base, overlay)
    assert merged.vendor == "nvidia"
    assert merged.chipset_target == "t186"
    assert "tegra_blob" in merged.metadata


def test_merge_preserves_competing_vendor() -> None:
    """Tegra evidence does NOT override a competing vendor — if the
    filename-stage parser set vendor=qualcomm confidently, that wins."""
    base = ParsedBlob(
        vendor="qualcomm", chipset_target="sm8450", metadata={},
    )
    overlay = ParsedBlob(
        vendor="nvidia", chipset_target="t186", metadata={},
    )
    merged = merge_tegra_evidence(base, overlay)
    assert merged.vendor == "qualcomm"
    assert merged.chipset_target == "sm8450"


def test_merge_preserves_existing_chipset_target_when_already_set() -> None:
    """Tegra evidence only populates chipset_target when None."""
    base = ParsedBlob(
        vendor="nvidia",
        chipset_target="t194",  # already set by filename-stage parser
        metadata={},
    )
    overlay = ParsedBlob(
        vendor="nvidia",
        chipset_target="t186",  # different
        metadata={},
    )
    merged = merge_tegra_evidence(base, overlay)
    # chipset_target stays as the filename-stage value (not overridden).
    assert merged.chipset_target == "t194"


def test_merge_initializes_metadata_dict_if_none() -> None:
    """If base.metadata is None, merge initializes it to {} before update."""
    base = ParsedBlob(vendor=None, chipset_target=None, metadata=None)
    overlay = ParsedBlob(
        vendor="nvidia",
        metadata={"tegra_blob": {"subset": "elf"}},
    )
    merged = merge_tegra_evidence(base, overlay)
    assert merged.metadata is not None
    assert "tegra_blob" in merged.metadata


def test_merge_debian_only_overrides_unknown_vendor() -> None:
    """Debian ar evidence: only overrides None/unknown vendors —
    if filename-stage parser already set vendor (e.g. nvidia from
    inner-deb-name filename pattern), don't override."""
    base = ParsedBlob(vendor="nvidia", metadata={})
    overlay = ParsedBlob(
        vendor="debian", metadata={"tegra_blob": {"subset": "deb_ar"}},
    )
    merged = merge_tegra_evidence(base, overlay)
    # Filename-stage vendor=nvidia wins; Debian doesn't override.
    assert merged.vendor == "nvidia"
    # But Tegra metadata still merged.
    assert "tegra_blob" in merged.metadata


# ---------------------------------------------------------------------------
# Rule #46 verification canary — confirm the negative gate fires
# on a synthesized violation. Without this canary, the negative
# tests above are silently-passing Rule #17 instances.
# ---------------------------------------------------------------------------


def test_negative_gate_canary_a_section_name_fires(tmp_path: Path) -> None:
    """SYNTHESIZED VIOLATION — adding a Tegra section name byte
    sequence to an otherwise-clean ELF MUST flip the negative test
    to positive. Confirms test_generic_arm_elf_returns_none would
    catch a regression where the parser stopped scanning for
    section names.
    """
    fixture = tmp_path / "regression_canary.elf"
    payload = bytearray()
    payload += _ELF_MAGIC
    payload += b"\x02\x01\x01\x00" + b"\x00" * 8
    payload += struct.pack("<H", 2)
    payload += struct.pack("<H", 0xB7)
    payload += struct.pack("<I", 1)
    payload += b"\x00" * 2048
    payload += b".bpmp_fw\x00"  # synthesized violation
    payload += b"\x00" * 2048
    fixture.write_bytes(bytes(payload))
    magic = _read_magic(fixture)

    # The synthesized violation MUST be caught.
    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)
    assert result is not None, (
        "Rule #46 canary FAILED: synthesized .bpmp_fw section name "
        "did not trigger Tegra detection — the section-name scan is "
        "silently broken"
    )
    assert result.vendor == "nvidia"
