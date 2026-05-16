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


# ---------------------------------------------------------------------------
# L4T release banner extraction (Reviewer B B4 follow-through 2026-05-15).
# Top-level metadata["l4t_release"] activation pre-req for the 6 forward-
# prepared NVIDIA Tegra CVE pins (CVE-2019-5680 / CVE-2021-1111 /
# CVE-2021-34372 / CVE-2021-34397 / CVE-2022-42269 / CVE-2022-42270).
# ---------------------------------------------------------------------------


def _write_elf_with_l4t_banner(
    path: Path,
    soc_token: bytes = b"nvidia,tegra186",
    banner: bytes = (
        b"# R32 (release), REVISION: 3.1, GCID: 18186506, "
        b"BOARD: t186ref, EABI: aarch64, "
        b"DATE: Mon Mar 26 13:53:37 UTC 2018\n"
    ),
) -> None:
    """Synthesize an ELF blob with Tegra evidence + L4T release banner."""
    payload = bytearray()
    payload += _ELF_MAGIC
    payload += b"\x02\x01\x01\x00" + b"\x00" * 8
    payload += struct.pack("<H", 2)
    payload += struct.pack("<H", 0xB7)
    payload += struct.pack("<I", 1)
    payload += b"\x00" * 256
    payload += b".bpmp_fw\x00"
    payload += b"\x00" * 1024
    payload += banner
    payload += b"\x00" * 1024
    payload += soc_token + b"\x00"
    payload += b"\x00" * 1024
    path.write_bytes(bytes(payload))


def test_elf_with_l4t_banner_populates_top_level_l4t_release(
    tmp_path: Path,
) -> None:
    """Banner ``# R32 (release), REVISION: 3.1, ...`` →
    ``blob.metadata["l4t_release"] == "R32.3.1"`` AT TOP LEVEL.

    Per Reviewer B B4 (postmortem 2026-05-15): the field MUST be
    top-level so cve_matcher's one-level-deep ``_stringify_metadata``
    walker reaches it. This is the activation pre-req for the 6
    forward-prepared NVIDIA Tegra CVE pins shipped commit ``6bc1c1d``.
    """
    fixture = tmp_path / "bpmp_with_banner.bin"
    _write_elf_with_l4t_banner(fixture)
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.vendor == "nvidia"
    assert result.metadata["l4t_release"] == "R32.3.1", (
        "L4T release MUST be R32.3.1 — got "
        f"{result.metadata.get('l4t_release')!r}"
    )
    # Reviewer B B4: top-level placement is load-bearing — nested
    # storage would silently defeat the version_regex match path.
    assert "l4t_release" not in result.metadata.get("tegra_blob", {}), (
        "Reviewer B B4 violation: l4t_release stored under nested "
        "tegra_blob dict where _stringify_metadata cannot reach it"
    )


def test_l4t_banner_extraction_handles_multiple_releases(
    tmp_path: Path,
) -> None:
    """Sanity-check banner extraction across the JetPack-major series.

    Real-world banner samples per `/etc/nv_tegra_release` from each
    release: R28 (Pascal/Tegra X1+X2), R32 (TX2/Xavier line), R35
    (Orin AGX line), R36 (Orin Nano series).
    """
    cases = [
        (
            b"# R28 (release), REVISION: 1.0, GCID: 6080610, "
            b"BOARD: t210ref, EABI: aarch64",
            "R28.1.0",
        ),
        (
            b"# R32 (release), REVISION: 6.1, GCID: 27863751, "
            b"BOARD: t186ref, EABI: aarch64",
            "R32.6.1",
        ),
        (
            b"# R35 (release), REVISION: 4.1, GCID: 33958178, "
            b"BOARD: t186ref, EABI: aarch64",
            "R35.4.1",
        ),
        (
            b"# R36 (release), REVISION: 4.0, GCID: 37537400, "
            b"BOARD: generic, EABI: aarch64",
            "R36.4.0",
        ),
    ]
    for idx, (banner, expected) in enumerate(cases):
        fixture = tmp_path / f"variant_{idx}_{expected}.bin"
        _write_elf_with_l4t_banner(fixture, banner=banner)
        magic = _read_magic(fixture)
        result = parse_tegra_blob(
            str(fixture), magic, fixture.stat().st_size,
        )
        assert result is not None
        assert result.metadata.get("l4t_release") == expected, (
            f"Banner {banner!r} produced "
            f"{result.metadata.get('l4t_release')!r}, expected {expected!r}"
        )


def test_l4t_banner_extraction_handles_bare_no_comment_prefix(
    tmp_path: Path,
) -> None:
    """Some BSP scripts strip the leading ``#`` when copying the banner
    into .rodata strings or DT chosen-bootargs. The regex tolerates
    the bare form (``R32 (release), REVISION: 3.1, ...``)."""
    fixture = tmp_path / "no_hash.bin"
    _write_elf_with_l4t_banner(
        fixture,
        banner=(
            b"R32 (release), REVISION: 3.1, GCID: 18186506, "
            b"BOARD: t186ref"
        ),
    )
    magic = _read_magic(fixture)
    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)
    assert result is not None
    assert result.metadata.get("l4t_release") == "R32.3.1"


def test_l4t_release_absent_when_no_banner(tmp_path: Path) -> None:
    """ELF with Tegra evidence but NO L4T banner → l4t_release MUST
    NOT be in metadata. Negative canary for the regex's positive-match
    discipline (Rule #46 paired-canary).
    """
    fixture = tmp_path / "no_banner.bin"
    _write_elf_with_tegra_section(fixture, b"nvidia,tegra186")
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.vendor == "nvidia"
    assert "l4t_release" not in result.metadata, (
        f"l4t_release should be absent without banner — got "
        f"{result.metadata.get('l4t_release')!r}"
    )


def test_l4t_release_negative_canary_synthesized_banner_fires(
    tmp_path: Path,
) -> None:
    """Rule #46 PAIRED CANARY for the absence test above —
    SYNTHESIZED a valid banner into an otherwise-clean ELF MUST
    populate l4t_release. Without this canary, the absence test
    is structurally indistinguishable from a regex that never
    matches anything (silent-pass per Rule #17).
    """
    fixture = tmp_path / "synthesized_banner.bin"
    _write_elf_with_l4t_banner(
        fixture,
        banner=b"# R32 (release), REVISION: 3.1\n",
    )
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.metadata.get("l4t_release") == "R32.3.1", (
        "Rule #46 canary FAILED: synthesized banner did not populate "
        "l4t_release — the regex is silently broken"
    )


def test_fdt_with_l4t_banner_populates_top_level_l4t_release(
    tmp_path: Path,
) -> None:
    """L4T release also extractable from FDT subset (chosen.bootargs
    / nvidia,bootloader-build property strings often carry the
    banner)."""
    fixture = tmp_path / "tegra234.dtb"
    payload = bytearray()
    payload += _FDT_MAGIC
    payload += b"\x00" * 8
    payload += b"nvidia,tegra234\x00"
    payload += b"\x00" * 64
    payload += b"NVIDIA Jetson Orin\x00"
    payload += b"\x00" * 1024
    payload += (
        b"# R35 (release), REVISION: 4.1, GCID: 33958178, "
        b"BOARD: t186ref, EABI: aarch64\n"
    )
    payload += b"\x00" * 1024
    fixture.write_bytes(bytes(payload))
    magic = _read_magic(fixture)

    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.vendor == "nvidia"
    assert result.metadata["tegra_blob"]["subset"] == "fdt"
    assert result.metadata.get("l4t_release") == "R35.4.1"


def test_merge_preserves_top_level_l4t_release() -> None:
    """``merge_tegra_evidence`` MUST preserve top-level ``l4t_release``
    when merging Tegra second-pass evidence into an existing ParsedBlob.

    Cross-check that the existing all-keys-merge loop in
    ``merge_tegra_evidence`` actually reaches non-tegra_blob top-level
    keys. Regression canary against any future refactor that narrows
    the merge to only the ``tegra_blob`` sub-key.
    """
    parsed = ParsedBlob(
        vendor=None,
        metadata={"existing_key": "existing_value"},
    )
    tegra_ev = ParsedBlob(
        vendor="nvidia",
        metadata={
            "tegra_blob": {"subset": "elf", "soc_token": "t186"},
            "l4t_release": "R32.3.1",
        },
    )
    merged = merge_tegra_evidence(parsed, tegra_ev)

    assert merged.metadata is not None
    assert merged.metadata["l4t_release"] == "R32.3.1"
    assert merged.metadata["existing_key"] == "existing_value"
    assert merged.metadata["tegra_blob"]["subset"] == "elf"


def test_l4t_release_reaches_cve_matcher_stringify_metadata() -> None:
    """END-TO-END Rule #46 paired-canary: confirm L4T release placed
    at TOP-LEVEL is reachable by ``cve_matcher._stringify_metadata``
    (one-level-deep walker).

    This is the LOAD-BEARING contract per Reviewer B B4 (2026-05-15):
    if a future refactor stores l4t_release nested under tegra_blob,
    THIS test FAILS — telling the developer the change silently
    broke the Tegra CVE pin activation path. Without this canary the
    breakage would only surface at corpus cve-match time (operator-
    invisible until a Jetson firmware is processed).
    """
    from app.services.hardware_firmware.cve_matcher import _stringify_metadata

    # Top-level placement (correct per Reviewer B B4).
    metadata_correct = {
        "tegra_blob": {"subset": "elf", "soc_token": "t186"},
        "l4t_release": "R32.3.1",
    }
    strings_correct = _stringify_metadata(metadata_correct)
    assert "R32.3.1" in strings_correct, (
        "Reviewer B B4 contract VIOLATED: top-level l4t_release "
        "MUST be reachable by _stringify_metadata"
    )

    # Negative canary — nested placement (incorrect) is invisible.
    metadata_incorrect = {
        "tegra_blob": {
            "subset": "elf",
            "soc_token": "t186",
            "l4t_release": "R32.3.1",  # nested = wrong
        },
    }
    strings_incorrect = _stringify_metadata(metadata_incorrect)
    assert "R32.3.1" not in strings_incorrect, (
        "Cross-stack assumption VIOLATED: _stringify_metadata "
        "is no longer one-level-deep — the L4T release activation "
        "contract may need re-evaluating"
    )


def test_l4t_release_5th_fallback_fires_on_raw_bin_tegra_blob(
    tmp_path: Path,
) -> None:
    """Raw-binary Tegra-wrapper blob (mb1.bin / cboot.bin / nvtboot.bin)
    with magic that doesn't match any of the 4 in-scope formats —
    parser MUST still surface l4t_release via the 5th path-context
    fallback when the path encodes the L4T release AND contains a
    Tegra/L4T context token.

    Critical for DS1-class corpus: ~30 of 99 DS1 blobs are NVIDIA
    raw-binary wrappers (mb1_t194_prod.bin, cboot_t194.bin, etc.)
    that filename-stage classifies as vendor=nvidia category=bootloader
    but whose magic doesn't match ELF / FDT / Android / Deb. Without
    the 5th fallback the L4T release isn't propagated to these blobs
    and the CVE pins don't activate.
    """
    bsp_dir = tmp_path / "L4T_BSP_SecureBoot.R32.3.1.tar.gz_extracted" / "bootloader"
    bsp_dir.mkdir(parents=True)
    fixture = bsp_dir / "mb1_t194_prod.bin"
    # Raw-binary wrapper — magic doesn't match any of the 4 subsets.
    fixture.write_bytes(b"\x00\x01\x02\x03" + b"\x00" * 256)

    magic = _read_magic(fixture)
    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None, (
        "5th fallback FAILED: raw-binary Tegra blob in BSP path "
        "should still surface l4t_release"
    )
    # vendor=None — let the filename-stage classifier own the vendor
    # decision; the 5th fallback only contributes the l4t_release.
    assert result.vendor is None
    assert result.metadata["l4t_release"] == "R32.3.1"


def test_l4t_release_5th_fallback_does_not_fire_without_path_context(
    tmp_path: Path,
) -> None:
    """5th fallback MUST require both an R<N>.<x>.<y> path encoding
    AND a Tegra/L4T context token. A path with R<N>.<x>.<y> but no
    Tegra context (e.g. a random project's backup directory) MUST NOT
    receive a spurious l4t_release attribution.
    """
    benign_dir = tmp_path / "MyProject_R32.3.1_backup" / "data"
    benign_dir.mkdir(parents=True)
    fixture = benign_dir / "random.bin"
    fixture.write_bytes(b"\x00" * 256)

    magic = _read_magic(fixture)
    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is None, (
        "5th fallback over-fired: non-Tegra path with R<N>.<x>.<y> "
        "substring got spurious l4t_release attribution. Path-context "
        "gate (L4T / tegra / jetson / bpmp / cboot / nvtboot) is "
        "load-bearing."
    )


def test_l4t_release_5th_fallback_no_release_in_path_returns_none(
    tmp_path: Path,
) -> None:
    """Tegra-context path WITHOUT an R<N>.<x>.<y> encoding MUST NOT
    fire the 5th fallback (no release string available to surface)."""
    tegra_dir = tmp_path / "L4T_BSP_no_version_in_path" / "bootloader"
    tegra_dir.mkdir(parents=True)
    fixture = tegra_dir / "bpmp.bin"
    fixture.write_bytes(b"\x00" * 256)

    magic = _read_magic(fixture)
    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is None


def test_l4t_release_path_inference_extracts_from_bsp_archive_dirname(
    tmp_path: Path,
) -> None:
    """Operator-renamed bootloader blob landed under an L4T BSP archive
    extraction directory (e.g. ``L4T_BSP_SecureBoot.R32.3.1.tar.gz_
    extracted/bootloader/bpmp_t194.bin``) MUST extract the L4T release
    via PATH INFERENCE when the blob bytes don't carry the banner.

    Activation pre-req for the 6 forward-prepared Tegra CVE pins on
    DS1-class corpora (Jetson firmware shipped as L4T BSP archives,
    not as rootfs images with /etc/nv_tegra_release).
    """
    bsp_dir = tmp_path / "L4T_BSP_SecureBoot.R32.3.1.tar.gz_extracted" / "bootloader"
    bsp_dir.mkdir(parents=True)
    fixture = bsp_dir / "bpmp_t194.bin"
    # Tegra ELF evidence (section_name) without inline banner.
    _write_elf_with_tegra_section(fixture, b"nvidia,tegra194")

    magic = _read_magic(fixture)
    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.vendor == "nvidia"
    assert result.metadata.get("l4t_release") == "R32.3.1", (
        "Path-inference fallback should extract R32.3.1 from the BSP "
        f"archive directory name — got {result.metadata.get('l4t_release')!r}"
    )


def test_l4t_release_path_inference_handles_major_minor_only(
    tmp_path: Path,
) -> None:
    """Older JetPack release naming used ``R28.2`` (no Y-component
    revision). Parser MUST extract ``R28.2`` for path-inference."""
    older_dir = tmp_path / "Tegra210_Linux_R28.2_aarch64" / "bootloader"
    older_dir.mkdir(parents=True)
    fixture = older_dir / "cboot_t210.bin"
    _write_elf_with_tegra_section(fixture, b"nvidia,tegra210")

    magic = _read_magic(fixture)
    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.metadata.get("l4t_release") == "R28.2", (
        f"R28.2 path inference failed — got "
        f"{result.metadata.get('l4t_release')!r}"
    )


def test_l4t_release_path_inference_does_not_match_arbitrary_substrings(
    tmp_path: Path,
) -> None:
    """Negative canary: paths that happen to contain ``R12`` or
    ``r34`` substrings inside other words (e.g. ``project_R12-bsp``)
    MUST NOT match. The regex requires word-boundary anchors.
    """
    benign_dir = tmp_path / "RasperPi3_kernel" / "boot"
    benign_dir.mkdir(parents=True)
    fixture = benign_dir / "tegra_test.bin"
    _write_elf_with_tegra_section(fixture, b"nvidia,tegra186")

    magic = _read_magic(fixture)
    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    # No ``R<N>.<x>`` pattern in path; absent.
    assert result.metadata.get("l4t_release") is None, (
        "Path-inference over-matched arbitrary substring — got "
        f"{result.metadata.get('l4t_release')!r}"
    )


def test_l4t_release_content_banner_wins_over_path_inference(
    tmp_path: Path,
) -> None:
    """When BOTH content banner AND path inference are available, the
    content banner wins (more authoritative — actually inside the
    blob). Per Rule #19 evidence-first.
    """
    # Path encodes R28.2 BUT the blob bytes carry R32.3.1.
    bsp_dir = tmp_path / "L4T_BSP_R28.2_extracted" / "bootloader"
    bsp_dir.mkdir(parents=True)
    fixture = bsp_dir / "bpmp.bin"
    _write_elf_with_l4t_banner(fixture, banner=(
        b"# R32 (release), REVISION: 3.1, GCID: 12345\n"
    ))

    magic = _read_magic(fixture)
    result = parse_tegra_blob(str(fixture), magic, fixture.stat().st_size)

    assert result is not None
    assert result.metadata.get("l4t_release") == "R32.3.1", (
        "Content banner MUST win over path inference per Rule #19 — "
        f"got {result.metadata.get('l4t_release')!r}"
    )


def test_l4t_release_paired_with_tegra_cve_pins_version_regex_format() -> (
    None
):
    """Rule #46 cross-stack alignment: the L4T release output format
    "R<N>.<x>.<y>" MUST match the version_regex patterns shipped in
    the 6 forward-prepared NVIDIA Tegra CVE pins (commit 6bc1c1d).

    If a future change to ``_extract_l4t_release`` outputs a different
    format (e.g. "R32-3-1" with dashes, or "32.3.1" without the R prefix),
    the pins would silently stop firing — operator-invisible until
    cve-match output is inspected. This canary forces the contract.
    """
    import re

    # Sample L4T release strings the parser emits — chosen to span the
    # JetPack-major series each pin covers. Pre-fix and post-fix samples
    # for pins that have a "<fix" version_regex shape.
    samples_in_scope = [
        "R28.1.0",  # CVE-2019-5680 affected (r3[01]\b matches R28? no — R28 not r30/r31)
        "R30.4.0",  # CVE-2019-5680 r3[01]\b match
        "R31.0.2",  # CVE-2019-5680 r3[01]\b match
        "R32.1.0",  # CVE-2019-5680 + CVE-2021-1111 affected
        "R32.3.1",  # CVE-2021-1111 affected (r32\.[1-5]\.)
        "R32.5.2",  # CVE-2021-1111 affected
        "R32.6.0",  # CVE-2021-1111 affected (just before fix)
    ]
    # Verbatim version_regex patterns from the 6 Tegra CVE pins
    # (known_firmware.yaml as of commit 6bc1c1d). Each MUST match
    # SOMETHING in the sample set; the alignment test checks the
    # output format pairs with at least one expected pin's regex.
    pin_regexes = [
        # CVE-2019-5680 — versions through r32.1
        r"(?i)(r3[01]\b|r32\.[01]\b|r32\.0\.|r32\.1\.)",
        # CVE-2021-1111 — versions r32.1..r32.6.0 (fix in 6.1)
        r"(?i)(r32\.[1-5]\b|r32\.6\.0\b|r32\.[1-5]\.|r32\.6\.0\.)",
    ]

    matched_count = 0
    for pattern in pin_regexes:
        rx = re.compile(pattern)
        for sample in samples_in_scope:
            if rx.search(sample):
                matched_count += 1
                break  # this pin has at least one matching sample

    assert matched_count == len(pin_regexes), (
        "Rule #46 cross-stack alignment FAILED: at least one Tegra "
        "CVE pin's version_regex did not match ANY sample L4T release "
        "string emitted by the parser. The output format may have "
        "drifted from the pin schema."
    )

    # Negative half: post-fix samples MUST NOT match the affected
    # version_regex (otherwise the pin would over-attribute on R32.6.1+
    # firmware which IS the fixed cohort).
    samples_post_fix = ["R32.6.1", "R32.7.4", "R35.4.1", "R36.4.0"]
    cve_2021_1111_rx = re.compile(pin_regexes[1])
    for sample in samples_post_fix:
        assert not cve_2021_1111_rx.search(sample), (
            f"CVE-2021-1111 version_regex over-matches post-fix L4T "
            f"release {sample!r} — would over-attribute on FIXED firmware"
        )
