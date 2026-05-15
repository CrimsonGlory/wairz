"""Tests for NVIDIA Tegra (Jetson L4T) classifier patterns.

The DS1 d360f8f5 incident (Tegra TX2 + Xavier nested firmware bundles)
motivated wairz to extend firmware_patterns.yaml beyond the
Qualcomm/MediaTek/Broadcom/Cypress/Realtek corpus. Per Scout A research
(2026-05-18) covering the L4T R32+ payload structure.

The patterns are content-evidence-friendly: each Tegra blob (bpmp /
cboot / nvtboot / tos-trusty / spe / adsp-fw / mce_* / camera-rtcpu /
dram-ecc) gets classified via filename heuristic with HIGH confidence
when the canonical naming convention applies. Operator-customised
filenames fall through to the default 'other' classification — no
hard-coded vendor allowlist for the recursion gate (per the 2026-05-18
adaptability lens).

The signing-posture metadata, content-evidence parsing (ELF / DTB /
Android boot.img magic), L4T version mining from the BSP .deb, and
CVE attribution (CVE-2019-5680 / CVE-2021-1111 / CVE-2021-34372..34397)
are FUTURE work — this commit ships the CLASSIFICATION-only layer so
the recursion-unlocked blobs are visible in the UI + countable via
detection_audit.blobs_detected.
"""

from __future__ import annotations

import pytest

from app.services.hardware_firmware import patterns_loader as PL


# ---------------------------------------------------------------------------
# Bootloaders — BPMP, MB1, MB2/nvtboot, cboot, u-boot, warmboot,
# slot_metadata. All should map to vendor=nvidia, category=bootloader.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename",
    [
        "bpmp.bin",
        "bpmp_t186.bin",
        "bpmp_t194.bin",
        "mb1_recovery.bin",
        "mb1_recovery_prod.bin",
        "mb1_t194_prod.bin",
        "nvtboot.bin",
        "nvtboot_t194.bin",
        "nvtboot_recovery.bin",
        "nvtboot_cpu.bin",
        "nvtboot_recovery_cpu_t194.bin",
        "nvtboot_applet_t194.bin",
        "cboot.bin",
        "cboot_t194.bin",
        "u-boot-jetson-tx2-cot.bin",
        "u-boot-jetson-xavier.bin",
        "warmboot.bin",
        "warmboot_t194_prod.bin",
        "nvtbootwb0.bin",
    ],
)
def test_tegra_bootloader_classification(filename: str) -> None:
    m = PL.match(filename)
    assert m is not None, f"{filename} should classify as nvidia bootloader"
    assert m.vendor == "nvidia", f"{filename} got vendor={m.vendor}"
    assert m.category == "bootloader", f"{filename} got category={m.category}"
    assert m.confidence == "high"


# ---------------------------------------------------------------------------
# TEE — Trusty + ATF BL31 bundle (tos-trusty.img / tos-mon-only.img /
# tos_t194.img), plus the Encrypted Key Set (eks.img).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename",
    [
        "tos-trusty.img",
        "tos-trusty_t194.img",
        "tos-mon-only.img",
        "tos-mon-only_t194.img",
        "tos_t194.img",
        "eks.img",
    ],
)
def test_tegra_tee_classification(filename: str) -> None:
    m = PL.match(filename)
    assert m is not None
    assert m.vendor == "nvidia"
    assert m.category == "tee"


# ---------------------------------------------------------------------------
# MCU — MCE/MTS microcode (Denver d15 + Carmel c10) + preboot + SPE
# + DRAM ECC. The TX2 ships combined mce_mts_d15_prod_cr.bin (one blob
# carrying both MCE + MTS); regex accepts mce_/mts_/mce_mts_ prefixes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename",
    [
        "mce_mts_d15_prod_cr.bin",
        "mts_mce_d15_prod_cr.bin",
        "mce_c10_prod_cr.bin",
        "mts_c10_prod_cr.bin",
        "mce_c10_prod.bin",
        "preboot_c10_prod_cr.bin",
        "preboot_d15_prod_cr.bin",
        "spe.bin",
        "spe_t194.bin",
        "dram-ecc.bin",
        "dram-ecc_t194.bin",
        "badpage.bin",
    ],
)
def test_tegra_mcu_classification(filename: str) -> None:
    m = PL.match(filename)
    assert m is not None, f"{filename} should classify as nvidia mcu"
    assert m.vendor == "nvidia"
    assert m.category == "mcu"


# ---------------------------------------------------------------------------
# DSP — ADSP firmware (Tensilica HiFi DSP).
# ---------------------------------------------------------------------------


def test_tegra_adsp_classification() -> None:
    m = PL.match("adsp-fw.bin")
    assert m is not None
    assert m.vendor == "nvidia"
    assert m.category == "dsp"


# ---------------------------------------------------------------------------
# Camera RTCPU — R-Core Engine + Sensor-Capture Engine images.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename",
    [
        "camera-rtcpu-rce.img",
        "camera-rtcpu-sce.img",
        "camera-rtcpu-rce_t194.img",
    ],
)
def test_tegra_camera_rtcpu_classification(filename: str) -> None:
    m = PL.match(filename)
    assert m is not None
    assert m.vendor == "nvidia"
    assert m.category == "camera"


# ---------------------------------------------------------------------------
# USB — XUSB SIL host firmware.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename",
    [
        "xusb_sil_rel_fw",
        "xusb_sil_prod_fw",
    ],
)
def test_tegra_xusb_classification(filename: str) -> None:
    m = PL.match(filename)
    assert m is not None
    assert m.vendor == "nvidia"
    assert m.category == "usb"


# ---------------------------------------------------------------------------
# DTBs — Tegra device tree blobs (T186/T194/T210/T234).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename",
    [
        "tegra186-quill-p3310-1000-c03-00-base.dtb",
        "tegra194-p2972-0000-p2888-0004.dtb",
        "tegra210-jetson-nano.dtb",
        "tegra234-p3701-0000-p3737-0000.dtb",
        "tegra186-something.dtbo",
    ],
)
def test_tegra_dtb_classification(filename: str) -> None:
    m = PL.match(filename)
    assert m is not None
    assert m.vendor == "nvidia"
    assert m.category == "dtb"
    assert m.format == "dtb"


# ---------------------------------------------------------------------------
# Bootloader Update Payloads + L4T Debian + DS1 vendor images +
# slot_metadata + bmp.blob — all under category "other" with
# format=signed_archive where appropriate.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename,expected_format",
    [
        ("bl_update_payload", "signed_archive"),
        ("bl_only_payload", "signed_archive"),
        ("kernel_only_payload", "signed_archive"),
        ("my_payload.bup", "signed_archive"),
        ("nvidia-l4t-bootloader_32.3.1-20191209230245_arm64.deb", "signed_archive"),
    ],
)
def test_tegra_signed_archive_classification(filename: str, expected_format: str) -> None:
    m = PL.match(filename)
    assert m is not None, f"{filename} unclassified"
    assert m.vendor == "nvidia"
    assert m.category == "other"
    assert m.format == expected_format


def test_tegra_slot_metadata() -> None:
    m = PL.match("slot_metadata.bin")
    assert m is not None
    assert m.vendor == "nvidia"


def test_jetson_ds1_image_classification() -> None:
    """Vendor-customised image names get MEDIUM confidence because the
    prefix is operator-supplied — downstream content parsing
    (ANDROID! magic check) refines to high."""
    m_boot = PL.match("ds1-boot.img")
    assert m_boot is not None
    assert m_boot.vendor == "nvidia"
    assert m_boot.confidence == "medium"

    m_image = PL.match("ds1-image.img")
    assert m_image is not None
    assert m_image.vendor == "nvidia"


# ---------------------------------------------------------------------------
# Negative cases — non-Tegra filenames must NOT classify as nvidia.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename",
    [
        "modem.b00",
        "tz.mbn",
        "BTFM.bin",
        "wcnss.bin",
        "boot.img",  # generic Android boot.img, not Jetson ds1-*
        "system.img",
        "modem.bin",
    ],
)
def test_non_tegra_filenames_do_not_misclassify_as_nvidia(filename: str) -> None:
    m = PL.match(filename)
    if m is not None:
        assert m.vendor != "nvidia", (
            f"{filename} should NOT classify as nvidia; got vendor={m.vendor}"
        )
