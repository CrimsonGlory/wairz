"""Bluetooth firmware banner-string parser (content-based vendor attribution).

Handles classifier format ``bt_fw_banner``. Reads up to ``_SCAN_BYTES`` of
a candidate BT firmware blob and identifies the vendor + chipset + version
banner from CONTENT, not filename.

This parser exists to make the BTFM→Broadcom misattribution class
IMPOSSIBLE by construction (see ``.planning/postmortems/postmortem-btfm-
correction-and-corpus-2026-05-15.md``). Filename heuristics alone produced
a confident-looking mistake (yesterday's commit ``f6bdc4e`` mapped BTFM.bin
to vendor=broadcom because the filename "looked Broadcom-ish"); the
content evidence (``BTFM.CMC.x.y.z-QCACHROMZ-1`` banners, ``PF=WCN3950ROM=``
build strings, zero ``broadcom``/``brcm`` strings anywhere in the file) was
unambiguous. This parser reads those banners directly and populates
``ParsedBlob.vendor`` + ``ParsedBlob.version`` + ``ParsedBlob.chipset_target``
so downstream classification (and CVE matching) sees content-derived
attribution that cannot be wrong about the vendor.

Supported families:

* **QCA Atheros Rome / WCN3xx0 / FastConnect** — TLV-wrapped Bluetooth
  patch payloads with ``BTFM.<3-letter-codename>.<major>.<minor>.<patch>
  -<build>-<rom>-N`` banners. Codenames observed in the wild + via
  ``drivers/bluetooth/btqca.c`` upstream Linux: CMC (Comanche → WCN3950),
  CHE (Cherokee → WCN3990/3991/3998), APA (Apache → WCN3988 / AR3002
  legacy), HAS (Hastings → QCA6390), MOS (Moselle → WCN6750). The
  ``Patch Release PF=<chip>ROM=`` ASCII line carries the authoritative
  chipset name when present.

* **Broadcom / Cypress / Infineon HCD** — concatenated HCI command stream
  with ``BRCMcfgS`` / ``BRCMcfgD`` magic tags in the first 1 KB. Chip ID
  is encoded as ``BCM43455`` / ``BCM4345C0`` / etc. ASCII inside the
  descriptor block. Format is identical across Broadcom, Cypress, and
  Infineon AIROC successor packages (Cypress acquired Broadcom IoT 2016;
  Infineon acquired Cypress connectivity 2020). The walker validates an
  HCI stream of ``0xFC4C`` (WRITE_RAM) commands terminated by ``0xFC4E``
  (LAUNCH_RAM) — the textbook Broadcom HCD shape.

* **MediaTek WMT / btmtk patches** — 32-byte ``btmtk_patch_header``
  struct (datetime[16] + platform[4] + hwver/swver + magicnum) per
  upstream ``drivers/bluetooth/btmtk.c``. Disambiguated from MediaTek
  WLAN firmware via BT-specific ASCII markers (``WMT``, ``BT_FW``,
  ``btmtk``, ``bluetooth``) in the first 4 KB.

* **Unknown / negative case** — files that pass the BT-category filename
  filter but don't match any of the above signatures (e.g. NV calibration
  ``.bin`` files without banner data) return a ``ParsedBlob`` with no
  vendor / version / chipset_target populated and ``metadata.bt_fw_banner
  ={"family": "unknown", ...}``. This is deliberate: the classifier's
  filename-stage decision stays as the authoritative answer when the
  parser can't refine it.

Tier 0 version-pin output:

* QCA Rome WCN3950 / WCN3990 / WCN3998 builds get a BRAKTOOTH
  (CVE-2021-28139 cluster) pin populated into
  ``metadata.known_vulnerabilities`` with confidence="high".
  Rationale: per the ASSET disclosure matrix (Garbelini et al. 2021),
  Qualcomm marked Rome BT patches "TBA" — the in-field BTFM builds
  remain unpatched, so any banner that confirms a Rome chipset is
  direct evidence the device participates in the BRAKTOOTH attack
  surface. The curated YAML Tier 3 also fires this cluster via
  soft-chipset match; Tier 0 produces the higher-confidence signal
  because the parser saw the banner directly.

Parser contract reminders:

* MUST NOT raise. On any internal error return ``ParsedBlob(metadata=
  {"error": "..."})`` so detection continues for other blobs.
* The vendor extension to ``ParsedBlob`` (``vendor: str | None``) is
  consumed by ``detector.py`` which overrides ``Classification.vendor``
  with ``ParsedBlob.vendor`` when set — content evidence overrides
  filename evidence by design.

Refs:
* ``drivers/bluetooth/btqca.c`` / ``btqca.h`` (Linux upstream) — TLV
  header layout + codename↔chipset switch.
* ``drivers/bluetooth/btmtk.c`` / ``btmtksdio.c`` (Linux upstream) —
  MediaTek btmtk_patch_header struct.
* ``drivers/bluetooth/btbcm.c`` (Linux upstream) — Broadcom HCD load.
* Scout research notes 2026-05-16 (this campaign).
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


# Read windows. Banner location varies by family:
#   * BTFM .ver files (33 bytes total) — banner is the file itself
#   * BTFM .tlv files — banner is at the FILE TAIL (e.g. cmbtfw13.tlv
#     places `BTFM.CMC.1.3.0-...` at offset 14584 / size 15375; crbtfw21.tlv
#     places it at offset 217936 / size 220140). The TLV payload contains
#     the patch first; ASCII metadata is appended after.
#   * Broadcom HCD — BRCMcfgS tag in the first 1 KB
#   * MediaTek WMT — 32-byte btmtk_patch_header at offset 0
# We scan a generous HEAD window (handles HCD/MediaTek/short .ver files)
# AND a TAIL window (handles all .tlv BTFM patches regardless of size).
# Combined I/O is ~12 KB per blob — cheap.
_HEAD_SCAN_BYTES = 4 * 1024
_TAIL_SCAN_BYTES = 8 * 1024

# Broadcom config-block magic — anchors HCD verdicts.
_BRCM_CFG_TAGS = (b"BRCMcfgS", b"BRCMcfgD")

# QCA Rome BTFM banner — handles the variants observed in the wild AND
# in linux-firmware /qca/:
#   BTFM.CMC.1.3.0-00069-QCACHROMZ-1            (signed-Z, integer build)
#   BTFM.CHE.2.0.0-00082-QCACHROMZ-1
#   BTFM.CHE.1.1.0-00027-QCACHROM-1             (unsigned-no-Z)
#   CI_BTFM.CHE.2.0.0-00076.1-QCACHROM-16       (CI prefix + dotted build)
#   BTFM.CMC.1.0.0-00013-QCACHROM-1             (early Comanche)
#   BTFM.HAS.2.0.0-00043-QCAHTROM-1             (Hastings / QCA6390)
#   BTFM.MOS.2.1.0-00027-QCAMTROM-1             (Moselle / WCN6750)
# Reviewer B (2026-05-16): keep codename match at 3 letters per upstream
# kernel pattern (Qualcomm's CAF release scripts always emit 3-letter tags);
# rom_tag stays general (QCA[A-Z0-9]+) so new family tags (QCAHTROM,
# QCAMTROM, …) work without per-family regex tweaks.
_QCA_BANNER_RE = re.compile(
    rb"(?P<prefix>(?:CI_)?)"
    rb"BTFM\."
    rb"(?P<codename>[A-Z]{3})\."
    rb"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    rb"-(?P<build>\d+(?:\.\d+)?)"
    rb"-(?P<rom_tag>QCA[A-Z0-9]+?)"
    rb"-(?P<patchn>\d+)"
)

# QCA Rome patch-release line — carries the AUTHORITATIVE chipset name.
# Example observed on G32 cmbtfw13.tlv:
#   "Patch Release PF=WCN3950ROM= 0103 BUILD=BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
# Note the lack of separator between the chip and "ROM=" — the firmware
# printf joins them. Match the chip name non-greedy-up-to-ROM=.
_QCA_PATCH_RELEASE_RE = re.compile(
    rb"PF=(?P<chip>(?:WCN|QCA)\d{4,5}[A-Z]?)ROM=\s*(?P<rom_rev>[0-9A-Fa-f]+)"
    rb"\s+BUILD=(?P<build_banner>(?:CI_)?BTFM\.[A-Z]{3}\.\d+\.\d+\.\d+-\d+(?:\.\d+)?-QCA[A-Z0-9]+-\d+)"
)

# Codename → canonical chipset target. Sources (Linux upstream, both
# headers + driver source code; Yocto meta-qcom; Fairphone 4 BT patches):
#   * btqca.c qca_uart_setup() switch / btqca.h enum qca_btsoc_type
#   * patches.linaro.org/project/linux-devicetree/cover/20230421-fp4-bluetooth
#   * github.com/bgodavar/qca_wcn3990_firmware (CodeAurora reference)
# The codename column is the FIRST chipset the codename ships on; ranges
# are recorded in the comment when the same codename spans multiple chips
# (e.g. Cherokee = WCN3990 + WCN3991 + WCN3998). Emits ``None`` when
# codename is unrecognised so chipset_target stays NULL rather than
# guessing wrong.
_QCA_CODENAME_TO_CHIPSET: dict[str, str] = {
    "CMC": "wcn3950",   # Comanche → WCN3950 (single-core BT for SDM4xx/6xx)
    "CHE": "wcn3990",   # Cherokee → WCN3990/3991/3998 (FastConnect 6200)
    "APA": "wcn3988",   # Apache → WCN3988 (Fairphone 4) / AR3002 legacy
    "HAS": "qca6390",   # Hastings → QCA6390
    "MOS": "wcn6750",   # Moselle → WCN6750
}

# Codename → human-readable display name for metadata.
_QCA_CODENAME_DISPLAY: dict[str, str] = {
    "CMC": "Comanche",
    "CHE": "Cherokee",
    "APA": "Apache",
    "HAS": "Hastings",
    "MOS": "Moselle",
}

# BRAKTOOTH (CVE-2021-28139 cluster, ASSET Group / SUTD disclosure 2021).
# WCN3990 / WCN3950 / WCN3998 in the ASSET vulnerability matrix.
# Qualcomm marked patches "TBA" in their 2021 PSIRT response; in-field
# WCN3xx0 BTFM patches remain unpatched. Any banner that confirms a Rome
# chipset is direct evidence the device participates in the BRAKTOOTH
# attack surface.
_BRAKTOOTH_CHIPSETS = frozenset({"wcn3950", "wcn3990", "wcn3991", "wcn3998"})
_BRAKTOOTH_CVES: tuple[tuple[str, str], ...] = (
    ("CVE-2021-28139", "high"),     # RCE via crafted LMP packets (CVSS 8.8)
    ("CVE-2021-34147", "medium"),   # LMP_timing_accuracy DoS
    ("CVE-2021-31609", "medium"),   # Oversized-packet DoS
    ("CVE-2021-31612", "medium"),   # Oversized-packet DoS
)

# Broadcom HCI vendor-specific opcodes (little-endian 16-bit on disk).
# OGF=0x3F → high byte = 0xFC.
_BCM_OPCODE_WRITE_RAM = b"\x4c\xfc"
_BCM_OPCODE_LAUNCH_RAM = b"\x4e\xfc"
_BCM_OPCODE_LAUNCH_RAM_ALT = b"\x4f\xfc"
_BCM_OPCODE_DOWNLOAD_MINIDRIVER = b"\x2e\xfc"
_BCM_VALID_OPCODES = frozenset(
    {_BCM_OPCODE_WRITE_RAM, _BCM_OPCODE_LAUNCH_RAM,
     _BCM_OPCODE_LAUNCH_RAM_ALT, _BCM_OPCODE_DOWNLOAD_MINIDRIVER}
)

# Broadcom chip-ID extraction. Examples: "BCM43430A1", "BCM4345C0",
# "BCM43455", "CYW43455". CYW43xxx is Cypress (later Infineon AIROC).
_BCM_CHIP_RE = re.compile(rb"\b(BCM\d{4,5}[A-Z0-9_-]*)\b")
_CYW_CHIP_RE = re.compile(rb"\b(CYW\d{4,5}[A-Z0-9_-]*)\b")
_BCM_BUILD_LINE_RE = re.compile(
    rb"(?:BCM|CYW)\d{4,5}[A-Z0-9_-]*"
    rb"(?:[ \t][\x20-\x7e]{0,128})?"  # optional rest of build line (NUL-terminated typically)
)
_BCM_BUILD_DATE_RE = re.compile(
    rb"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}\b"
)

# MediaTek WMT / btmtk patch identifiers. Header struct from upstream
# Linux ``drivers/bluetooth/btmtk.c``:
#   offset  0..15  datetime[16]   (ASCII build timestamp; NUL-padded)
#   offset 16..19  platform[4]    (ASCII chip family tag)
#   offset 20..21  hwver (le16)
#   offset 22..23  swver (le16)
#   offset 24..27  magicnum (le32; vendor-specific, no public constant)
# BT vs WiFi disambiguation: both subsystems share this header shape;
# BT-specific markers (WMT/BT_FW/btmtk/bluetooth) in the first 4 KB are
# the distinguishing signal.
_MTK_BT_TAG_RES: tuple[re.Pattern[bytes], ...] = (
    re.compile(rb"\bWMT(?:[_ ]?(?:OP|TEST|CMD|EVT|FW|PATCH|RESET|ANT))?\b"),
    re.compile(rb"\bbtmtk\b", re.IGNORECASE),
    re.compile(rb"\bBT_FW\b"),
    re.compile(rb"\bBTPatch\b", re.IGNORECASE),
    re.compile(rb"\bbluetooth\b", re.IGNORECASE),
    re.compile(rb"\bbt_patch_release\b", re.IGNORECASE),
)

# MediaTek BT chip IDs from upstream linux-firmware mediatek/ + DPCS10
# corpus survey. Used to disambiguate MT-prefixed chip names from the
# generic MT regex when the firmware embeds them in the platform tag.
_MTK_KNOWN_CHIPS = (
    b"MT7961", b"MT7921", b"MT7922", b"MT7925", b"MT7902", b"MT7927",
    b"MT7663", b"MT7668", b"MT6620", b"MT6628", b"MT6630", b"MT6632",
    b"MT6635", b"MT6639", b"MT6789", b"MT6895", b"MT6983", b"MT6985",
)

# MediaTek generic chip-id regex — fallback when no known-chip token
# matched. The classifier already gates this code path to BT files.
_MTK_CHIP_RE = re.compile(rb"\bMT(?P<chip>\d{4})\b")

# Filename → MediaTek chipset (extracted when content didn't pin the chip
# — e.g. headerless ROM patch chunks).
_MTK_FILENAME_CHIP_RE = re.compile(r"^(?:mt|romv)(?P<chip>\d{4})", re.IGNORECASE)


def _read_head(path: str, limit: int) -> bytes:
    """Read up to ``limit`` bytes from ``path``. Empty bytes on any OSError."""
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _read_tail(path: str, size: int, limit: int) -> bytes:
    """Read up to ``limit`` bytes from the END of ``path``.

    Returns the same bytes as ``head`` when the file is shorter than
    ``limit`` (caller can de-dup if needed). Empty bytes on any OSError.
    """
    if size <= limit:
        return _read_head(path, size)
    try:
        with open(path, "rb") as f:
            f.seek(size - limit)
            return f.read(limit)
    except OSError:
        return b""


def _parse_qca_banner(data: bytes) -> dict[str, Any] | None:
    """Parse a QCA Rome BTFM banner from ``data`` (first ~4 KB).

    Returns ``None`` if no banner found, else a dict with the structured
    banner fields. Looks for the rich ``Patch Release PF=...ROM= ... BUILD=``
    line first (carries the authoritative chipset name); falls back to the
    plain ``BTFM.<codename>.x.y.z-...`` regex when only the banner is
    present (typical for .ver companion files).
    """
    # First try the PF= patch-release line — strongest evidence including chip.
    pr = _QCA_PATCH_RELEASE_RE.search(data)
    if pr:
        chip_raw = pr.group("chip").decode("ascii", errors="replace")
        rom_rev = pr.group("rom_rev").decode("ascii", errors="replace")
        banner_bytes = pr.group("build_banner")
        bm = _QCA_BANNER_RE.search(banner_bytes)
        if bm is None:
            # Shouldn't happen given the regex composition, but fail soft.
            return None
        return _build_qca_record(bm, chip_override=chip_raw.lower(), rom_rev=rom_rev)
    # Fallback: bare banner anywhere in the scan window.
    bm = _QCA_BANNER_RE.search(data)
    if bm:
        return _build_qca_record(bm, chip_override=None, rom_rev=None)
    return None


def _build_qca_record(
    m: re.Match[bytes],
    *,
    chip_override: str | None,
    rom_rev: str | None,
) -> dict[str, Any]:
    """Build the canonical QCA Rome record dict from a banner regex match."""
    codename = m.group("codename").decode("ascii", errors="replace").upper()
    major = m.group("major").decode("ascii", errors="replace")
    minor = m.group("minor").decode("ascii", errors="replace")
    patch = m.group("patch").decode("ascii", errors="replace")
    build = m.group("build").decode("ascii", errors="replace")
    rom_tag = m.group("rom_tag").decode("ascii", errors="replace")
    patchn = m.group("patchn").decode("ascii", errors="replace")
    prefix = m.group("prefix").decode("ascii", errors="replace") or ""
    # Signed marker is the trailing "Z" on QCACHROMZ / QCAMTROMZ / etc.
    signed = rom_tag.endswith("Z")

    # Reconstruct the canonical banner string for blob.version.
    banner = (
        f"{prefix}BTFM.{codename}.{major}.{minor}.{patch}"
        f"-{build}-{rom_tag}-{patchn}"
    )

    # Chipset preference: PF= override > codename table > None.
    chipset_target: str | None = None
    chipset_source: str = "none"
    if chip_override:
        chipset_target = chip_override
        chipset_source = "pf_field"
    elif codename in _QCA_CODENAME_TO_CHIPSET:
        chipset_target = _QCA_CODENAME_TO_CHIPSET[codename]
        chipset_source = "codename_map"

    rec: dict[str, Any] = {
        "family": "qca_rome",
        "vendor": "qualcomm",
        "banner": banner,
        "codename": codename,
        "codename_display": _QCA_CODENAME_DISPLAY.get(codename),
        "version_tuple": [int(major), int(minor), int(patch)],
        "build_id": build,
        "rom_tag": rom_tag,
        "patch_index": int(patchn) if patchn.isdigit() else patchn,
        "signed": "signed" if signed else "unsigned",
        "ci_build": prefix == "CI_",
        "chipset_target": chipset_target,
        "chipset_source": chipset_source,
    }
    if rom_rev is not None:
        rec["rom_revision"] = rom_rev
    return rec


def _walk_hci_stream(data: bytes) -> dict[str, Any] | None:
    """Walk a candidate HCI command stream and decide if it's a Broadcom HCD.

    Returns a dict with parse stats on success, or None when the walk
    fails (un-recognised opcodes / truncation / no LAUNCH_RAM terminator).

    Conservative validator per Scout B (2026-05-16):
    1. data[0:2] == 0x4c 0xfc (WRITE_RAM) AND data[2] >= 4
    2. Sequential walk i += 3 + data[i+2] terminates EXACTLY at len(data)
    3. Final opcode is LAUNCH_RAM (0x4e fc) or alias (0x4f fc)
    4. All intermediate opcodes ∈ _BCM_VALID_OPCODES
    """
    n = len(data)
    if n < 7:
        return None
    if data[0:2] != _BCM_OPCODE_WRITE_RAM:
        return None
    if data[2] < 4:  # WRITE_RAM payload must include the 4-byte address at least
        return None

    i = 0
    cmds = 0
    write_ram = 0
    launch_ram = 0
    last_opcode: bytes | None = None
    while i + 3 <= n:
        op = bytes(data[i : i + 2])
        plen = data[i + 2]
        if op not in _BCM_VALID_OPCODES:
            return None
        if i + 3 + plen > n:
            return None
        if op == _BCM_OPCODE_WRITE_RAM:
            write_ram += 1
        elif op in (_BCM_OPCODE_LAUNCH_RAM, _BCM_OPCODE_LAUNCH_RAM_ALT):
            launch_ram += 1
        last_opcode = op
        i += 3 + plen
        cmds += 1

    if i != n:
        return None
    if last_opcode not in (_BCM_OPCODE_LAUNCH_RAM, _BCM_OPCODE_LAUNCH_RAM_ALT):
        return None

    return {
        "commands": cmds,
        "write_ram": write_ram,
        "launch_ram": launch_ram,
    }


def _parse_broadcom_hcd(
    head: bytes, full_data: bytes | None, size: int
) -> dict[str, Any] | None:
    """Parse a candidate Broadcom HCD file.

    Args:
        head: First ``_SCAN_BYTES`` of the file (always read).
        full_data: Full file bytes, OR ``None`` if not loaded. The HCI
            command-stream walk requires the full file; when ``full_data``
            is None we fall back to the BRCMcfgS/BRCMcfgD tag check on
            ``head`` alone, producing a lower-confidence verdict.
        size: Total file size in bytes.

    Returns ``None`` when the file doesn't pass the HCD signature gates.
    """
    # Tag-presence fast-path on the read window (always available).
    cfg_tag_seen = any(tag in head for tag in _BRCM_CFG_TAGS)

    # If the file is small enough, walk the full HCI stream.
    walk: dict[str, Any] | None = None
    if full_data is not None:
        walk = _walk_hci_stream(full_data)

    # Decision logic:
    #   * walk passes → definitive HCD verdict (high confidence)
    #   * walk None + BRCMcfg tag present → tag-only verdict (medium)
    #   * neither → not a Broadcom HCD
    if walk is None and not cfg_tag_seen:
        return None

    # Chipset extraction from in-payload BRCMcfgD string.
    chipset: str | None = None
    chipset_source = "none"
    for rx in (_BCM_CHIP_RE, _CYW_CHIP_RE):
        m = rx.search(head)
        if m:
            chipset = m.group(1).decode("ascii", errors="replace").lower()
            chipset_source = "brcm_cfg_block"
            break

    # Build-line + date extraction (best-effort).
    build_line: str | None = None
    lm = _BCM_BUILD_LINE_RE.search(head)
    if lm:
        try:
            build_line = lm.group(0).decode("ascii", errors="replace")
        except Exception:  # noqa: BLE001
            build_line = None
    build_date: str | None = None
    dm = _BCM_BUILD_DATE_RE.search(head)
    if dm:
        build_date = dm.group(0).decode("ascii", errors="replace")

    # Vendor disambiguation: CYW prefix → cypress; default broadcom.
    vendor = "broadcom"
    if chipset and chipset.startswith("cyw"):
        vendor = "cypress"

    rec: dict[str, Any] = {
        "family": "broadcom_hcd",
        "vendor": vendor,
        "banner": build_line,
        "build_date": build_date,
        "chipset_target": chipset,
        "chipset_source": chipset_source,
        "brcm_cfg_tag": cfg_tag_seen,
    }
    if walk is not None:
        rec["hci_walk"] = walk
        rec["confidence"] = "high"
    else:
        rec["confidence"] = "medium"
        rec["walk_skipped_reason"] = (
            "file larger than full-read window; tag-only verdict"
        )
    rec["size"] = size
    return rec


def _mtk_header_passes_gates(head: bytes) -> dict[str, Any] | None:
    """Check the 32-byte btmtk_patch_header shape per upstream btmtk.c.

    Returns dict with the header fields when the gates pass; None otherwise.

    Gates (designed to reject HCD/QCA/random binary that LOOKS struct-shaped):
      1. >=32 bytes available
      2. datetime[0..15] is mostly printable ASCII (>=12/16, NUL padding ok)
         AND contains at least one decimal digit. Real btmtk build
         timestamps always carry digits (e.g. ``2024/06/15 12:30``); the
         digit requirement rejects zero-padded HCI command bytes that
         happen to be printable letters (e.g. ``L\xfc\x18\x00...`` from a
         truncated HCD start would otherwise pass).
      3. platform[16..19] is printable ASCII AND not all-NUL (real
         btmtk firmware carries a chip-family tag).
      4. hwver/swver are NOT 0xFFFF (uninitialised) AND NOT all-zero
         with magicnum=0.
    """
    if len(head) < 32:
        return None
    datetime_field = head[0:16]
    platform = head[16:20]
    try:
        hwver = int.from_bytes(head[20:22], "little")
        swver = int.from_bytes(head[22:24], "little")
        magicnum = int.from_bytes(head[24:28], "little")
    except Exception:  # noqa: BLE001
        return None

    # Gate 2a — datetime mostly printable.
    printable = sum(1 for b in datetime_field if 0x20 <= b <= 0x7E or b == 0)
    if printable < 12:
        return None
    # Gate 2b — datetime contains at least one decimal digit. Catches the
    # false-positive case where zero-padded HCI opcode bytes (0x4c='L',
    # 0xfc=non-print, 0x18=non-print, NUL padding) appear "printable enough"
    # for gate 2a but obviously aren't a build timestamp.
    if not any(0x30 <= b <= 0x39 for b in datetime_field):
        return None
    # Gate 3a — platform printable.
    if not all(0x20 <= b <= 0x7E or b == 0 for b in platform):
        return None
    # Gate 3b — platform tag not all-NUL (real firmware always carries a chip
    # family tag; HCI write_ram address payload bytes are typically all-zero).
    if all(b == 0 for b in platform):
        return None
    # Gate 4 — sanity-check version fields.
    if hwver == 0xFFFF or swver == 0xFFFF:
        return None
    if hwver == 0 and swver == 0 and magicnum == 0:
        return None

    return {
        "datetime": datetime_field.rstrip(b"\x00").decode("ascii", errors="replace"),
        "platform_tag": platform.rstrip(b"\x00").decode("ascii", errors="replace"),
        "hwver": f"0x{hwver:04x}",
        "swver": f"0x{swver:04x}",
        "version_str": f"0x{hwver:04x}{swver:04x}",
        "magicnum": f"0x{magicnum:08x}",
    }


def _parse_mediatek_bt(data: bytes, filename: str) -> dict[str, Any] | None:
    """Parse MediaTek WMT / btmtk patches.

    Two-stage detection per Scout C (2026-05-16):
      A. The 32-byte ``btmtk_patch_header`` struct gates (printable
         datetime[16] + printable platform[4] + sane hwver/swver).
      B. BT-specific marker scan in the first 4 KB to distinguish from
         MediaTek WiFi firmware (which uses the SAME struct shape).

    Returns None when neither stage matches.
    """
    header = _mtk_header_passes_gates(data)

    # Stage B — BT marker scan.
    tag_hits: list[str] = []
    for rx in _MTK_BT_TAG_RES:
        m = rx.search(data)
        if m:
            try:
                tag_hits.append(m.group(0).decode("ascii", errors="replace"))
            except Exception:  # noqa: BLE001
                continue

    if header is None and not tag_hits:
        return None

    # Chipset extraction — prefer known-chip list (lowest false-positive),
    # then generic MT regex, then filename fallback.
    chip: str | None = None
    chipset_source = "none"
    for known in _MTK_KNOWN_CHIPS:
        if known in data:
            chip = known.decode("ascii", errors="replace").lower()
            chipset_source = "content_known_chip"
            break
    if chip is None:
        cm = _MTK_CHIP_RE.search(data)
        if cm:
            chip = cm.group(0).decode("ascii", errors="replace").lower()
            chipset_source = "content_mt_regex"
    if chip is None:
        fm = _MTK_FILENAME_CHIP_RE.match(os.path.basename(filename))
        if fm:
            chip = f"mt{fm.group('chip')}"
            chipset_source = "filename"

    # Build a candidate version from the btmtk header when present —
    # downstream CVE matching can regex against blob.version.
    version: str | None = None
    if header is not None:
        # version_str captures hwver|swver hex which is what btmtk.c
        # itself prints. Compose with the datetime so blob.version
        # carries enough banner shape for human inspection.
        version = f"btmtk hwver/swver {header['version_str']} built {header['datetime']!r}"

    rec: dict[str, Any] = {
        "family": "mediatek_bt",
        "vendor": "mediatek",
        "banner": version,
        "chipset_target": chip,
        "chipset_source": chipset_source,
        "tag_hits": tag_hits,
    }
    if header is not None:
        rec["btmtk_header"] = header
    # Discount the verdict when we ONLY saw the header but no BT-specific
    # tag (could be MediaTek WiFi firmware with the same struct shape).
    if header is not None and not tag_hits:
        rec["confidence"] = "low"
        rec["note"] = "btmtk header gates passed but no BT-specific marker found"
    return rec


def _maybe_pin_braktooth(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Tier 0 BRAKTOOTH pin for QCA Rome WCN3950 / WCN3990 / WCN3998 banners.

    Per the ASSET Group disclosure (Garbelini et al. 2021), Qualcomm
    marked Rome BT patches "TBA" in the 2021 PSIRT response and the
    in-field BTFM builds remain unpatched. When the banner confirms a
    Rome chipset (WCN3950 / WCN3990 / WCN3991 / WCN3998), the device
    participates in the BRAKTOOTH attack surface. Tier 0 fires with
    confidence="high" because the banner is direct evidence of the
    vulnerable chipset (not just a vendor+category match).
    """
    chipset = (record.get("chipset_target") or "").lower()
    if record.get("family") != "qca_rome":
        return []
    if chipset not in _BRAKTOOTH_CHIPSETS:
        return []
    banner = record.get("banner", "")
    out: list[dict[str, Any]] = []
    for cve_id, severity in _BRAKTOOTH_CVES:
        out.append({
            "cve_id": cve_id,
            "severity": severity,
            "subcomponent": "bluetooth",
            "confidence": "high",
            "source": "parser_version_pin",
            "rationale": (
                f"BT firmware banner {banner!r} confirms {chipset.upper()} "
                f"(QCA Rome family). Per the ASSET BRAKTOOTH disclosure "
                f"(Garbelini et al. 2021), Qualcomm marked Rome BT patches "
                f"'TBA' — in-field BTFM builds remain unpatched. "
                f"This blob's banner is direct evidence of the vulnerable "
                f"chipset."
            ),
            "reference": "https://asset-group.github.io/disclosures/braktooth/",
        })
    return out


class BtFirmwareBannerParser:
    """Parser for Bluetooth firmware blobs — content-based vendor attribution."""

    FORMAT = "bt_fw_banner"

    # Files larger than this are walked with head-only checks (no full
    # HCI command-stream walk). Real HCD files are <200 KB; BTFM patches
    # are <50 KB. The cap is a defence against malformed huge files that
    # classifiers might accidentally route here.
    _FULL_WALK_MAX_BYTES = 4 * 1024 * 1024

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        try:
            head = _read_head(path, _HEAD_SCAN_BYTES)
            if not head:
                return ParsedBlob(metadata={"error": "empty file or read failed"})
            tail = _read_tail(path, size, _TAIL_SCAN_BYTES)
            # QCA scan buffer = head + tail. The QCA banner sits at the
            # TAIL of multi-KB .tlv files (file-tail metadata convention);
            # the .ver companion files are tiny so head==tail anyway.
            # Use a NUL gap so a regex straddling the boundary can't
            # accidentally match across head/tail.
            if size > _HEAD_SCAN_BYTES and size > _TAIL_SCAN_BYTES:
                qca_scan = head + b"\x00\x00\x00\x00" + tail
            else:
                qca_scan = head  # file fully in head (head==tail when size<=HEAD)

            # Read full file ONLY if it's small enough for the HCI walk —
            # the Broadcom HCD validator needs the complete stream to
            # confirm the LAUNCH_RAM terminator.
            full_data: bytes | None = None
            if size <= self._FULL_WALK_MAX_BYTES:
                try:
                    with open(path, "rb") as f:
                        full_data = f.read(size)
                except OSError:
                    full_data = None

            # Family detection — order matters. QCA Rome FIRST because
            # its TLV header byte (0x01) collides with HCI command byte
            # but the banner regex is unambiguous and cheap to evaluate.
            # Broadcom HCD second — the walker rejects non-HCI streams
            # in O(commands) time. MediaTek last as the "everything
            # else BT" fallback.
            qca = _parse_qca_banner(qca_scan)
            if qca:
                meta["bt_fw_banner"] = qca
                version = qca.get("banner")
                chipset = qca.get("chipset_target")
                known = _maybe_pin_braktooth(qca)
                if known:
                    meta["known_vulnerabilities"] = known
                return ParsedBlob(
                    version=version,
                    signed=qca.get("signed"),
                    chipset_target=chipset,
                    vendor=qca.get("vendor"),
                    metadata=meta,
                )

            bcm = _parse_broadcom_hcd(head, full_data, size)
            if bcm:
                meta["bt_fw_banner"] = bcm
                return ParsedBlob(
                    version=bcm.get("banner"),
                    signed="unsigned",  # BCM/CYW HCDs are unsigned HCI streams
                    chipset_target=bcm.get("chipset_target"),
                    vendor=bcm.get("vendor"),
                    metadata=meta,
                )

            mtk = _parse_mediatek_bt(head, path)
            if mtk:
                meta["bt_fw_banner"] = mtk
                return ParsedBlob(
                    version=mtk.get("banner"),
                    chipset_target=mtk.get("chipset_target"),
                    vendor=mtk.get("vendor"),
                    metadata=meta,
                )

            # Unknown family — leave classification authoritative.
            meta["bt_fw_banner"] = {"family": "unknown", "checked": True}
            return ParsedBlob(metadata=meta)

        except Exception as exc:  # noqa: BLE001
            logger.debug("BtFirmwareBannerParser failed on %s: %s", path, exc)
            return ParsedBlob(metadata={"error": str(exc)})


register_parser(BtFirmwareBannerParser())
