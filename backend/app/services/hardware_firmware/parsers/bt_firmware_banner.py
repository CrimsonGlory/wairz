"""Bluetooth firmware banner-string parser (content-based vendor attribution).

Handles classifier format ``bt_fw_banner``. Reads up to ``_HEAD_SCAN_BYTES``
from the start AND ``_TAIL_SCAN_BYTES`` from the end of a candidate BT
firmware blob, identifying vendor + chipset + version banner from
CONTENT, not filename. (Tail scan is necessary because QCA Rome .tlv
files place the BTFM banner at the FILE END, not the start.)

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
  CHE (Cherokee → WCN3990/3991/3998), APA (Apache → WCN3988 UART
  attached; **NOT** AR3002 — that legacy USB-attached BT chip uses
  ath3k.ko + a different per-chip OTP firmware format and does NOT
  carry BTFM banners), HAS (Hastings → QCA6390), MOS (Moselle →
  WCN6750). The ``Patch Release PF=<chip>ROM=`` ASCII line carries
  the authoritative chipset name when present.

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
  DoS cluster (CVE-2021-34147 / 31609 / 31612) pin populated into
  ``metadata.known_vulnerabilities`` with confidence="high".
  Rationale: per the ASSET disclosure matrix (Garbelini et al. 2021),
  Qualcomm marked Rome BT patches "TBA" — the in-field BTFM builds
  remain unpatched, so any banner that confirms a Rome chipset is
  direct evidence the device participates in these LMP-handling DoS
  bugs. **Important:** CVE-2021-28139 is ESP32-only per NVD's CPE
  list — it is NOT pinned by this parser despite being part of the
  ASSET BrakTooth disclosure batch (Reviewer B 2026-05-16 caught
  this would have been a fresh false-positive RCE attribution).
  The curated YAML Tier 3 also fires this cluster via soft-chipset
  match; Tier 0 produces the higher-confidence signal because the
  parser saw the banner directly.

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
import string
from datetime import datetime
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser
from app.services.hardware_firmware.patterns_loader import (
    BannerCvePin,
    get_banner_cve_pins,
    get_mtk_chips,
    get_qca_codename_display,
    get_qca_codename_map,
    get_realtek_chipset_by_project_id,
)

logger = logging.getLogger(__name__)


class _SafeRationaleFormatter(string.Formatter):
    """``str.Formatter`` subclass that rejects attribute + item access.

    Reviewer A 2026-05-17 finding: a YAML pin authored as ``rationale:
    "leak {banner.__class__.__mro__}"`` would resolve via Python's
    default str.format attribute-access semantics. While the YAML files
    are git-reviewed today, the H2 design EXPLICITLY invites operator
    extension — future operator-supplied YAMLs (vendor uploads, fleet
    rollouts) inherit any attack surface the engine ships with.

    This formatter:

    * Allows the documented placeholder syntax: ``{banner}``,
      ``{chipset_upper}``, etc.
    * Rejects any field name containing ``.`` (attribute access) or
      ``[`` (item access) by raising ValueError, which the caller
      catches + logs.
    * Inherits all other ``string.Formatter`` behaviour (positional
      args, conversion flags ``!r``/``!s``, format specs ``:d``/``:>10``
      etc. — these are non-leaky on their own).
    """

    def get_field(
        self,
        field_name: str,
        args: tuple,
        kwargs: dict,
    ) -> tuple[Any, str]:
        if "." in field_name or "[" in field_name:
            raise ValueError(
                f"rationale field {field_name!r} uses attribute or item "
                "access (not allowed in banner-pin rationale templates)"
            )
        return super().get_field(field_name, args, kwargs)


_SAFE_FORMATTER = _SafeRationaleFormatter()


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

# Codename → canonical chipset target + codename → display name + BrakTooth
# chipset scope are externalized to ``data/bt_qca_codenames.yaml``
# (graceful-degrade fallback to in-tree ``_BT_CODENAME_DEFAULTS`` if YAML
# is missing or malformed — see Rule #34 in CLAUDE.md). The parser reads
# via accessors ``get_qca_codename_map`` / ``get_qca_codename_display``
# / ``get_mtk_chips`` — operator-supplied YAML additions surface
# immediately without Python changes.
#
# Banner-pin → CVE rules are externalized to ``data/bt_banner_cve_pins.yaml``
# (loaded via ``patterns_loader._load_banner_cve_pins``; the H2 engine
# below walks the rule list, applies match conditions, and emits CVEs).
# The shipping YAML's first pin reproduces the BRAKTOOTH Tier 0 pin that
# was previously hardcoded as ``_maybe_pin_braktooth`` (deleted; in-tree
# ``_BANNER_CVE_PIN_DEFAULTS`` in patterns_loader carries the same data
# as the YAML's first pin so detection keeps working under YAML loss).
#
# CRITICAL invariant: CVE-2021-28139 (BrakTooth RCE CVSS 8.8) is ESP32-only
# per NVD's CPE list (Reviewer B 2026-05-16) — it is NOT in the shipped
# YAML and MUST NOT be added to any qca_rome-family pin.

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

# MediaTek BT chip IDs are externalized to ``data/bt_qca_codenames.yaml``
# (the file also covers MTK because it owns the BT-vendor-table data;
# operators extending coverage for new MediaTek silicon edit one file).
# Loaded via ``patterns_loader.get_mtk_chips()`` which returns
# ``tuple[bytes, ...]`` (ASCII-encoded once at load time for cheap
# byte-wise ``in firmware_bytes`` membership tests downstream).

# MediaTek generic chip-id regex — fallback when no known-chip token
# matched. The classifier already gates this code path to BT files.
_MTK_CHIP_RE = re.compile(rb"\bMT(?P<chip>\d{4})\b")

# Filename → MediaTek chipset (extracted when content didn't pin the chip
# — e.g. headerless ROM patch chunks).
_MTK_FILENAME_CHIP_RE = re.compile(r"^(?:mt|romv)(?P<chip>\d{4})", re.IGNORECASE)

# ----- Realtek BT firmware -----
#
# Two canonical header shapes per upstream Linux drivers/bluetooth/btrtl.h:
#   * v1 (rtl_epatch_header):
#       offset  0..7   "Realtech"  (note the "ch" spelling — Realtek's
#                       own typo, preserved for ABI)
#       offset  8..11  __le32 fw_version
#       offset 12..13  __le16 num_patches
#   * v2 (rtl_epatch_header_v2):
#       offset  0..7   "RTBTCore"
#       offset  8..15  __u8 fw_version[8]  (ASCII version string)
#       offset 16..19  __le32 num_sections
#
# project_id is NOT at offset 8 (despite what some downstream
# documentation claims). Per btrtl.c, project_id is encoded as TLV
# records at the END of the firmware blob: reverse-scan from the tail
# for the pattern (opcode=0, length=1, data=PID) — `data` is the
# project_id (small int 0-51).
#
# Adaptive parser policy:
#   * Accept BOTH canonical magic forms ("Realtech" AND "RTBTCore").
#   * SOFT-match "Realtek" / "REALTEK" / "RealTek" anywhere in head as
#     LOW-confidence fallback (operator-uploaded SDK builds may carry
#     vendor-modified blobs that don't use the canonical magic).
#   * Magic doesn't have to be at offset 0 — scan first 64 bytes
#     (some downstream variants prepend a small wrapper). HIGH
#     confidence only when offset == 0; non-zero offset → MEDIUM.
#   * project_id outside the YAML chipset map → MEDIUM (operator can
#     extend bt_realtek_project_ids.yaml without Python change).
#   * Build-date extraction is NOT present in btrtl.c — Realtek firmware
#     does NOT carry a textual `Date:` line. The fw_version uint32 IS
#     the version-bearing field; surfaced as record["fw_version"].
_RTL_MAGIC_V1 = b"Realtech"
_RTL_MAGIC_V2 = b"RTBTCore"
_RTL_SOFT_RE = re.compile(rb"[Rr][Ee][Aa][Ll][Tt][Ee][CcKk]")
_RTL_HEAD_MAGIC_SCAN_BYTES = 64


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


# Filename prefix → codename mapping (per upstream Linux btqca.c).
# Used to flag filename↔content mismatches as forensic-interest metadata
# (Reviewer B M2 2026-05-16: e.g. apbtfw10.tlv containing a CHE banner
# is a real-world filename/content discrepancy worth surfacing).
_QCA_FILENAME_PREFIX_TO_CODENAME: dict[str, str] = {
    "cmbtfw": "CMC",   # Comanche
    "crbtfw": "CHE",   # Cherokee
    "apbtfw": "APA",   # Apache
    "htbtfw": "HAS",   # Hastings
    "msbtfw": "MOS",   # Moselle
}


def _expected_codename_from_filename(path: str) -> str | None:
    """Look up the codename implied by a QCA BT filename prefix.

    Returns ``None`` if the filename doesn't match a known QCA BT
    family naming convention (e.g. raw ``btfm.bin`` or unprefixed
    ``.tlv`` files).
    """
    if not path:
        return None
    base = os.path.basename(path).lower()
    for prefix, codename in _QCA_FILENAME_PREFIX_TO_CODENAME.items():
        if base.startswith(prefix):
            return codename
    return None


def _parse_qca_banner(data: bytes, filename: str = "") -> dict[str, Any] | None:
    """Parse a QCA Rome BTFM banner from ``data`` (first ~4 KB).

    Returns ``None`` if no banner found, else a dict with the structured
    banner fields. Looks for the rich ``Patch Release PF=...ROM= ... BUILD=``
    line first (carries the authoritative chipset name); falls back to the
    plain ``BTFM.<codename>.x.y.z-...`` regex when only the banner is
    present (typical for .ver companion files).

    ``filename`` is consulted ONLY for the filename↔content mismatch
    flag — content evidence remains authoritative for vendor / chipset.
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
        rec = _build_qca_record(bm, chip_override=chip_raw.lower(), rom_rev=rom_rev)
        _annotate_filename_mismatch(rec, filename)
        return rec
    # Fallback: bare banner anywhere in the scan window.
    bm = _QCA_BANNER_RE.search(data)
    if bm:
        rec = _build_qca_record(bm, chip_override=None, rom_rev=None)
        _annotate_filename_mismatch(rec, filename)
        return rec
    return None


def _annotate_filename_mismatch(rec: dict[str, Any], filename: str) -> None:
    """Stamp a forensic-interest mismatch flag when filename prefix
    disagrees with the content-banner codename.

    Real-world example: G32's apbtfw10.tlv contains a CHE (Cherokee)
    banner — content says WCN3990, filename suggests WCN3988 (Apache).
    Parser trusts content (Rule #19) but surfaces the discrepancy so
    forensic operators can audit it without re-reading parser source.
    """
    if not filename:
        return
    expected = _expected_codename_from_filename(filename)
    content_codename = rec.get("codename")
    if expected and content_codename and expected != content_codename:
        rec["filename_codename_mismatch"] = {
            "filename_codename": expected,
            "content_codename": content_codename,
            "filename": os.path.basename(filename),
        }


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

    # Chipset preference: PF= override > codename table (YAML-driven) > None.
    codename_map = get_qca_codename_map()
    chipset_target: str | None = None
    chipset_source: str = "none"
    if chip_override:
        chipset_target = chip_override
        chipset_source = "pf_field"
    elif codename in codename_map:
        chipset_target = codename_map[codename]
        chipset_source = "codename_map"

    rec: dict[str, Any] = {
        "family": "qca_rome",
        "vendor": "qualcomm",
        "banner": banner,
        "codename": codename,
        "codename_display": get_qca_codename_display().get(codename),
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
        head: First ``_HEAD_SCAN_BYTES`` of the file (always read).
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
    for known in get_mtk_chips():
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


def _scan_realtek_project_id_from_tail(tail: bytes) -> int | None:
    """Reverse-scan ``tail`` for the project_id TLV record per btrtl.c.

    Realtek BT firmware encodes project_id (small integer 0-51 mapping
    to a chipset) as a trailing TLV record:
      (opcode_byte, length_byte, data_byte) read RIGHT-TO-LEFT.
    Walk backward from the end:
      - opcode == 0xFF → EOF marker, stop.
      - opcode == 0, length == 1 → data is the project_id.
      - else → skip `length` bytes and continue.

    Returns the project_id int on success; None if not found within the
    given tail buffer (operator can grow _TAIL_SCAN_BYTES if needed).
    """
    n = len(tail)
    if n < 4:
        return None
    # Walk right-to-left through TLV triples.
    i = n - 1
    iterations = 0
    # Cap iterations to bound CPU on adversarial inputs.
    max_iter = 4096
    while i >= 2 and iterations < max_iter:
        iterations += 1
        opcode = tail[i]
        i -= 1
        if opcode == 0xFF:
            return None
        if i < 1:
            return None
        length = tail[i]
        i -= 1
        if length == 1 and opcode == 0:
            # data is the next byte (one to the left).
            if i < 0:
                return None
            return tail[i]
        # Skip `length` bytes of data + advance.
        if length > 0:
            i -= length
    return None


def _parse_realtek_bt(
    head: bytes, tail: bytes, filename: str, size: int
) -> dict[str, Any] | None:
    """Parse a Realtek BT firmware blob (rtl_epatch_header v1 or v2).

    Adaptive design (per Scout C 2026-05-18 research):
    - Accepts BOTH "Realtech" (v1) and "RTBTCore" (v2) at offset 0..63
      (scans first 64 bytes — some downstream variants prepend a small
      wrapper preamble).
    - SOFT-matches "Realtek"/"REALTEK"/"RealTek" anywhere in head as
      LOW-confidence fallback when neither canonical magic is found.
    - Reads fw_version + num_patches/num_sections from the header.
    - Tail-scans for the (opcode=0, length=1, data=PID) TLV record →
      project_id → chipset via YAML (operators extend without Python).
    - Confidence ladder:
        HIGH: canonical magic at offset 0 + project_id in YAML map
        MEDIUM: magic at offset 0..63 (non-zero) OR project_id unknown
        LOW: soft Realtek/Realtech ASCII anywhere + no other validation

    Returns ``None`` only when NO Realtek evidence is found whatsoever.
    Always emits a vendor=realtek record otherwise — operator value lives
    in the metadata fields even at LOW confidence.
    """
    # Scan head for canonical magic.
    magic_offset: int | None = None
    version: str = "v1"  # default to v1; flipped if RTBTCore found
    head_scan_window = head[: _RTL_HEAD_MAGIC_SCAN_BYTES]
    idx_v1 = head_scan_window.find(_RTL_MAGIC_V1)
    idx_v2 = head_scan_window.find(_RTL_MAGIC_V2)
    if idx_v1 >= 0 and (idx_v2 < 0 or idx_v1 < idx_v2):
        magic_offset = idx_v1
        version = "v1"
    elif idx_v2 >= 0:
        magic_offset = idx_v2
        version = "v2"
    else:
        # Soft fallback: any case variant of "Realtek" or "Realtec" in
        # the head window? LOW confidence — emit record so operators
        # know the parser saw Realtek-like evidence, but stamp
        # confidence accordingly.
        soft = _RTL_SOFT_RE.search(head_scan_window)
        if not soft:
            # No Realtek signal anywhere. Not our format.
            return None
        return {
            "family": "realtek_bt",
            "vendor": "realtek",
            "banner": None,
            "chipset_target": None,
            "chipset_source": "none",
            "confidence": "low",
            "note": (
                "Realtek-like ASCII pattern in head but no canonical "
                "magic (Realtech/RTBTCore) — possible vendor-modified "
                "blob or unrelated coincidence"
            ),
            "header_version": None,
            "magic_offset": soft.start(),
            "size": size,
        }

    # Canonical magic present. Parse header fields.
    fw_version_raw: int | str | None = None
    num_records: int | None = None
    record_key: str = "num_patches"
    header_len: int = 14
    try:
        if version == "v1":
            # v1: __u8 signature[8] + __le32 fw_version + __le16 num_patches
            hdr_end = magic_offset + 14
            if len(head) >= hdr_end:
                fw_version_raw = int.from_bytes(
                    head[magic_offset + 8 : magic_offset + 12], "little"
                )
                num_records = int.from_bytes(
                    head[magic_offset + 12 : magic_offset + 14], "little"
                )
                header_len = 14
        else:
            # v2: __u8 signature[8] + __u8 fw_version[8] (ASCII) +
            #     __le32 num_sections
            hdr_end = magic_offset + 20
            if len(head) >= hdr_end:
                fw_version_bytes = head[magic_offset + 8 : magic_offset + 16]
                fw_version_raw = (
                    fw_version_bytes.rstrip(b"\x00")
                    .decode("ascii", errors="replace")
                    .strip()
                ) or None
                num_records = int.from_bytes(
                    head[magic_offset + 16 : magic_offset + 20], "little"
                )
                record_key = "num_sections"
                header_len = 20
    except (ValueError, IndexError, OSError):
        # Header truncation or partial reads — preserve what we have.
        pass

    # Tail TLV scan for project_id.
    project_id = _scan_realtek_project_id_from_tail(tail)

    # Chipset lookup via YAML hot-reloaded table.
    chipset_entry = (
        get_realtek_chipset_by_project_id(project_id)
        if project_id is not None
        else None
    )

    chipset: str | None = None
    chipset_source: str = "none"
    if chipset_entry is not None:
        chipset = chipset_entry.chipset
        chipset_source = "project_id_tlv"

    # Confidence ladder per the parser policy described above.
    if magic_offset == 0 and chipset is not None:
        confidence = "high"
    elif magic_offset == 0 or chipset is not None:
        confidence = "medium"
    else:
        # Magic found at non-zero offset AND no chipset resolved — LOW.
        confidence = "low"

    # Reconstruct a banner string for record["banner"] / blob.version.
    banner_parts: list[str] = [
        f"Realtek BT firmware ({version}, magic@{magic_offset})"
    ]
    if fw_version_raw is not None:
        if isinstance(fw_version_raw, int):
            banner_parts.append(f"fw_version=0x{fw_version_raw:08x}")
        else:
            banner_parts.append(f"fw_version={fw_version_raw!r}")
    if num_records is not None:
        banner_parts.append(f"{record_key}={num_records}")
    if project_id is not None:
        banner_parts.append(f"project_id={project_id}")
    if chipset_entry is not None and chipset_entry.lmp_subver is not None:
        banner_parts.append(f"lmp_subver=0x{chipset_entry.lmp_subver:04x}")
    banner = "; ".join(banner_parts)

    rec: dict[str, Any] = {
        "family": "realtek_bt",
        "vendor": "realtek",
        "banner": banner,
        "header_version": version,
        "magic_offset": magic_offset,
        "fw_version": (
            f"0x{fw_version_raw:08x}"
            if isinstance(fw_version_raw, int)
            else fw_version_raw
        ),
        "num_patches": num_records if record_key == "num_patches" else None,
        "num_sections": num_records if record_key == "num_sections" else None,
        "project_id": project_id,
        "chipset_target": chipset,
        "chipset_source": chipset_source,
        "confidence": confidence,
        "size": size,
        "header_length": header_len,
    }
    if chipset_entry is not None:
        rec["chipset_display"] = chipset_entry.display
        rec["lmp_subver"] = (
            f"0x{chipset_entry.lmp_subver:04x}"
            if chipset_entry.lmp_subver is not None
            else None
        )
        rec["hci_rev"] = (
            f"0x{chipset_entry.hci_rev:02x}"
            if chipset_entry.hci_rev is not None
            else None
        )
        rec["hci_ver"] = (
            f"0x{chipset_entry.hci_ver:02x}"
            if chipset_entry.hci_ver is not None
            else None
        )
        rec["family_tag"] = chipset_entry.family
    return rec


def _coerce_build_id(raw: Any) -> int | None:
    """Coerce a record.build_id value to int for build_id_lt comparison.

    The QCA banner regex captures ``build_id`` as ``\\d+(?:\\.\\d+)?`` so
    the string may be ``"00069"`` or ``"00076.1"`` (CI build with dotted
    micro). We compare on the integer head only; non-integer inputs return
    ``None`` so the gate fails closed (won't pin under uncertainty).
    """
    if raw is None:
        return None
    try:
        return int(str(raw).split(".", 1)[0])
    except (TypeError, ValueError):
        return None


def _parse_build_date(raw: Any) -> "datetime | None":
    """Parse a BCM HCD-style build date ('Sep 12 2017') to a datetime.

    Returns ``None`` on any failure so the build_date_before gate fails
    closed under uncertainty (won't pin a CVE we can't date-bound).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return datetime.strptime(raw.strip(), "%b %d %Y")
    except ValueError:
        return None


def _pin_matches(pin: BannerCvePin, record: dict[str, Any]) -> bool:
    """Evaluate a single banner-pin rule's match conditions against a record.

    All present conditions must evaluate true (logical AND). A condition
    set to ``None`` on the pin means "don't gate on this dimension".

    Fail-closed semantics on missing or unparseable data (Reviewer B
    2026-05-17): under uncertainty, the engine does NOT pin a CVE. Over-
    attribution is materially worse than under-attribution for operator
    trust. The DEBUG log surfaces the audit trail without flooding the
    info-level stream.
    """
    # Family gate (cheapest — common rejection).
    if pin.family is not None and record.get("family") != pin.family:
        return False
    # Codename gate (qca_rome only — record['codename'] is the 3-letter tag).
    if pin.codename_in is not None:
        cn = (record.get("codename") or "").upper()
        if cn not in pin.codename_in:
            return False
    # Chipset gate.
    if pin.chipset_target_in is not None:
        chipset = (record.get("chipset_target") or "").lower()
        if chipset not in pin.chipset_target_in:
            return False
    # Banner regex gate.
    if pin.banner_re is not None:
        banner = record.get("banner") or ""
        if not pin.banner_re.search(banner):
            return False
    # Build date gate (broadcom_hcd uses record['build_date'] format
    # "Sep 12 2017"). Fails closed: missing or unparseable date → no pin.
    if pin.build_date_before is not None:
        parsed = _parse_build_date(record.get("build_date"))
        if parsed is None:
            logger.debug(
                "BT banner-pin %s: build_date_before gate fail-closed "
                "(value=%r unparseable as 'MMM DD YYYY')",
                pin.pin_id,
                record.get("build_date"),
            )
            return False
        if not parsed.date() < pin.build_date_before:
            return False
    # Build ID gate (qca_rome / mediatek). Fails closed on non-int.
    if pin.build_id_lt is not None:
        n = _coerce_build_id(record.get("build_id"))
        if n is None:
            logger.debug(
                "BT banner-pin %s: build_id_lt gate fail-closed "
                "(value=%r non-int)",
                pin.pin_id,
                record.get("build_id"),
            )
            return False
        if not n < pin.build_id_lt:
            return False
    # Signed gate — qca_rome banner parser emits 'signed' / 'unsigned';
    # broadcom_hcd parser always emits 'unsigned'; mediatek_bt parser
    # does not populate record['signed']. Reviewer C 2026-05-17.
    if pin.signed_eq is not None:
        signed = (record.get("signed") or "").lower()
        if signed != pin.signed_eq:
            return False
    return True


def _format_rationale(template: str, pin_id: str, record: dict[str, Any]) -> str:
    """Render the rationale template with record-derived placeholders.

    Uses ``_SAFE_FORMATTER`` (Reviewer A 2026-05-17) which rejects
    attribute access (``{banner.__class__}``) and item access
    (``{banner[0]}``) — defense-in-depth for the operator-extensible
    YAML surface. Falls back to the raw template if a placeholder is
    missing OR uses a disallowed access pattern; the WARN log surfaces
    the gap so the operator notices without losing the finding.
    """
    chipset = str(record.get("chipset_target") or "unknown")
    template_vars = {
        "banner": str(record.get("banner") or ""),
        "chipset": chipset,
        "chipset_upper": chipset.upper(),
        "codename": str(record.get("codename") or ""),
        "build_id": str(record.get("build_id") or ""),
        "build_date": str(record.get("build_date") or ""),
        "signed": str(record.get("signed") or ""),
    }
    try:
        return _SAFE_FORMATTER.vformat(template, (), template_vars).strip()
    except (KeyError, IndexError, ValueError) as exc:
        logger.warning(
            "BT banner-pin %s: rationale template error (%s); "
            "emitting raw template",
            pin_id,
            exc,
        )
        return template.strip()


def _pin_from_yaml_rules(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply the YAML banner-pin → CVE engine to a parsed record.

    Walks every loaded :class:`patterns_loader.BannerCvePin`; for each pin
    whose match conditions all evaluate true, emits one finding per CVE in
    the pin's ``cves`` list. Returns the aggregate across all matching
    pins (multiple pins CAN fire on the same record — operators add narrow
    pins above generic ones; the engine does not deduplicate).
    """
    out: list[dict[str, Any]] = []
    for pin in get_banner_cve_pins():
        if not _pin_matches(pin, record):
            continue
        for cve in pin.cves:
            out.append({
                "cve_id": cve.cve_id,
                "severity": cve.severity,
                "subcomponent": cve.subcomponent,
                "confidence": cve.confidence,
                "source": "parser_version_pin",
                "rationale": _format_rationale(cve.rationale, pin.pin_id, record),
                "reference": cve.reference,
                "pin_id": pin.pin_id,
            })
    return out


def _emit_pins(record: dict[str, Any], meta: dict[str, Any]) -> None:
    """Run the banner-pin engine + stamp results into the parser metadata."""
    pins = _pin_from_yaml_rules(record)
    if pins:
        meta["known_vulnerabilities"] = pins


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

            # Family detection — order matters. QCA Rome FIRST because
            # its TLV header byte (0x01) collides with HCI command byte
            # but the banner regex is unambiguous and cheap to evaluate.
            # Broadcom HCD second — requires reading the full file for
            # the HCI walker (lazy-read deferred until QCA + MediaTek
            # rule out — Reviewer A M2 2026-05-16: defers a 4 MB read in
            # the common QCA-hit case). MediaTek third as the BT-fallback.
            # Realtek inserted AFTER MediaTek but BEFORE Broadcom: its
            # "Realtech"/"RTBTCore" magic is unambiguous in the head
            # window, and the parser only needs head + tail (no full-
            # file read), so it's cheap.
            qca = _parse_qca_banner(qca_scan, filename=path)
            if qca:
                meta["bt_fw_banner"] = qca
                _emit_pins(qca, meta)
                return ParsedBlob(
                    version=qca.get("banner"),
                    signed=qca.get("signed"),
                    chipset_target=qca.get("chipset_target"),
                    vendor=qca.get("vendor"),
                    metadata=meta,
                )

            # Try MediaTek BEFORE Broadcom HCD — MTK detection uses head
            # only, no full-file read. Broadcom HCD's HCI walker is the
            # expensive case so we defer it until last to avoid a wasted
            # 4 MB allocation on non-HCD inputs.
            mtk = _parse_mediatek_bt(head, path)
            if mtk:
                meta["bt_fw_banner"] = mtk
                _emit_pins(mtk, meta)
                return ParsedBlob(
                    version=mtk.get("banner"),
                    chipset_target=mtk.get("chipset_target"),
                    vendor=mtk.get("vendor"),
                    metadata=meta,
                )

            # Realtek BT — head+tail scan, no full-file read needed.
            # Per Scout C 2026-05-18: accepts BOTH "Realtech" (v1) AND
            # "RTBTCore" (v2) magic + soft Realtek ASCII fallback;
            # project_id read from tail TLV records (NOT offset 8 as
            # the prompt initially suggested — offset 8 is fw_version
            # per upstream btrtl.h).
            rtl = _parse_realtek_bt(head, tail, path, size)
            if rtl:
                meta["bt_fw_banner"] = rtl
                _emit_pins(rtl, meta)
                return ParsedBlob(
                    version=rtl.get("banner"),
                    chipset_target=rtl.get("chipset_target"),
                    vendor=rtl.get("vendor"),
                    metadata=meta,
                )

            # Lazy full-file read ONLY for the HCD walker (Reviewer A M2).
            # The Broadcom HCD validator needs the complete stream to
            # confirm the LAUNCH_RAM terminator. Cap at _FULL_WALK_MAX_BYTES
            # to bound memory cost.
            full_data: bytes | None = None
            if size <= self._FULL_WALK_MAX_BYTES:
                try:
                    with open(path, "rb") as f:
                        full_data = f.read(size)
                except OSError:
                    full_data = None

            bcm = _parse_broadcom_hcd(head, full_data, size)
            if bcm:
                meta["bt_fw_banner"] = bcm
                _emit_pins(bcm, meta)
                return ParsedBlob(
                    version=bcm.get("banner"),
                    signed="unsigned",  # BCM/CYW HCDs are unsigned HCI streams
                    chipset_target=bcm.get("chipset_target"),
                    vendor=bcm.get("vendor"),
                    metadata=meta,
                )

            # Unknown family — leave classification authoritative.
            meta["bt_fw_banner"] = {"family": "unknown", "checked": True}
            return ParsedBlob(metadata=meta)

        except Exception as exc:  # noqa: BLE001
            logger.debug("BtFirmwareBannerParser failed on %s: %s", path, exc)
            return ParsedBlob(metadata={"error": str(exc)})


register_parser(BtFirmwareBannerParser())
