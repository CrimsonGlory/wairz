"""Stage C — Android A/B OTA ``payload.bin`` (CrAU) manifest walker.

Parses the ``update_engine`` ``payload.bin`` wire format (magic ``CrAU``)
enough to (a) locate the ``boot`` partition's install operations and
(b) classify them. For standard ops (``REPLACE`` / ``REPLACE_XZ`` /
``REPLACE_BZ``) the boot partition can be reassembled and handed to
Stage B. For the proprietary ``ff12d941`` block-format op (the Elo tablet
case, ``R47.1b`` §2 — exhausted xz/lzma/bz2/gzip/zlib/lz4/zstd/brotli/7z,
NOT standard-decodable) this module emits an HONEST ``EXTRACTION_BLOCKED``
record carrying the recommendation + fallback identity — it does NOT
attempt to decode the proprietary block (Rule #36 no-execute /
no-vendor-bundle; a future vendor-tool plugin would ride the Rule #52
plugin escape hatch + Rule #36 Exception-3 hardened side-container).

The DeltaArchiveManifest is a protobuf message; we use a HAND-ROLLED
minimal varint + length-delimited reader (NO protobuf dependency — the
tablet scout proved a minimal reader suffices to IDENTIFY the boot
partition + classify ops). We only read the field numbers we need; all
other fields are skipped by wire-type.

PARSE-ONLY (Rule #36 + Rule #45): reads header + manifest bytes AS DATA;
never invokes anything.

CrAU header layout (``update_engine/update_metadata.proto`` +
``payload_consumer/payload_metadata.cc``):

    offset  size  field
    0       4     magic "CrAU"
    4       8     version (u64 BE) — must be 2
    12      8     manifest_size (u64 BE)
    20      4     metadata_signature_size (u32 BE)   [version >= 2]
    24      N     DeltaArchiveManifest protobuf (manifest_size bytes)

DeltaArchiveManifest fields we read:

    field 13 (partitions, repeated PartitionUpdate, wire-type 2)
      PartitionUpdate.field 1 (partition_name, string, wire-type 2)
      PartitionUpdate.field 8 (operations, repeated InstallOperation, wire-type 2)
        InstallOperation.field 1 (type, enum/varint, wire-type 0)

InstallOperation.type enum (subset):
    0 REPLACE, 1 REPLACE_BZ, 8 REPLACE_XZ  (standard, decodable)
    others (notably the vendor ``ff12d941`` block class) → BLOCKED
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_CRAU_MAGIC = b"CrAU"
_CRAU_HEADER_FIXED = 24  # magic(4)+version(8)+manifest_size(8)+metasig(4)

# Bound the manifest we will parse — a real A/B manifest is well under a
# few MB; cap at 64 MB to prevent a pathological header claiming a huge
# manifest_size from forcing an enormous slice.
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024

# Standard, decodable InstallOperation.type enum values.
_OP_REPLACE = 0
_OP_REPLACE_BZ = 1
_OP_REPLACE_XZ = 8
_STANDARD_OP_TYPES = frozenset({_OP_REPLACE, _OP_REPLACE_BZ, _OP_REPLACE_XZ})


@dataclass
class PayloadPartition:
    """One partition's identity + op classification from the manifest."""

    name: str
    op_types: list[int] = field(default_factory=list)

    @property
    def all_standard(self) -> bool:
        """True iff EVERY op is a standard (decodable) type."""
        return bool(self.op_types) and all(
            t in _STANDARD_OP_TYPES for t in self.op_types
        )

    @property
    def has_nonstandard_op(self) -> bool:
        """True iff ANY op is a non-standard (proprietary/blocked) type."""
        return any(t not in _STANDARD_OP_TYPES for t in self.op_types)


@dataclass
class PayloadManifest:
    """Parsed CrAU manifest summary."""

    version: int
    partitions: list[PayloadPartition]

    def boot_partition(self) -> PayloadPartition | None:
        for p in self.partitions:
            if p.name == "boot":
                return p
        return None


# ── Minimal protobuf wire reader (varint + length-delimited only) ──────────


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Read a base-128 varint at ``pos``; return ``(value, new_pos)``.

    Raises ``ValueError`` on truncation or an over-long varint (guards
    against a corrupt manifest spinning the decoder).
    """
    result = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(buf):
            raise ValueError("varint truncated")
        if pos - start > 9:  # a 64-bit varint is at most 10 bytes
            raise ValueError("varint too long")
        byte = buf[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not (byte & 0x80):
            return result, pos
        shift += 7


def _skip_field(buf: bytes, pos: int, wire_type: int) -> int:
    """Skip a field of the given wire type; return the new position."""
    if wire_type == 0:  # varint
        _, pos = _read_varint(buf, pos)
        return pos
    if wire_type == 1:  # 64-bit
        return pos + 8
    if wire_type == 2:  # length-delimited
        length, pos = _read_varint(buf, pos)
        return pos + length
    if wire_type == 5:  # 32-bit
        return pos + 4
    # Groups (3/4) are deprecated + unused here.
    raise ValueError(f"unsupported wire type {wire_type}")


def _parse_install_operation(buf: bytes) -> int | None:
    """Return the InstallOperation.type (field 1, varint), or None."""
    pos = 0
    op_type: int | None = None
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num == 1 and wire_type == 0:
            op_type, pos = _read_varint(buf, pos)
        else:
            pos = _skip_field(buf, pos, wire_type)
    return op_type


def _parse_partition_update(buf: bytes) -> PayloadPartition | None:
    """Parse a PartitionUpdate sub-message: name (field 1) + ops (field 8)."""
    pos = 0
    name: str | None = None
    op_types: list[int] = []
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num == 1 and wire_type == 2:  # partition_name
            length, pos = _read_varint(buf, pos)
            name = buf[pos : pos + length].decode("utf-8", errors="replace")
            pos += length
        elif field_num == 8 and wire_type == 2:  # operations (repeated)
            length, pos = _read_varint(buf, pos)
            op_buf = buf[pos : pos + length]
            pos += length
            op_type = _parse_install_operation(op_buf)
            if op_type is not None:
                op_types.append(op_type)
        else:
            pos = _skip_field(buf, pos, wire_type)
    if name is None:
        return None
    return PayloadPartition(name=name, op_types=op_types)


def parse_payload_manifest(data: bytes) -> PayloadManifest | None:
    """Parse a CrAU ``payload.bin`` header + manifest; return the summary.

    Returns ``None`` when ``data`` is not a CrAU payload or the header is
    too short / malformed. Idempotent + side-effect free.
    """
    if data[:4] != _CRAU_MAGIC:
        return None
    if len(data) < _CRAU_HEADER_FIXED:
        return None
    try:
        (version,) = struct.unpack_from(">Q", data, 4)
        (manifest_size,) = struct.unpack_from(">Q", data, 12)
    except struct.error:
        return None
    if version != 2:
        # Only CrAU v2 carries the metadata_signature_size field at @20 +
        # the manifest at @24. v1 is pre-Android-8 and not in scope.
        logger.debug("parse_payload_manifest: unsupported CrAU version %d", version)
        return None
    if manifest_size <= 0 or manifest_size > _MAX_MANIFEST_BYTES:
        logger.debug(
            "parse_payload_manifest: implausible manifest_size=%d", manifest_size
        )
        return None
    manifest_start = _CRAU_HEADER_FIXED
    manifest_end = manifest_start + manifest_size
    if len(data) < manifest_end:
        # Header-only / truncated payload (the carved-chunk case): we have
        # the CrAU header but not the full manifest. Return None so the
        # caller records a blocked/identity-only result.
        logger.debug(
            "parse_payload_manifest: manifest truncated (have %d need %d)",
            len(data),
            manifest_end,
        )
        return None
    manifest_buf = data[manifest_start:manifest_end]

    partitions: list[PayloadPartition] = []
    pos = 0
    try:
        while pos < len(manifest_buf):
            tag, pos = _read_varint(manifest_buf, pos)
            field_num = tag >> 3
            wire_type = tag & 0x07
            if field_num == 13 and wire_type == 2:  # partitions (repeated)
                length, pos = _read_varint(manifest_buf, pos)
                part_buf = manifest_buf[pos : pos + length]
                pos += length
                part = _parse_partition_update(part_buf)
                if part is not None:
                    partitions.append(part)
            else:
                pos = _skip_field(manifest_buf, pos, wire_type)
    except (ValueError, IndexError) as exc:
        logger.debug("parse_payload_manifest: manifest walk failed: %s", exc)
        # Return whatever partitions we recovered before the error — a
        # partial manifest still IDENTIFIES the boot partition for the
        # honest BLOCKED record.

    return PayloadManifest(version=version, partitions=partitions)


@dataclass
class PayloadBootVerdict:
    """C1 Stage-C verdict for the boot partition of a CrAU payload.

    ``extraction_status`` is one of:
      * ``"standard"`` — boot ops are all standard (REPLACE/REPLACE_XZ/
        REPLACE_BZ); a future commit MAY reassemble + hand to Stage B.
      * ``"blocked"`` — boot ops include a non-standard (proprietary)
        op (e.g. the ff12d941 block class); honest BLOCKED record,
        recommendation=live_adb_or_vendor_tool.
      * ``"no_boot_partition"`` — the manifest has no ``boot`` partition.
    """

    extraction_status: str
    blocked_reason: str | None
    recommendation: str | None
    boot_op_types: list[int]


def classify_boot_partition(manifest: PayloadManifest) -> PayloadBootVerdict:
    """Classify the boot partition's ops into a C1 Stage-C verdict.

    Per Rule #36 the proprietary ``ff12d941`` block op is NEVER decoded —
    we emit an honest ``blocked`` verdict so the operator sees the gap.
    """
    boot = manifest.boot_partition()
    if boot is None:
        return PayloadBootVerdict(
            extraction_status="no_boot_partition",
            blocked_reason=None,
            recommendation=None,
            boot_op_types=[],
        )
    if boot.has_nonstandard_op:
        return PayloadBootVerdict(
            extraction_status="blocked",
            blocked_reason="ff12d941_proprietary_block",
            recommendation="live_adb_or_vendor_tool",
            boot_op_types=list(boot.op_types),
        )
    if boot.all_standard:
        return PayloadBootVerdict(
            extraction_status="standard",
            blocked_reason=None,
            recommendation=None,
            boot_op_types=list(boot.op_types),
        )
    # No ops parsed at all (manifest truncated mid-boot) — treat as blocked
    # with an honest "undeterminable" recommendation.
    return PayloadBootVerdict(
        extraction_status="blocked",
        blocked_reason="boot_ops_unparseable",
        recommendation="live_adb_or_vendor_tool",
        boot_op_types=list(boot.op_types),
    )


__all__ = [
    "PayloadBootVerdict",
    "PayloadManifest",
    "PayloadPartition",
    "classify_boot_partition",
    "parse_payload_manifest",
]
