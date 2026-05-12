"""Clean-room minimal parser for Windows Application Compatibility Shim
Database (`.sdb`) files.

**Format source:** https://github.com/williballenthin/python-sdb
(master @ ``8ac378546e72a3f9f4bf00a1ea6a89fbb0f77c2e``, Apache 2.0,
2026-05-12). Author: Willi Ballenthin. The TAG-ID constants and
type-bit masks below are reproduced under fair-use reference; see
``ATTRIBUTION.md`` for the full attribution + adaptation log.

**Why a clean-room rewrite:** upstream depends on
``vivisect-vstruct-wb==1.0.3`` for binary parsing. To avoid pulling a
heavyweight transitive dependency into the wairz worker container,
this vendor implements the same format from documentation only using
the Python standard library (``struct``, ``dataclasses``). Functional
contract: ``parse_sdb(bytez: bytes) -> ParsedSDB`` returning a flat
aggregate of APP / SHIM / PATCH entries — sufficient for the
``app.services.sdb_walker`` triage surface.

**.sdb binary format** (per upstream's ``sdb/sdb.py``):

- File header at offset 0: ``unknown0: uint32`` + ``unknown1: uint32``
  + ``magic: 4-byte "sdbf"``. We validate the magic and skip to
  offset 12 for the first chunk.
- Each subsequent chunk: ``tag: uint16`` + payload. The payload size
  is derived from the high nibble of the tag:

  - ``0x1000`` TAG_TYPE_NULL → 0 bytes payload (boolean flag).
  - ``0x3000`` TAG_TYPE_WORD → 2 bytes payload (uint16).
  - ``0x4000`` TAG_TYPE_DWORD → 4 bytes payload (uint32).
  - ``0x5000`` TAG_TYPE_QWORD → 8 bytes payload (uint64).
  - ``0x6000`` TAG_TYPE_STRINGREF → 4 bytes payload (uint32; offset
    into TAG_STRINGTABLE).
  - ``0x7000`` TAG_TYPE_LIST → 4 bytes size prefix (uint32) followed
    by nested chunks of that size.
  - ``0x8000`` TAG_TYPE_STRING → 4 bytes size prefix (uint32)
    followed by UTF-16-LE encoded string of that byte size.
  - ``0x9000`` TAG_TYPE_BINARY → 4 bytes size prefix (uint32) followed
    by raw bytes of that size.

Top-level structure: 3 LIST chunks — TAG_INDEXES (0x7802),
TAG_DATABASE (0x7001), TAG_STRINGTABLE (0x7801). The walker
operates on TAG_DATABASE (which contains APP / SHIM / PATCH /
LAYER children) and uses TAG_STRINGTABLE to resolve STRINGREF
offsets back to UTF-16-LE strings.

**CLAUDE.md Rule #36 no-execute compliance:** this module is 100%
binary parsing. There is ZERO subprocess / shell / exec / eval /
runpy / dynamic-import activity. Wairz NEVER passes parsed shim
payloads to ``sdbinst.exe`` / ``AppHelp.dll`` / ``Mscoree.dll`` /
any other Windows shim infrastructure on the host. The entries
surface as DATA via the consumer in ``app.services.sdb_walker``.

Caller pattern from ``app.services.sdb_walker``::

    from backend.third_party.python_sdb import parse_sdb

    parsed = parse_sdb(sdb_bytes)
    for app in parsed.apps:
        for shim in app.shims:
            # persist a WindowsSdbEntry row per shim
            ...
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

__all__ = [
    # Public API.
    "InvalidSDBFileError",
    "ParsedSDB",
    "SDBApp",
    "SDBPatch",
    "SDBShim",
    "parse_sdb",
    "tag_name_for",
    # Constants — reproduced under fair-use reference from
    # williballenthin/python-sdb.
    "SDB_MAGIC",
    "SDB_HEADER_SIZE",
    "TAG_TYPE_NULL",
    "TAG_TYPE_WORD",
    "TAG_TYPE_DWORD",
    "TAG_TYPE_QWORD",
    "TAG_TYPE_STRINGREF",
    "TAG_TYPE_LIST",
    "TAG_TYPE_STRING",
    "TAG_TYPE_BINARY",
    "TAG_DATABASE",
    "TAG_LIBRARY",
    "TAG_SHIM",
    "TAG_PATCH",
    "TAG_APP",
    "TAG_EXE",
    "TAG_NAME",
    "TAG_DLLFILE",
    "TAG_COMMAND_LINE",
    "TAG_STRINGTABLE",
    "TAG_STRINGTABLE_ITEM",
    "TAG_PATCH_BITS",
    "TAG_DATABASE_ID",
]


# ── File magic + header ──────────────────────────────────────────────────────

# 4-byte file magic. Lives at offset 8 (after two unknown uint32s).
SDB_MAGIC: bytes = b"sdbf"

# Size of the fixed-shape file header: unknown0 (4) + unknown1 (4) +
# magic (4) = 12 bytes. The first chunk begins at offset 12.
SDB_HEADER_SIZE: int = 12


# ── TAG type masks (high nibble of the 16-bit tag value) ─────────────────────
#
# Reproduced under fair-use reference from williballenthin/python-sdb
# `sdb/sdb.py` (Apache 2.0; SHA 8ac378546e72a3f9f4bf00a1ea6a89fbb0f77c2e).
# These are protocol-level constants describing the Windows SDB file
# format and not copyrightable expression; cited per the upstream
# Apache 2.0 §4(c) attribution clause.

TAG_TYPE_NULL: int = 0x1000      # 0-byte payload (boolean flag)
TAG_TYPE_WORD: int = 0x3000      # 2-byte payload (uint16)
TAG_TYPE_DWORD: int = 0x4000     # 4-byte payload (uint32)
TAG_TYPE_QWORD: int = 0x5000     # 8-byte payload (uint64)
TAG_TYPE_STRINGREF: int = 0x6000  # 4-byte payload (uint32 stringtable offset)
TAG_TYPE_LIST: int = 0x7000      # 4-byte size prefix + nested chunks
TAG_TYPE_STRING: int = 0x8000    # 4-byte size prefix + UTF-16-LE bytes
TAG_TYPE_BINARY: int = 0x9000    # 4-byte size prefix + raw bytes

_TAG_TYPE_MASK: int = 0xF000  # High nibble carries the type
_TAG_VALUE_MASK: int = 0x0FFF  # Low 12 bits carry the per-type tag id


# ── TAG IDs (LIST type) ──────────────────────────────────────────────────────
#
# Top-level container tags from upstream `sdb/sdb.py`. These are the
# LIST chunks that contain other chunks recursively.

TAG_DATABASE: int = 0x1 | TAG_TYPE_LIST
TAG_LIBRARY: int = 0x2 | TAG_TYPE_LIST
TAG_INEXCLUDE: int = 0x3 | TAG_TYPE_LIST
TAG_SHIM: int = 0x4 | TAG_TYPE_LIST
TAG_PATCH: int = 0x5 | TAG_TYPE_LIST
TAG_APP: int = 0x6 | TAG_TYPE_LIST
TAG_EXE: int = 0x7 | TAG_TYPE_LIST
TAG_MATCHING_FILE: int = 0x8 | TAG_TYPE_LIST
TAG_SHIM_REF: int = 0x9 | TAG_TYPE_LIST
TAG_PATCH_REF: int = 0xA | TAG_TYPE_LIST
TAG_LAYER: int = 0xB | TAG_TYPE_LIST
TAG_FILE: int = 0xC | TAG_TYPE_LIST
TAG_APPHELP: int = 0xD | TAG_TYPE_LIST
TAG_LINK: int = 0xE | TAG_TYPE_LIST
TAG_DATA: int = 0xF | TAG_TYPE_LIST
TAG_STRINGTABLE: int = 0x801 | TAG_TYPE_LIST
TAG_INDEXES: int = 0x802 | TAG_TYPE_LIST
TAG_INDEX: int = 0x803 | TAG_TYPE_LIST


# ── TAG IDs (STRINGREF type) — string-table-resolved fields ─────────────────

TAG_NAME: int = 0x1 | TAG_TYPE_STRINGREF
TAG_DESCRIPTION: int = 0x2 | TAG_TYPE_STRINGREF
TAG_MODULE: int = 0x3 | TAG_TYPE_STRINGREF
TAG_API: int = 0x4 | TAG_TYPE_STRINGREF
TAG_VENDOR: int = 0x5 | TAG_TYPE_STRINGREF
TAG_APP_NAME: int = 0x6 | TAG_TYPE_STRINGREF
TAG_COMMAND_LINE: int = 0x8 | TAG_TYPE_STRINGREF
TAG_COMPANY_NAME: int = 0x9 | TAG_TYPE_STRINGREF
TAG_DLLFILE: int = 0xA | TAG_TYPE_STRINGREF


# ── TAG IDs (STRING type) — string-table entry ───────────────────────────────

TAG_STRINGTABLE_ITEM: int = 0x801 | TAG_TYPE_STRING


# ── TAG IDs (BINARY type) — binary blobs ─────────────────────────────────────

TAG_PATCH_BITS: int = 0x2 | TAG_TYPE_BINARY
TAG_FILE_BITS: int = 0x3 | TAG_TYPE_BINARY
TAG_EXE_ID: int = 0x4 | TAG_TYPE_BINARY
TAG_DATA_BITS: int = 0x5 | TAG_TYPE_BINARY
TAG_DATABASE_ID: int = 0x7 | TAG_TYPE_BINARY


# ── Reverse map: tag-int → readable name ─────────────────────────────────────

_TAG_NAMES: dict[int, str] = {
    TAG_DATABASE: "TAG_DATABASE",
    TAG_LIBRARY: "TAG_LIBRARY",
    TAG_INEXCLUDE: "TAG_INEXCLUDE",
    TAG_SHIM: "TAG_SHIM",
    TAG_PATCH: "TAG_PATCH",
    TAG_APP: "TAG_APP",
    TAG_EXE: "TAG_EXE",
    TAG_MATCHING_FILE: "TAG_MATCHING_FILE",
    TAG_SHIM_REF: "TAG_SHIM_REF",
    TAG_PATCH_REF: "TAG_PATCH_REF",
    TAG_LAYER: "TAG_LAYER",
    TAG_FILE: "TAG_FILE",
    TAG_APPHELP: "TAG_APPHELP",
    TAG_LINK: "TAG_LINK",
    TAG_DATA: "TAG_DATA",
    TAG_STRINGTABLE: "TAG_STRINGTABLE",
    TAG_INDEXES: "TAG_INDEXES",
    TAG_INDEX: "TAG_INDEX",
    TAG_NAME: "TAG_NAME",
    TAG_DESCRIPTION: "TAG_DESCRIPTION",
    TAG_MODULE: "TAG_MODULE",
    TAG_API: "TAG_API",
    TAG_VENDOR: "TAG_VENDOR",
    TAG_APP_NAME: "TAG_APP_NAME",
    TAG_COMMAND_LINE: "TAG_COMMAND_LINE",
    TAG_COMPANY_NAME: "TAG_COMPANY_NAME",
    TAG_DLLFILE: "TAG_DLLFILE",
    TAG_STRINGTABLE_ITEM: "TAG_STRINGTABLE_ITEM",
    TAG_PATCH_BITS: "TAG_PATCH_BITS",
    TAG_FILE_BITS: "TAG_FILE_BITS",
    TAG_EXE_ID: "TAG_EXE_ID",
    TAG_DATA_BITS: "TAG_DATA_BITS",
    TAG_DATABASE_ID: "TAG_DATABASE_ID",
}


def tag_name_for(tag: int) -> str:
    """Return a readable name for ``tag`` (e.g. ``"TAG_APP"``) or
    ``"TAG_UNKNOWN_<hex>"`` for tags we don't recognise. Pure
    function. Used by the walker for human-readable evidence."""
    name = _TAG_NAMES.get(tag)
    if name is not None:
        return name
    return f"TAG_UNKNOWN_0x{tag:04X}"


# ── Defensive limits ─────────────────────────────────────────────────────────

# Cap on .sdb size we'll attempt to parse. Real shim databases are
# typically 50 KB – 5 MB (sysmain.sdb ships ~5 MB on Windows 10). 64
# MiB is a hard upper bound to prevent attacker DoS via pathologically-
# large files.
_DEFAULT_MAX_FILE_BYTES: int = 64 * 1024 * 1024  # 64 MiB

# Cap on the number of chunks (TAG/value pairs) we'll descend through
# in one parse. 200_000 covers full sysmain.sdb (typically ~50,000
# chunks); higher values are attacker DoS shapes.
_DEFAULT_MAX_CHUNKS: int = 200_000


class InvalidSDBFileError(Exception):
    """Raised when the input bytes are not a valid .sdb file."""


# ── Result dataclasses ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class SDBShim:
    """One decoded TAG_SHIM entry.

    A SHIM is a function-redirect record — it specifies a ``module``
    DLL + ``name`` (e.g. ``"InjectDll"``, ``"RedirectEXE"``,
    ``"GetCommandLineW"``) that Windows AppHelp infrastructure invokes
    when the target application matches the parent TAG_APP's matching
    rules.

    Attacker-controlled SHIMs are the primary T1546.011 (Application
    Shimming) persistence mechanism. The most concerning SHIM names
    (``InjectDll``, ``RedirectEXE``, ``RedirectShortcut``,
    ``GetCommandLineW``) DIRECTLY execute attacker code in the target
    application's context.
    """
    name: str                         # SHIM identifier (e.g. "InjectDll")
    description: str                  # Human-readable description (TAG_DESCRIPTION) or ""
    module: str                       # Backing DLL (TAG_MODULE or TAG_DLLFILE) or ""
    command_line: str                 # Parameter string (TAG_COMMAND_LINE) or ""


@dataclass(frozen=True)
class SDBPatch:
    """One decoded TAG_PATCH entry.

    A PATCH is a byte-modification record — it specifies a sequence of
    binary patches Windows applies to the target application's
    in-memory image at load time. We surface the raw PATCH_BITS bytes
    as ``patch_bits_hex`` for operator inspection (no opcode
    interpretation needed for triage)."""
    name: str                         # PATCH identifier (e.g. "MaxVersionLie")
    patch_bits_hex: str               # Hex-encoded TAG_PATCH_BITS payload (or "")
    patch_bits_size: int              # Number of bytes in patch_bits_hex / 2


@dataclass(frozen=True)
class SDBApp:
    """One decoded TAG_APP entry.

    An APP is a per-application bundle. Each APP carries:

    - ``name``: TAG_NAME (the application's name as the shim author
      sees it — e.g. ``"MyApp.exe Compatibility Fix"``).
    - ``app_name``: TAG_APP_NAME (the displayed app name —
      e.g. ``"MyApp"``).
    - ``vendor``: TAG_VENDOR (the application vendor).
    - ``exes``: list of EXE matching records. Each EXE record has its
      own ``name`` (the .exe filename to match) and may carry FILE
      records (per-file matching rules). We surface only the bare
      EXE name list for triage simplicity.
    - ``shims``: list of decoded SHIM records (see SDBShim).
    - ``patches``: list of decoded PATCH records (see SDBPatch).
    """
    name: str
    app_name: str
    vendor: str
    exes: tuple[str, ...]
    shims: tuple[SDBShim, ...]
    patches: tuple[SDBPatch, ...]


@dataclass(frozen=True)
class ParsedSDB:
    """Top-level parse result: aggregate of APP / SHIM / PATCH entries
    + a flag indicating whether parsing reached the natural end.

    ``apps`` is the primary triage surface. Top-level orphan SHIMs and
    PATCHes (not under an APP) are surfaced separately for
    completeness; attacker-planted shims OCCASIONALLY appear without a
    matching APP parent (Library-only shims).
    """
    apps: tuple[SDBApp, ...]
    orphan_shims: tuple[SDBShim, ...]
    orphan_patches: tuple[SDBPatch, ...]
    stringtable_entries: int  # Number of strings in the table
    chunks_parsed: int        # Total chunks visited (DoS observability)
    truncated: bool           # True if max_chunks / max_file_bytes hit


# ── Parser implementation ────────────────────────────────────────────────────


def _read_chunk_header(buf: bytes, offset: int) -> tuple[int, int]:
    """Read the 2-byte tag at ``offset``. Returns (tag, new_offset).
    Defensive — raises InvalidSDBFileError on EOF."""
    if offset + 2 > len(buf):
        raise InvalidSDBFileError(
            f"truncated SDB at chunk tag (offset {offset})"
        )
    tag = struct.unpack_from("<H", buf, offset)[0]
    return tag, offset + 2


def _read_payload_size_prefixed(
    buf: bytes, offset: int
) -> tuple[int, int]:
    """Read the 4-byte size prefix at ``offset``. Returns (size,
    payload_start_offset). Used for LIST, STRING, BINARY tag types."""
    if offset + 4 > len(buf):
        raise InvalidSDBFileError(
            f"truncated SDB at size prefix (offset {offset})"
        )
    size = struct.unpack_from("<I", buf, offset)[0]
    return size, offset + 4


def _build_stringtable(
    buf: bytes, stringtable_offset: int, stringtable_size: int
) -> dict[int, str]:
    """Walk the TAG_STRINGTABLE LIST payload and build a map from
    payload-relative offset → UTF-16-LE-decoded string.

    The STRINGREF tag carries a uint32 offset that points to a STRING
    chunk inside the stringtable LIST. The key in the returned map is
    that uint32 offset (measured from the LIST's payload start, NOT
    from the absolute file offset).
    """
    table: dict[int, str] = {}
    end = stringtable_offset + stringtable_size
    cur = stringtable_offset
    # The stringtable consists of TAG_STRINGTABLE_ITEM chunks back to
    # back. The KEY in the returned map is the offset of the
    # STRING_ITEM chunk header (the tag's uint16) RELATIVE to the
    # stringtable LIST payload start — that's what STRINGREF points
    # at.
    base = stringtable_offset
    while cur < end:
        # Track the relative offset BEFORE reading the tag so STRINGREF
        # readers can index into the resulting map by their stored
        # value.
        relative = cur - base
        tag, cur = _read_chunk_header(buf, cur)
        if tag != TAG_STRINGTABLE_ITEM:
            # Defensive: skip past unknown entries by treating as
            # size-prefixed.
            try:
                size, cur = _read_payload_size_prefixed(buf, cur)
            except InvalidSDBFileError:
                break
            cur += size
            continue
        size, cur = _read_payload_size_prefixed(buf, cur)
        if cur + size > len(buf):
            break
        raw = buf[cur:cur + size]
        # UTF-16-LE; strip trailing NUL.
        try:
            decoded = raw.decode("utf-16-le", errors="replace")
        except Exception:
            decoded = ""
        if decoded.endswith("\x00"):
            decoded = decoded.rstrip("\x00")
        table[relative] = decoded
        cur += size
    return table


def _decode_string_payload(buf: bytes, offset: int, size: int) -> str:
    """Decode a UTF-16-LE STRING chunk payload defensively."""
    if offset + size > len(buf):
        return ""
    raw = buf[offset:offset + size]
    try:
        decoded = raw.decode("utf-16-le", errors="replace")
    except Exception:
        return ""
    return decoded.rstrip("\x00")


def _parse_shim(
    buf: bytes, payload_offset: int, payload_size: int,
    stringtable: dict[int, str], chunk_budget: list[int],
) -> SDBShim:
    """Decode one TAG_SHIM payload's child chunks into an SDBShim."""
    name = ""
    description = ""
    module = ""
    command_line = ""
    end = payload_offset + payload_size
    cur = payload_offset
    while cur < end and chunk_budget[0] > 0:
        chunk_budget[0] -= 1
        try:
            tag, cur = _read_chunk_header(buf, cur)
        except InvalidSDBFileError:
            break
        type_mask = tag & _TAG_TYPE_MASK
        if type_mask == TAG_TYPE_STRINGREF:
            if cur + 4 > len(buf):
                break
            stringref = struct.unpack_from("<I", buf, cur)[0]
            cur += 4
            value = stringtable.get(stringref, "")
            if tag == TAG_NAME:
                name = value
            elif tag == TAG_DESCRIPTION:
                description = value
            elif tag == TAG_MODULE or tag == TAG_DLLFILE:
                module = value
            elif tag == TAG_COMMAND_LINE:
                command_line = value
        elif type_mask in (TAG_TYPE_LIST, TAG_TYPE_STRING, TAG_TYPE_BINARY):
            try:
                size, cur = _read_payload_size_prefixed(buf, cur)
            except InvalidSDBFileError:
                break
            cur += size
        elif type_mask == TAG_TYPE_WORD:
            cur += 2
        elif type_mask == TAG_TYPE_DWORD:
            cur += 4
        elif type_mask == TAG_TYPE_QWORD:
            cur += 8
        elif type_mask == TAG_TYPE_NULL:
            pass  # 0-byte payload
        else:
            # Unknown type — bail to avoid infinite loop.
            break
    return SDBShim(
        name=name,
        description=description,
        module=module,
        command_line=command_line,
    )


def _parse_patch(
    buf: bytes, payload_offset: int, payload_size: int,
    stringtable: dict[int, str], chunk_budget: list[int],
) -> SDBPatch:
    """Decode one TAG_PATCH payload's child chunks into an SDBPatch."""
    name = ""
    patch_bits_hex = ""
    patch_bits_size = 0
    end = payload_offset + payload_size
    cur = payload_offset
    while cur < end and chunk_budget[0] > 0:
        chunk_budget[0] -= 1
        try:
            tag, cur = _read_chunk_header(buf, cur)
        except InvalidSDBFileError:
            break
        type_mask = tag & _TAG_TYPE_MASK
        if type_mask == TAG_TYPE_STRINGREF:
            if cur + 4 > len(buf):
                break
            stringref = struct.unpack_from("<I", buf, cur)[0]
            cur += 4
            if tag == TAG_NAME:
                name = stringtable.get(stringref, "")
        elif type_mask == TAG_TYPE_BINARY:
            try:
                size, cur = _read_payload_size_prefixed(buf, cur)
            except InvalidSDBFileError:
                break
            if tag == TAG_PATCH_BITS:
                # Cap the hex payload to ~16 KB raw (32 KB hex) so a
                # rogue PATCH_BITS doesn't bloat a single Finding
                # evidence string.
                snip = buf[cur:cur + min(size, 16 * 1024)]
                patch_bits_hex = snip.hex()
                patch_bits_size = size
            cur += size
        elif type_mask in (TAG_TYPE_LIST, TAG_TYPE_STRING):
            try:
                size, cur = _read_payload_size_prefixed(buf, cur)
            except InvalidSDBFileError:
                break
            cur += size
        elif type_mask == TAG_TYPE_WORD:
            cur += 2
        elif type_mask == TAG_TYPE_DWORD:
            cur += 4
        elif type_mask == TAG_TYPE_QWORD:
            cur += 8
        elif type_mask == TAG_TYPE_NULL:
            pass
        else:
            break
    return SDBPatch(
        name=name,
        patch_bits_hex=patch_bits_hex,
        patch_bits_size=patch_bits_size,
    )


def _parse_exe(
    buf: bytes, payload_offset: int, payload_size: int,
    stringtable: dict[int, str], chunk_budget: list[int],
) -> str:
    """Decode one TAG_EXE payload — return the .exe filename
    (TAG_NAME STRINGREF). Skip the per-FILE matching detail."""
    end = payload_offset + payload_size
    cur = payload_offset
    name = ""
    while cur < end and chunk_budget[0] > 0:
        chunk_budget[0] -= 1
        try:
            tag, cur = _read_chunk_header(buf, cur)
        except InvalidSDBFileError:
            break
        type_mask = tag & _TAG_TYPE_MASK
        if type_mask == TAG_TYPE_STRINGREF:
            if cur + 4 > len(buf):
                break
            stringref = struct.unpack_from("<I", buf, cur)[0]
            cur += 4
            if tag == TAG_NAME and not name:
                name = stringtable.get(stringref, "")
        elif type_mask in (TAG_TYPE_LIST, TAG_TYPE_STRING, TAG_TYPE_BINARY):
            try:
                size, cur = _read_payload_size_prefixed(buf, cur)
            except InvalidSDBFileError:
                break
            cur += size
        elif type_mask == TAG_TYPE_WORD:
            cur += 2
        elif type_mask == TAG_TYPE_DWORD:
            cur += 4
        elif type_mask == TAG_TYPE_QWORD:
            cur += 8
        elif type_mask == TAG_TYPE_NULL:
            pass
        else:
            break
    return name


def _parse_app(
    buf: bytes, payload_offset: int, payload_size: int,
    stringtable: dict[int, str], chunk_budget: list[int],
) -> SDBApp:
    """Decode one TAG_APP payload's child chunks into an SDBApp.

    Walks the APP's nested chunks; recursively decodes TAG_EXE,
    TAG_SHIM, TAG_PATCH children."""
    name = ""
    app_name = ""
    vendor = ""
    exes: list[str] = []
    shims: list[SDBShim] = []
    patches: list[SDBPatch] = []
    end = payload_offset + payload_size
    cur = payload_offset
    while cur < end and chunk_budget[0] > 0:
        chunk_budget[0] -= 1
        try:
            tag, cur = _read_chunk_header(buf, cur)
        except InvalidSDBFileError:
            break
        type_mask = tag & _TAG_TYPE_MASK
        if type_mask == TAG_TYPE_STRINGREF:
            if cur + 4 > len(buf):
                break
            stringref = struct.unpack_from("<I", buf, cur)[0]
            cur += 4
            value = stringtable.get(stringref, "")
            if tag == TAG_NAME:
                name = value
            elif tag == TAG_APP_NAME:
                app_name = value
            elif tag == TAG_VENDOR:
                vendor = value
        elif type_mask == TAG_TYPE_LIST:
            try:
                size, cur = _read_payload_size_prefixed(buf, cur)
            except InvalidSDBFileError:
                break
            payload_end = cur + size
            if payload_end > len(buf):
                break
            if tag == TAG_EXE:
                exe_name = _parse_exe(
                    buf, cur, size, stringtable, chunk_budget
                )
                if exe_name:
                    exes.append(exe_name)
            elif tag == TAG_SHIM:
                shim = _parse_shim(
                    buf, cur, size, stringtable, chunk_budget
                )
                shims.append(shim)
            elif tag == TAG_PATCH:
                patch = _parse_patch(
                    buf, cur, size, stringtable, chunk_budget
                )
                patches.append(patch)
            cur = payload_end
        elif type_mask in (TAG_TYPE_STRING, TAG_TYPE_BINARY):
            try:
                size, cur = _read_payload_size_prefixed(buf, cur)
            except InvalidSDBFileError:
                break
            cur += size
        elif type_mask == TAG_TYPE_WORD:
            cur += 2
        elif type_mask == TAG_TYPE_DWORD:
            cur += 4
        elif type_mask == TAG_TYPE_QWORD:
            cur += 8
        elif type_mask == TAG_TYPE_NULL:
            pass
        else:
            break
    return SDBApp(
        name=name,
        app_name=app_name,
        vendor=vendor,
        exes=tuple(exes),
        shims=tuple(shims),
        patches=tuple(patches),
    )


def _parse_database(
    buf: bytes, payload_offset: int, payload_size: int,
    stringtable: dict[int, str], chunk_budget: list[int],
) -> tuple[list[SDBApp], list[SDBShim], list[SDBPatch]]:
    """Walk a TAG_DATABASE LIST payload's children. Top-level APP /
    SHIM / PATCH are decoded; SHIM / PATCH outside any APP are
    'orphans' surfaced separately for triage completeness."""
    apps: list[SDBApp] = []
    orphan_shims: list[SDBShim] = []
    orphan_patches: list[SDBPatch] = []
    end = payload_offset + payload_size
    cur = payload_offset
    while cur < end and chunk_budget[0] > 0:
        chunk_budget[0] -= 1
        try:
            tag, cur = _read_chunk_header(buf, cur)
        except InvalidSDBFileError:
            break
        type_mask = tag & _TAG_TYPE_MASK
        if type_mask == TAG_TYPE_LIST:
            try:
                size, cur = _read_payload_size_prefixed(buf, cur)
            except InvalidSDBFileError:
                break
            payload_end = cur + size
            if payload_end > len(buf):
                break
            if tag == TAG_APP:
                apps.append(
                    _parse_app(buf, cur, size, stringtable, chunk_budget)
                )
            elif tag == TAG_SHIM:
                orphan_shims.append(
                    _parse_shim(buf, cur, size, stringtable, chunk_budget)
                )
            elif tag == TAG_PATCH:
                orphan_patches.append(
                    _parse_patch(buf, cur, size, stringtable, chunk_budget)
                )
            cur = payload_end
        elif type_mask in (TAG_TYPE_STRING, TAG_TYPE_BINARY):
            try:
                size, cur = _read_payload_size_prefixed(buf, cur)
            except InvalidSDBFileError:
                break
            cur += size
        elif type_mask == TAG_TYPE_STRINGREF:
            cur += 4
        elif type_mask == TAG_TYPE_WORD:
            cur += 2
        elif type_mask == TAG_TYPE_DWORD:
            cur += 4
        elif type_mask == TAG_TYPE_QWORD:
            cur += 8
        elif type_mask == TAG_TYPE_NULL:
            pass
        else:
            break
    return apps, orphan_shims, orphan_patches


def parse_sdb(
    bytez: bytes,
    *,
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
    max_chunks: int = _DEFAULT_MAX_CHUNKS,
) -> ParsedSDB:
    """Parse a .sdb file's bytes into a ParsedSDB aggregate.

    Defensive boundary — raises ``InvalidSDBFileError`` if the magic
    is wrong or the file is hopelessly truncated. Otherwise tolerates
    truncation / unknown tag types gracefully (returns whatever it
    decoded with ``truncated=True``).

    :param bytez: raw .sdb bytes.
    :param max_file_bytes: DoS guard; .sdb files larger than this are
        rejected (default 64 MiB).
    :param max_chunks: DoS guard; we visit at most this many chunks
        across all recursive descents (default 200_000).
    """
    if len(bytez) > max_file_bytes:
        raise InvalidSDBFileError(
            f"SDB file too large: {len(bytez)} > {max_file_bytes}"
        )
    if len(bytez) < SDB_HEADER_SIZE:
        raise InvalidSDBFileError(
            f"SDB file too small: {len(bytez)} < {SDB_HEADER_SIZE}"
        )
    # Validate magic at offset 8.
    magic = bytez[8:12]
    if magic != SDB_MAGIC:
        raise InvalidSDBFileError(
            f"invalid SDB magic: expected {SDB_MAGIC!r}, got {magic!r}"
        )

    # First pass: locate TAG_STRINGTABLE so we can build the string map.
    chunk_budget = [max_chunks]
    truncated = False
    cur = SDB_HEADER_SIZE
    stringtable: dict[int, str] = {}
    database_offset: int | None = None
    database_size: int = 0
    while cur < len(bytez) and chunk_budget[0] > 0:
        chunk_budget[0] -= 1
        try:
            tag, cur = _read_chunk_header(bytez, cur)
        except InvalidSDBFileError:
            truncated = True
            break
        type_mask = tag & _TAG_TYPE_MASK
        if type_mask == TAG_TYPE_LIST:
            try:
                size, cur = _read_payload_size_prefixed(bytez, cur)
            except InvalidSDBFileError:
                truncated = True
                break
            if tag == TAG_STRINGTABLE:
                stringtable = _build_stringtable(bytez, cur, size)
            elif tag == TAG_DATABASE:
                database_offset = cur
                database_size = size
            cur += size
        elif type_mask in (TAG_TYPE_STRING, TAG_TYPE_BINARY):
            try:
                size, cur = _read_payload_size_prefixed(bytez, cur)
            except InvalidSDBFileError:
                truncated = True
                break
            cur += size
        elif type_mask == TAG_TYPE_STRINGREF:
            cur += 4
        elif type_mask == TAG_TYPE_WORD:
            cur += 2
        elif type_mask == TAG_TYPE_DWORD:
            cur += 4
        elif type_mask == TAG_TYPE_QWORD:
            cur += 8
        elif type_mask == TAG_TYPE_NULL:
            pass
        else:
            # Unknown / corrupted — bail.
            truncated = True
            break

    if chunk_budget[0] <= 0:
        truncated = True

    apps: list[SDBApp] = []
    orphan_shims: list[SDBShim] = []
    orphan_patches: list[SDBPatch] = []
    if database_offset is not None and not truncated:
        apps, orphan_shims, orphan_patches = _parse_database(
            bytez, database_offset, database_size, stringtable,
            chunk_budget,
        )

    if chunk_budget[0] <= 0:
        truncated = True

    return ParsedSDB(
        apps=tuple(apps),
        orphan_shims=tuple(orphan_shims),
        orphan_patches=tuple(orphan_patches),
        stringtable_entries=len(stringtable),
        chunks_parsed=max_chunks - chunk_budget[0],
        truncated=truncated,
    )
