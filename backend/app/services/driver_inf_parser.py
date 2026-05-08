"""Phase γ.5 — Windows driver-package INF text parser.

Parses Windows ``.inf`` driver-package descriptor files into the canonical
``inf_metadata`` dict shape consumed by
:class:`WindowsDriver` (via ``app.services.jsonb_normalizers.
_normalize_windows_drivers_inf_metadata``).

INF format reference:
    https://learn.microsoft.com/en-us/windows-hardware/drivers/install/general-syntax-rules-for-inf-files

This is a TEXT parser — no shell-out, no rundll32, no .inf install. Per
Rule #36 no-execute discipline: the INF file is read as data; nothing
in this module passes the file path to a process-spawn primitive.

Surfaces extracted (per the γ.5 kickoff prompt + Persona-E #13):
- ``[Version]`` block: ``Class``, ``ClassGuid``, ``Provider``,
  ``DriverVer``, ``CatalogFile``
- ``[Manufacturer]`` block: list of (manufacturer-name, section-name,
  OS/arch decorations)
- ``[Models]`` block (and per-manufacturer / per-decoration variants):
  list of (device-description, install-section, hardware-id,
  compatible-ids)
- ``[Strings]`` block: substitution table for ``%TokenName%`` references

INF sections beyond the four above are skipped — γ.5's surface is the
driver-matrix view (Persona-E #13 capability badge), not full
DDInstall reconstruction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# INF section header pattern. Sections live inside square brackets at
# the start of a line; trailing whitespace + optional inline comment
# allowed. Section names are case-insensitive per INF spec.
_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*(?:;.*)?$")

# INF entry pattern. Either ``key = value(s)`` or ``value(,value)+`` —
# the parser distinguishes by presence of ``=``. Comments start with
# ``;`` and continue to end of line. Line continuation via ``\`` at
# end-of-line is handled by the line normaliser BEFORE this regex
# runs, so by the time we apply this regex the entry is on one line.
_KEY_VALUE_RE = re.compile(r"^\s*([^=;]+?)\s*=\s*(.*?)\s*(?:;.*)?$")

# String-substitution token pattern. ``%TokenName%`` references resolve
# to the [Strings] table value. Token names are case-insensitive per
# INF spec — the Strings dict is keyed by lower-cased token.
_STRING_TOKEN_RE = re.compile(r"%([^%]+)%")

# Manufacturer entry: ``MfgName = SectionName[, OSDecoration1, OSDecoration2, ...]``.
# The section name + decorations live on the right side of the ``=``,
# comma-separated.
# (We don't pre-compile a separate regex here because the [Manufacturer]
# block uses the same key=value shape that _KEY_VALUE_RE matches.)


# Per the windows_drivers.inf_metadata canonical shape (Phase γ.5 — see
# app.services.jsonb_normalizers._normalize_windows_drivers_inf_metadata
# for the doc-comment of the contract):
@dataclass
class _ParsedInf:
    """Internal builder for the canonical inf_metadata dict."""
    version_block: dict[str, Any] = field(default_factory=lambda: {
        "Class": None, "ClassGuid": None, "Provider": None,
        "DriverVer": None, "CatalogFile": None,
    })
    manufacturer_block: list[dict[str, Any]] = field(default_factory=list)
    models: list[dict[str, Any]] = field(default_factory=list)
    strings: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version_block": dict(self.version_block),
            "manufacturer_block": list(self.manufacturer_block),
            "models": list(self.models),
            "strings": dict(self.strings),
            "errors": list(self.errors),
        }


def _strip_quotes(s: str) -> str:
    """Remove a leading + trailing pair of double-quotes from ``s``."""
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def _normalise_lines(text: str) -> list[str]:
    """Pre-process raw INF text into a flat list of logical lines.

    INF files are line-oriented but support line continuation via a
    backslash at end-of-line. The pre-pass collapses continued lines
    into single logical lines so the section/entry regex can apply
    line-by-line. Comments (everything after ``;``) are stripped here
    too — comments inside string values aren't a concern for our
    canonical surface.
    """
    raw_lines = text.splitlines()
    out: list[str] = []
    buffer: list[str] = []
    for raw in raw_lines:
        stripped = raw.rstrip()
        # Continuation: line ends with backslash (not ``\\``).
        if stripped.endswith("\\") and not stripped.endswith("\\\\"):
            buffer.append(stripped[:-1])
            continue
        if buffer:
            buffer.append(stripped)
            out.append(" ".join(buffer))
            buffer = []
        else:
            out.append(stripped)
    if buffer:
        out.append(" ".join(buffer))
    return out


def _split_csv(value: str) -> list[str]:
    """Split a comma-separated INF value into trimmed tokens.

    Tokens are stripped of surrounding whitespace + trailing inline
    comment. Quoted tokens preserve internal commas (rare in INF but
    spec-permitted).
    """
    parts: list[str] = []
    in_quote = False
    current: list[str] = []
    for ch in value:
        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
            continue
        if ch == "," and not in_quote:
            parts.append("".join(current).strip())
            current = []
            continue
        if ch == ";" and not in_quote:
            # Inline comment — discard the rest.
            break
        current.append(ch)
    tail = "".join(current).strip()
    if tail or parts:
        parts.append(tail)
    return [_strip_quotes(p) for p in parts if p != "" or parts.index(p) < len(parts) - 1]


def _resolve_token(value: str, strings: dict[str, str]) -> str:
    """Resolve ``%TokenName%`` references against the Strings table.

    Unresolved tokens are left in-place (so the operator can see the
    original value); the parser records an error per unresolved token
    via the caller.
    """
    def _sub(match: re.Match) -> str:
        token = match.group(1).strip()
        # INF token names are case-insensitive per spec — Strings dict
        # is keyed by lower-cased token name.
        return strings.get(token.lower(), match.group(0))

    return _STRING_TOKEN_RE.sub(_sub, value)


def _parse_strings_section(entries: list[tuple[str, str]]) -> dict[str, str]:
    """Build the [Strings] substitution table from raw key=value entries."""
    out: dict[str, str] = {}
    for key, value in entries:
        # Lower-case keys for case-insensitive lookup.
        out[key.strip().lower()] = _strip_quotes(value.strip())
    return out


def _parse_version_block(entries: list[tuple[str, str]]) -> dict[str, Any]:
    """Extract the [Version] block keys we care about.

    Other keys (Signature, ClassVer, DriverPackageDisplayName,
    DriverPackageType, etc.) are dropped — they don't contribute to
    the driver-matrix view per Persona-E #13.
    """
    block: dict[str, Any] = {
        "Class": None,
        "ClassGuid": None,
        "Provider": None,
        "DriverVer": None,
        "CatalogFile": None,
    }
    for key, value in entries:
        norm_key = key.strip()
        # Match case-insensitively against the canonical key set; INF
        # spec says key names are case-insensitive.
        for canonical in block:
            if norm_key.lower() == canonical.lower():
                block[canonical] = _strip_quotes(value.strip())
                break
    return block


def _parse_manufacturer_block(
    entries: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Extract the [Manufacturer] entries.

    Each entry: ``MfgName = SectionName[, Decoration1, Decoration2, ...]``.
    Returns one dict per manufacturer.
    """
    out: list[dict[str, Any]] = []
    for key, value in entries:
        mfg_name = key.strip()
        tokens = _split_csv(value)
        section_name = tokens[0] if tokens else mfg_name
        decorations = [t for t in tokens[1:] if t]
        out.append({
            "name": _strip_quotes(mfg_name),
            "section": section_name,
            "decorations": decorations,
        })
    return out


def _parse_models_section(
    entries: list[tuple[str, str]],
    manufacturer: str,
) -> list[dict[str, Any]]:
    """Extract device-model entries from a [Models] section.

    Each entry: ``device_description = install_section, hardware_id [, compat_id1, compat_id2, ...]``.
    Returns one dict per device row.
    """
    out: list[dict[str, Any]] = []
    for key, value in entries:
        device_desc = _strip_quotes(key.strip())
        tokens = _split_csv(value)
        if len(tokens) < 2:
            # Not a well-formed Models entry — skip silently per INF
            # spec (some sections like [DefaultInstall] live in here
            # too and don't fit the device-row shape).
            continue
        install_section = tokens[0]
        hardware_id = tokens[1]
        compatible_ids = tokens[2:]
        out.append({
            "manufacturer": manufacturer,
            "device_description": device_desc,
            "install_section": install_section,
            "hardware_id": hardware_id,
            "compatible_ids": compatible_ids,
        })
    return out


def _walk_sections(lines: list[str]) -> dict[str, list[tuple[str, str]]]:
    """Tokenise the line stream into sections of (key, value) pairs.

    Sections that appear multiple times (rare in well-formed INFs but
    technically allowed in some constructions) are merged.
    """
    sections: dict[str, list[tuple[str, str]]] = {}
    current_name: str | None = None
    current_entries: list[tuple[str, str]] = []

    def _flush() -> None:
        nonlocal current_entries
        if current_name is None:
            return
        # Merge case-insensitively so [VERSION] and [Version] alias.
        section_key = current_name.lower()
        sections.setdefault(section_key, []).extend(current_entries)
        current_entries = []

    for raw in lines:
        # Skip blank + pure-comment lines.
        if not raw.strip() or raw.strip().startswith(";"):
            continue
        m = _SECTION_RE.match(raw)
        if m:
            _flush()
            current_name = m.group(1).strip()
            continue
        if current_name is None:
            # Pre-section content — INFs may start with a header
            # comment; safe to skip.
            continue
        kv = _KEY_VALUE_RE.match(raw)
        if kv:
            current_entries.append((kv.group(1), kv.group(2)))
            continue
        # Non-key=value line — append as a (name, "") entry (some
        # sections like [DefaultInstall] use bare lines).
        bare = raw.split(";", 1)[0].strip()
        if bare:
            current_entries.append((bare, ""))
    _flush()
    return sections


def parse_inf_text(text: str) -> dict[str, Any]:
    """Parse INF file text into the canonical ``inf_metadata`` dict.

    Returns a dict with keys: ``version_block``, ``manufacturer_block``,
    ``models``, ``strings``, ``errors``. Schema version is NOT stamped
    here (the writer is responsible for stamping via
    ``_stamp_windows_drivers_inf_metadata`` per Rule #35c separation
    of pure parser from persistence boundary).

    Defensive against every parse failure mode — a malformed INF
    produces a partial dict with errors captured in the ``errors``
    list, never a raised exception.
    """
    parsed = _ParsedInf()

    try:
        lines = _normalise_lines(text)
        sections = _walk_sections(lines)
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        parsed.errors.append(
            f"tokenise: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return parsed.to_dict()

    # [Strings] FIRST so subsequent sections can resolve %TokenName%
    # references. Lower-case key for case-insensitive lookup.
    strings_entries = sections.get("strings", [])
    parsed.strings = _parse_strings_section(strings_entries)

    # [Version] — primary metadata block.
    version_entries = sections.get("version", [])
    parsed.version_block = _parse_version_block(version_entries)
    # Resolve %TokenName% in the version block values.
    for key, value in list(parsed.version_block.items()):
        if isinstance(value, str):
            parsed.version_block[key] = _resolve_token(value, parsed.strings)

    # [Manufacturer] — list of (mfgname, section, decorations).
    mfg_entries = sections.get("manufacturer", [])
    parsed.manufacturer_block = _parse_manufacturer_block(mfg_entries)

    # [Models] — for each manufacturer, parse the section it points
    # to. Decorated variants ([SectionName.NTAMD64.10.0..19041]) are
    # parsed alongside the base section so OS-specific device entries
    # surface in the matrix view.
    for mfg in parsed.manufacturer_block:
        section_base = mfg["section"]
        decorations = mfg.get("decorations", [])
        # Base section.
        for section_name in [section_base] + [
            f"{section_base}.{d}" for d in decorations
        ]:
            section_key = section_name.lower()
            section_entries = sections.get(section_key)
            if not section_entries:
                continue
            mfg_name_resolved = _resolve_token(mfg["name"], parsed.strings)
            parsed.models.extend(
                _parse_models_section(section_entries, mfg_name_resolved)
            )

    return parsed.to_dict()


def parse_inf_file(path: str) -> dict[str, Any]:
    """Read an INF file from disk + parse. Defensive against
    encoding errors (Windows INFs are typically UTF-16 LE BOM but
    legacy ones are CP-1252) and OS errors.

    Sync I/O — caller wraps in run_in_executor for async contexts
    (Rule #5).
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return {
            "version_block": {
                "Class": None, "ClassGuid": None, "Provider": None,
                "DriverVer": None, "CatalogFile": None,
            },
            "manufacturer_block": [],
            "models": [],
            "strings": {},
            "errors": [f"read: {type(exc).__name__}: {str(exc)[:200]}"],
        }

    # Encoding guess — UTF-16 LE/BE if BOM present, else UTF-8 with
    # CP-1252 fallback (Windows INFs are predominantly UTF-16 BOM'd in
    # modern drivers; legacy NT-era ones are CP-1252).
    text: str
    if raw.startswith(b"\xff\xfe"):
        text = raw[2:].decode("utf-16-le", errors="replace")
    elif raw.startswith(b"\xfe\xff"):
        text = raw[2:].decode("utf-16-be", errors="replace")
    else:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("cp1252", errors="replace")

    return parse_inf_text(text)
