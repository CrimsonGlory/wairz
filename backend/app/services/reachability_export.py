"""Reachability evidence export — binary-axis MVP (bridge to the CVE assessment framework).

Produces the per-binary SYMBOL-PRESENCE facts the framework consumes as Gate-1
``FUNCTION_NOT_LINKED`` evidence (the one reachability axis that is artifact-immutable under
Axiom 1: a *defined* function symbol either is or is not in the ELF symbol table). The
framework intersects its own per-CVE sink set against ``defined_symbols`` at ingest — wairz
has no CVE knowledge and never emits a CVE->sink map.

SOUNDNESS (the iron law — a wairz MISS may NEVER clear):
- Symbol PRESENCE is a mechanical fact. Symbol ABSENCE is only trustworthy on a NON-STRIPPED
  binary — so ``stripped`` is computed and carried; the framework ABSTAINS (never clears) when
  it is true (absence-of-evidence != code-absence).
- ``link_b_reachable`` / ``link_c_dataflow_path`` / ``indirect_calls`` are explicitly NULL:
  wairz has no reliable indirect-call enumerator today (function pointers / vtables / dlsym /
  PLT are unresolvable at -O2/-O3), so the ``call_graph_unreachable`` path is DEFERRED — the
  MVP emits NOTHING whose clear depends on absence-of-evidence.

PARSE-ONLY (Rule #45/#36): reads the ELF symbol table via pyelftools; never executes the
binary. Every function degrades to None/[] on any failure — export must never break.
See .planning/research/ast-kg-bridge-binary-axis-spec-2026-06-08.md.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

REACHABILITY_EXPORT_SCHEMA_VERSION = 1
_ANALYZER = "pyelftools"

# pyelftools renders these as strings.
_FUNC_TYPES = ("STT_FUNC", "STT_GNU_IFUNC")
_IMPORT_TYPES = ("STT_FUNC", "STT_GNU_IFUNC", "STT_NOTYPE")
_UNDEF = "SHN_UNDEF"


def _analyzer_version() -> str:
    try:
        import elftools  # noqa: PLC0415
        return getattr(elftools, "__version__", "unknown")
    except Exception:  # noqa: BLE001
        return "unknown"


def extract_elf_symbols(path: str) -> dict | None:
    """Parse-only ELF symbol-table extraction. Returns the symbol facts, or None on non-ELF /
    read failure (so the caller skips the binary rather than fabricating absence).

    Returns:
        {
          "defined_symbols": [str],   # st_shndx != SHN_UNDEF, STT_FUNC/STT_GNU_IFUNC
          "imported_symbols": [str],  # SHN_UNDEF (what this binary calls out to)
          "stripped": bool,           # no .symtab AND no .dynsym symbols -> absence is UNRELIABLE
          "has_symtab": bool, "has_dynsym": bool,
          "arch": str, "format": "elf",
        }
    """
    try:
        from elftools.elf.elffile import ELFFile  # noqa: PLC0415 (Rule #30 lazy; heavy dep)
        from elftools.elf.sections import SymbolTableSection  # noqa: PLC0415
    except ImportError:
        return None
    try:
        with open(path, "rb") as f:
            head = f.read(4)
            if head != b"\x7fELF":
                return None
            f.seek(0)
            elf = ELFFile(f)
            arch = elf.get_machine_arch()
            defined: set[str] = set()
            imported: set[str] = set()
            has_symtab = False
            has_dynsym = False
            for sec_name in (".symtab", ".dynsym"):
                sec = elf.get_section_by_name(sec_name)
                if not isinstance(sec, SymbolTableSection) or sec.num_symbols() == 0:
                    continue
                if sec_name == ".symtab":
                    has_symtab = True
                else:
                    has_dynsym = True
                for sym in sec.iter_symbols():
                    name = sym.name
                    if not name:
                        continue
                    shndx = sym.entry["st_shndx"]
                    stype = sym.entry["st_info"]["type"]
                    if shndx == _UNDEF:
                        if stype in _IMPORT_TYPES:
                            imported.add(name)
                    elif stype in _FUNC_TYPES:
                        defined.add(name)
            # Stripped = no symbol-bearing table at all -> symbol ABSENCE is unreliable.
            stripped = not (has_symtab or has_dynsym)
            return {
                "defined_symbols": sorted(defined),
                "imported_symbols": sorted(imported),
                "stripped": stripped,
                "has_symtab": has_symtab,
                "has_dynsym": has_dynsym,
                "arch": arch or "unknown",
                "format": "elf",
            }
    except Exception:  # noqa: BLE001 — non-ELF / malformed / read error -> skip, never fabricate
        logger.debug("ELF symbol extraction failed for %s", path, exc_info=True)
        return None


def build_reachability_record(
    firmware_id, binary_path_rel: str, binary_sha256: str,
    symbols: dict, fingerprints: dict | None = None, link_a: dict | None = None,
) -> dict:
    """Build one ``wairz_reachability.jsonl`` record (per (binary_path, firmware_id)).

    The wire format the framework gate accepts. Deferred axes are explicitly NULL so a consumer
    cannot misread them as a negative. ``defined_symbols`` is the full defined-function set; the
    framework intersects its per-CVE sink set against it (wairz emits no CVE->sink map).
    """
    fp = fingerprints or {}
    return {
        "schema_version": REACHABILITY_EXPORT_SCHEMA_VERSION,
        "firmware_id": str(firmware_id),
        "binary_path": binary_path_rel,
        "binary_sha256": binary_sha256,
        "binary_tlsh": fp.get("tlsh"),
        "imphash": fp.get("imphash"),
        "link_a": link_a,  # advisory; never clears. None when no listener binds this binary.
        "defined_symbols": symbols.get("defined_symbols", []),
        "imported_symbols": symbols.get("imported_symbols", []),
        # DEFERRED to the source axis — explicitly NULL (not a negative):
        "link_b_reachable": None,
        "link_c_dataflow_path": None,
        "completeness_proof": {
            "stripped": bool(symbols.get("stripped", True)),
            "has_symtab": bool(symbols.get("has_symtab", False)),
            "has_dynsym": bool(symbols.get("has_dynsym", False)),
            "demangled": False,  # raw names in the MVP; demangle is a follow-up (framework matches raw)
            "arch": symbols.get("arch", "unknown"),
            "format": symbols.get("format", "unknown"),
            "analyzer": _ANALYZER,
            "analyzer_version": _analyzer_version(),
            "indirect_calls": None,            # DEFERRED — never 0 in the MVP (gate-honest)
            "decompiler_success_ratio": None,  # DEFERRED
        },
        "confidence_score": None,  # DEFERRED — no graph-completeness measured
        "derivation": "symbol_table",
        "_wairz_disclaimer": (
            "severity/cvss NOT an input; Axiom 3. Symbol absence valid ONLY on a non-stripped, "
            "sha256-matched binary."
        ),
    }


def _rel_path(blob_path: str, detection_roots: list[str] | None = None) -> str:
    """Detection-root-relative path for the wire format.

    Prefers ``os.path.relpath`` against the firmware's detection roots (Rule #16) — this handles
    scatter-zip / container-root layouts whose absolute paths do NOT contain ``/extracted/``.
    Falls back to the legacy ``/extracted/`` split, then the bare path. NEVER raises: the producer
    must never break on a path it cannot relativise (the red-team flagged a bare ``assert relative``
    as a crash risk on the common scatter-zip case).
    """
    import os  # noqa: PLC0415

    for root in detection_roots or []:
        if not root:
            continue
        norm = root.rstrip("/")
        if blob_path == norm or blob_path.startswith(norm + "/"):
            try:
                return os.path.relpath(blob_path, norm)
            except (ValueError, TypeError):
                continue
    if "/extracted/" in blob_path:
        return blob_path.split("/extracted/", 1)[-1]
    return blob_path


async def export_reachability_records(firmware_id, db) -> list[dict]:
    """Build the ``wairz_reachability.jsonl`` record set for one firmware (binary-axis MVP).

    Reuses the already-detected ``HardwareFirmwareBlob`` rows (their sha256 + R2 fingerprints),
    so there is no second tree walk. ``extract_elf_symbols`` self-gates on the ELF magic, so
    non-ELF blobs (mbn/dtb/raw_bin/...) are silently skipped. Parse-only (Rule #45); symbol reads
    run in an executor (Rule #5). ``link_a`` is left None in the MVP (advisory only — it does not
    affect the FUNCTION_NOT_LINKED clear; the network_exposure join is a follow-up). Paths are
    relativised against the firmware's detection roots (Rule #16) for the wire format.
    """
    import asyncio  # noqa: PLC0415

    from sqlalchemy import select  # noqa: PLC0415

    from app.models.firmware import Firmware  # noqa: PLC0415
    from app.models.hardware_firmware import HardwareFirmwareBlob  # noqa: PLC0415
    from app.services.firmware_paths import get_detection_roots  # noqa: PLC0415

    firmware = await db.get(Firmware, firmware_id)
    detection_roots = (
        await get_detection_roots(firmware, db=db) if firmware is not None else []
    )
    blobs = (
        await db.execute(select(HardwareFirmwareBlob).where(
            HardwareFirmwareBlob.firmware_id == firmware_id))
    ).scalars().all()
    loop = asyncio.get_event_loop()
    records: list[dict] = []
    for blob in blobs:
        syms = await loop.run_in_executor(None, extract_elf_symbols, blob.blob_path)
        if syms is None:
            continue  # non-ELF -> skip (never fabricate a record)
        fp = (blob.metadata_ or {}).get("fingerprints")
        records.append(build_reachability_record(
            firmware_id, _rel_path(blob.blob_path, detection_roots),
            blob.blob_sha256, syms, fp, link_a=None))
    return records


def write_reachability_jsonl(records: list[dict], out_path: str) -> int:
    """Write records to a ``wairz_reachability.jsonl`` (one JSON object per line). Returns count."""
    import json  # noqa: PLC0415

    with open(out_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, default=str) + "\n")
    return len(records)
