"""Memory-dump-image candidate enumeration (Phase λ.α.B helper).

Companion to ``firmware_paths.py``: where that module enumerates
filesystem detection roots, this one enumerates RAM-acquisition
file candidates inside those roots. Used by the λ.α.B enumerator
to populate ``memory_dump_image`` rows for the firmware.

Per CLAUDE.md Rule #16: callers MUST resolve detection roots via
``get_detection_roots(firmware)`` first and pass the resulting
``Iterable[str]`` to :func:`enumerate_memory_image_candidates`. The
enumerator never reads ``firmware.extracted_path`` directly — that
would miss scatter-zip / multi-archive medical-firmware extractions.

Per CLAUDE.md Rule #36 no-execute discipline: this helper opens
candidate files READ-ONLY and reads only the first :data:`_MAGIC_PROBE_BYTES`
bytes for magic detection. wairz NEVER invokes any binary inside a
memory image, NEVER ``qemu-system -hda`` an image, NEVER ``insmod``
a Linux memory-driver capture. Memory artefacts are DATA, parsed by
the pure-Python Vol3 framework in λ.α.D.

Per CLAUDE.md Rule #19 evidence-first: the 100 MB minimum size gate
(:data:`MIN_MEMORY_IMAGE_BYTES`) was chosen from observed real-world
RAM-acquisition sizes (~4 GB typical Win10, ~8-32 GB Win11, ~1-8 GB
Linux). Sub-100 MB candidates are almost always NOT memory images —
typical false-positive sources include firmware boot dumps, partial
crash logs, driver dumps, and BIOS images.

Magic-byte signatures detected (head probe over first 16 bytes):

================== ========================== =============
Magic              Format                     OS family
================== ========================== =============
``MDMP``           Windows minidump           windows
``PAGEDU64``       Windows kernel dump 64-bit windows
``PAGEDUMP``       Windows kernel dump 32-bit windows
``LiME``           Linux LiME format          linux
``VMware``         VMware suspended VM        unknown
``hibr``           Windows hibernation        windows
(no magic)         Flat RAM acquisition       unknown
================== ========================== =============

Unrecognised magic falls through to ``"raw"`` + ``"unknown"`` family.
Vol3's automagic LayerStacker handles flat acquisitions just fine
during the λ.α.D vol3_runner pass; magic detection is purely an
indexing hint for the operator UI / cross-firmware MCP tools.
"""
from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

# Filename-extension allowlist. Lowercased + leading dot. Match is
# case-insensitive; matched candidates still subject to the size gate.
MEMORY_IMAGE_EXTENSIONS: tuple[str, ...] = (
    ".raw",
    ".dmp",
    ".vmem",
    ".lime",
    ".mem",
    ".crash",
)

# Minimum file size in bytes for a candidate to be considered a memory
# image. Real RAM acquisitions are typically 4-128 GB. 100 MB excludes
# the common false-positive sources (driver dumps, BIOS images, partial
# crashes) while letting through the smallest plausible acquisitions
# (e.g. CTF-grade Windows XP 256 MB images).
MIN_MEMORY_IMAGE_BYTES: int = 100 * 1024 * 1024

# Head-bytes read for magic-byte detection. 16 bytes covers every
# known magic in the family without ever reading multi-MB into memory.
_MAGIC_PROBE_BYTES: int = 16

# Magic-byte mapping. Each entry is (signature_bytes, magic_label,
# os_family). Tested in declaration order; first match wins.
_MAGIC_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"MDMP", "MDMP", "windows"),
    (b"PAGEDU64", "PAGEDU64", "windows"),
    (b"PAGEDUMP", "PAGEDUMP", "windows"),
    (b"LiME", "LiME", "linux"),
    (b"VMware", "VMware", "unknown"),
    (b"hibr", "hibr", "windows"),
)


@dataclass(frozen=True, slots=True)
class MemoryImageCandidate:
    """One enumerated memory-image candidate with classification metadata."""

    image_path: str
    image_filename: str
    file_size: int
    magic_detected: str
    os_family: str


def _has_memory_image_extension(filename: str) -> bool:
    """True iff ``filename``'s extension is in :data:`MEMORY_IMAGE_EXTENSIONS`."""
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in MEMORY_IMAGE_EXTENSIONS)


def _sniff_memory_image_magic(path: str) -> tuple[str, str]:
    """Read the first :data:`_MAGIC_PROBE_BYTES` of ``path`` and classify.

    Returns ``(magic_label, os_family)``. Unrecognised magic yields
    ``("raw", "unknown")``. Any IOError surfaces as ``("error", "unknown")``
    so the enumerator can record the candidate without crashing.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(_MAGIC_PROBE_BYTES)
    except OSError:
        return ("error", "unknown")
    for signature, label, family in _MAGIC_SIGNATURES:
        if head.startswith(signature):
            return (label, family)
    return ("raw", "unknown")


def enumerate_memory_image_candidates(
    detection_roots: Iterable[str],
) -> Iterator[MemoryImageCandidate]:
    """Yield every memory-image candidate under ``detection_roots``.

    Per Rule #16, ``detection_roots`` should come from
    :func:`app.services.firmware_paths.get_detection_roots`. Each
    candidate satisfies (a) extension in :data:`MEMORY_IMAGE_EXTENSIONS`,
    (b) size ≥ :data:`MIN_MEMORY_IMAGE_BYTES`. The magic-byte head
    probe runs per-candidate AFTER the size gate (the gate is much
    cheaper than the IO, so it runs first).

    The walk is non-recursive across detection_roots — the helper
    descends INTO each root (recursive os.walk) but does not re-cross
    root boundaries. Symlinks are NOT followed (consistent with
    `firmware_paths.py:_compute_roots_sync` and Rule #36 — we never
    follow a symlink out of the firmware tree).

    Duplicate paths can occur if detection_roots overlap (rare but
    possible after multi-archive extraction); the caller is responsible
    for de-duping before INSERT. The enumerator emits ALL candidates
    from ALL roots in walk order.
    """
    seen: set[str] = set()
    for root in detection_roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for filename in filenames:
                if not _has_memory_image_extension(filename):
                    continue
                full_path = os.path.join(dirpath, filename)
                if full_path in seen:
                    continue
                seen.add(full_path)
                try:
                    size = os.path.getsize(full_path)
                except OSError:
                    continue
                if size < MIN_MEMORY_IMAGE_BYTES:
                    continue
                magic, family = _sniff_memory_image_magic(full_path)
                yield MemoryImageCandidate(
                    image_path=full_path,
                    image_filename=filename,
                    file_size=size,
                    magic_detected=magic,
                    os_family=family,
                )
