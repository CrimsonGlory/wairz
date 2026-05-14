"""Firmware detection-roots helper.

Returns every directory under a firmware's on-disk storage that a
downstream consumer (detector, SBOM, YARA, MCP filesystem tools) should
walk to find extracted content.

The existing ``extracted_path`` column is a single-string pointer to what
the unpacker chose as the "primary" rootfs. Real extractions often
produce content in sibling directories (scatter-zip scans, raw partition
dumps, recursive nested archives). This helper enumerates ALL of them.

Results are cached in ``Firmware.device_metadata["detection_roots"]``
JSONB so repeated lookups do not re-walk the filesystem.

Public API
----------
``get_detection_roots(firmware, *, db=None, use_cache=True) -> list[str]``
    The main resolver. Async so it can update the JSONB cache when a DB
    session is provided, but the heavy lifting is a single ``scandir``
    per extraction container.

``invalidate_detection_roots(firmware, db) -> None``
    Clears the cache. Used by the Phase-4 backfill and by consumers that
    know the layout has changed (e.g., re-unpack).

``get_primary_root(firmware) -> str | None``
    Scalar-path helper for consumers that can only accept a single root
    (legacy MCP tools, sandbox resolution).

The helper is the single sanctioned call-site for anything that walks a
firmware's extracted tree. Phase 3 migrates ~13 consumers over to it;
Phase 5 lands a grep-based regression guard (CLAUDE.md Learned Rule #16).
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.firmware import Firmware

from app.services.jsonb_normalizers import (
    _normalize_firmware_device_metadata,
    _stamp_firmware_device_metadata,
)

logger = logging.getLogger(__name__)


# Android partition-style sibling directory names. When these appear as
# siblings of a ``partition_*``-like dir, the layout is a multi-partition
# container and ``extracted_path`` should be widened to the parent.
_ANDROID_PARTITION_SIBLINGS: frozenset[str] = frozenset({
    "system", "vendor", "odm", "product", "system_ext",
    "boot", "init_boot", "vendor_boot", "data", "metadata",
    "apex", "firmware", "dsp", "tee",
    # legacy MediaTek / Qualcomm extras frequently seen alongside:
    "modem",
})

# File extensions that mark a directory as "has extractable content" for
# purposes of root-candidate scoring. Kept deliberately narrow so that a
# dir full of .log / .txt noise is NOT promoted to a detection root.
# ``.raw`` was added 2026-05-13 to close a latent gap shared with
# ``unpack_vhdx``: VHDX-extracted disks land at ``extraction_dir/disk.raw``;
# without ``.raw`` here the resolver caught the parent extraction_dir via a
# different code path, but a multi-volume extractor (planned for tibx
# BYOB-SC) that lands ``extraction_dir/vol1/disk.raw`` + ``vol2/disk.raw``
# needed ``.raw`` for each vol-dir to qualify as a detection root.
_RAW_IMAGE_EXTENSIONS: frozenset[str] = frozenset({
    ".img", ".bin", ".elf", ".mbn", ".hcd", ".tar", ".zip",
    ".lz4", ".ota", ".sin", ".pac", ".raw",
})

# Directory names that are always detection roots on sight.
_NAME_HINT_ROOTS: frozenset[str] = frozenset({
    "rootfs", "partitions", "images",
})

# Patterns matched as prefixes (not exact) — these are suffix-bearing
# partition-container conventions emitted by Wairz unpackers.
_PREFIX_HINT_ROOTS: tuple[str, ...] = (
    "rootfs-",
    "partition_",
)

# Directory name suffixes that mark a dir as a detection root.
_SUFFIX_HINT_ROOTS: tuple[str, ...] = (
    "-root",
)

# Ignored dir basenames / prefixes.
_IGNORED_BASENAMES: frozenset[str] = frozenset({
    ".git", "__pycache__", "node_modules",
})

# File extensions that mark a file as a firmware blob / partition image for
# the deep-walk scorer. Distinct from ``_RAW_IMAGE_EXTENSIONS`` (used by the
# shallow sweep, which is narrower so that ``.tar`` / ``.zip`` archive-bearing
# dirs get promoted there but not down here where they'd flood the candidate
# set). ``.image`` covers unblob's literal ``raw.image`` filename emitted for
# each recursive extract step. ``.so``/``.so.[0-9]+`` covers Android DSP
# firmware bundles (``AlacDecoderModule.so.1`` shape). ``.mbn`` is Qualcomm
# modem firmware; ``.tlv`` is Bluetooth firmware; ``.elf32`` / ``.elf64`` are
# the bootloader-payload ELF variants Motorola emits.
_FIRMWARE_BLOB_EXTENSIONS: frozenset[str] = frozenset({
    ".img", ".bin", ".raw", ".image",
    ".ext2", ".ext3", ".ext4", ".extfs", ".erofs", ".squashfs", ".f2fs",
    ".mbn", ".tlv", ".fw", ".ko", ".dtb", ".uimage",
    ".so", ".so.0", ".so.1", ".so.2", ".so.3",
    ".elf", ".elf32", ".elf64",
    ".tee", ".bl1", ".bl2", ".mcu",
})

# Files that are noise — when a candidate dir has nothing but these, it
# does NOT count as substantive content for the "substantial" bonus.
_NOISE_FILE_BASENAMES: frozenset[str] = frozenset({
    "lost+found",
})

# Directory basenames the deep-walk should NEVER enter (Linux filesystem
# pseudo-mounts, ext mountpoints, ramdisk noise). Avoids picking up
# /apex/com.android.foo, /system/apex/* etc. when the parent already
# scored highly.
_DEEP_WALK_SKIP_DIRS: frozenset[str] = frozenset({
    "lost+found", "proc", "sys", "dev",
})


def _is_hint_root_name(name: str) -> bool:
    if name in _NAME_HINT_ROOTS:
        return True
    if any(name.startswith(p) for p in _PREFIX_HINT_ROOTS):
        return True
    if any(name.endswith(s) for s in _SUFFIX_HINT_ROOTS):
        return True
    return False


def _dir_has_raw_image(path: str) -> bool:
    """Return True if ``path`` contains any file with a raw-image extension."""
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if not entry.is_file(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                lower = entry.name.lower()
                for ext in _RAW_IMAGE_EXTENSIONS:
                    if lower.endswith(ext):
                        return True
    except OSError:
        return False
    return False


def _dir_has_android_siblings(path: str) -> bool:
    """True if ``path`` has >=2 Android-partition-style immediate subdirs."""
    try:
        with os.scandir(path) as it:
            subdirs = {
                e.name for e in it
                if e.is_dir(follow_symlinks=False)
            }
    except OSError:
        return False
    return len(subdirs & _ANDROID_PARTITION_SIBLINGS) >= 2


def _score_root_order(name: str) -> tuple[int, str]:
    """Key for ordering candidate roots.

    Lower primary key wins. ``rootfs`` first, then partition-style
    buckets, then alphabetical.
    """
    if name == "rootfs" or name.startswith("rootfs-") or name.endswith("-root"):
        return (0, name)
    if name in {"partitions", "images"}:
        return (2, name)
    if name.startswith("partition_"):
        return (3, name)
    # Default bucket — zip-basename dirs, etc.
    return (1, name)


def _scan_container_for_roots(container: str) -> list[str]:
    """Walk ``container`` one level deep, returning qualifying detection roots.

    A direct child directory qualifies if:
      - it matches a name hint (``rootfs``, ``partitions``, ``images``,
        ``rootfs-*``, ``*-root``, ``partition_*``), OR
      - it directly contains a raw-image file (``*.img`` / ``*.bin`` / ...),
        OR
      - it has >=2 Android partition-style immediate subdirs
        (``system``, ``vendor``, ``odm``, ...).

    Hidden dirs, ``.git``, ``__pycache__``, ``node_modules`` are skipped.
    """
    if not container or not os.path.isdir(container):
        return []

    roots: list[str] = []
    try:
        with os.scandir(container) as it:
            entries = list(it)
    except OSError:
        return []

    for entry in entries:
        try:
            if not entry.is_dir(follow_symlinks=False):
                continue
        except OSError:
            continue
        name = entry.name
        if name.startswith(".") or name in _IGNORED_BASENAMES:
            continue
        path = entry.path
        qualifies = (
            _is_hint_root_name(name)
            or _dir_has_raw_image(path)
            or _dir_has_android_siblings(path)
        )
        if qualifies:
            roots.append(path)

    roots.sort(key=lambda p: _score_root_order(os.path.basename(p)))
    return roots


def _dedup_by_realpath(paths: list[str]) -> list[str]:
    """Return ``paths`` with realpath duplicates removed, preserving order."""
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        try:
            real = os.path.realpath(p)
        except OSError:
            real = p
        if real in seen:
            continue
        seen.add(real)
        out.append(p)
    return out


def _is_partition_like_name(name: str) -> bool:
    """True if ``name`` looks like a single partition, not an extraction container.

    Partition-like names are climbed *past* when locating the extraction
    container. This is how ``extracted/rootfs/partition_2_erofs`` resolves
    up two levels to ``extracted/`` so scatter-zip siblings are visible.
    """
    if name in _ANDROID_PARTITION_SIBLINGS:
        return True
    if name.startswith("partition_"):
        return True
    if name == "rootfs" or name.startswith("rootfs-"):
        return True
    if name.endswith("-root"):
        return True
    return False


def _path_isfile(base: str, *parts: str) -> bool:
    """Safe ``os.path.isfile(os.path.join(base, *parts))`` with OSError suppression."""
    try:
        return os.path.isfile(os.path.join(base, *parts))
    except OSError:
        return False


def _has_blob_extension(name: str) -> bool:
    """Return True if ``name`` ends in any extension in ``_FIRMWARE_BLOB_EXTENSIONS``."""
    lower = name.lower()
    for ext in _FIRMWARE_BLOB_EXTENSIONS:
        if lower.endswith(ext):
            return True
    # Versioned shared libs that we didn't explicitly enumerate (.so.42).
    if ".so." in lower:
        tail = lower.rsplit(".so.", 1)[1]
        if tail and all(c.isdigit() or c == "." for c in tail):
            return True
    return False


def _rootfs_score(path: str) -> int:
    """Score ``path`` as a detection-root candidate (Issue #20 heuristic).

    Higher score = stronger candidate. Returns 0 for non-candidates.

    Scoring layers (per Issue #20 ask: ``/etc/passwd`` OR
    ``/system/build.prop`` OR ``/vendor`` at depth ≤3):

    * **T1 — definitive rootfs markers (≥300 pts):** ``system/build.prop``,
      a direct ``build.prop`` (this dir IS the system partition),
      ``etc/passwd``.
    * **T2 — partition-container markers (100–300 pts):** ``vendor`` direct
      child, ≥2 Android partition siblings, ``etc + bin`` Linux shape.
    * **T3 — firmware-blob bundle (10–80 pts):** dir of ``.mbn`` / ``.tlv``
      / ``.so`` / ``.elf32`` etc. (Motorola radio, BTFM, dspso).
    * **T4 — sole partition image (10 pts):** single ``.image`` / ``.bin``
      / ``.raw`` file with no siblings (unblob's ``super.img_sparsechunk.N/
      raw.image`` shape).
    * **Initramfs demotion (−80 pts):** small dir (<15 entries) carrying an
      ``init`` file with no ``vendor`` and no ``system/build.prop`` — the
      "tiny ramdisk with init + 5 binaries" shape Issue #20 calls out.

    Scoring is deliberately additive: a dir that is BOTH a partition root
    AND a firmware blob bundle (e.g., the Moto ``vendor_boot.img_extract``
    ramdisk that has /odm + /etc + many .mbn files) outranks a pure blob
    bundle.
    """
    try:
        with os.scandir(path) as it:
            entries = list(it)
    except OSError:
        return 0

    dirs: set[str] = set()
    files: set[str] = set()
    for entry in entries:
        name = entry.name
        if name in _NOISE_FILE_BASENAMES:
            continue
        try:
            if entry.is_dir(follow_symlinks=False):
                dirs.add(name)
            elif entry.is_file(follow_symlinks=False):
                files.add(name)
        except OSError:
            continue

    score = 0

    # T1 — definitive rootfs markers
    if "system" in dirs and _path_isfile(path, "system", "build.prop"):
        score += 400
    if "build.prop" in files:
        score += 400
    if "etc" in dirs and _path_isfile(path, "etc", "passwd"):
        score += 300

    # T2 — partition-container markers
    if "vendor" in dirs:
        score += 150
    android_count = len(dirs & _ANDROID_PARTITION_SIBLINGS)
    if android_count >= 2:
        score += 100 * android_count
    elif android_count == 1 and score == 0:
        # Single Android sibling alone is weak signal — only bump if we
        # have nothing else yet (avoid double-counting with the +150 vendor).
        score += 30
    if "etc" in dirs and "bin" in dirs:
        score += 100

    # T3 — firmware blob bundle
    blob_count = sum(1 for f in files if _has_blob_extension(f))
    if blob_count >= 3:
        score += min(80, blob_count * 5)

    # T4 — sole partition image (sparsechunk raw.image shape)
    if (
        score == 0
        and len(dirs) == 0
        and len(files) == 1
        and blob_count == 1
    ):
        score += 10

    # Substantial content bonus
    if len(files) + len(dirs) >= 10:
        score += 20

    # Initramfs demotion: tiny dir + init file + no real rootfs marker
    if (
        "init" in files
        and len(files) + len(dirs) < 15
        and "vendor" not in dirs
        and not _path_isfile(path, "system", "build.prop")
    ):
        score -= 80

    return max(0, score)


def _find_unblob_extraction_top(root: str) -> str:
    """Climb from ``root`` through unblob's nested ``_extract`` chain.

    unblob's recursive extractor emits a sibling ``<basename>_extract/``
    directory for each archive / image / payload it cracks open. For
    Motorola firmware the chain is::

        extracted/
            Moto-G32-XT2235-1.zip_extract/      ← we want this
                boot.img_extract/
                    14880768-27311594.gzip_extract/
                        gzip.uncompressed_extract/   ← ``root``
                vendor_boot.img_extract/
                radio.img_extract/
                super.img_sparsechunk.N_extract/  (×11)

    The existing ``_find_extraction_container`` only climbs partition-like
    names (``rootfs`` / ``partition_*`` / Android sibling names) — none of
    the path components above match, so for Motorola it returns ``root``
    unchanged. This helper extends the climb to traverse ``_extract``-
    suffixed directories so the deep walk can sweep the whole nested
    extraction tree, finding the sibling dirs the shallow sweep can't see.

    Stops when:

    * The parent directory's name is ``extracted`` (or a synonym) — the
      child is the firmware-named container we want.
    * The current directory name does NOT end in ``_extract``.
    * Hard cap of 12 climbs (degenerate path safety).
    """
    if not root or not os.path.isdir(root):
        return root
    cur = root.rstrip("/") or root
    for _ in range(12):
        parent = os.path.dirname(cur)
        if not parent or parent == cur:
            return cur
        if not os.path.isdir(parent):
            return cur
        parent_name = os.path.basename(parent.rstrip("/"))
        cur_name = os.path.basename(cur.rstrip("/"))
        # Hit the storage-root marker — stop, cur is the per-firmware container.
        if parent_name in {"extracted", "Extracted", "extraction"}:
            return cur
        # Climb through _extract-chained dirs.
        if cur_name.endswith("_extract") or parent_name.endswith("_extract"):
            cur = parent
            continue
        return cur
    return cur


def _walk_for_additional_roots(
    top: str,
    *,
    max_depth: int = 8,
    max_dirs: int = 20_000,
    prune_threshold: int = 200,
) -> list[tuple[int, str]]:
    """Recursively walk ``top`` looking for rootfs-like dirs (Issue #20).

    The deep-walk runs in addition to the existing shallow sweep so we
    catch sibling content buried 3-4 levels deep under unblob's nested
    ``_extract`` chain (Motorola firmware shape). Bounded by:

    * ``max_depth`` (default 8) — Moto's deepest content sits at 5 levels.
    * ``max_dirs`` (default 20,000) — protective cap; the 5.9 GB Moto-G32
      tree has well under 1,000 dirs but pathological samples could blow up.
    * ``prune_threshold`` (default 200 score) — when a dir scores high
      enough to be a definitive rootfs (e.g. /system/build.prop present),
      we stop descending into it. Without pruning the walk would pick up
      ``/system/apex/com.android.foo/`` and every nested ``priv-app``
      subdir as candidates.

    Returns ``(score, path)`` tuples for every qualifying dir. Caller is
    responsible for dedup / merge / final ordering.
    """
    if not top or not os.path.isdir(top):
        return []

    results: list[tuple[int, str]] = []
    walked = 0
    for current, dirs, _files in os.walk(top, followlinks=False):
        walked += 1
        if walked > max_dirs:
            break
        rel = os.path.relpath(current, top)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        if depth > max_depth:
            dirs[:] = []
            continue
        # Filter out hidden / ignored / pseudo-mount dirs (in-place so
        # os.walk respects the change).
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".")
            and d not in _IGNORED_BASENAMES
            and d not in _DEEP_WALK_SKIP_DIRS
        ]
        score = _rootfs_score(current)
        if score > 0:
            results.append((score, current))
            if score >= prune_threshold:
                # Don't recurse into a clear rootfs.
                dirs[:] = []
    return results


def _find_extraction_container(root: str) -> tuple[str, bool]:
    """Climb ``root`` until we find a dir that is NOT partition-like.

    Returns ``(container_path, climbed)`` where ``climbed`` is True when
    at least one partition-like parent was traversed (i.e., the caller
    pointed us at a sub-partition, not the extraction container itself).
    """
    cur = root
    climbed = False
    # Hard cap to avoid runaway on degenerate paths (e.g. "/rootfs").
    for _ in range(8):
        parent = os.path.dirname(cur.rstrip("/")) or cur
        if parent == cur:
            break
        if not os.path.isdir(parent):
            break
        parent_name = os.path.basename(parent.rstrip("/"))
        cur_name = os.path.basename(cur.rstrip("/"))
        # Climb while the current dir looks like a partition AND the
        # parent has a reasonable "container" shape (multiple qualifying
        # children or a non-partition name).
        if _is_partition_like_name(cur_name) and parent_name and not _is_partition_like_name(parent_name):
            cur = parent
            climbed = True
            break
        if _is_partition_like_name(cur_name):
            cur = parent
            climbed = True
            continue
        break
    return cur, climbed


def _compute_roots_sync(extracted_path: str | None) -> list[str]:
    """Synchronous root computation — safe to run inside ``asyncio.to_thread``.

    The resolution logic:

    1. No ``extracted_path`` → ``[]``.
    2. ``extracted_path`` missing on disk → ``[]``.
    3. Climb any partition-like parents (``rootfs``, ``partition_*``,
       ``system``, ``vendor``, ...) to locate the extraction container.
    4. Enumerate qualifying children of the container.
    5. If the caller's ``extracted_path`` points at a specific
       sub-partition not covered by the shallow sweep, include it.
    6. Fallback: return ``[extracted_path]`` when nothing else qualified.
    7. Deduplicate by ``realpath`` and order so ``extracted_path`` leads
       when it is itself a detection root.
    """
    if not extracted_path:
        return []
    if not os.path.exists(extracted_path):
        return []

    # Normalise: strip trailing slashes for stable dirname()
    root = extracted_path.rstrip("/") or extracted_path

    container, climbed = _find_extraction_container(root)

    # Walk the container for qualifying children.
    roots = _scan_container_for_roots(container)

    # Include the container itself as a detection root when it holds raw
    # image files directly at its top level.  This covers the post-
    # scatter-relocation layout where ``_relocate_scatter_subdirs`` moves
    # ``.img`` / ``.bin`` files out of the version subdir into the
    # extraction root — the files become direct children of ``container/``
    # rather than sitting inside ``container/<name>/``.  Without this
    # branch ``_scan_container_for_roots`` only inspects subdirectories,
    # leaving the top-level firmware blobs (lk.img, tee.img, gz.img,
    # preloader*.bin, scp.img, sspm.img, ...) invisible to the detector.
    # ``_dir_has_raw_image`` is strict (specific extensions, no recursion)
    # so containers without firmware-shaped files are NOT promoted.
    if container and os.path.isdir(container) and _dir_has_raw_image(container):
        real_container = os.path.realpath(container)
        existing = {os.path.realpath(r) for r in roots}
        if real_container not in existing:
            roots.append(container)

    # If the caller's extracted_path points at a specific sub-partition
    # (e.g. rootfs/partition_2_erofs/) that isn't in the shallow sweep,
    # add it as a detection root.
    if climbed and os.path.isdir(root):
        real_root = os.path.realpath(root)
        if real_root not in {os.path.realpath(r) for r in roots}:
            roots.append(root)

    # Fallback: if nothing qualified but extracted_path is a real dir,
    # at least return it so consumers have something to walk.
    if not roots and os.path.isdir(root):
        roots = [root]

    # Shallow-container rescue: the classifier occasionally chooses an
    # inner archive (e.g., ``rootfs_partition.tar.xz``) inside a
    # multi-archive ZIP as the unpack target. That produces an
    # ``extracted_path`` deep inside ``container/extracted/`` while the
    # real firmware binaries (.bin MCU firmware, sibling .tar.xz
    # bundles, boot-partition archives, etc.) sit at the parent level.
    # When the scan yields at most one root AND the parent of the
    # container holds raw firmware files at its own file level, include
    # the parent as an additional detection root so those blobs surface.
    # Safe because _dir_has_raw_image is strict (specific extensions,
    # non-recursive) — a parent dir without firmware-shaped files is
    # not promoted.
    if len(roots) <= 1 and container and os.path.isdir(container):
        parent = os.path.dirname(container.rstrip("/"))
        parent_parent = os.path.dirname(parent.rstrip("/")) if parent else ""
        if (
            parent
            and parent != container
            and parent != parent_parent  # not at filesystem root
            and os.path.isdir(parent)
            and _dir_has_raw_image(parent)
        ):
            real_parent = os.path.realpath(parent)
            existing = {os.path.realpath(r) for r in roots}
            if real_parent not in existing:
                roots.append(parent)

    # If the extracted_path itself is directly a candidate root (e.g. a
    # bare Linux rootfs with etc/, bin/ children), ensure it leads the
    # ordering rather than getting buried behind a sibling.
    if not climbed and os.path.isdir(root):
        real_root = os.path.realpath(root)
        if real_root in {os.path.realpath(r) for r in roots}:
            roots.sort(
                key=lambda p: (os.path.realpath(p) != real_root,)
            )

    # ── Deep walk for nested unblob output (Issue #20) ──────────────────
    # The shallow sweep only inspects ONE level of children under the
    # extraction container. unblob's recursive extractor produces a
    # ``<basename>_extract/`` chain that can run 4–5 levels deep (Motorola
    # factory flash packages have boot.img_extract/<offset>.gzip_extract/
    # gzip.uncompressed_extract/ as one path AND super.img_sparsechunk.N_
    # extract/, radio.img_extract/, BTFM.bin_extract/, dspso.bin_extract/
    # as siblings two levels up). The shallow sweep + fallback picks ONE
    # of those leaves and returns. The deep walk catches the rest so
    # downstream walkers (SBOM, security audit, hardware firmware) see
    # all extracted content, not just the first plausible rootfs.
    unblob_top = _find_unblob_extraction_top(container)
    deep_candidates: list[tuple[int, str]] = _walk_for_additional_roots(unblob_top)
    # When extracted_path is deep inside the tree AND the climb landed us
    # at a higher container, also sweep starting from extracted_path so
    # any rootfs-like dirs visible from the leaf's vantage point are
    # captured even if they fall outside the unblob-top subtree.
    if (
        climbed
        and os.path.isdir(root)
        and os.path.realpath(root) != os.path.realpath(unblob_top)
    ):
        deep_candidates.extend(_walk_for_additional_roots(root))

    if deep_candidates:
        existing_real = {os.path.realpath(r) for r in roots}
        # Sort high-to-low so high-score additions append in priority order.
        deep_candidates.sort(key=lambda sp: (-sp[0], sp[1]))
        for _score, candidate in deep_candidates:
            rp = os.path.realpath(candidate)
            if rp not in existing_real:
                roots.append(candidate)
                existing_real.add(rp)

        # Final re-order: anything with a definitive rootfs score
        # (≥ definitive_threshold) MUST lead pure-blob and fallback
        # entries. This realises Issue #20's "initramfs must NOT outrank
        # a real Android filesystem" — a true /system/build.prop dir
        # scores 400+; a Moto-style boot.img ramdisk with /odm + /apex +
        # /etc scores ~340; a sole-partition-image dir scores 10. The
        # sort below keeps an existing high-score lead intact while
        # promoting newly-discovered better candidates above weaker
        # existing entries.
        path_scores: dict[str, int] = {}
        for s, p in deep_candidates:
            path_scores[os.path.realpath(p)] = s
        # Score entries that came from the shallow sweep (didn't appear in
        # deep_candidates because of pruning OR they were the fallback).
        for r in roots:
            rp = os.path.realpath(r)
            path_scores.setdefault(rp, _rootfs_score(r))
        # Preserve the original index as a tie-breaker so the shallow-sweep
        # ordering (rootfs leads scatter in DPCS10) survives equal scores.
        original_index = {os.path.realpath(r): i for i, r in enumerate(roots)}
        roots.sort(
            key=lambda r: (
                -path_scores.get(os.path.realpath(r), 0),
                original_index.get(os.path.realpath(r), 0),
            )
        )

    return _dedup_by_realpath(roots)


def _cached_roots(firmware: Firmware) -> list[str] | None:
    """Return cached detection_roots list (all paths must still exist).

    Returns ``None`` if no cache entry, the cache is empty, or any cached
    path is missing on disk (stale cache).
    """
    meta = _normalize_firmware_device_metadata(getattr(firmware, "device_metadata", None))
    cached = meta.get("detection_roots")
    if not isinstance(cached, list) or not cached:
        return None
    if not all(isinstance(p, str) for p in cached):
        return None
    # Stale check — any missing path invalidates the cache.
    for p in cached:
        if not os.path.exists(p):
            return None
    return list(cached)


def _persist_roots(
    firmware: Firmware,
    roots: list[str],
) -> None:
    """Merge ``roots`` into ``firmware.device_metadata`` (preserve other keys).

    Caller is responsible for flushing the session.
    """
    existing = _normalize_firmware_device_metadata(getattr(firmware, "device_metadata", None))
    # Shallow copy so SQLAlchemy registers the JSONB mutation.
    merged = dict(existing)
    merged["detection_roots"] = list(roots)
    firmware.device_metadata = _stamp_firmware_device_metadata(merged)


def populate_detection_roots(
    firmware: Firmware,
    *,
    extra_roots: list[str] | None = None,
) -> list[str]:
    """Canonical detection_roots writer for firmware rows at extraction time.

    Computes the primary roots from ``firmware.extracted_path`` via
    ``_compute_roots_sync`` (same logic downstream consumers use when
    resolving), merges ``extra_roots`` (e.g. vendor-AES decrypt output
    dirs) with realpath deduplication, and writes the result into
    ``firmware.device_metadata['detection_roots']``. Caller owns the
    session flush/commit.

    Callers:
        - firmware_service.py tar + zip-rootfs shortcut paths (upload-time)
        - routers/firmware.py _run_unpack_background (async /unpack path)
        - workers/arq_worker.py unpack_firmware_job (arq /unpack path)

    Before this helper existed, each call site hand-rolled the merge,
    and some sites omitted ``_compute_roots_sync`` entirely, producing
    divergent ``detection_roots`` content across upload formats. This
    helper eliminates that divergence — single source of truth.

    Returns the final merged root list (post-dedup) for logging.
    """
    extracted = getattr(firmware, "extracted_path", None)
    if not extracted:
        # Nothing to persist — raw-binary uploads that never extract
        # legitimately have no detection roots.
        return []
    roots = _compute_roots_sync(extracted)
    if extra_roots:
        existing_real = {os.path.realpath(r) for r in roots if r}
        for p in extra_roots:
            if not p or not os.path.isdir(p):
                continue
            real = os.path.realpath(p)
            if real in existing_real:
                continue
            roots.append(p)
            existing_real.add(real)
    _persist_roots(firmware, roots)
    return roots


async def get_detection_roots(
    firmware: Firmware,
    *,
    db: AsyncSession | None = None,
    use_cache: bool = True,
) -> list[str]:
    """Return all detection-root directories for ``firmware``, ordered.

    Primary root first (rootfs / Linux rootfs / APK extract dir), then
    any sibling containers that hold extractable content.

    Parameters
    ----------
    firmware:
        SQLAlchemy ``Firmware`` ORM row. Its ``device_metadata`` JSONB
        column is read/written for the cache.
    db:
        Optional async session. When provided, the computed list is
        written back to the JSONB cache and ``db.flush()`` is called
        (the caller owns the transaction).
    use_cache:
        If ``False``, skip the cache read and recompute from disk.
        Useful in backfill scripts that want a fresh resolution.

    Returns
    -------
    list[str]
        Ordered list of detection-root absolute paths. Empty when no
        extraction has happened yet.
    """
    if use_cache:
        cached = _cached_roots(firmware)
        if cached is not None:
            return cached

    extracted_path = getattr(firmware, "extracted_path", None)
    roots = await asyncio.to_thread(_compute_roots_sync, extracted_path)

    if db is not None and roots:
        _persist_roots(firmware, roots)
        try:
            await db.flush()
        except Exception:  # noqa: BLE001
            logger.debug(
                "detection_roots cache flush failed; continuing with in-memory result",
                exc_info=True,
            )

    return roots


async def invalidate_detection_roots(
    firmware: Firmware,
    db: AsyncSession,
) -> None:
    """Clear ``firmware.device_metadata['detection_roots']`` and flush.

    No-op when the key is absent. Preserves every other key in
    ``device_metadata``.
    """
    existing = _normalize_firmware_device_metadata(getattr(firmware, "device_metadata", None))
    if "detection_roots" not in existing:
        return
    merged = {k: v for k, v in existing.items() if k != "detection_roots"}
    firmware.device_metadata = _stamp_firmware_device_metadata(merged)
    await db.flush()


def get_primary_root(firmware: Firmware) -> str | None:
    """Return the first detection root (scalar-path consumers).

    Order of resolution:

    1. Cached ``device_metadata['detection_roots'][0]``, if still exists.
    2. ``firmware.extracted_path`` as a fallback.
    3. ``None`` if neither is available.

    This function is intentionally synchronous and does NOT perform a
    filesystem walk — it is called on hot code paths (sandbox resolution,
    MCP tool entry). Callers who need the full list must use
    ``get_detection_roots``.
    """
    meta = _normalize_firmware_device_metadata(getattr(firmware, "device_metadata", None))
    cached = meta.get("detection_roots")
    if isinstance(cached, list) and cached:
        first = cached[0]
        if isinstance(first, str) and os.path.exists(first):
            return first
    return getattr(firmware, "extracted_path", None)
