"""Canonical version extraction — universal helper for SBOM / CVE matching.

Different firmware shapes encode versions differently:
- L4T BSP kernel: "R32.3.1" (release tag) vs "4.9.140-tegra-..." (deb pkg)
- Android: "11", "12" (API release) + "30", "31" (SDK level)
- Ubuntu/Debian kernel: "4.9.140" or "5.15.0-1059-tegra"
- Yocto: "5.4.106-yocto-standard-..."

For NVD CPE matching, kernels need the canonical SemVer (e.g. "4.9.140").
Hand-patching per firmware shape doesn't scale — every shape grows its
own special case. This helper centralizes the extraction so every
strategy / bridge / parser uses the same logic.

Add new patterns here, not in per-strategy code.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

# SemVer-like patterns ordered from most-specific to most-permissive.
# Anchored at start-of-string OR after a non-alnum boundary so we don't
# match arbitrary digit runs inside paths or hashes.
_SEMVER_RE = re.compile(r"(?:^|[^0-9a-zA-Z])(\d+\.\d+\.\d+)(?:[^0-9]|$)")
_TWO_PART_RE = re.compile(r"(?:^|[^0-9a-zA-Z])(\d+\.\d+)(?:[^0-9]|$)")

# Patterns we explicitly recognize as NON-canonical and want to STRIP
# before falling back. NVIDIA L4T release tags, Yocto vendor suffixes,
# build IDs, etc.
_NON_CANONICAL = (
    re.compile(r"^R\d+\.\d+(\.\d+)?$"),  # L4T tag "R32.3.1"
    re.compile(r"^v?\d{4}\.\d+(\.\d+)?$", re.IGNORECASE),  # Yocto YY.MM
)


def canonical_kernel_version(
    raw: str | None,
    *,
    sibling_versions: Iterable[str] = (),
) -> str | None:
    """Return the most-canonical Linux kernel SemVer from ``raw`` + siblings.

    Priority order:
    1. ``raw`` contains a SemVer (e.g. "4.9.140-tegra-32.3.1-..." → "4.9.140")
    2. Any of ``sibling_versions`` contains a SemVer (use the first hit)
    3. ``None`` (no canonical match)

    L4T release tags ("R32.3.1") and similar non-canonical strings are
    DROPPED rather than passed through, since they would emit invalid
    CPEs that pollute SBOM exports without producing NVD matches.

    Args:
        raw: the primary version string (e.g. from blob.metadata.l4t_release
             OR blob.version OR sbom_component.version).
        sibling_versions: optional iterable of related component versions
             (e.g. the `nvidia-l4t-kernel` deb's version field). Used as
             fallback when ``raw`` is non-canonical.

    Returns:
        Canonical SemVer string like "4.9.140", or None when no extraction
        is possible. Callers building CPE strings should emit cpe=None
        when this returns None.
    """
    candidates: list[str] = []
    if raw:
        candidates.append(raw)
    candidates.extend(sibling_versions)
    for s in candidates:
        if not s:
            continue
        m = _SEMVER_RE.search(s)
        if m:
            return m.group(1)
    # Two-part SemVer fallback (e.g. "5.4" — rare but happens for
    # some Linux kernel cpe versions before patch-level).
    for s in candidates:
        if not s:
            continue
        if any(p.match(s) for p in _NON_CANONICAL):
            continue
        m = _TWO_PART_RE.search(s)
        if m:
            return m.group(1)
    return None


def canonical_android_version(raw: str | None) -> str | None:
    """Return the canonical Android marketing version (e.g. "11", "12", "15").

    Android NVD CPEs use the marketing version (single integer in most
    cases — "11", "12", "13", "14", "15"; older releases like "4.4"
    use the 2-part form).
    """
    if not raw:
        return None
    s = str(raw).strip()
    # Marketing version is a single integer (post-2.x) or a 2-part for
    # pre-5.0. NVD CPE uses the bare integer (e.g. cpe:2.3:o:google:android:11).
    if re.match(r"^\d+$", s):
        return s
    if re.match(r"^\d+\.\d+$", s):
        return s
    # Strip any trailing suffix like "11.0.0_r45" → "11"
    m = re.match(r"^(\d+)(?:[.\-_]|$)", s)
    if m:
        return m.group(1)
    return None
