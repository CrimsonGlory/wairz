"""Shared primitives for the security_audit subpackage.

Split out from the monolithic ``security_audit_service.py`` as the first
step of Phase 5 part 2. Contains only the dataclasses and file-walking
helpers that every scanner needs — no business logic lives here.
"""

import math
import os
from collections import Counter
from dataclasses import dataclass, field

# Bumped 50 → 500 on 2026-05-22 (over-constraint sweep). Original 50-cap was
# silently truncating security audit results on real-world firmware:
# Medtronic ILLUMISITE-class images surface hundreds of insecure permissions
# / dozens of hardcoded credentials / many network misconfigs, all
# legitimately distinct findings. The 50-cap dropped findings 51-N with no
# `... +N more` notice and no operator override, masking systemic
# insecurity. 500 covers the vast majority of legitimate workflows; any
# firmware with >500 findings per check is "remediate holistically"
# territory where the operator's response doesn't depend on seeing
# items 501-N individually. Follow-up: add a +N-more sentinel at every
# call site (~25 edit sites across credentials/network/permissions/
# external_scanners) — deferred per Rule #25 single-slice discipline.
MAX_FINDINGS_PER_CHECK = 500

# Binary extensions to skip during text scanning
_BINARY_EXTENSIONS = frozenset({
    ".bin", ".img", ".gz", ".xz", ".bz2", ".zst", ".lz4", ".lzma",
    ".zip", ".tar", ".elf", ".so", ".o", ".a", ".ko", ".dtb",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mkv",
    ".pyc", ".pyo", ".class", ".wasm",
})


@dataclass
class SecurityFinding:
    """A single security finding ready for DB insertion."""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    cwe_ids: list[str] | None = None


@dataclass
class ScanResult:
    """Aggregate result of a full security scan."""
    findings: list[SecurityFinding] = field(default_factory=list)
    checks_run: int = 0
    errors: list[str] = field(default_factory=list)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


def _is_text_file(path: str) -> bool:
    _, ext = os.path.splitext(path.lower())
    if ext in _BINARY_EXTENSIONS:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
            if b"\x00" in chunk:
                return False
    except OSError:
        return False
    return True


def _rel(abs_path: str, root: str) -> str:
    return "/" + os.path.relpath(abs_path, root)
