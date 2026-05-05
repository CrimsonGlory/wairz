"""CLAUDE.md Rule #16 + audit-2026-05-04 stream D F-D-05 verification.

Two MCP tool surfaces previously walked only ``context.extracted_path``
and missed APKs / binaries that lived in sibling detection roots
(scatter-zip uploads, multi-archive medical firmware, nested unblob
output).  The fix wires both through ``context.get_detection_roots()``.

Test shape: assemble a fake firmware extraction with a primary root
AND a sibling root; assert each call surfaces content from BOTH.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.ai.tool_registry import ToolContext
from app.ai.tools._android_helpers import find_apk
from app.ai.tools.vulhunt import _find_binaries


@pytest.fixture
def scatter_zip_layout(tmp_path: Path) -> tuple[str, list[str]]:
    """Build a fake scatter-zip layout:

        primary/
            system/app/PrimaryApp/PrimaryApp.apk
            usr/bin/primary_bin       (ELF stub)
        sibling/
            system/priv-app/SiblingApp/SiblingApp.apk
            opt/sibling_bin           (ELF stub)

    Returns (primary_path, [primary_path, sibling_path]).
    """
    elf_magic = b"\x7fELF" + b"\x00" * 4096

    primary = tmp_path / "primary"
    sibling = tmp_path / "sibling"

    # APK contents are arbitrary — find_apk only checks extension and dir layout.
    apk_bytes = b"PK\x03\x04dummy-apk"

    p_app = primary / "system" / "app" / "PrimaryApp"
    p_app.mkdir(parents=True)
    (p_app / "PrimaryApp.apk").write_bytes(apk_bytes)

    p_bin_dir = primary / "usr" / "bin"
    p_bin_dir.mkdir(parents=True)
    (p_bin_dir / "primary_bin").write_bytes(elf_magic)

    s_app = sibling / "system" / "priv-app" / "SiblingApp"
    s_app.mkdir(parents=True)
    (s_app / "SiblingApp.apk").write_bytes(apk_bytes)

    s_bin_dir = sibling / "opt"
    s_bin_dir.mkdir(parents=True)
    (s_bin_dir / "sibling_bin").write_bytes(elf_magic)

    return str(primary), [str(primary), str(sibling)]


def _make_context(extracted_path: str, detection_roots: list[str]) -> ToolContext:
    return ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path=extracted_path,
        db=MagicMock(),
        detection_roots=detection_roots,
    )


def test_find_apk_resolves_app_in_secondary_root(scatter_zip_layout):
    """An APK that lives ONLY in the sibling detection root must still
    be resolvable by name — pre-fix this returned `App not found`."""
    primary, roots = scatter_zip_layout
    ctx = _make_context(primary, roots)

    # SiblingApp lives only under `sibling/`, not under `primary/`.
    resolved = find_apk(ctx, app_name="SiblingApp", path=None)
    # File must exist and be the sibling's APK
    assert os.path.isfile(resolved)
    assert "sibling" in resolved
    assert resolved.endswith("SiblingApp.apk")


def test_find_apk_still_resolves_app_in_primary_root(scatter_zip_layout):
    """The primary-root path must still work — adding sibling search
    is additive, not a regression."""
    primary, roots = scatter_zip_layout
    ctx = _make_context(primary, roots)

    resolved = find_apk(ctx, app_name="PrimaryApp", path=None)
    assert os.path.isfile(resolved)
    assert "primary" in resolved
    assert resolved.endswith("PrimaryApp.apk")


def test_find_apk_missing_app_raises_clear_error(scatter_zip_layout):
    """Missing-everywhere case must still raise ValueError."""
    primary, roots = scatter_zip_layout
    ctx = _make_context(primary, roots)

    with pytest.raises(ValueError, match="not found"):
        find_apk(ctx, app_name="NonExistentApp", path=None)


def test_vulhunt_find_binaries_walks_all_detection_roots(scatter_zip_layout):
    """`_find_binaries` is the per-root primitive; the MCP tool handler
    iterates `context.get_detection_roots()` over it.  Verify each root
    surfaces its own binary."""
    primary, roots = scatter_zip_layout

    found = []
    for root in roots:
        found.extend(_find_binaries(root, max_count=10, min_size=512))

    found_basenames = {os.path.basename(p) for p in found}
    assert "primary_bin" in found_basenames, (
        f"primary_bin missing from per-root scan; found={found}"
    )
    assert "sibling_bin" in found_basenames, (
        f"sibling_bin missing — was the root iteration broken? found={found}"
    )


def test_get_detection_roots_falls_back_to_extracted_path():
    """When `detection_roots` is empty, `get_detection_roots()` must
    fall back to `[extracted_path]` so the iteration still produces a
    valid root and old/uncached firmware rows don't error."""
    ctx = _make_context("/tmp/some/path", detection_roots=[])
    assert ctx.get_detection_roots() == ["/tmp/some/path"]
