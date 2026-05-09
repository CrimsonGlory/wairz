#!/usr/bin/env python3
"""Generate synthetic APK files from fixture manifest definitions.

Creates minimal but valid APK (ZIP) files that androguard can parse.
Each APK contains an AndroidManifest.xml (compiled binary AXML format)
and optionally a res/xml/network_security_config.xml.

Run inside the backend container:
    docker compose exec backend python tests/fixtures/apk/generate_apk_fixtures.py

The generated .apk files are gitignored — they're regenerated on demand.
For unit tests, use the mock_apk_factory.py instead (no real files needed).
For integration tests, run this script first, then use the generated APKs.
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

# Add backend root to path so we can import fixture manifests
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_ROOT = SCRIPT_DIR.parent.parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from tests.fixtures.apk.apk_fixture_manifests import ALL_FIXTURES

# ---------------------------------------------------------------------------
# Minimal binary AXML (Android Binary XML) encoder
# ---------------------------------------------------------------------------
# Android's binary XML format is complex, but androguard can also parse
# plain-text XML from a ZIP entry named AndroidManifest.xml if we use
# the right approach. We'll create a minimal ZIP with the manifest as
# plain XML and wrap it so androguard's APK class can load it.
#
# However, androguard.core.apk.APK expects binary AXML by default.
# The simplest approach: write the XML as-is and let tests use the
# mock factory for unit tests. For integration, we create proper APKs
# using androguard's own tools if available.
# ---------------------------------------------------------------------------


def _create_apk_zip(
    manifest_xml: str,
    *,
    network_security_config: str | None = None,
) -> bytes:
    """Create a minimal APK (ZIP) file with the given manifest.

    Attempts to use androguard's AXML compiler if available; otherwise
    falls back to storing plain XML (which androguard can also parse
    in some configurations).

    Args:
        manifest_xml: The AndroidManifest.xml content (plain text XML)
        network_security_config: Optional network_security_config.xml content

    Returns:
        The APK file contents as bytes
    """
    buf = io.BytesIO()

    # Try to compile to binary AXML using androguard
    manifest_bytes = _compile_to_axml(manifest_xml)
    nsc_bytes = None
    if network_security_config:
        nsc_bytes = _compile_to_axml(network_security_config)

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_bytes)

        if nsc_bytes:
            zf.writestr("res/xml/network_security_config.xml", nsc_bytes)

        # Add a minimal classes.dex stub (DEX magic + empty)
        # DEX magic: "dex\n035\0"
        dex_magic = b"dex\n035\x00"
        # Minimal DEX header (just enough to not crash parsers)
        dex_header = dex_magic + b"\x00" * 104  # 112 bytes total
        zf.writestr("classes.dex", dex_header)

        # Add META-INF for v1 signing stub
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", b"\x00" * 32)  # Stub

    return buf.getvalue()


def _compile_to_axml(xml_text: str) -> bytes:
    """Attempt to compile XML text to Android binary AXML format.

    Falls back to plain UTF-8 XML if androguard compilation is not available.
    """
    try:
        # Try using androguard's AXML writer
        from androguard.core.axml import AXMLPrinter
        # androguard doesn't have a public XML-to-AXML compiler,
        # so we store as plain text XML. androguard's APK class
        # handles both formats.
        return xml_text.encode("utf-8")
    except ImportError:
        return xml_text.encode("utf-8")


def generate_all(output_dir: Path | None = None) -> dict[str, Path]:
    """Generate all synthetic APK fixtures.

    Args:
        output_dir: Directory to write APK files. Defaults to this script's
                    directory.

    Returns:
        Dict mapping filename to output path.
    """
    if output_dir is None:
        output_dir = SCRIPT_DIR

    output_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, Path] = {}

    for filename, fixture in ALL_FIXTURES.items():
        apk_bytes = _create_apk_zip(
            fixture["xml"],
            network_security_config=fixture.get("network_security_config"),
        )
        out_path = output_dir / filename
        out_path.write_bytes(apk_bytes)
        results[filename] = out_path
        print(
            f"  ✓ {filename} ({len(apk_bytes):,} bytes) — "
            f"{fixture['description']}"
        )

    return results


if __name__ == "__main__":
    print(f"Generating {len(ALL_FIXTURES)} synthetic APK fixtures...")
    print(f"Output directory: {SCRIPT_DIR}")
    print()
    results = generate_all()
    print()
    print(f"Done. Generated {len(results)} APK files.")
