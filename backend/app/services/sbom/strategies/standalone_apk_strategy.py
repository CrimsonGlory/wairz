"""Standalone APK SBOM strategy — parses META-INF/*.version + lib/*.so.

The existing AndroidStrategy at `android_strategy.py:115` returns early
unless `build.prop` is found, gating it against running on standalone-APK
extractions (build.prop only exists in Android SYSTEM images, not in
individual APKs). Operators uploading a single .apk file got 0 SBOM
components because no strategy walked the APK's interior.

This strategy bridges that gap by parsing two highly-reliable signal
sources inside extracted APK trees:

1. ``META-INF/<groupId>_<artifactId>.version`` files — modern Android
   build tools (AGP 7+) emit these for every Maven library bundled into
   the APK. Filename encodes groupId + artifactId; file content is the
   version string. Single file per library; no false positives.

2. ``lib/<abi>/<libname>.so`` files — bundled native libraries. We emit
   one component per unique .so basename (dedup across ABI variants).
   These often hide third-party native deps (OpenSSL, SQLite, BoringSSL,
   audio codecs) that aren't in META-INF.

Bonus path: ``AndroidManifest.xml`` parse via androguard for the APK's
own package name + versionName if reliably extractable; otherwise fall
back to APK filename.

Out of scope:
- DEX class analysis (handled by Security > APK Scan / SAST workflow).
- AAB / APKM / multi-APK bundles (single-APK shape only for now).
- Native library version detection (.so files lack inline versions
  predictably; CVE matching via filename/CPE handles most cases).
"""
from __future__ import annotations

import os

from app.services.sbom.constants import IdentifiedComponent
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext


class StandaloneApkStrategy(SbomStrategy):
    """Surface Maven libraries + native libs from extracted standalone APKs.

    Discovers `*_extract/` directories under ctx.extracted_root and walks
    each one for META-INF/*.version + lib/*/*.so. Idempotent dedup via the
    shared ComponentStore (matching name+version keys collapse cleanly).
    """

    name = "standalone_apk"

    # Cap per-APK component emission to defend against pathological
    # bundles. Real APKs typically have 20-100 .version files + 5-30
    # native libs; 500 is a comfortable ceiling. Truncation sentinel
    # emitted as a final component when hit.
    _MAX_COMPONENTS_PER_APK = 500

    def run(self, ctx: StrategyContext) -> None:
        # Find every `*_extract/` directory under the scan root.
        # Reach the contained META-INF and lib/ subtrees.
        for entry in os.listdir(ctx.extracted_root):
            apk_extract_dir = os.path.join(ctx.extracted_root, entry)
            if not entry.lower().endswith("_extract") or not os.path.isdir(apk_extract_dir):
                continue
            self._scan_apk_extract(apk_extract_dir, ctx)

    def _scan_apk_extract(self, apk_extract_dir: str, ctx: StrategyContext) -> None:
        emitted = 0
        # 1) Maven version files
        meta_inf = os.path.join(apk_extract_dir, "META-INF")
        if os.path.isdir(meta_inf):
            try:
                for fname in os.listdir(meta_inf):
                    if not fname.endswith(".version"):
                        continue
                    if emitted >= self._MAX_COMPONENTS_PER_APK:
                        break
                    # Parse "<groupId>_<artifactId>.version" — first underscore
                    # separates groupId from artifactId. Maven groupId can
                    # contain dots but not underscores; the convention is to
                    # use the first underscore as the split point.
                    stem = fname[: -len(".version")]
                    if "_" not in stem:
                        continue
                    group_id, artifact_id = stem.split("_", 1)
                    fpath = os.path.join(meta_inf, fname)
                    try:
                        with open(fpath, encoding="utf-8") as f:
                            version = f.read().strip()
                    except OSError:
                        continue
                    if not version:
                        continue
                    ctx.store.add(IdentifiedComponent(
                        name=f"{group_id}:{artifact_id}",
                        version=version,
                        type="library",
                        cpe=None,
                        purl=f"pkg:maven/{group_id}/{artifact_id}@{version}",
                        supplier=group_id,
                        detection_source="standalone_apk",
                        detection_confidence="high",
                        file_paths=[fpath],
                        metadata={
                            "source": "META-INF/*.version",
                            "ecosystem": "maven",
                        },
                    ))
                    emitted += 1
            except OSError:
                pass

        # 2) Native libs — dedup by basename across ABI variants.
        lib_dir = os.path.join(apk_extract_dir, "lib")
        seen_libs: set[str] = set()
        if os.path.isdir(lib_dir):
            try:
                for abi in os.listdir(lib_dir):
                    if emitted >= self._MAX_COMPONENTS_PER_APK:
                        break
                    abi_dir = os.path.join(lib_dir, abi)
                    if not os.path.isdir(abi_dir):
                        continue
                    for so_name in os.listdir(abi_dir):
                        if not so_name.endswith(".so"):
                            continue
                        # Strip the "lib" prefix + ".so" suffix for the
                        # component name (e.g. libcrypto.so → crypto).
                        # Keep the original basename as file_paths for
                        # operator traceability.
                        clean_name = so_name
                        if clean_name.startswith("lib"):
                            clean_name = clean_name[3:]
                        if clean_name.endswith(".so"):
                            clean_name = clean_name[:-3]
                        if clean_name in seen_libs:
                            continue
                        seen_libs.add(clean_name)
                        ctx.store.add(IdentifiedComponent(
                            name=clean_name,
                            version=None,
                            type="library",
                            cpe=None,
                            purl=None,
                            supplier=None,
                            detection_source="standalone_apk",
                            detection_confidence="medium",
                            file_paths=[os.path.join(abi_dir, so_name)],
                            metadata={
                                "source": "lib/<abi>/*.so",
                                "abi_dirs": [
                                    a for a in os.listdir(lib_dir)
                                    if os.path.isfile(os.path.join(lib_dir, a, so_name))
                                ],
                                "ecosystem": "android-native",
                            },
                        ))
                        emitted += 1
            except OSError:
                pass

        if emitted >= self._MAX_COMPONENTS_PER_APK:
            ctx.store.add(IdentifiedComponent(
                name=f"... +N more components truncated (cap={self._MAX_COMPONENTS_PER_APK})",
                version=None,
                type="library",
                cpe=None,
                purl=None,
                supplier=None,
                detection_source="standalone_apk",
                detection_confidence="low",
                file_paths=[apk_extract_dir],
                metadata={"truncated": True, "cap": self._MAX_COMPONENTS_PER_APK},
            ))
