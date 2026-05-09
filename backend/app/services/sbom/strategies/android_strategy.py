"""Android firmware components: build.prop, APKs, init services, modules.

Detects the presence of an Android rootfs via ``build.prop``, then
enumerates APKs under the 10 standard ``{system,product,vendor,
system_ext,odm}/{app,priv-app}`` directories (per CLAUDE.md Rule 14),
parses ``.rc`` init files for services, and scans vendor kernel
modules.

Also resolves the AOSP base-tag + patch date from the Google-format
build ID.

Previously ``SbomService._scan_android_components / _parse_build_prop /
_parse_build_id_date / _resolve_aosp_tag / _parse_android_init_rc`` +
the ``_AOSP_BUILD_TAG_MAP`` constant in the ``sbom_service.py``
monolith.
"""

from __future__ import annotations

import os
import re

from app.services.sbom.constants import IdentifiedComponent
from app.services.sbom.strategies.base import SbomStrategy, StrategyContext

# Known AOSP build ID → tag version mapping (major releases).
# Source: https://source.android.com/docs/setup/reference/build-numbers
AOSP_BUILD_TAG_MAP: dict[str, str] = {
    # Android 15
    "AP3A": "android-15.0.0_r1",
    "AP4A": "android-15.0.0_r2",
    "AE3A": "android-15.0.0_r5",
    "BP31": "android-15.0.0_r8",
    "BP3A": "android-15.0.0_r11",
    "BD3A": "android-15.0.0_r17",
    # Android 14
    "UP1A": "android-14.0.0_r1",
    "UD1A": "android-14.0.0_r14",
    "AP1A": "android-14.0.0_r29",
    "AP2A": "android-14.0.0_r53",
    # Android 13
    "TP1A": "android-13.0.0_r1",
    "TQ3A": "android-13.0.0_r35",
    "TD4A": "android-13.0.0_r75",
    # Android 12
    "SP1A": "android-12.0.0_r1",
    "SQ3A": "android-12.0.0_r26",
    "SD2A": "android-12.0.0_r34",
}


def parse_build_id_date(build_id: str) -> str | None:
    """Extract the AOSP base patch date from a Google-format build ID.

    Google build IDs follow the pattern: ``XXYY.YYMMDD.NNN[.suffix]``
    e.g. ``AP3A.240905.015.A2`` → ``2024-09-05``.
    """
    m = re.match(r"^[A-Z0-9]{3,4}\.(\d{6})\.", build_id)
    if not m:
        return None
    yymmdd = m.group(1)
    try:
        yy, mm, dd = int(yymmdd[:2]), int(yymmdd[2:4]), int(yymmdd[4:6])
        year = 2000 + yy
        if 1 <= mm <= 12 and 1 <= dd <= 31:
            return f"{year}-{mm:02d}-{dd:02d}"
    except (ValueError, IndexError):
        pass
    return None


def resolve_aosp_tag(build_id: str) -> str | None:
    """Resolve a build ID prefix (e.g. 'AP3A') to its AOSP tag version."""
    m = re.match(r"^([A-Z0-9]{3,4})\.", build_id)
    if m:
        return AOSP_BUILD_TAG_MAP.get(m.group(1))
    return None


class AndroidStrategy(SbomStrategy):
    """Detect Android-specific components: APKs, system properties, init."""

    name = "android"

    # Standard AOSP app directories (per CLAUDE.md rule 14)
    _APP_DIRS = (
        "system/app", "system/priv-app",
        "product/app", "product/priv-app",
        "vendor/app", "vendor/priv-app",
        "system_ext/app", "system_ext/priv-app",
        "odm/app", "odm/priv-app",
    )

    _INIT_DIRS = (
        "system/etc/init",
        "vendor/etc/init",
        "product/etc/init",
    )

    _KMOD_DIRS = (
        "vendor/lib/modules",
        "vendor/lib64/modules",
        "system/lib/modules",
    )

    def run(self, ctx: StrategyContext) -> None:
        # Check if this is an Android filesystem
        build_prop: str | None = None
        for bp_path in ("system/build.prop", "build.prop", "vendor/build.prop"):
            abs_bp = os.path.join(ctx.extracted_root, bp_path)
            if os.path.isfile(abs_bp):
                build_prop = abs_bp
                break

        if build_prop is None:
            return  # Not Android

        # 1. Parse build.prop for system metadata
        self._parse_build_prop(build_prop, ctx)

        # 2. Scan APKs
        for app_dir in self._APP_DIRS:
            self._scan_apks(app_dir, ctx)

        # 3. Parse init services from .rc files
        for init_dir in self._INIT_DIRS:
            self._scan_init(init_dir, ctx)

        # 4. Scan kernel modules
        for mod_dir in self._KMOD_DIRS:
            self._scan_kmods(mod_dir, ctx)

    # --- APK enumeration -----------------------------------------------

    @staticmethod
    def _scan_apks(app_dir: str, ctx: StrategyContext) -> None:
        abs_dir = os.path.join(ctx.extracted_root, app_dir)
        if not os.path.isdir(abs_dir):
            return
        try:
            for app_name in os.listdir(abs_dir):
                app_path = os.path.join(abs_dir, app_name)
                if not os.path.isdir(app_path):
                    continue
                priv = "priv-app" in app_dir
                comp = IdentifiedComponent(
                    name=app_name,
                    version=None,
                    type="application",
                    cpe=None,
                    purl=None,
                    supplier=None,
                    detection_source="android_apk",
                    detection_confidence="high",
                    file_paths=[f"/{app_dir}/{app_name}"],
                    metadata={
                        "android_app_type": "privileged" if priv else "system",
                        "source": "android",
                    },
                )
                ctx.store.add(comp)
        except OSError:
            return

    # --- init .rc service enumeration ----------------------------------

    @staticmethod
    def _scan_init(init_dir: str, ctx: StrategyContext) -> None:
        abs_dir = os.path.join(ctx.extracted_root, init_dir)
        if not os.path.isdir(abs_dir):
            return
        try:
            for rc_name in os.listdir(abs_dir):
                if not rc_name.endswith(".rc"):
                    continue
                rc_path = os.path.join(abs_dir, rc_name)
                AndroidStrategy._parse_init_rc(rc_path, init_dir, ctx)
        except OSError:
            return

    @staticmethod
    def _parse_init_rc(abs_path: str, rel_dir: str, ctx: StrategyContext) -> None:
        try:
            with open(abs_path, errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("service "):
                        parts = line.split()
                        if len(parts) >= 3:
                            service_name = parts[1]
                            binary_path = parts[2]
                            rc_name = os.path.basename(abs_path)
                            comp = IdentifiedComponent(
                                name=f"init-{service_name}",
                                version=None,
                                type="application",
                                cpe=None,
                                purl=None,
                                supplier=None,
                                detection_source="android_init_service",
                                detection_confidence="medium",
                                file_paths=[f"/{rel_dir}/{rc_name}"],
                                metadata={
                                    "binary": binary_path,
                                    "source": "android",
                                    "type": "init_service",
                                },
                            )
                            ctx.store.add(comp)
        except OSError:
            pass

    # --- vendor kernel module enumeration ------------------------------

    @staticmethod
    def _scan_kmods(mod_dir: str, ctx: StrategyContext) -> None:
        abs_dir = os.path.join(ctx.extracted_root, mod_dir)
        if not os.path.isdir(abs_dir):
            return
        try:
            for mod_name in os.listdir(abs_dir):
                if not mod_name.endswith(".ko"):
                    continue
                comp = IdentifiedComponent(
                    name=mod_name.replace(".ko", ""),
                    version=None,
                    type="library",
                    cpe=None,
                    purl=None,
                    supplier=None,
                    detection_source="android_kernel_module",
                    detection_confidence="medium",
                    file_paths=[f"/{mod_dir}/{mod_name}"],
                    metadata={"source": "android", "type": "kernel_module"},
                )
                ctx.store.add(comp)
        except OSError:
            return

    # --- build.prop parsing --------------------------------------------

    def _parse_build_prop(self, abs_path: str, ctx: StrategyContext) -> None:
        """Parse Android build.prop for version info and platform details."""
        props: dict[str, str] = {}
        try:
            with open(abs_path, errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    props[key.strip()] = value.strip()
        except OSError:
            return

        # Android OS version
        android_version = (
            props.get("ro.build.version.release")
            or props.get("ro.system.build.version.release")
        )
        security_patch = props.get("ro.build.version.security_patch")
        build_id = (
            props.get("ro.build.id")
            or props.get("ro.system.build.id")
            or props.get("ro.build.display.id")
        )
        platform = props.get("ro.board.platform", "")
        model = (
            props.get("ro.product.model")
            or props.get("ro.product.system.model", "")
        )

        if android_version:
            sdk_version = props.get("ro.build.version.sdk")
            incremental = (
                props.get("ro.build.version.incremental")
                or props.get("ro.system.build.version.incremental")
            )

            # Resolve AOSP tag and base patch date from build ID
            aosp_tag = resolve_aosp_tag(build_id) if build_id else None
            build_id_date = parse_build_id_date(build_id) if build_id else None

            comp = IdentifiedComponent(
                name="android",
                version=android_version,
                type="operating-system",
                cpe=f"cpe:2.3:o:google:android:{android_version}:*:*:*:*:*:*:*",
                purl=None,
                supplier="google",
                detection_source="android_build_prop",
                detection_confidence="high",
                file_paths=[abs_path.replace(ctx.extracted_root, "")],
                metadata={
                    "security_patch": security_patch,
                    "build_id": build_id,
                    "aosp_tag": aosp_tag,
                    "build_id_base_date": build_id_date,
                    "sdk_version": sdk_version,
                    "incremental": incremental,
                    "platform": platform,
                    "model": model,
                    "build_fingerprint": (
                        props.get("ro.build.fingerprint")
                        or props.get("ro.system.build.fingerprint")
                    ),
                    "source": "android",
                },
            )
            ctx.store.add(comp)

        # SELinux status
        selinux_dir = os.path.join(ctx.extracted_root, "system", "etc", "selinux")
        if os.path.isdir(selinux_dir):
            comp = IdentifiedComponent(
                name="android-selinux-policy",
                version=None,
                type="library",
                cpe=None,
                purl=None,
                supplier="google",
                detection_source="android_selinux",
                detection_confidence="high",
                file_paths=["/system/etc/selinux"],
                metadata={"source": "android", "type": "security_policy"},
            )
            ctx.store.add(comp)
