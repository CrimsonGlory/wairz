"""C4 Android DEPLOYMENT-POSTURE REACHABILITY-EVIDENCE collector.

This walker synthesizes, per firmware, the ``gates_open`` deployment posture
the cve-assessment-framework L4 kill-chain ``LockdownGate`` consumes (spec
Topic 2 + ``AndroidAdapter.get_security_posture()`` /
``get_entry_surfaces()``).

THE HONEST GATING (the C4-defining contract). A static firmware IMAGE can
SUPPORT a lockdown — a Device-Policy-Controller / kiosk / custom-launcher app
present, a telephony stack present — but it CANNOT confirm THIS unit is
enrolled / active / SIM-provisioned. Enrollment + provisioning + the SIM are
RUNTIME facts, not image properties. So C4 emits ``runtime_confirmed=false``
for EVERY image-inferred posture → the framework consumer HOLDS THE GATE OPEN
(guilty per Axiom 1, NO reduction) and surfaces the ``settling_command`` — the
one-shot live capture (``adb shell dumpsys device_policy`` / ``dpm
list-owners`` / ``getprop``) that, when run, is the ONLY thing that can set
``runtime_confirmed=true``.

Absence-in-an-extracted-partition is NOT proof of absence. C3 (and the prior
Moto-detection-roots work) saw phones ship INCOMPLETE partitions — a DPC app
may live on a ``/data`` partition that was never imaged. So an ABSENT DPC
yields ``kiosk`` inferred-FALSE at ``config_inferred`` confidence — NOT
``runtime_confirmed`` — and the framework treats a config_inferred negative as
a STILL-OPEN gate (guilty). Only a live capture flips it.

The emitted gates (``gates_open``):

  * **``kiosk``** — is a Device Policy Controller / lockTask / MDM-enrollment /
    custom-launcher app present? Signals: a known-DPC package name in any APK
    dir; a ``device_owner.xml`` / ``device_policies.xml`` under ``/data/system``;
    a parsed ``<receiver>`` declaring ``BIND_DEVICE_ADMIN`` /
    ``android.app.action.DEVICE_ADMIN_ENABLED`` (Androguard manifest parse —
    optional enrichment, gated on availability). PRESENT → kiosk SUPPORTED
    (inferred-true); ABSENT → inferred-false (config_inferred — never
    confirmed).
  * **``cellular_active``** — is a telephony stack present? Signals: RIL libs
    (``libril*.so`` / ``rild``), telephony HAL, carrier/SIM APKs
    (``CarrierDefaultApp`` / ``SimAppDialog`` / ``Telephony*`` / ``Phone*``),
    ``ro.telephony.*`` build-props. PRESENT → the modem ADJACENT surface stays
    OPEN (inferred-true); the SIM-provisioned state is the LIVE gap.
  * **``sideloading_allowed``** — the install-unknown-sources default. Signals:
    ``ro.secure`` / ``ro.adb.secure`` / ``persist.sys.usb.config`` build-props,
    ``Settings.Secure install_non_market_apps`` /
    ``Settings.Global package_verifier_enable`` (settings XML when imaged).
    A ``user``/``release-keys`` build with no override → inferred guilty-OPEN
    at config_inferred (the default posture cannot be confirmed from the image).

Sources (all PARSE-ONLY, read as DATA across get_detection_roots per Rule #16):

  * build.prop (``ro.build.type`` / ``ro.build.tags`` / ``ro.secure`` /
    ``ro.adb.secure`` / ``ro.telephony.*`` / ``persist.sys.usb.config``) —
    closed-grammar key=value parse.
  * APK directory inventory (``system/app`` / ``priv-app`` / ``product/*`` /
    ``vendor/app`` per ``_android_helpers.APK_DIRS``) — PRESENCE only.
  * ``/data/system/device_owner*.xml`` / ``device_policies.xml`` — PRESENCE.
  * APK manifest device-admin component scan (OPTIONAL, via
    :class:`AndroguardService` — the S2 reuse; gated on
    ``AndroguardService.is_available()`` so the walker degrades cleanly when
    androguard is absent). The manifest is read AS DATA via ``APK()`` — the
    fast manifest-only parse — never the DEX / AnalyzeAPK path.

Cross-platform: a non-Android firmware (no APK dirs + no Android build.prop)
→ ``platform="not_applicable"`` no-op (guilty-safe: no Android posture to
infer; the framework's Android adapter never runs on it).

Three functions per CLAUDE.md Rule #39 (inner/outer/safe triplet):

  - :func:`_do_android_posture_run` — INNER pure-logic orchestrator. Caller
    owns the session + transaction. Resolves detection roots (Rule #16). Walks
    every posture source, computes ``gates_open`` + ``posture_confidence`` +
    the supporting evidence, ALWAYS sets ``runtime_confirmed=false`` (image
    walk). Returns the result aggregate UNSTAMPED (caller stamps via
    ``_stamp_firmware_android_posture_walk_result``). Clears stale
    ``android_posture_walk_result`` at entry.

  - :func:`run_android_posture_walk_background` — OUTER Rule #33 .a state
    machine. Owns its own ``async_session_factory()``. Cycles
    ``queued → running → completed | failed``. Failure persistence on a FRESH
    session (the inner session rolled back).

  - :func:`auto_android_posture_walk_firmware_safe` — SAFE
    unpack-post-detection hook. Owns own session. Stamps the result so
    operators see the last-known result. Does NOT mutate
    ``android_posture_walk_status`` (leaves it ``idle`` so an operator-triggered
    re-walk via ``trigger_android_posture_walk`` MCP tool works without a 409
    conflict).

**Rule #36 + Rule #45 PARSE-ONLY contract.** The walker reads build.prop /
APK manifests / device_owner XML / settings XML AS DATA. It NEVER passes any
path to a spawn primitive (``subprocess`` / ``os.system`` / ``exec`` /
``runpy`` / etc.) — it NEVER executes dex, NEVER invokes an APK — and NEVER
decrypts anything. Test gate
``test_android_posture_walker.py::test_walker_no_execute_no_decrypt`` enforces
via tokenize-walk; Rule #46 paired META-CANARY confirms the gate fires on a
synthetic violation.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os
import traceback
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_android_posture_walk_result,
)

logger = logging.getLogger(__name__)


# ── Bounds (Rule #5). ───────────────────────────────────────────────────────
# A build.prop is small; cap defensively.
_MAX_PROP_TEXT_BYTES = 2 * 1024 * 1024
# A device-policy / settings XML is small; cap defensively.
_MAX_XML_TEXT_BYTES = 4 * 1024 * 1024
# Per-walk hard cap on APK files manifest-scanned via Androguard (the optional
# enrichment) so a huge phone image doesn't stall the walk.
_MAX_APK_MANIFEST_SCANS = 400
# Per-walk hard cap on APK directory entries enumerated for the presence
# inventory (cheap scandir, but bound it).
_MAX_APK_DIR_ENTRIES = 50_000


# The one-shot live capture the operator must run to set runtime_confirmed.
# Named in the emitted aggregate so the framework consumer (which holds the
# gate OPEN on an image-inferred posture) surfaces a RANKED evidence request
# rather than a dead end (spec L4-10 evidence-gap request shape).
_SETTLING_COMMAND = (
    "adb shell dumpsys device_policy; "
    "adb shell dpm list-owners; "
    "adb shell getprop | grep -E 'sim|radio|airplane|ro.secure'"
)


# ── Closed-grammar signal sets (no eval; PURE). ─────────────────────────────
#
# Known Device-Policy-Controller / MDM / kiosk package-name TOKENS. Matched as
# a token against an APK directory / package basename, case-insensitive, with
# WORD-BOUNDARY-ish containment so a benign dir like Motorola's ``mdmctbk``
# (modem crash-tracking) does NOT false-match ``mdm`` (we require the token to
# be a recognised DPC vendor identifier, not the bare 3-letter ``mdm``).
_DPC_PACKAGE_TOKENS: frozenset[str] = frozenset({
    # Major EMM / MDM vendors (device-owner / profile-owner DPCs).
    "afw",                       # Android-for-Work test DPC family
    "workspaceone",              # VMware Workspace ONE / AirWatch
    "airwatch",
    "intune",                    # Microsoft Intune Company Portal
    "mobileiron",
    "maas360",                   # IBM MaaS360
    "knox",                      # Samsung Knox (KME / KSP)
    "soti",                      # SOTI MobiControl
    "scalefusion",
    "hexnode",
    "miradore",
    "meraki",                    # Cisco Meraki Systems Manager
    "jamf",
    "kandji",
    "esper",                     # Esper kiosk/COSU
    "kme",
    "devicepolicycontroller",    # AOSP test DPC
    "managedprovisioning",       # AOSP ManagedProvisioning (provisioning DPC)
    "cosu",                      # COSU / dedicated-device provisioning
})

# Telephony / RIL native-lib + binary tells (PRESENCE only). RIL libs are the
# strongest "modem hardware stack BUILT" signal; the SIM-provisioned state is
# the LIVE gap C4 cannot confirm.
_TELEPHONY_LIB_TOKENS: frozenset[str] = frozenset({
    "libril",
    "librilutils",
    "libril-qc",
    "rild",
    "libqcril",
    "libsec-ril",
    "libreference-ril",
})

# Telephony / carrier / SIM APK directory-name tells (PRESENCE only).
_TELEPHONY_APK_TOKENS: frozenset[str] = frozenset({
    "carrierdefaultapp",
    "simappdialog",
    "telephonyprovider",
    "telephony",
    "phone",                     # the Phone / TeleService priv-app
    "teleservice",
    "carrierconfig",
    "ims",                       # IMS / VoLTE service
    "carrierservices",
})

# Telephony build-prop keys → presence of a telephony stack config.
_TELEPHONY_PROP_PREFIXES: tuple[str, ...] = (
    "ro.telephony.",
    "persist.radio.",
    "gsm.",
    "ril.",
)

# build.prop / settings keys that bear on the sideloading-allowed default.
_PROP_RO_SECURE = "ro.secure"
_PROP_RO_ADB_SECURE = "ro.adb.secure"
_PROP_BUILD_TYPE = "ro.build.type"
_PROP_BUILD_TAGS = "ro.build.tags"
_PROP_USB_CONFIG = "persist.sys.usb.config"

# APK dirs to inventory (mirror _android_helpers.APK_DIRS + the partition
# variants). PRESENCE only — never invoke.
_APK_DIRS: tuple[str, ...] = (
    "system/app",
    "system/priv-app",
    "system_ext/app",
    "system_ext/priv-app",
    "product/app",
    "product/priv-app",
    "vendor/app",
    "vendor/priv-app",
    "app",          # a bare partition root (the unpacker sometimes promotes
    "priv-app",     # the partition contents to the detection-root top level)
)

# Device-owner / device-policy XML well-known relative paths (PRESENCE).
_DEVICE_OWNER_XML_RELPATHS: tuple[str, ...] = (
    "data/system/device_owner.xml",
    "data/system/device_owner_2.xml",
    "data/system/device_policies.xml",
    "system/data/system/device_owner.xml",
)

# build.prop well-known relative paths (per the real-data Moto layout — etc/
# AND system/ AND a bare root).
_BUILD_PROP_RELPATHS: tuple[str, ...] = (
    "build.prop",
    "system/build.prop",
    "etc/build.prop",
    "system/etc/build.prop",
    "vendor/build.prop",
    "product/build.prop",
    "system_ext/etc/build.prop",
)

# Settings XML well-known relative paths (when /data was imaged).
_SETTINGS_XML_RELPATHS: tuple[str, ...] = (
    "data/system/users/0/settings_secure.xml",
    "data/system/users/0/settings_global.xml",
    "data/system/settings_secure.xml",
    "data/system/settings_global.xml",
)

# An Android firmware tell: build.prop keys that only Android sets. Used to
# decide platform="android" vs "not_applicable".
_ANDROID_PROP_KEYS: frozenset[str] = frozenset({
    "ro.build.version.sdk",
    "ro.build.fingerprint",
    "ro.product.cpu.abi",
    "ro.build.type",
})


# ── Sync filesystem helpers (Rule #5 — wrapped in run_in_executor). ─────────


def _read_text_file_sync(path: str, cap: int) -> str | None:
    """Read up to ``cap`` bytes of a text file (sync), decode best-effort."""
    try:
        with open(path, "rb") as fh:  # noqa: ASYNC240 — sync helper run via executor
            data = fh.read(cap)
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def _parse_build_prop(text: str) -> dict[str, str]:
    """Parse a build.prop's ``key=value`` lines into a dict. PURE — last value
    wins (Android's runtime resolution). Comments (``#``) + blanks skipped."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key:
            out[key] = value
    return out


def _scan_apk_inventory_sync(root_path: str) -> tuple[list[str], list[str]]:
    """Enumerate APK app-directory entry names under one detection root.

    Returns ``(dpc_app_dirs, telephony_app_dirs)`` — directory basenames that
    matched a DPC token or a telephony/carrier token. PRESENCE only — reads
    nothing inside the APKs, never invokes. PURE (sync — executor-wrapped)."""
    dpc_hits: list[str] = []
    tele_hits: list[str] = []
    entries_seen = 0
    for app_dir in _APK_DIRS:
        base = os.path.join(root_path, app_dir)
        if not os.path.isdir(base):
            continue
        try:
            entries = sorted(os.listdir(base))
        except OSError:
            continue
        for entry in entries:
            entries_seen += 1
            if entries_seen > _MAX_APK_DIR_ENTRIES:
                return dpc_hits, tele_hits
            low = entry.lower()
            # DPC: require a recognised vendor token contained in the dir name.
            if any(tok in low for tok in _DPC_PACKAGE_TOKENS):
                dpc_hits.append(f"{app_dir}/{entry}")
            # Telephony APK presence.
            if any(tok in low for tok in _TELEPHONY_APK_TOKENS):
                tele_hits.append(f"{app_dir}/{entry}")
    return dpc_hits, tele_hits


def _scan_telephony_libs_sync(root_path: str) -> list[str]:
    """Find RIL / telephony native libs under one detection root's lib dirs.
    PRESENCE only. PURE (sync — executor-wrapped)."""
    hits: list[str] = []
    for lib_dir in (
        "lib",
        "lib64",
        "system/lib",
        "system/lib64",
        "vendor/lib",
        "vendor/lib64",
        "vendor/lib64/hw",
        "vendor/lib/hw",
    ):
        base = os.path.join(root_path, lib_dir)
        if not os.path.isdir(base):
            continue
        try:
            entries = os.listdir(base)
        except OSError:
            continue
        for entry in entries:
            low = entry.lower()
            if any(low.startswith(tok) or tok in low for tok in _TELEPHONY_LIB_TOKENS):
                hits.append(f"{lib_dir}/{entry}")
    return hits


def _find_first_existing(root_path: str, relpaths: tuple[str, ...]) -> str | None:
    """Return the first existing absolute path among ``relpaths`` under
    ``root_path`` (PURE; sync). os.path.* are pure-string + a stat each."""
    for rel in relpaths:
        full = os.path.join(root_path, rel)
        if os.path.isfile(full):  # noqa: ASYNC240 — bounded stat in executor-run sync helper
            return full
    return None


def _collect_root_signals_sync(root_path: str) -> dict:
    """Collect every posture signal from ONE detection root (sync, bounded).

    Returns a per-root partial-signal dict the inner runner merges across all
    roots. PARSE-ONLY across the board. PURE (sync — executor-wrapped)."""
    signals: dict = {
        "props": {},
        "dpc_app_dirs": [],
        "telephony_app_dirs": [],
        "telephony_libs": [],
        "device_owner_xml": None,
        "settings_xml": None,
        "apk_dirs_present": False,
    }

    # build.prop merge (first found per relpath; later props override earlier).
    for rel in _BUILD_PROP_RELPATHS:
        full = os.path.join(root_path, rel)
        if not os.path.isfile(full):
            continue
        text = _read_text_file_sync(full, _MAX_PROP_TEXT_BYTES)
        if text:
            signals["props"].update(_parse_build_prop(text))

    dpc_hits, tele_apk_hits = _scan_apk_inventory_sync(root_path)
    signals["dpc_app_dirs"] = dpc_hits
    signals["telephony_app_dirs"] = tele_apk_hits
    signals["telephony_libs"] = _scan_telephony_libs_sync(root_path)

    # Did this root even have an APK dir? (the platform=android tell).
    signals["apk_dirs_present"] = any(
        os.path.isdir(os.path.join(root_path, d)) for d in _APK_DIRS
    )

    signals["device_owner_xml"] = _find_first_existing(
        root_path, _DEVICE_OWNER_XML_RELPATHS
    )
    signals["settings_xml"] = _find_first_existing(
        root_path, _SETTINGS_XML_RELPATHS
    )
    return signals


# ── Optional Androguard manifest device-admin enrichment (S2 reuse). ────────


def _scan_device_admin_manifests_sync(root_path: str) -> list[str]:
    """OPTIONAL enrichment — scan APK manifests for a device-admin / DPC
    declaration via :class:`AndroguardService` (the S2 reuse target).

    Gated on ``AndroguardService.is_available()`` so the walker degrades
    cleanly when androguard is absent (returns ``[]``). Reads each APK's
    MANIFEST AS DATA via the fast ``APK()`` path — NEVER AnalyzeAPK (no DEX),
    NEVER invokes the APK. A receiver that requests ``BIND_DEVICE_ADMIN`` /
    declares ``DEVICE_ADMIN_ENABLED`` / a service requesting
    ``BIND_DEVICE_ADMIN`` is a device-admin component → the app SUPPORTS a
    lockdown.

    Returns the list of APK package names (or relative paths) declaring a
    device-admin component. PURE (sync — executor-wrapped)."""
    try:
        from app.services.androguard_service import AndroguardService
    except Exception:  # pragma: no cover — defensive import guard
        return []
    if not AndroguardService.is_available():
        return []

    # Lazy import the manifest-only APK parser (NOT AnalyzeAPK — no DEX).
    try:
        from androguard.core.apk import APK
    except Exception:  # pragma: no cover
        return []

    admin_apks: list[str] = []
    scans = 0
    # Device-admin tells in a parsed manifest (case-insensitive substring
    # over the manifest XML / permission set).
    admin_perm = "android.permission.bind_device_admin"
    admin_meta = "android.app.action.device_admin_enabled"
    admin_device_admin_meta = "android.app.device_admin"

    for app_dir in _APK_DIRS:
        base = os.path.join(root_path, app_dir)
        if not os.path.isdir(base):
            continue
        try:
            entries = sorted(os.listdir(base))
        except OSError:
            continue
        for entry in entries:
            apk_path = None
            sub = os.path.join(base, entry)
            if os.path.isfile(sub) and entry.lower().endswith(".apk"):
                apk_path = sub
            elif os.path.isdir(sub):
                # priv-app/<Name>/<Name>.apk layout.
                try:
                    for inner in os.listdir(sub):
                        if inner.lower().endswith(".apk"):
                            apk_path = os.path.join(sub, inner)
                            break
                except OSError:
                    continue
            if apk_path is None:
                continue
            scans += 1
            if scans > _MAX_APK_MANIFEST_SCANS:
                return admin_apks
            try:
                apk_obj = APK(apk_path)  # manifest-only parse; reads AS DATA
                # uses_permissions + the raw manifest both surface the
                # device-admin declaration.
                perms = {p.lower() for p in (apk_obj.get_permissions() or [])}
                manifest_blob = ""
                try:
                    manifest_blob = (
                        apk_obj.get_android_manifest_axml().get_xml().decode(
                            "utf-8", errors="replace"
                        ).lower()
                    )
                except Exception:
                    manifest_blob = ""
                is_admin = (
                    admin_perm in perms
                    or admin_meta in manifest_blob
                    or admin_device_admin_meta in manifest_blob
                    or admin_perm in manifest_blob
                )
                if is_admin:
                    pkg = None
                    try:
                        pkg = apk_obj.get_package()
                    except Exception:
                        pkg = None
                    admin_apks.append(pkg or f"{app_dir}/{entry}")
            except Exception:
                # A malformed / unreadable APK manifest is skipped — PARSE-ONLY
                # discipline: never crash the walk, never invoke.
                continue
    return admin_apks


# ── Posture synthesis (PURE). ───────────────────────────────────────────────


def _classify_sideloading(props: dict[str, str], settings_xml: str | None) -> tuple[bool, str]:
    """Classify the sideloading-allowed posture from build-props + settings.

    Returns ``(sideloading_allowed, sideload_default_evidence)``. THE GUILTY
    DEFAULT: when the install-source posture cannot be confirmed from the image
    (no explicit lock-down prop / settings), default OPEN (Axiom 1 at the
    parser seam) — the framework caps it at the held-open gate anyway because
    runtime_confirmed is false. PURE."""
    # An explicit hardened build (ro.secure=1 + adb.secure=1 + user build) is
    # the closest the image can come to "sideloading restricted" — but it is
    # STILL only the default; a user can enable unknown sources at runtime.
    ro_secure = props.get(_PROP_RO_SECURE, "")
    adb_secure = props.get(_PROP_RO_ADB_SECURE, "")
    build_type = props.get(_PROP_BUILD_TYPE, "")
    if settings_xml is not None:
        text = _read_text_file_sync(settings_xml, _MAX_XML_TEXT_BYTES) or ""
        low = text.lower()
        if "install_non_market_apps" in low:
            # The presence of an explicit setting is the strongest image
            # signal; surface the raw line region. value=0 → restricted.
            if 'name="install_non_market_apps" value="0"' in low:
                return False, "settings:install_non_market_apps=0"
            if 'name="install_non_market_apps" value="1"' in low:
                return True, "settings:install_non_market_apps=1"
            return True, "settings:install_non_market_apps=present"
    if ro_secure == "1" and adb_secure == "1" and build_type == "user":
        # Hardened defaults — but still the DEFAULT, not a runtime confirmation.
        return False, "build.prop:ro.secure=1,ro.adb.secure=1,user (default-restricted)"
    # No explicit signal → guilty-open default (config_inferred).
    return True, "unknown"


def _empty_aggregate(walked_at: str, platform: str, errors: list[str]) -> dict:
    """Stable empty-result shape (firmware missing / no roots / non-Android).

    For a non-Android firmware, platform="not_applicable" and the gates are
    all False — the framework's Android adapter never runs on it (guilty-safe
    no-op). runtime_confirmed is ALWAYS false (an image can never confirm)."""
    return {
        "walked_at": walked_at,
        "platform": platform,
        "gates_open": {
            "cellular_active": False,
            "sideloading_allowed": False,
            "kiosk": False,
        },
        "runtime_confirmed": False,
        "posture_confidence": "config_inferred",
        "evidence": {
            "dpc_apps": [],
            "telephony_present": False,
            "telephony_evidence": [],
            "sideload_default": "unknown",
            "build_type": None,
            "build_tags": None,
            "device_owner_xml_present": False,
        },
        "settling_command": _SETTLING_COMMAND,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# INNER pure-logic walker (Rule #39).
# ---------------------------------------------------------------------------


async def _do_android_posture_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict:
    """INNER pure-logic orchestrator.

    Caller owns the session + transaction. Resolves detection roots
    (Rule #16). Walks every posture source across all roots, computes
    ``gates_open`` + ``posture_confidence`` + the supporting evidence, and
    ALWAYS sets ``runtime_confirmed=false`` (this is an image walk — an image
    can never confirm enrollment / provisioning / SIM). Returns the result
    aggregate UNSTAMPED. Clears stale ``android_posture_walk_result`` at entry.
    """
    walked_at = dt.datetime.now(dt.UTC).isoformat()

    firmware = await db.get(Firmware, firmware_id)
    if firmware is None:
        return _empty_aggregate(
            walked_at, "not_applicable", [f"firmware {firmware_id} not found"]
        )

    # Clear stale JSONB at entry (mirrors C1 / C2 / C3 + the ICS δ-mitigation).
    firmware.android_posture_walk_result = None

    detection_roots = await get_detection_roots(firmware, db=db)
    if not detection_roots:
        return _empty_aggregate(
            walked_at,
            "not_applicable",
            ["no detection_roots for firmware (extraction may have failed)"],
        )

    loop = asyncio.get_running_loop()
    errors: list[str] = []

    merged_props: dict[str, str] = {}
    dpc_app_dirs: list[str] = []
    telephony_app_dirs: list[str] = []
    telephony_libs: list[str] = []
    device_owner_xml: str | None = None
    settings_xml: str | None = None
    any_apk_dirs = False

    for root_path in detection_roots:
        sig = await loop.run_in_executor(
            None, _collect_root_signals_sync, root_path
        )
        merged_props.update(sig["props"])
        dpc_app_dirs.extend(sig["dpc_app_dirs"])
        telephony_app_dirs.extend(sig["telephony_app_dirs"])
        telephony_libs.extend(sig["telephony_libs"])
        if sig["device_owner_xml"] and device_owner_xml is None:
            device_owner_xml = sig["device_owner_xml"]
        if sig["settings_xml"] and settings_xml is None:
            settings_xml = sig["settings_xml"]
        any_apk_dirs = any_apk_dirs or sig["apk_dirs_present"]

    # platform=android iff we found an Android build.prop key OR an APK dir.
    is_android = any_apk_dirs or any(
        k in merged_props for k in _ANDROID_PROP_KEYS
    )
    if not is_android:
        return _empty_aggregate(walked_at, "not_applicable", errors)

    # Optional Androguard manifest device-admin enrichment (S2 reuse) — run
    # per-root, gated on availability inside the helper.
    admin_manifest_apks: list[str] = []
    for root_path in detection_roots:
        try:
            hits = await loop.run_in_executor(
                None, _scan_device_admin_manifests_sync, root_path
            )
            admin_manifest_apks.extend(hits)
        except Exception as exc:  # pragma: no cover — enrichment never fatal
            errors.append(f"androguard manifest enrichment skipped: {exc!r}")

    # ── KIOSK gate ──────────────────────────────────────────────────────
    # SUPPORTED (inferred-true) iff a DPC package / device_owner.xml /
    # device-admin manifest component is PRESENT. ABSENT → inferred-FALSE at
    # config_inferred (NEVER confirmed — absence-in-partition is not proof of
    # absence; the framework keeps the gate OPEN on the config_inferred
    # negative).
    dpc_apps = sorted(set(dpc_app_dirs) | set(admin_manifest_apks))
    device_owner_present = device_owner_xml is not None
    kiosk_supported = bool(dpc_apps) or device_owner_present

    # ── CELLULAR gate ───────────────────────────────────────────────────
    # inferred-true iff a telephony stack is present (RIL libs / carrier APKs /
    # ro.telephony.* props). The modem ADJACENT surface stays OPEN; the
    # SIM-provisioned state is the LIVE gap.
    telephony_prop_hits = sorted(
        k for k in merged_props
        if any(k.startswith(p) for p in _TELEPHONY_PROP_PREFIXES)
    )
    telephony_evidence = sorted(
        set(telephony_libs) | set(telephony_app_dirs)
    ) + [f"prop:{k}" for k in telephony_prop_hits[:10]]
    telephony_present = bool(
        telephony_libs or telephony_app_dirs or telephony_prop_hits
    )

    # ── SIDELOADING gate ────────────────────────────────────────────────
    sideloading_allowed, sideload_default = _classify_sideloading(
        merged_props, settings_xml
    )

    # posture_confidence: ALWAYS config_inferred for an image walk — the only
    # source that could raise it is a live capture (runtime_confirmed), which
    # an image walk can never produce. THE HONEST GATING.
    posture_confidence = "config_inferred"

    return {
        "walked_at": walked_at,
        "platform": "android",
        "gates_open": {
            "cellular_active": telephony_present,
            "sideloading_allowed": sideloading_allowed,
            "kiosk": kiosk_supported,
        },
        # ALWAYS false — an image SUPPORTS a lockdown but cannot CONFIRM
        # enrollment / provisioning / SIM. The framework consumer HOLDS THE
        # GATE OPEN (guilty, no reduction) and surfaces settling_command.
        "runtime_confirmed": False,
        "posture_confidence": posture_confidence,
        "evidence": {
            "dpc_apps": dpc_apps,
            "telephony_present": telephony_present,
            "telephony_evidence": telephony_evidence[:50],
            "sideload_default": sideload_default,
            "build_type": merged_props.get(_PROP_BUILD_TYPE),
            "build_tags": merged_props.get(_PROP_BUILD_TAGS),
            "device_owner_xml_present": device_owner_present,
        },
        "settling_command": _SETTLING_COMMAND,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# OUTER state-machine wrapper (Rule #33 .a + Rule #39).
# ---------------------------------------------------------------------------


async def run_android_posture_walk_background(firmware_id: uuid.UUID) -> None:
    """OUTER wrapper — owns the Rule #33 .a state machine + outer guard.

    Transitions ``firmware.android_posture_walk_status``:
        queued (set by caller via MCP trigger)
          → running (this fn, on entry)
          → completed | failed (this fn, on exit)

    Failure persistence on a FRESH session (the inner session rolled back on
    the exception). On failure, ``android_posture_walk_result`` is cleared.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                logger.warning(
                    "android_posture_walk: firmware %s not found", firmware_id,
                )
                return
            firmware.android_posture_walk_status = "running"
            firmware.android_posture_walk_started_at = dt.datetime.now(dt.UTC)
            firmware.android_posture_walk_error = None
            await db.commit()
            try:
                result = await _do_android_posture_run(db, firmware_id)
                firmware.android_posture_walk_status = "completed"
                firmware.android_posture_walk_finished_at = dt.datetime.now(
                    dt.UTC
                )
                firmware.android_posture_walk_result = (
                    _stamp_firmware_android_posture_walk_result(result)
                )
                await db.commit()
            except Exception as exc:
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.android_posture_walk_status = "failed"
                        fail_row.android_posture_walk_finished_at = (
                            dt.datetime.now(dt.UTC)
                        )
                        fail_row.android_posture_walk_error = err
                        fail_row.android_posture_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "android_posture_walk: inner runner failed for %s",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "android_posture_walk: unrecoverable outer failure for %s",
            firmware_id,
        )


# ---------------------------------------------------------------------------
# SAFE unpack-post-detection hook (Rule #39 — never raises).
# ---------------------------------------------------------------------------


async def auto_android_posture_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Auto-triggered post-detection hook (Rule #39 .safe contract).

    Owns own session. Runs the inner walker to populate the
    ``android_posture_walk_result`` JSONB so operators see the last-known
    result even on the first upload. DOES NOT mutate
    ``android_posture_walk_status`` — leaves it ``idle`` so an
    operator-triggered re-walk via ``trigger_android_posture_walk`` MCP tool
    works without a 409 conflict.

    ORDERING (Rule #47): order-independent of C1/C2/C3 — C4 reads no other
    walker's output (it synthesizes the posture straight from the APK / prop
    / XML tree). Registered near the android walkers in
    walker_registry.WALKER_AUTO_TRIGGERS.

    Swallows exceptions silently with structured ``logger.exception``.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                return
            try:
                result = await _do_android_posture_run(db, firmware_id)
                firmware.android_posture_walk_result = (
                    _stamp_firmware_android_posture_walk_result(result)
                )
                # No status flip per Rule #39 .safe.
                await db.commit()
            except Exception:
                await db.rollback()
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.android_posture_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "auto_android_posture_walk_firmware_safe: inner failed "
                    "for %s",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "auto_android_posture_walk_firmware_safe: unrecoverable for %s",
            firmware_id,
        )


__all__ = [
    "_do_android_posture_run",
    "auto_android_posture_walk_firmware_safe",
    "run_android_posture_walk_background",
]
