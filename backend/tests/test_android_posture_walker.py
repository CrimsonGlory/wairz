"""C4 Android DEPLOYMENT-POSTURE REACHABILITY-EVIDENCE walker tests (Rule #39
triplet + Rule #45/#46 parse-only canary + Rule #35b live canary + THE POSTURE
FIXTURES proving THE HONEST GATING).

THE HONEST GATING is the C4-defining contract: a static firmware IMAGE can
SUPPORT a lockdown (a DPC / kiosk / launcher app present, a telephony stack
present) but CANNOT confirm THIS unit is enrolled / active / SIM-provisioned —
that is provisioning + runtime. So the walker emits runtime_confirmed=FALSE
for EVERY image-inferred posture → the framework consumer (ALREADY BUILT)
HOLDS THE GATE OPEN (guilty, no reduction) and surfaces the settling_command.
Absence-in-an-extracted-partition is NOT proof of absence → an absent DPC
yields kiosk inferred-FALSE at config_inferred, NEVER runtime_confirmed.

Coverage axes:

* **Rule #39 triplet exports** — inner / outer / safe runners exported.
* **Rule #36 + Rule #45 no-execute + no-decrypt + Rule #46 paired
  META-CANARY** — token-scan over ``android_posture_walker.py`` asserting NO
  subprocess / dex-exec / APK-invoke / decrypt / eval / exec. Paired
  META-CANARY confirms the gate fires on a synthetic violation.
* **THE POSTURE FIXTURES (THE HONEST GATING):**
  - DPC-app-present → kiosk SUPPORTED (gates_open.kiosk=true) but
    runtime_confirmed=FALSE → gate held open + settling_command named.
  - no-DPC stock build → kiosk inferred-FALSE at config_inferred.
  - telephony-stack-present → cellular_active inferred-true,
    runtime_confirmed=FALSE.
  - non-Android firmware → platform=not_applicable no-op.
* **Rule #35b LIVE CANARY** — round-trip through the real ORM: run the inner
  runner against a fixture Android rootfs, commit, SELECT, assert the
  gates_open + runtime_confirmed=false + posture_confidence + settling_command
  survive the JSONB round-trip.
* **Stamp-helper-used** — source scan that the walker writes the JSONB only
  via ``_stamp_firmware_android_posture_walk_result``.
"""
from __future__ import annotations

import io
import re
import tokenize
import uuid
from pathlib import Path

import pytest

from app.services import android_posture_walker
from tests._live_db import make_live_db

# ───────────────────────────────────────────────────────────────────────
# Rule #39 triplet exports.
# ───────────────────────────────────────────────────────────────────────


def test_walker_triplet_exports_all_three_runners():
    assert hasattr(android_posture_walker, "_do_android_posture_run")
    assert hasattr(
        android_posture_walker, "run_android_posture_walk_background"
    )
    assert hasattr(
        android_posture_walker, "auto_android_posture_walk_firmware_safe"
    )


# ───────────────────────────────────────────────────────────────────────
# Rule #36 + Rule #45 no-execute / no-decrypt token-scan + Rule #46
# paired META-CANARY.
# ───────────────────────────────────────────────────────────────────────

_FORBIDDEN_PATTERNS: tuple[str, ...] = (
    r"\bsubprocess\s*\.\s*(?:Popen|run|call|check_output|check_call|getoutput)\s*\(",
    r"\basyncio\s*\.\s*create_subprocess_(?:exec|shell)\s*\(",
    r"\bos\s*\.\s*(?:system|execvp|execve|spawnvp|spawnv|spawnl)\s*\(",
    r"\brunpy\s*\.\s*run_(?:path|module)\s*\(",
    r"\bimportlib\s*\.\s*import_module\s*\(",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    # DEX / APK-invoke analog (Rule #45) — the walker reads dex/manifest AS
    # DATA; it never runs dex.
    r"\bAnalyzeAPK\s*\(\s*\)",  # bare-call form; APK() manifest parse is OK
    r"\.\s*run_dex\s*\(",
    # No-decrypt analog (Rule #45).
    r"\bCryptUnprotectData\s*\(",
    r"\.\s*decrypt\s*\(",
    r"\bcryptography\s*\.\s*fernet\b",
    r"\bCrypto\s*\.\s*Cipher\b",
)


def _tokens_stripped(src_bytes: bytes) -> str:
    """Tokenize; drop comment + string + structural tokens; join with single
    spaces (so ``subprocess.run`` appears as ``subprocess . run (``).
    Stripping STRING tokens means regex literals + error-message strings
    don't trigger; the gate fires only on actual calls."""
    tokens = list(tokenize.tokenize(io.BytesIO(src_bytes).readline))
    out: list[str] = []
    for tok in tokens:
        if tok.type in (
            tokenize.COMMENT,
            tokenize.STRING,
            tokenize.ENCODING,
            tokenize.NEWLINE,
            tokenize.NL,
            tokenize.INDENT,
            tokenize.DEDENT,
        ):
            continue
        if tok.string.strip():
            out.append(tok.string)
    return " ".join(out)


def test_walker_no_execute_no_decrypt():
    """Rule #36 + Rule #45 gate — token-scan over the walker asserts NO
    forbidden tokens. The walker reads build.prop / APK manifests / device_owner
    XML AS DATA; it NEVER executes dex / invokes an APK / spawns / decrypts.
    (Note: ``APK()`` — the manifest-only parse — is permitted; ``AnalyzeAPK``,
    which loads DEX, is NOT used by the walker.)"""
    src_path = Path(android_posture_walker.__file__)
    with open(src_path, "rb") as fh:
        src_repr = _tokens_stripped(fh.read())
    matches = [
        (p, m.group(0))
        for p in _FORBIDDEN_PATTERNS
        if (m := re.search(p, src_repr))
    ]
    assert not matches, (
        f"Rule #36 + Rule #45 no-execute / no-decrypt gate FIRED on "
        f"android_posture_walker — forbidden tokens: {matches!r}. The C4 "
        f"android-posture walker MUST be PARSE-ONLY (reads APK manifests / "
        f"build.prop / XML AS DATA; never executes dex / invokes an APK / "
        f"spawns / decrypts)."
    )


def test_walker_no_execute_gate_actually_fires():
    """Rule #46 paired META-CANARY — synthesize a forbidden-token violation
    IN MEMORY (concatenated string, NOT f-string — tokenize strips f-string
    contents) and confirm the gate WOULD reject it. Without this, the gate
    is a Rule #17 silent-pass instance."""
    synthetic_violation_lines = [
        "import subprocess",
        "result = subprocess.run(['am', 'start', '-n', 'pkg/.Activity'])",
        "import asyncio",
        "x = asyncio.create_subprocess_exec('dalvikvm')",
        "key.decrypt(ciphertext)",
    ]
    fake_src = "\n".join(synthetic_violation_lines).encode("utf-8")
    src_repr = _tokens_stripped(fake_src)
    matched = [p for p in _FORBIDDEN_PATTERNS if re.search(p, src_repr)]
    assert matched, (
        "Rule #46 paired META-CANARY FAILED — the no-execute/no-decrypt gate "
        "did NOT match a synthesized violation containing subprocess.run + "
        "asyncio.create_subprocess_exec + .decrypt(). The patterns are too "
        "narrow; the production scan would pass silently regardless of walker "
        "source. Tighten the regexes."
    )


# ───────────────────────────────────────────────────────────────────────
# Stamp-helper-used source scan.
# ───────────────────────────────────────────────────────────────────────


def test_walker_uses_jsonb_stamp_helper_not_direct_dict_assign():
    """The walker MUST write android_posture_walk_result only via
    _stamp_firmware_android_posture_walk_result (Rule #35c) or by clearing
    it to None (entry-clear + failure-clear)."""
    src = Path(android_posture_walker.__file__).read_text()
    assigns = re.findall(r"\.android_posture_walk_result\s*=\s*(.+)", src)
    assert assigns, "no android_posture_walk_result assignment found — unexpected"
    for rhs in assigns:
        rhs_stripped = rhs.strip()
        ok = (
            rhs_stripped == "None"
            or rhs_stripped.startswith("(")  # multiline stamp wrap
            or "_stamp_firmware_android_posture_walk_result" in rhs_stripped
        )
        assert ok, (
            f"android_posture_walk_result assigned from {rhs_stripped!r} — must "
            f"be either None (clear) or _stamp_firmware_android_posture_walk_"
            f"result(...) (Rule #35c stamp); never a raw dict literal."
        )
    # And the stamp helper IS referenced.
    assert "_stamp_firmware_android_posture_walk_result(" in src


# ───────────────────────────────────────────────────────────────────────
# THE POSTURE FIXTURES — THE HONEST GATING.
# ───────────────────────────────────────────────────────────────────────


def _android_buildprop(root, relpath="system/build.prop", extra=""):
    """Write a minimal Android build.prop so platform=android is detected."""
    p = root / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "ro.build.version.sdk=33\n"
        "ro.build.type=user\n"
        "ro.build.tags=release-keys\n"
        "ro.build.fingerprint=motorola/devon/devon:13/T1/abc:user/release-keys\n"
        + extra
    )


@pytest.mark.asyncio
async def test_dpc_present_kiosk_supported_but_runtime_unconfirmed(tmp_path):
    """FIXTURE 1 — a DPC app present → kiosk SUPPORTED (gates_open.kiosk=true)
    BUT runtime_confirmed=FALSE → the framework HOLDS THE GATE OPEN (guilty,
    no reduction) and the settling_command is named. THE HONEST GATING: the
    image proves a DPC CAN enforce a kiosk; it CANNOT prove THIS unit is
    enrolled (that is the live dumpsys device_policy capture)."""
    from app.models.firmware import Firmware

    root = tmp_path / "rootfs"
    _android_buildprop(root)
    # A recognised DPC vendor app (Workspace ONE) present in priv-app.
    (root / "system" / "priv-app" / "WorkspaceONE").mkdir(parents=True)
    (root / "system" / "priv-app" / "WorkspaceONE" / "WorkspaceONE.apk").write_bytes(b"PK\x03\x04stub")

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="a" * 64,
            original_filename="kiosk-tablet.zip",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await android_posture_walker._do_android_posture_run(
            db, firmware.id
        )

    assert result["platform"] == "android"
    assert result["gates_open"]["kiosk"] is True, (
        "a recognised DPC app present → kiosk SUPPORTED (inferred-true)."
    )
    # THE HONEST GATING — the image SUPPORTS but does not CONFIRM.
    assert result["runtime_confirmed"] is False, (
        "an image can SUPPORT a lockdown but NEVER confirm THIS unit is "
        "enrolled — runtime_confirmed MUST be false so the consumer holds the "
        "gate OPEN (guilty, no reduction)."
    )
    assert result["posture_confidence"] == "config_inferred"
    assert "WorkspaceONE" in " ".join(result["evidence"]["dpc_apps"]) or any(
        "workspaceone" in a.lower() for a in result["evidence"]["dpc_apps"]
    )
    # The settling capture is NAMED so the held-open gate is a RANKED evidence
    # request, not a dead end (spec L4-10).
    assert "dumpsys device_policy" in result["settling_command"]
    assert "dpm list-owners" in result["settling_command"]


@pytest.mark.asyncio
async def test_no_dpc_stock_build_kiosk_inferred_false_config_inferred(tmp_path):
    """FIXTURE 2 — a stock build with NO DPC app → kiosk inferred-FALSE at
    config_inferred. Absence-in-an-extracted-partition is NOT proof of
    absence (a DPC could live on a /data partition that was never imaged), so
    the negative is config_inferred, NEVER runtime_confirmed — the framework
    keeps the gate OPEN on the config_inferred negative."""
    from app.models.firmware import Firmware

    root = tmp_path / "rootfs"
    _android_buildprop(root)
    # A stock launcher (NOT a locked kiosk launcher) + a stock app — no DPC.
    (root / "system" / "app" / "LauncherConfig").mkdir(parents=True)
    (root / "system" / "app" / "Calculator").mkdir(parents=True)

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="b" * 64,
            original_filename="stock-phone.zip",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await android_posture_walker._do_android_posture_run(
            db, firmware.id
        )

    assert result["platform"] == "android"
    assert result["gates_open"]["kiosk"] is False, (
        "no DPC app present → kiosk inferred-FALSE."
    )
    assert result["posture_confidence"] == "config_inferred", (
        "the kiosk negative is INFERRED from the imaged partitions — "
        "config_inferred, never runtime_confirmed (absence-in-partition is "
        "NOT proof of absence)."
    )
    assert result["runtime_confirmed"] is False
    assert result["evidence"]["dpc_apps"] == []
    assert result["evidence"]["device_owner_xml_present"] is False


@pytest.mark.asyncio
async def test_telephony_present_cellular_inferred_true_runtime_unconfirmed(tmp_path):
    """FIXTURE 3 — a telephony stack present (RIL libs + carrier APK +
    ro.telephony prop) → cellular_active inferred-true, runtime_confirmed=FALSE.
    The modem ADJACENT surface stays OPEN; the SIM-provisioned state is the
    LIVE gap (the image proves the modem stack is BUILT, not that a SIM is
    inserted/provisioned)."""
    from app.models.firmware import Firmware

    root = tmp_path / "rootfs"
    _android_buildprop(root, extra="ro.telephony.default_network=33,33\n")
    # RIL libs (the strongest modem-built signal).
    (root / "system" / "lib64").mkdir(parents=True)
    (root / "system" / "lib64" / "libril.so").write_bytes(b"\x7fELFstub")
    (root / "system" / "lib64" / "librilutils.so").write_bytes(b"\x7fELFstub")
    # Carrier/SIM APKs.
    (root / "system" / "app" / "CarrierDefaultApp").mkdir(parents=True)
    (root / "system" / "priv-app" / "SimAppDialog").mkdir(parents=True)

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="c" * 64,
            original_filename="cellular-phone.zip",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await android_posture_walker._do_android_posture_run(
            db, firmware.id
        )

    assert result["platform"] == "android"
    assert result["gates_open"]["cellular_active"] is True, (
        "a telephony stack present → cellular_active inferred-true (the modem "
        "ADJACENT surface stays OPEN)."
    )
    assert result["runtime_confirmed"] is False, (
        "the image proves the modem stack is BUILT — NOT that a SIM is "
        "inserted/provisioned. The SIM-provisioned state is the LIVE gap; "
        "runtime_confirmed MUST be false."
    )
    assert result["evidence"]["telephony_present"] is True
    tele_ev = " ".join(result["evidence"]["telephony_evidence"]).lower()
    assert "libril" in tele_ev
    assert "carrierdefaultapp" in tele_ev or "simappdialog" in tele_ev


@pytest.mark.asyncio
async def test_non_android_firmware_is_not_applicable(tmp_path):
    """A non-Android firmware (a Linux rootfs with no APK dirs + no Android
    build.prop) → platform=not_applicable no-op. Guilty-safe: there is no
    Android posture to infer, and the framework's Android adapter never runs
    on it."""
    from app.models.firmware import Firmware

    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "os-release").write_text('NAME="OpenWrt"\n')
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "busybox").write_bytes(b"\x7fELFstub")

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="d" * 64,
            original_filename="openwrt.bin",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await android_posture_walker._do_android_posture_run(
            db, firmware.id
        )

    assert result["platform"] == "not_applicable"
    assert result["gates_open"] == {
        "cellular_active": False,
        "sideloading_allowed": False,
        "kiosk": False,
    }
    assert result["runtime_confirmed"] is False


@pytest.mark.asyncio
async def test_device_owner_xml_sets_kiosk_supported(tmp_path):
    """A /data/system/device_owner.xml present → kiosk SUPPORTED (a device
    owner IS provisioned in the image) BUT runtime_confirmed still FALSE (the
    image shows a device-owner descriptor; the live dumpsys is what confirms
    THIS unit's active enrollment)."""
    from app.models.firmware import Firmware

    root = tmp_path / "rootfs"
    _android_buildprop(root)
    (root / "data" / "system").mkdir(parents=True)
    (root / "data" / "system" / "device_owner.xml").write_text(
        '<?xml version="1.0"?><device-owner package="com.example.dpc" />'
    )

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="e" * 64,
            original_filename="managed.zip",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await android_posture_walker._do_android_posture_run(
            db, firmware.id
        )

    assert result["gates_open"]["kiosk"] is True
    assert result["evidence"]["device_owner_xml_present"] is True
    assert result["runtime_confirmed"] is False


# ───────────────────────────────────────────────────────────────────────
# Rule #35b LIVE CANARY — round-trip through the real ORM.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_live_canary_posture_round_trips_through_orm(tmp_path):
    """Run the inner runner against a fixture Android rootfs carrying a
    telephony stack + a stock build (no DPC). Round-trip through the ORM
    (stamp + commit + SELECT) and assert the gates_open + runtime_confirmed=
    false + posture_confidence + settling_command survive the JSONB
    round-trip. THE HONEST GATING is asserted on the persisted row."""
    from sqlalchemy import select

    from app.models.firmware import Firmware
    from app.services.jsonb_normalizers import (
        _stamp_firmware_android_posture_walk_result,
    )

    root = tmp_path / "rootfs"
    _android_buildprop(root, extra="ro.telephony.default_network=22\n")
    (root / "system" / "lib").mkdir(parents=True)
    (root / "system" / "lib" / "libril.so").write_bytes(b"\x7fELFstub")
    (root / "system" / "app" / "CarrierDefaultApp").mkdir(parents=True)

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="f" * 64,
            original_filename="phone.zip",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await android_posture_walker._do_android_posture_run(
            db, firmware.id
        )
        firmware.android_posture_walk_result = (
            _stamp_firmware_android_posture_walk_result(result)
        )
        await db.commit()

        reread = (
            await db.execute(select(Firmware).where(Firmware.id == firmware.id))
        ).scalar_one()
        walk = reread.android_posture_walk_result

    assert walk is not None
    assert walk["provenance"] == "walker"
    assert walk["schema_version"] == 1
    assert walk["platform"] == "android"
    # THE HONEST GATING survives the round-trip.
    assert walk["gates_open"]["cellular_active"] is True
    assert walk["gates_open"]["kiosk"] is False
    assert walk["runtime_confirmed"] is False, (
        "runtime_confirmed MUST round-trip as false — an image walk can never "
        "confirm enrollment / SIM; the consumer holds the gate OPEN."
    )
    assert walk["posture_confidence"] == "config_inferred"
    assert "dumpsys device_policy" in walk["settling_command"]


# ───────────────────────────────────────────────────────────────────────
# Empty / no-roots stable shape.
# (The Rule #47 registry-membership test lives in
# test_android_posture_walker_ordering.py — lands green in the Piece 5
# registration commit so each commit stays bisect-clean.)
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_walker_missing_firmware_returns_not_applicable():
    """A missing firmware row → stable not_applicable empty aggregate (never
    raises). runtime_confirmed false; gates all closed."""
    async with make_live_db() as db:
        result = await android_posture_walker._do_android_posture_run(
            db, uuid.uuid4()
        )
    assert result["platform"] == "not_applicable"
    assert result["runtime_confirmed"] is False
    assert result["gates_open"]["kiosk"] is False
