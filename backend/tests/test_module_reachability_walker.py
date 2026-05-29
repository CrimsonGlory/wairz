"""C2 module/driver REACHABILITY-EVIDENCE walker tests (Rule #39 triplet +
Rule #45/#46 parse-only canary + Rule #35b live canary + the KRACK-reducer
static-builtin regression).

Coverage axes:

* **Rule #39 triplet exports** — inner / outer / safe runners exported.
* **Rule #36 + Rule #45 no-execute + no-decrypt + Rule #46 paired
  META-CANARY** — token-scan over ``module_reachability_walker.py`` + the
  reused ``kmod.py`` parser asserting NO subprocess / insmod / modprobe /
  decrypt / eval / exec. Paired META-CANARY confirms the gate fires on a
  synthetic violation.
* **Rule #35b LIVE CANARY (modular)** — round-trip through the real ORM:
  run the inner runner against a fixture detection root carrying real ``.ko``
  files + a ``modules.builtin``, commit, SELECT, assert the 3-way diff
  (available / builtin / loaded=null) is populated.
* **KRACK-reducer static-builtin regression** — a static-builtin fixture
  (0 ``.ko`` on disk; ``bcmdhd`` in modules.builtin / =y config; ``mac80211``
  ABSENT from builtin) → assert ``static_builtin_posture is True`` +
  ``available == []`` + ``loaded is None`` + ``bcmdhd in builtin`` +
  ``mac80211 not in builtin``. This is the evidence the framework L4
  classifier consumes to route the WiFi-driver CVE to ``not_reachable``
  (the wairz side asserts the EVIDENCE shape; the framework repo asserts the
  VERDICT per R51.2 critique #5).
* **builtin_y_from_config** — C1's back-filled ``metadata.kernel_config``
  ``=y`` symbols feed ``builtin_y_from_config``.
* **Stamp-helper-used** — source scan that the walker writes the JSONB only
  via ``_stamp_firmware_module_reachability_walk_result``.
* **Empty / no-roots** — stable empty-aggregate shape.
"""
from __future__ import annotations

import io
import re
import tokenize
import uuid
from pathlib import Path

import pytest

from app.services import module_reachability_walker
from app.services.hardware_firmware.parsers import kmod
from tests._live_db import make_live_db

# ───────────────────────────────────────────────────────────────────────
# Rule #39 triplet exports.
# ───────────────────────────────────────────────────────────────────────


def test_walker_triplet_exports_all_three_runners():
    assert hasattr(module_reachability_walker, "_do_module_reachability_run")
    assert hasattr(
        module_reachability_walker, "run_module_reachability_walk_background"
    )
    assert hasattr(
        module_reachability_walker, "auto_module_reachability_walk_firmware_safe"
    )


# ───────────────────────────────────────────────────────────────────────
# Rule #36 + Rule #45 no-execute / no-decrypt token-scan + Rule #46
# paired META-CANARY (over the walker + the reused kmod parser).
# ───────────────────────────────────────────────────────────────────────

_FORBIDDEN_PATTERNS: tuple[str, ...] = (
    r"\bsubprocess\s*\.\s*(?:Popen|run|call|check_output|check_call|getoutput)\s*\(",
    r"\basyncio\s*\.\s*create_subprocess_(?:exec|shell)\s*\(",
    r"\bos\s*\.\s*(?:system|execvp|execve|spawnvp|spawnv|spawnl)\s*\(",
    r"\brunpy\s*\.\s*run_(?:path|module)\s*\(",
    r"\bimportlib\s*\.\s*import_module\s*\(",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    # No-decrypt analog (Rule #45).
    r"\bCryptUnprotectData\s*\(",
    r"\.\s*decrypt\s*\(",
    r"\bcryptography\s*\.\s*fernet\b",
    r"\bCrypto\s*\.\s*Cipher\b",
)

_SCANNED_MODULES = (
    module_reachability_walker,
    kmod,
)


def _tokens_stripped(src_bytes: bytes) -> str:
    """Tokenize; drop comment + string + structural tokens; join with single
    spaces (so ``subprocess.run`` appears as ``subprocess . run (``).
    Stripping STRING tokens means the ``insmod`` regex literal + error-message
    strings containing "decrypt" don't trigger; the gate fires only on actual
    calls."""
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
    """Rule #36 + Rule #45 gate — token-scan over the walker + the reused
    kmod parser asserts NO forbidden tokens. The walker reads ``.ko`` modinfo
    + the depmod text files AS DATA; it NEVER insmod/modprobe/spawns."""
    for module in _SCANNED_MODULES:
        src_path = Path(module.__file__)
        with open(src_path, "rb") as fh:
            src_repr = _tokens_stripped(fh.read())
        matches = [
            (p, m.group(0))
            for p in _FORBIDDEN_PATTERNS
            if (m := re.search(p, src_repr))
        ]
        assert not matches, (
            f"Rule #36 + Rule #45 no-execute / no-decrypt gate FIRED on "
            f"{module.__name__} — forbidden tokens: {matches!r}. The C2 "
            f"module-reachability walker MUST be PARSE-ONLY (reads modinfo + "
            f"depmod files AS DATA; never insmod/modprobe/spawns)."
        )


def test_walker_no_execute_gate_actually_fires():
    """Rule #46 paired META-CANARY — synthesize a forbidden-token violation
    IN MEMORY (concatenated string, NOT f-string — tokenize strips f-string
    contents) and confirm the gate WOULD reject it. Without this, the gate
    is a Rule #17 silent-pass instance."""
    synthetic_violation_lines = [
        "import subprocess",
        "result = subprocess.run(['insmod', 'foo.ko'])",
        "import asyncio",
        "x = asyncio.create_subprocess_exec('modprobe')",
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
    """The walker MUST write module_reachability_walk_result only via
    _stamp_firmware_module_reachability_walk_result (Rule #35c)."""
    src = Path(module_reachability_walker.__file__).read_text()
    assigns = re.findall(r"\.module_reachability_walk_result\s*=\s*(.+)", src)
    for rhs in assigns:
        rhs = rhs.strip()
        assert (
            rhs == "("
            or rhs.startswith("None")
            or "_stamp_firmware_module_reachability_walk_result" in src
        ), (
            f"module_reachability_walk_result assigned via {rhs!r} — must use "
            f"_stamp_firmware_module_reachability_walk_result or be a None-clear."
        )
    assert "_stamp_firmware_module_reachability_walk_result" in src


# ───────────────────────────────────────────────────────────────────────
# Synthetic fixture builders.
# ───────────────────────────────────────────────────────────────────────


def _build_minimal_elf_ko(*, signed: bool = False) -> bytes:
    """Build a MINIMAL but VALID 64-bit little-endian ELF so pyelftools'
    ``ELFFile`` parses it (the kmod parser early-returns signed='unknown' on
    an ELF parse failure, so a junk-ELF fixture can't exercise the signature
    path). No ``.modinfo`` section is needed — kmod records the module + still
    checks the appended-signature tail. When ``signed`` is True the CMS
    appendix magic is appended so ``_has_appended_signature`` flags it."""
    import struct

    # ELF64 header (64 bytes): e_ident + type/machine/version + entry/phoff/
    # shoff + flags + ehsize + phentsize/phnum + shentsize/shnum/shstrndx.
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # 64-bit, LE
    header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        1,        # e_type = ET_REL (a .ko is relocatable)
        0xB7,     # e_machine = AArch64
        1,        # e_version
        0,        # e_entry
        0,        # e_phoff
        0,        # e_shoff (no section headers — kmod handles "no .modinfo")
        0,        # e_flags
        64,       # e_ehsize
        0, 0,     # e_phentsize, e_phnum
        0, 0, 0,  # e_shentsize, e_shnum, e_shstrndx
    )
    body = header + b"\x00" * 256
    if signed:
        body += kmod._MODSIG_MAGIC
    return body


def _write_fake_ko(path: Path, *, signed: bool = False) -> None:
    """Write a minimal valid-ELF .ko fixture to ``path``."""
    path.write_bytes(_build_minimal_elf_ko(signed=signed))


# ───────────────────────────────────────────────────────────────────────
# Empty / no-roots smoke (against make_live_db).
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_walker_empty_firmware_returns_empty_aggregate():
    from app.models.firmware import Firmware

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="0" * 64,
            original_filename="empty.bin",
        )
        db.add(firmware)
        await db.flush()
        result = await module_reachability_walker._do_module_reachability_run(
            db, firmware.id
        )
        assert result["available"] == []
        assert result["available_count"] == 0
        assert result["builtin"] == []
        assert result["loaded"] is None
        assert result["kernel_posture"] == "not_applicable"
        assert result["static_builtin_posture"] is False
        assert any("detection_roots" in e for e in result["errors"])


# ───────────────────────────────────────────────────────────────────────
# Rule #35b LIVE CANARY — modular 3-way diff round-trip.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_live_canary_modular_three_way_diff(tmp_path):
    """Run the inner runner against a fixture detection root carrying real
    ``.ko`` files + a ``modules.builtin``. Round-trip through the ORM (stamp
    + commit + SELECT) and assert the 3-way diff is populated:
      - available[] carries the on-disk .ko names + sha256 + signed flag
      - builtin[] carries the modules.builtin names
      - loaded is None (live-only — static image has no loaded set)
      - kernel_posture == 'mixed' (both available AND builtin present)
      - provenance == 'walker' after the stamp.
    """
    from app.models.firmware import Firmware
    from app.services.jsonb_normalizers import (
        _stamp_firmware_module_reachability_walk_result,
    )

    root = tmp_path / "rootfs"
    mod_dir = root / "lib" / "modules" / "5.10.0"
    mod_dir.mkdir(parents=True)
    # AVAILABLE set: two .ko (one signed).
    _write_fake_ko(mod_dir / "ath9k.ko", signed=True)
    _write_fake_ko(mod_dir / "usbcore.ko.xz", signed=False)
    # A symlink that must NOT double-count.
    try:
        (mod_dir / "ath9k_alias.ko").symlink_to(mod_dir / "ath9k.ko")
    except OSError:
        pass
    # BUILTIN set via modules.builtin.
    (mod_dir / "modules.builtin").write_text(
        "kernel/fs/ext4/ext4.ko\nkernel/net/mac80211/mac80211.ko\n"
    )
    # Configured-to-load: /etc/modules + modules-load.d.
    (root / "etc").mkdir()
    (root / "etc" / "modules").write_text("# header\nath9k\n")

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="a" * 64,
            original_filename="router.bin",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()

        result = await module_reachability_walker._do_module_reachability_run(
            db, firmware.id
        )
        firmware.module_reachability_walk_result = (
            _stamp_firmware_module_reachability_walk_result(result)
        )
        await db.commit()

        from sqlalchemy import select

        reread = (
            await db.execute(select(Firmware).where(Firmware.id == firmware.id))
        ).scalar_one()
        walk = reread.module_reachability_walk_result
        assert walk is not None
        assert walk["provenance"] == "walker"
        assert walk["schema_version"] == 1

        # AVAILABLE: ath9k + usbcore (the symlink did NOT double-count).
        avail_names = sorted(m["name"] for m in walk["available"])
        assert avail_names == ["ath9k", "usbcore"], (
            f"available set wrong: {avail_names!r} (symlink double-count or "
            f"suffix-strip bug?)"
        )
        ath9k = next(m for m in walk["available"] if m["name"] == "ath9k")
        assert ath9k["signed"] is True, "kmod should have flagged ath9k signed"
        assert ath9k["sha256"] and len(ath9k["sha256"]) == 64
        usbcore = next(m for m in walk["available"] if m["name"] == "usbcore")
        assert usbcore["signed"] is False

        # BUILTIN: ext4 + mac80211.
        assert sorted(walk["builtin"]) == ["ext4", "mac80211"]
        assert walk["builtin_count"] == 2

        # LOADED is null (live-only).
        assert walk["loaded"] is None

        # CONFIGURED-TO-LOAD picked up ath9k from /etc/modules.
        assert "ath9k" in walk["configured_to_load"]

        # POSTURE: both available AND builtin → mixed (NOT static_builtin).
        assert walk["kernel_posture"] == "mixed"
        assert walk["static_builtin_posture"] is False


# ───────────────────────────────────────────────────────────────────────
# KRACK-reducer static-builtin regression (the headline behavioral claim).
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_static_builtin_posture_krack_reducer(tmp_path):
    """The KRACK-reducer evidence regression. A static-builtin fixture:
      - 0 ``.ko`` on disk (monolithic Android-style kernel)
      - ``bcmdhd`` BUILT-IN (via modules.builtin) — the FullMAC WiFi driver
      - ``mac80211`` ABSENT from the builtin set — softMAC stack NOT built

    Assert the EVIDENCE shape the framework L4 classifier consumes to route
    the WiFi-driver CVE to ``not_reachable`` (R51.2 critique #5 — wairz
    asserts the evidence, the framework asserts the verdict):
      - static_builtin_posture is True
      - available == [] (0 modular .ko)
      - loaded is None
      - bcmdhd in builtin AND mac80211 NOT in builtin.
    """
    from app.models.firmware import Firmware
    from app.services.jsonb_normalizers import (
        _stamp_firmware_module_reachability_walk_result,
    )

    root = tmp_path / "rootfs"
    mod_dir = root / "lib" / "modules" / "4.19.157-perf"
    mod_dir.mkdir(parents=True)
    # NO .ko files — only the builtin manifest (Android boot.img kernel ships
    # one even though the kernel body is monolithic). bcmdhd built-in;
    # mac80211 absent.
    (mod_dir / "modules.builtin").write_text(
        "kernel/fs/ext4/ext4.ko\n"
        "kernel/drivers/net/wireless/bcmdhd/bcmdhd.ko\n"
    )

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="b" * 64,
            original_filename="phone.zip",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()

        result = await module_reachability_walker._do_module_reachability_run(
            db, firmware.id
        )
        firmware.module_reachability_walk_result = (
            _stamp_firmware_module_reachability_walk_result(result)
        )
        await db.commit()

        from sqlalchemy import select

        reread = (
            await db.execute(select(Firmware).where(Firmware.id == firmware.id))
        ).scalar_one()
        walk = reread.module_reachability_walk_result

        assert walk["static_builtin_posture"] is True, (
            "KRACK-reducer: 0 .ko on disk + bcmdhd built-in MUST yield "
            "static_builtin_posture=True — the framework reads this to know "
            "the BUILTIN set is the reachability axis (no module diff)."
        )
        assert walk["kernel_posture"] == "static_builtin"
        assert walk["available"] == [], "static-builtin image has 0 modular .ko"
        assert walk["loaded"] is None
        # The load-bearing KRACK evidence:
        assert "bcmdhd" in walk["builtin"], (
            "FullMAC driver bcmdhd MUST appear in the builtin set"
        )
        assert "mac80211" not in walk["builtin"], (
            "softMAC stack mac80211 MUST be ABSENT from the builtin set — "
            "this is the evidence that lets the L4 classifier declare the "
            "FullMAC compound-immutable negative → not_reachable."
        )


# ───────────────────────────────────────────────────────────────────────
# builtin_y_from_config — C1's back-filled kernel_config feeds the =y axis.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_builtin_y_from_c1_kernel_config(tmp_path):
    """A blob carrying C1's back-filled metadata.kernel_config with =y driver
    symbols → those symbols surface in builtin_y_from_config, AND a firmware
    with 0 .ko on disk but =y config is static_builtin (the phone case where
    no modules.builtin extracted to disk but C1 recovered the .config)."""
    from app.models.firmware import Firmware
    from app.models.hardware_firmware import HardwareFirmwareBlob
    from app.services.jsonb_normalizers import (
        _stamp_firmware_module_reachability_walk_result,
    )

    root = tmp_path / "rootfs"
    root.mkdir()  # no .ko, no modules.builtin on disk

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="c" * 64,
            original_filename="phone2.zip",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()

        blob = HardwareFirmwareBlob(
            firmware_id=firmware.id,
            blob_path=str(root / "boot.img"),
            blob_sha256="d" * 64,
            file_size=1024,
            category="kernel_module",
            format="raw_bin",
            detection_source="content_rescan",
            metadata_={
                "schema_version": 1,
                "kernel_config": {
                    "CONFIG_BCMDHD": "y",
                    "CONFIG_MAC80211": "n",
                    "CONFIG_EXT4_FS": "y",
                },
            },
        )
        db.add(blob)
        await db.flush()

        result = await module_reachability_walker._do_module_reachability_run(
            db, firmware.id
        )
        firmware.module_reachability_walk_result = (
            _stamp_firmware_module_reachability_walk_result(result)
        )
        await db.commit()

        from sqlalchemy import select

        reread = (
            await db.execute(select(Firmware).where(Firmware.id == firmware.id))
        ).scalar_one()
        walk = reread.module_reachability_walk_result

        # =y symbols surfaced; =n excluded.
        assert "CONFIG_BCMDHD" in walk["builtin_y_from_config"]
        assert "CONFIG_EXT4_FS" in walk["builtin_y_from_config"]
        assert "CONFIG_MAC80211" not in walk["builtin_y_from_config"]
        # 0 .ko on disk + =y config → static_builtin posture.
        assert walk["available_count"] == 0
        assert walk["static_builtin_posture"] is True
        assert walk["kernel_posture"] == "static_builtin"


# ───────────────────────────────────────────────────────────────────────
# Posture classifier unit table.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "available,builtin,builtin_y,expected_posture,expected_static",
    [
        (0, 0, 0, "not_applicable", False),   # RTOS / non-Linux blob
        (0, 2, 0, "static_builtin", True),    # phone: modules.builtin only
        (0, 0, 5, "static_builtin", True),    # phone: =y config only
        (10, 0, 0, "modular", False),         # classic modular Linux
        (10, 3, 0, "mixed", False),           # some modular, some built-in
    ],
)
def test_classify_posture_table(
    available, builtin, builtin_y, expected_posture, expected_static
):
    posture, static = module_reachability_walker._classify_posture(
        available, builtin, builtin_y
    )
    assert posture == expected_posture
    assert static is expected_static


# ───────────────────────────────────────────────────────────────────────
# Rule #47 — registry registration + ordering (C2 fires AFTER C1).
# ───────────────────────────────────────────────────────────────────────


def test_c2_runner_registered_in_walker_auto_triggers():
    """The C2 safe-runner MUST be registered in WALKER_AUTO_TRIGGERS — else
    it never auto-fires post-detection and module_reachability_walk_status
    stays 'idle' forever (Rule #47 orphan-state trap, the exact 847eae9
    consumer-orphan failure mode)."""
    from app.workers.walker_registry import get_walker_auto_triggers

    runners = get_walker_auto_triggers()
    assert (
        module_reachability_walker.auto_module_reachability_walk_firmware_safe
        in runners
    ), (
        "auto_module_reachability_walk_firmware_safe is NOT registered in "
        "WALKER_AUTO_TRIGGERS — the C2 walker will never auto-fire "
        "post-detection (Rule #47 orphan-state trap)."
    )


def test_c2_runner_fires_after_c1_kernel_config():
    """Rule #47 consumer-hook ordering — C2 reads C1's back-filled
    metadata.kernel_config for the builtin_y_from_config axis, so C2's index
    MUST be > C1's auto_kernel_config_walk_firmware_safe index in the
    sequentially-dispatched registry list."""
    from app.services import kernel_config_walker
    from app.workers.walker_registry import get_walker_auto_triggers

    runners = get_walker_auto_triggers()
    c1_idx = runners.index(
        kernel_config_walker.auto_kernel_config_walk_firmware_safe
    )
    c2_idx = runners.index(
        module_reachability_walker.auto_module_reachability_walk_firmware_safe
    )
    assert c2_idx > c1_idx, (
        f"C2 module-reachability runner (index {c2_idx}) MUST fire AFTER the "
        f"C1 kernel_config extraction runner (index {c1_idx}) so C1's "
        f"metadata.kernel_config back-fill precedes C2's "
        f"builtin_y_from_config read. Move the C2 runner BELOW "
        f"auto_kernel_config_walk_firmware_safe in WALKER_AUTO_TRIGGERS."
    )
