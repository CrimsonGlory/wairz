"""C1 kernel-config EXTRACTION walker tests (Rule #39 triplet + Rule #45/#46
parse-only canary + Rule #35b live canary + the Stage-A auto-fire-fix
isolated canary).

Coverage axes:

* **Rule #39 triplet exports** — inner / outer / safe runners exported.
* **Rule #36 + Rule #45 no-execute + no-decrypt + Rule #46 paired
  META-CANARY** — token-scan over ``kernel_config_walker.py`` + the 3
  parser/decompress modules asserting NO subprocess / decrypt / eval /
  exec. Paired META-CANARY confirms the gate fires on a synthetic.
* **Rule #35b LIVE CANARY** — round-trip through the real ORM: run the
  inner runner against a fixture detection root carrying a real IKCFG
  kernel, commit, SELECT, assert config_entries > 0 + provenance + the
  originating blob's metadata.kernel_config was back-filled AND a
  PRE-EXISTING blob metadata key SURVIVES the back-fill (R50.2 B2).
* **Stage-A auto-fire-fix ISOLATED canary** — a synthetic ZIP containing a
  boot.img with an embedded IKCFG'd kernel where the on-disk carved chunk
  is header-only; assert the walker re-extracts from the ZIP and produces
  config_entries > 0 (the headline behavioral claim — NOT a @realdata
  test that skips when the 2.97 GB blob is absent).
* **Stage-F banner-only degrade** — a vmlinux with a banner but NO IKCFG →
  ``fallback_banner_only``, no back-fill.
* **Empty / no-roots** — stable empty-aggregate shape.
* **Stamp-helper-used** — source scan that the walker writes the JSONB
  only via ``_stamp_firmware_kernel_config_walk_result``.
* **Ordering** — C1 runner index < audit runner index in
  get_walker_auto_triggers() (the back-fill must precede the audit read).
"""
from __future__ import annotations

import gzip
import io
import os
import re
import struct
import tokenize
import uuid
import zipfile
from pathlib import Path

import pytest

from app.services import kernel_config_walker
from app.services.hardware_firmware.parsers import (
    _kernel_ikconfig,
    android_boot_image,
    android_ota_payload,
)
from app.services import kernel_decompress
from tests._live_db import make_live_db

# ───────────────────────────────────────────────────────────────────────
# Rule #39 triplet exports.
# ───────────────────────────────────────────────────────────────────────


def test_walker_triplet_exports_all_three_runners():
    assert hasattr(kernel_config_walker, "_do_kernel_config_run")
    assert hasattr(kernel_config_walker, "run_kernel_config_walk_background")
    assert hasattr(kernel_config_walker, "auto_kernel_config_walk_firmware_safe")


# ───────────────────────────────────────────────────────────────────────
# Rule #36 + Rule #45 no-execute / no-decrypt token-scan + Rule #46
# paired META-CANARY (over ALL 4 new modules).
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
    kernel_config_walker,
    kernel_decompress,
    android_boot_image,
    android_ota_payload,
)


def _tokens_stripped(src_bytes: bytes) -> str:
    """Tokenize; drop comment + string + structural tokens; join with
    single spaces (so ``subprocess.run`` appears as ``subprocess . run (``).
    Stripping STRING tokens means string literals containing "decrypt" in
    error messages don't trigger; the gate fires only on actual calls.
    """
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
    """Rule #36 + Rule #45 gate — token-scan over the walker + the 3
    parser/decompress modules asserts NO forbidden tokens."""
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
            f"{module.__name__} — forbidden tokens: {matches!r}. The C1 "
            f"extraction walker MUST be PARSE-ONLY (reads/decompresses the "
            f"kernel AS DATA; never spawns)."
        )


def test_walker_no_execute_gate_actually_fires():
    """Rule #46 paired META-CANARY — synthesize a forbidden-token violation
    IN MEMORY (concatenated string, NOT f-string — tokenize strips
    f-string contents) and confirm the gate WOULD reject it. Without this,
    the gate is a Rule #17 silent-pass instance."""
    synthetic_violation_lines = [
        "import subprocess",
        "result = subprocess.run(['true'])",
        "import asyncio",
        "x = asyncio.create_subprocess_exec('cat')",
        "key.decrypt(ciphertext)",
    ]
    fake_src = "\n".join(synthetic_violation_lines).encode("utf-8")
    src_repr = _tokens_stripped(fake_src)
    matched = [p for p in _FORBIDDEN_PATTERNS if re.search(p, src_repr)]
    assert matched, (
        "Rule #46 paired META-CANARY FAILED — the no-execute/no-decrypt "
        "gate did NOT match a synthesized violation containing "
        "subprocess.run + asyncio.create_subprocess_exec + .decrypt(). "
        "The patterns are too narrow; the production scan would pass "
        "silently regardless of walker source. Tighten the regexes."
    )


# ───────────────────────────────────────────────────────────────────────
# Stamp-helper-used source scan.
# ───────────────────────────────────────────────────────────────────────


def test_walker_uses_jsonb_stamp_helper_not_direct_dict_assign():
    """The walker MUST write kernel_config_walk_result only via
    _stamp_firmware_kernel_config_walk_result (Rule #35c)."""
    src = Path(kernel_config_walker.__file__).read_text()
    # Every assignment to kernel_config_walk_result that's NOT a None-clear
    # must go through the stamp helper.
    assigns = re.findall(
        r"\.kernel_config_walk_result\s*=\s*(.+)", src
    )
    for rhs in assigns:
        rhs = rhs.strip()
        assert rhs == "(" or rhs.startswith("None") or "_stamp_firmware_kernel_config_walk_result" in src, (
            f"kernel_config_walk_result assigned via {rhs!r} — must use "
            f"_stamp_firmware_kernel_config_walk_result or be a None-clear."
        )
    assert "_stamp_firmware_kernel_config_walk_result" in src


# ───────────────────────────────────────────────────────────────────────
# Synthetic fixture builders (shared with the extraction tests' shape).
# ───────────────────────────────────────────────────────────────────────

# Key signals the assertions check + ~600 filler entries so the gzip
# payload + the resulting on-disk gzipped kernel comfortably exceed the
# walker's _MIN_CANDIDATE_SIZE = 512-byte floor (a real .config is
# 100-300 kB; the floor is honest for production — we just make the
# synthetic fixture realistically sized rather than lowering the floor).
_SAMPLE_CONFIG = (
    "CONFIG_DEVMEM=y\n"
    "CONFIG_WLAN=y\n"
    "CONFIG_MAC80211=n\n"
    "CONFIG_CLD_LL_CORE=y\n"
    "# CONFIG_TIPC is not set\n"
    'CONFIG_LOCALVERSION="-perf"\n'
) + "".join(f"CONFIG_FILLER_SYMBOL_{i}=y\n" for i in range(600))


def _build_ikconfig_vmlinux(config_text: str) -> bytes:
    inner = io.BytesIO()
    with gzip.GzipFile(fileobj=inner, mode="wb") as gz:
        gz.write(config_text.encode())
    gz_payload = inner.getvalue()
    banner = b"Linux version 4.19.157-perf+ (nobody@android-build) #1 SMP\x00"
    return (
        b"\x00" * 64
        + banner
        + b"\x00" * 64
        + _kernel_ikconfig.IKCFG_ST
        + gz_payload
        + _kernel_ikconfig.IKCFG_ED
        + b"\x00" * 32
    )


def _build_gzipped_kernel(vmlinux: bytes) -> bytes:
    """gzip-compress a vmlinux (the outer kernel envelope — phone shape)."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(vmlinux)
    return buf.getvalue()


def _build_boot_image_v3(kernel_bytes: bytes) -> bytes:
    hdr = bytearray(4096)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<I", hdr, 12, len(kernel_bytes))
    struct.pack_into("<I", hdr, 40, 3)
    return bytes(hdr) + kernel_bytes


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
        result = await kernel_config_walker._do_kernel_config_run(db, firmware.id)
        assert result["kernels"] == []
        assert result["kernels_found_count"] == 0
        assert result["kernels_extracted_count"] == 0
        assert any("detection_roots" in e for e in result["errors"])


# ───────────────────────────────────────────────────────────────────────
# Rule #35b LIVE CANARY — value-flow + metadata-survival (R50.2 B2).
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_live_canary_recovers_config_and_backfills_blob_preserving_keys(tmp_path):
    """Run the inner runner against a fixture detection root carrying a real
    IKCFG kernel (a bare gzipped vmlinux on disk). Assert:
      1. kernel_config_walk_result["kernels"][0]["config_entries"] > 0
      2. provenance == "walker" after the stamp (via outer/safe path proxy)
      3. the originating HardwareFirmwareBlob.metadata.kernel_config was
         back-filled
      4. a PRE-EXISTING blob metadata key SURVIVES the back-fill (the
         read-modify-write proof — R50.2 B2; the mock can't verify this).
    """
    from app.models.firmware import Firmware
    from app.models.hardware_firmware import HardwareFirmwareBlob
    from app.services.jsonb_normalizers import (
        _stamp_firmware_kernel_config_walk_result,
    )

    # A gzipped vmlinux written directly into the detection root, named so
    # it matches NO classifier filename pattern (proves content-rescan).
    root = tmp_path / "rootfs"
    root.mkdir()
    kernel_path = root / "0-4096.unknown"  # carved-chunk-style name
    gzipped = _build_gzipped_kernel(_build_ikconfig_vmlinux(_SAMPLE_CONFIG))
    kernel_path.write_bytes(gzipped)

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="a" * 64,
            original_filename="phone.zip",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()

        # A blob row whose blob_path == the kernel file, carrying a
        # PRE-EXISTING metadata key (kernel_banner) that MUST survive.
        blob = HardwareFirmwareBlob(
            firmware_id=firmware.id,
            blob_path=str(kernel_path),
            blob_sha256="b" * 64,
            file_size=len(gzipped),
            category="kernel_module",
            format="raw_bin",
            detection_source="content_rescan",
            metadata_={
                "kernel_banner": "PRE-EXISTING BANNER must survive",
                "vendor_specific_key": "do not clobber me",
                "schema_version": 1,
            },
        )
        db.add(blob)
        await db.flush()

        result = await kernel_config_walker._do_kernel_config_run(db, firmware.id)
        # Stamp + persist like the outer runner does.
        firmware.kernel_config_walk_result = (
            _stamp_firmware_kernel_config_walk_result(result)
        )
        await db.commit()

        # 1 + 2 — SELECT the firmware row back; value-flow + provenance.
        from sqlalchemy import select

        reread_fw = (
            await db.execute(select(Firmware).where(Firmware.id == firmware.id))
        ).scalar_one()
        walk_result = reread_fw.kernel_config_walk_result
        assert walk_result is not None
        assert walk_result["provenance"] == "walker"
        assert walk_result["schema_version"] == 1
        assert walk_result["kernels_extracted_count"] >= 1
        first = walk_result["kernels"][0]
        assert first["config_entries"] > 0, (
            "live canary: inner runner did NOT recover a non-empty config "
            "from the on-disk gzipped IKCFG kernel — the content-rescan + "
            "Stage-D decompress + Stage-E IKCFG chain is broken."
        )
        assert first["kernel_config"].get("CONFIG_DEVMEM") == "y"
        assert first["kernel_config"].get("CONFIG_MAC80211") == "n"

        # 3 + 4 — SELECT the blob row; back-fill happened AND pre-existing
        # keys survived (the read-modify-write proof — mocks can't catch
        # this; cf. Rule #35b confidence-bypass lesson).
        reread_blob = (
            await db.execute(
                select(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.id == blob.id
                )
            )
        ).scalar_one()
        meta = reread_blob.metadata_
        assert isinstance(meta, dict)
        assert "kernel_config" in meta, (
            "back-fill FAILED — blob.metadata.kernel_config not written; "
            "the downstream kernel_config_audit walker would still audit "
            "nothing."
        )
        assert meta["kernel_config"].get("CONFIG_DEVMEM") == "y"
        # THE metadata-survival assertion (R50.2 B2):
        assert meta.get("kernel_banner") == "PRE-EXISTING BANNER must survive", (
            "R50.2 B2 VIOLATION — the back-fill CLOBBERED the pre-existing "
            "kernel_banner key. The back-fill MUST be read-modify-write: "
            "read via _normalize_hardware_firmware_blobs_metadata, set "
            "kernel_config, reassign the whole attribute. A fresh-dict stamp "
            "destroys every other parser-populated key."
        )
        assert meta.get("vendor_specific_key") == "do not clobber me", (
            "R50.2 B2 VIOLATION — vendor_specific_key clobbered."
        )
        assert walk_result["kernels"][0]["back_filled_blob_id"] == str(blob.id)


# ───────────────────────────────────────────────────────────────────────
# Stage-A AUTO-FIRE-FIX isolated canary (the headline behavioral claim).
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stage_a_autofire_reextracts_boot_img_from_zip(tmp_path):
    """THE auto-fire-fix canary. A synthetic ZIP at firmware.storage_path
    contains a boot.img with an embedded IKCFG'd kernel; the on-disk
    detection root has only a HEADER-ONLY carved chunk (the phone case
    where unblob consumed the kernel body). Assert _do_kernel_config_run
    re-extracts boot.img from the ZIP and recovers config_entries > 0.

    This is the single most important behavioral claim of C1 (phone
    firmware that had 0 kernel blobs now produces config) — and it runs in
    isolation, NOT as a @realdata test that skips when the 2.97 GB blob is
    absent."""
    from app.models.firmware import Firmware

    # 1. Build a REAL boot.img-with-kernel (gzip-wrapped IKCFG vmlinux).
    vmlinux = _build_ikconfig_vmlinux(_SAMPLE_CONFIG)
    gzipped_kernel = _build_gzipped_kernel(vmlinux)
    full_boot_img = _build_boot_image_v3(gzipped_kernel)

    # 2. Write it into a ZIP at storage_path (the original upload).
    zip_path = tmp_path / "Moto-G32.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("Moto-G32-XT2235-1/boot.img", full_boot_img)
        zf.writestr("Moto-G32-XT2235-1/system.img", b"\x00" * 4096)  # decoy

    # 3. The detection root holds ONLY a header-only carved chunk — the
    # ANDROID! header + kernel_size field, but NO kernel body (unblob
    # consumed it). carve_kernel(header_only) returns None → re-extract.
    root = tmp_path / "boot.img_extract"
    root.mkdir()
    header_only = full_boot_img[:4096]  # just the boot header page
    (root / "0-4096.unknown").write_bytes(header_only)

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="c" * 64,
            original_filename="Moto-G32.zip",
            storage_path=str(zip_path),
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()

        result = await kernel_config_walker._do_kernel_config_run(db, firmware.id)

        # The header-only chunk triggered the Stage-A ZIP re-extract.
        assert result["kernels_extracted_count"] >= 1, (
            f"Stage-A auto-fire-fix FAILED — no kernel extracted. The "
            f"header-only carved chunk should have triggered the boot.img "
            f"re-extract from storage_path ZIP. errors={result['errors']!r}"
        )
        recovered = next(
            (k for k in result["kernels"] if k["extraction_status"] == "ok"), None
        )
        assert recovered is not None
        assert recovered["source"] == "reextracted_upload", (
            f"expected source='reextracted_upload' (proves the ZIP path "
            f"fired), got {recovered['source']!r}"
        )
        assert recovered["config_entries"] > 0
        assert recovered["kernel_config"].get("CONFIG_DEVMEM") == "y"
        assert recovered["compression"] == "gzip"


@pytest.mark.asyncio
async def test_stage_a_degrades_to_live_device_when_no_zip(tmp_path):
    """When the carved chunk is header-only AND storage_path is not a ZIP
    (or is gone), the walker degrades to live_device_recommended — NOT a
    crash (R50.2 gate: degrade gracefully)."""
    from app.models.firmware import Firmware

    vmlinux = _build_ikconfig_vmlinux(_SAMPLE_CONFIG)
    full_boot_img = _build_boot_image_v3(_build_gzipped_kernel(vmlinux))
    root = tmp_path / "boot.img_extract"
    root.mkdir()
    (root / "0-4096.unknown").write_bytes(full_boot_img[:4096])

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="d" * 64,
            original_filename="gone.tar",
            storage_path=str(tmp_path / "nonexistent.tar"),  # not a ZIP / gone
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await kernel_config_walker._do_kernel_config_run(db, firmware.id)
        # No crash; the boot candidate degraded to live_device_recommended.
        assert any(
            k["extraction_status"] == "live_device_recommended"
            for k in result["kernels"]
        ), f"expected a live_device_recommended record, got {result['kernels']!r}"


# ───────────────────────────────────────────────────────────────────────
# Stage-F banner-only degrade (the MODAL production case — R50.2 S5).
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stage_f_banner_only_degrades_no_backfill(tmp_path):
    """A bare vmlinux with a banner but NO IKCFG_ST → extraction_status
    'fallback_banner_only' + kernel_semver populated + kernel_config empty
    + NO blob back-fill (nothing to write). This is the modal production
    outcome (most kernels strip IKCFG) and must degrade cleanly."""
    from app.models.firmware import Firmware

    # vmlinux with a banner but NO IKCFG markers.
    banner = b"Linux version 5.10.110-generic (build@host) #1 SMP\x00"
    bare_vmlinux = b"\x00" * 1024 + banner + b"\x00" * 1024
    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "vmlinux.bin").write_bytes(bare_vmlinux)

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="e" * 64,
            original_filename="banner_only.bin",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await kernel_config_walker._do_kernel_config_run(db, firmware.id)
        banner_kernel = next(
            (
                k
                for k in result["kernels"]
                if k["extraction_status"] == "fallback_banner_only"
            ),
            None,
        )
        assert banner_kernel is not None, (
            f"expected a fallback_banner_only kernel, got {result['kernels']!r}"
        )
        assert banner_kernel["kernel_semver"] == "5.10.110"
        assert banner_kernel["kernel_config"] == {}
        assert banner_kernel["ikconfig_present"] is False
        assert banner_kernel["back_filled_blob_id"] is None
        assert result["kernels_extracted_count"] == 0


# ───────────────────────────────────────────────────────────────────────
# BLOCKED-path structural finding emit (kernel_config_extraction_blocked).
# ───────────────────────────────────────────────────────────────────────


def _build_crau_ff12d941_payload() -> bytes:
    """A CrAU v2 payload.bin whose boot partition uses a non-standard op
    (op type 13, simulating the ff12d941 proprietary block) → BLOCKED."""

    def varint(v: int) -> bytes:
        out = bytearray()
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                out.append(b | 0x80)
            else:
                out.append(b)
                return bytes(out)

    def tag(fn: int, wt: int) -> bytes:
        return varint((fn << 3) | wt)

    def ld(fn: int, payload: bytes) -> bytes:
        return tag(fn, 2) + varint(len(payload)) + payload

    install_op = tag(1, 0) + varint(13)  # InstallOperation.type = 13
    part = ld(1, b"boot") + ld(8, install_op)
    manifest = ld(13, part)
    header = b"CrAU" + struct.pack(">Q", 2) + struct.pack(">Q", len(manifest)) + struct.pack(">I", 0)
    payload = header + manifest
    # Pad above the _MIN_CANDIDATE_SIZE floor.
    return payload + b"\x00" * (1024 - len(payload) if len(payload) < 1024 else 0)


@pytest.mark.asyncio
async def test_blocked_payload_emits_extraction_blocked_finding(tmp_path):
    """A payload.bin with an ff12d941 boot op → extraction_status='blocked'
    AND a kernel_config_extraction_blocked INFO Finding is emitted (the
    honest BLOCKED verdict surfaces to the operator, not a silent no-op)."""
    from app.models.finding import Finding
    from app.models.firmware import Firmware
    from sqlalchemy import select

    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "payload.bin").write_bytes(_build_crau_ff12d941_payload())

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="f" * 64,
            original_filename="tablet_ota.zip",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()

        result = await kernel_config_walker._do_kernel_config_run(db, firmware.id)
        await db.commit()

        assert result["kernels_blocked_count"] >= 1, (
            f"expected a blocked kernel, got {result['kernels']!r}"
        )
        blocked = next(
            (k for k in result["kernels"] if k["extraction_status"] == "blocked"), None
        )
        assert blocked is not None
        assert blocked["blocked_reason"] == "ff12d941_proprietary_block"
        assert result["findings_emitted_count"] >= 1

        # The Finding row was persisted with the new source (proves the
        # cross-stack alignment — the DB CHECK accepts the value).
        findings = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware.id)
            )
        ).scalars().all()
        sources = {f.source for f in findings}
        assert "kernel_config_extraction_blocked" in sources, (
            f"expected a kernel_config_extraction_blocked Finding, got "
            f"sources={sources!r}"
        )
