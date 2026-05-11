"""Service-layer tests for ``app.services.firmware_metadata_service``.

Phase 2 Wave 7 file 1 of 5 — backfills service-layer tests for the
firmware-image metadata extractor (481 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

The service parses raw firmware image bytes (binwalk scan, U-Boot uImage
header, U-Boot environment block, MTD partition tables) and caches the
result via ``app.services._cache`` against the firmware-wide cache key
(``binary_sha256 IS NULL``).

Rule #30 distribution (inverse-Rule-30 case per Wave 1 + Wave 6
exemplars): every dependency is imported at MODULE scope. Patches MUST
target the CONSUMER module (``app.services.firmware_metadata_service.X``),
not the SOURCE module — the consumer's local binding is what the function
body resolves at call time.

* ``from app.services import _cache`` — line 18, top-level. Patches must
  hit ``app.services.firmware_metadata_service._cache.get_cached`` /
  ``_cache.store_cached``. ``app.services._cache.X`` IS visible (it's the
  same module object) but the consumer-module binding is the canonical
  target per the Wave 6 inverse-Rule-30 documentation in
  ``test_pcap_analysis_service.py``.
* ``binwalk3`` is invoked via ``asyncio.create_subprocess_exec`` —
  patched on the consumer-module ``asyncio`` reference, same shape as
  ``test_jadx_service.py``'s subprocess discipline.

Coverage targets:

* ``_parse_size`` — '0x' hex, k/m/g multipliers, plain int, empty.
* ``_detect_uboot_header`` — magic at offset 0; magic at offset > 0 within
  256KB scan; no magic; truncated header; OSError. Validates the OS /
  architecture / image-type / compression maps reverse correctly.
* ``_extract_uboot_env`` — real env block with multiple known patterns;
  below density threshold (best_count < 3); empty file; invalid keys.
* ``_parse_mtd_partitions`` — single partition; size with multiplier;
  ``-(name)`` rest-of-device; multi-MTD ``;`` separator; absent
  ``mtdparts=``.
* ``_run_binwalk_scan`` — happy path (returncode 0 → parsed sections
  with computed sizes); ``FileNotFoundError`` (binwalk missing) → [];
  ``asyncio.TimeoutError`` → []; non-zero returncode → [].
* ``_to_cache`` / ``_from_cache`` — round-trip preserves all fields
  including None uboot_header.
* ``scan_firmware_image`` — cache HIT short-circuits (no parser fires);
  cache MISS runs all 4 parsers + persists.
* **Rule #35b live canary** — cache round-trip on a real SQLite session.
  First ``scan_firmware_image`` call persists an ``analysis_cache`` row
  with ``operation='firmware_metadata'`` and ``binary_sha256 IS NULL``
  (firmware-wide entry). The persisted ``result`` JSONB is stamped with
  ``schema_version`` per ``_stamp_analysis_cache_result``; assertions
  follow the triage-pattern-#4 pop-and-assert shape so a future
  schema bump fails loudly with a clear stamp-mismatch signal rather
  than a confusing structural diff.

Inverse-Rule-30 reference: ``test_assessment_service.py:200`` (original
Wave 1 documentation); ``test_pcap_analysis_service.py``
``TestRule30InverseConsumerPatch`` (Wave 6 generalisation).
"""
from __future__ import annotations

import struct
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.analysis_cache import AnalysisCache
from app.models.firmware import Firmware
from app.models.project import Project
from app.services import firmware_metadata_service as fms_mod
from app.services.firmware_metadata_service import (
    UBOOT_MAGIC,
    FirmwareImageMetadata,
    FirmwareMetadataService,
    FirmwareSection,
    MTDPartition,
    UBootHeader,
)
from app.services.jsonb_normalizers import ANALYSIS_CACHE_RESULT_SCHEMA_VERSION
from tests._live_db import make_live_db

# ===========================================================================
# _parse_size — pure static helper
# ===========================================================================


class TestParseSize:
    def test_plain_int(self):
        assert FirmwareMetadataService._parse_size("4096") == 4096

    def test_hex_lower(self):
        assert FirmwareMetadataService._parse_size("0x40000") == 0x40000

    def test_hex_upper(self):
        assert FirmwareMetadataService._parse_size("0X40000") == 0x40000

    def test_kilo_lower(self):
        assert FirmwareMetadataService._parse_size("256k") == 256 * 1024

    def test_kilo_upper(self):
        assert FirmwareMetadataService._parse_size("256K") == 256 * 1024

    def test_mega(self):
        assert FirmwareMetadataService._parse_size("4m") == 4 * 1024 * 1024

    def test_giga(self):
        assert FirmwareMetadataService._parse_size("2g") == 2 * 1024 * 1024 * 1024

    def test_empty_returns_zero(self):
        assert FirmwareMetadataService._parse_size("") == 0
        assert FirmwareMetadataService._parse_size("   ") == 0


# ===========================================================================
# _detect_uboot_header — sync struct unpack of 64-byte header
# ===========================================================================


def _build_uboot_header(
    *,
    name: str = "Linux Kernel",
    os_type: int = 5,    # Linux
    arch: int = 5,       # MIPS
    img_type: int = 2,   # Kernel
    compression: int = 3,  # lzma
    data_size: int = 0x100000,
    timestamp: int = 0x60000000,
    load_addr: int = 0x80000000,
    entry_point: int = 0x80000000,
    header_crc: int = 0xAABBCCDD,
    data_crc: int = 0x11223344,
) -> bytes:
    """Construct a valid 64-byte uImage header big-endian."""
    name_bytes = name.encode("ascii").ljust(32, b"\x00")[:32]
    return struct.pack(
        ">IIIIIIIBBBB",
        UBOOT_MAGIC, header_crc, timestamp, data_size,
        load_addr, entry_point, data_crc, os_type,
        arch, img_type, compression,
    ) + name_bytes


class TestDetectUbootHeader:
    def test_magic_at_offset_zero(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        header = _build_uboot_header()
        path.write_bytes(header)

        service = FirmwareMetadataService()
        result = service._detect_uboot_header(str(path))
        assert result is not None
        assert result.magic == "0x27051956"
        assert result.os_type == "Linux"
        assert result.architecture == "MIPS"
        assert result.image_type == "Kernel"
        assert result.compression == "lzma"
        assert result.name == "Linux Kernel"
        assert result.data_size == 0x100000
        assert result.timestamp == 0x60000000
        assert result.load_address == "0x80000000"
        assert result.entry_point == "0x80000000"
        assert result.header_crc == "0xAABBCCDD"
        assert result.data_crc == "0x11223344"

    def test_magic_at_nonzero_offset(self, tmp_path: Path):
        """Magic not at byte 0 — scan first 256KB finds it."""
        path = tmp_path / "fw.bin"
        prefix = b"\x00" * 4096
        header = _build_uboot_header(name="kernel-img")
        path.write_bytes(prefix + header + b"\x00" * 1024)

        service = FirmwareMetadataService()
        result = service._detect_uboot_header(str(path))
        assert result is not None
        assert result.name == "kernel-img"

    def test_no_magic_returns_none(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        # 256KB of non-matching bytes (all 0xFF — magic 0x27051956 won't appear).
        path.write_bytes(b"\xff" * (256 * 1024))

        service = FirmwareMetadataService()
        assert service._detect_uboot_header(str(path)) is None

    def test_truncated_first_read_returns_none(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        # <64 bytes — first read insufficient AND no magic at offset 0;
        # the 256KB rescan also can't find the magic in <64-byte file.
        path.write_bytes(b"short")

        service = FirmwareMetadataService()
        assert service._detect_uboot_header(str(path)) is None

    def test_oserror_returns_none(self):
        service = FirmwareMetadataService()
        # Path that doesn't exist.
        assert service._detect_uboot_header("/nonexistent/path/fw.bin") is None

    def test_unknown_codes_format_unknown_label(self, tmp_path: Path):
        """Unknown OS / arch / type / compression codes are reported as
        ``Unknown (N)`` rather than raising KeyError."""
        path = tmp_path / "fw.bin"
        path.write_bytes(_build_uboot_header(
            os_type=99, arch=99, img_type=99, compression=99,
        ))
        service = FirmwareMetadataService()
        result = service._detect_uboot_header(str(path))
        assert result is not None
        assert result.os_type == "Unknown (99)"
        assert result.architecture == "Unknown (99)"
        assert result.image_type == "Unknown (99)"
        assert result.compression == "Unknown (99)"


# ===========================================================================
# _extract_uboot_env — sync byte-pattern density scan
# ===========================================================================


def _build_env_block(entries: dict[str, str]) -> bytes:
    """Build a U-Boot env block: \\x00\\x00\\x00\\x00 CRC + key=value\\x00 pairs + \\x00\\x00 end."""
    body = b""
    for k, v in entries.items():
        body += f"{k}={v}".encode("ascii") + b"\x00"
    body += b"\x00"  # double-null end
    # 4-byte CRC + 1-byte flags placeholder.
    return b"\xde\xad\xbe\xef\x00" + body


class TestExtractUbootEnv:
    def test_parses_known_patterns(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        env = _build_env_block({
            "bootcmd": "bootm 0x80000000",
            "bootargs": "console=ttyS0,115200 root=/dev/mtdblock2",
            "bootdelay": "3",
            "ipaddr": "192.168.1.1",
            "ethaddr": "AA:BB:CC:DD:EE:FF",
        })
        # Pad with non-matching bytes around the env block.
        path.write_bytes(b"\xff" * 1024 + env + b"\xff" * 1024)

        service = FirmwareMetadataService()
        result = service._extract_uboot_env(str(path))
        assert result["bootcmd"] == "bootm 0x80000000"
        assert result["bootargs"] == "console=ttyS0,115200 root=/dev/mtdblock2"
        assert result["bootdelay"] == "3"
        assert result["ipaddr"] == "192.168.1.1"
        assert result["ethaddr"] == "AA:BB:CC:DD:EE:FF"

    def test_below_density_threshold_returns_empty(self, tmp_path: Path):
        """Single env pattern hit (< 3 in the 4KB window) → returns {}."""
        path = tmp_path / "fw.bin"
        # Only `bootcmd=` appears, no clustering.
        path.write_bytes(b"\xff" * 1024 + b"bootcmd=foo\x00" + b"\xff" * 1024)

        service = FirmwareMetadataService()
        assert service._extract_uboot_env(str(path)) == {}

    def test_no_env_patterns_returns_empty(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        path.write_bytes(b"\x00" * 4096)
        service = FirmwareMetadataService()
        assert service._extract_uboot_env(str(path)) == {}

    def test_oserror_returns_empty(self):
        service = FirmwareMetadataService()
        assert service._extract_uboot_env("/nonexistent/path/fw.bin") == {}

    def test_invalid_key_skipped(self, tmp_path: Path):
        """An entry whose key fails the alphanumeric regex is dropped, but
        valid entries in the same block survive."""
        path = tmp_path / "fw.bin"
        body = (
            b"bootcmd=run boot\x00"
            b"bootargs=console=ttyS0\x00"
            b"bootdelay=3\x00"
            b"baudrate=115200\x00"
            # Invalid: starts with digit.
            b"42=invalid\x00"
            # Invalid: contains hyphen.
            b"my-var=skipme\x00"
            b"\x00"
        )
        path.write_bytes(b"\xff" * 1024 + b"\xde\xad\xbe\xef" + body + b"\xff" * 1024)

        service = FirmwareMetadataService()
        result = service._extract_uboot_env(str(path))
        assert "bootcmd" in result
        assert "bootargs" in result
        assert "42" not in result
        assert "my-var" not in result


# ===========================================================================
# _parse_mtd_partitions — sync regex parser
# ===========================================================================


class TestParseMtdPartitions:
    def test_no_mtdparts_returns_empty(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        path.write_bytes(b"\xff" * 4096)
        service = FirmwareMetadataService()
        assert service._parse_mtd_partitions(str(path)) == []

    def test_single_partition_with_offset(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        path.write_bytes(b"\xff" * 1024 + b"mtdparts=mtd0:256k@0x40000(boot)\x00" + b"\xff" * 1024)

        service = FirmwareMetadataService()
        partitions = service._parse_mtd_partitions(str(path))
        assert len(partitions) == 1
        assert partitions[0].name == "boot"
        assert partitions[0].offset == 0x40000
        assert partitions[0].size == 256 * 1024

    def test_size_multipliers_kmg(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        path.write_bytes(
            b"mtdparts=mtd0:128k(uboot),4m(kernel),2g(rootfs)\x00",
        )
        service = FirmwareMetadataService()
        partitions = service._parse_mtd_partitions(str(path))
        assert len(partitions) == 3
        assert partitions[0].size == 128 * 1024
        assert partitions[1].size == 4 * 1024 * 1024
        assert partitions[2].size == 2 * 1024 * 1024 * 1024

    def test_rest_of_device_form(self, tmp_path: Path):
        """``-(name)`` means "rest of device" — size=0 sentinel."""
        path = tmp_path / "fw.bin"
        path.write_bytes(b"mtdparts=mtd0:256k(boot),-(rootfs)\x00")
        service = FirmwareMetadataService()
        partitions = service._parse_mtd_partitions(str(path))
        assert len(partitions) == 2
        assert partitions[1].name == "rootfs"
        assert partitions[1].offset is None
        assert partitions[1].size == 0  # sentinel

    def test_multi_mtd_devices_separated_by_semicolon(self, tmp_path: Path):
        """Two MTD devices: ``mtd0:...;mtd1:...`` — both parsed."""
        path = tmp_path / "fw.bin"
        path.write_bytes(
            b"mtdparts=mtd0:128k(boot),256k(env);mtd1:1m(data),2m(logs)\x00",
        )
        service = FirmwareMetadataService()
        partitions = service._parse_mtd_partitions(str(path))
        names = [p.name for p in partitions]
        assert names == ["boot", "env", "data", "logs"]

    def test_oserror_returns_empty(self):
        service = FirmwareMetadataService()
        assert service._parse_mtd_partitions("/nonexistent/path/fw.bin") == []


# ===========================================================================
# _run_binwalk_scan — async subprocess
# ===========================================================================


_BINWALK_OUTPUT = b"""\
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, header CRC: 0xAA
64            0x40            LZMA compressed data, properties: 0x5D
1048576       0x100000        Squashfs filesystem, little endian, version 4.0
"""


def _make_subprocess_mock(stdout: bytes = _BINWALK_OUTPUT, returncode: int = 0):
    """Build an awaitable that returns a mock proc with given output."""
    async def fake_create_subprocess_exec(*args, **kwargs):
        proc = MagicMock()
        proc.returncode = returncode
        proc.communicate = AsyncMock(return_value=(stdout, b""))
        proc.kill = MagicMock()
        return proc
    return fake_create_subprocess_exec


class TestRunBinwalkScan:
    @pytest.mark.asyncio
    async def test_happy_path_parses_three_sections(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        path.write_bytes(b"\x00" * (2 * 1024 * 1024))  # 2 MB so size math works

        # Inverse Rule #30 — `asyncio` is bound at module scope (line 7);
        # patch the CONSUMER-module reference, not stdlib `asyncio`.
        with patch.object(
            fms_mod.asyncio, "create_subprocess_exec",
            new=_make_subprocess_mock(),
        ):
            service = FirmwareMetadataService()
            sections = await service._run_binwalk_scan(str(path))

        assert len(sections) == 3
        assert sections[0].offset == 0
        assert sections[0].size == 64
        assert sections[0].type == "uImage header"
        assert sections[1].offset == 64
        assert sections[1].size == 0x100000 - 64
        assert sections[1].type == "LZMA compressed data"
        assert sections[2].offset == 0x100000
        # Last section: size = file_size - offset.
        assert sections[2].size == 2 * 1024 * 1024 - 0x100000
        assert sections[2].type == "Squashfs filesystem"

    @pytest.mark.asyncio
    async def test_binwalk_missing_returns_empty(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        path.write_bytes(b"\x00" * 1024)

        async def _raise_fnf(*args, **kwargs):
            raise FileNotFoundError("binwalk3 not in PATH")

        with patch.object(
            fms_mod.asyncio, "create_subprocess_exec", new=_raise_fnf,
        ):
            service = FirmwareMetadataService()
            sections = await service._run_binwalk_scan(str(path))
        assert sections == []

    @pytest.mark.asyncio
    async def test_subprocess_timeout_returns_empty(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        path.write_bytes(b"\x00" * 1024)

        async def _hanging_create(*args, **kwargs):
            proc = MagicMock()
            proc.returncode = None

            async def _hang():
                # Will be cancelled by wait_for timeout.
                import asyncio as _asyncio
                await _asyncio.sleep(10)

            proc.communicate = _hang
            proc.kill = MagicMock()
            return proc

        # Force wait_for to raise TimeoutError immediately by patching it.
        async def _raise_timeout(coro, timeout):  # noqa: ASYNC109 — test stub: signature-mirroring fake for asyncio.wait_for monkeypatch; timeout= must match upstream signature
            # Cancel the coroutine to satisfy the linter / avoid leaks.
            task = MagicMock()
            del task
            try:
                coro.close()
            except Exception:
                pass
            raise TimeoutError()

        with patch.object(
            fms_mod.asyncio, "create_subprocess_exec", new=_hanging_create,
        ), patch.object(
            fms_mod.asyncio, "wait_for", new=_raise_timeout,
        ):
            service = FirmwareMetadataService()
            sections = await service._run_binwalk_scan(str(path))
        assert sections == []

    @pytest.mark.asyncio
    async def test_nonzero_returncode_returns_empty(self, tmp_path: Path):
        path = tmp_path / "fw.bin"
        path.write_bytes(b"\x00" * 1024)

        with patch.object(
            fms_mod.asyncio, "create_subprocess_exec",
            new=_make_subprocess_mock(stdout=b"", returncode=1),
        ):
            service = FirmwareMetadataService()
            sections = await service._run_binwalk_scan(str(path))
        assert sections == []


# ===========================================================================
# _to_cache / _from_cache round-trip
# ===========================================================================


class TestCacheRoundTrip:
    def test_full_metadata_round_trip(self):
        original = FirmwareImageMetadata(
            file_size=4096,
            sections=[
                FirmwareSection(offset=0, size=64, type="uImage header", description="uImage header, header size: 64"),
                FirmwareSection(offset=64, size=4032, type="LZMA compressed data", description="LZMA compressed data"),
            ],
            uboot_header=UBootHeader(
                magic="0x27051956", header_crc="0xAABB", timestamp=0,
                data_size=0, load_address="0x0", entry_point="0x0",
                data_crc="0xCCDD", os_type="Linux", architecture="MIPS",
                image_type="Kernel", compression="lzma", name="kernel",
            ),
            uboot_env={"bootcmd": "run boot", "bootargs": "console=ttyS0"},
            mtd_partitions=[
                MTDPartition(name="boot", offset=0, size=128 * 1024),
                MTDPartition(name="rootfs", offset=None, size=0),
            ],
        )

        service = FirmwareMetadataService()
        as_dict = service._to_cache(original)
        # Sanity: dict is JSON-compatible (no dataclass instances).
        import json
        assert json.dumps(as_dict)  # would raise if not serialisable

        restored = service._from_cache(as_dict)
        assert restored.file_size == 4096
        assert len(restored.sections) == 2
        assert restored.sections[0].type == "uImage header"
        assert restored.uboot_header is not None
        assert restored.uboot_header.os_type == "Linux"
        assert restored.uboot_env["bootcmd"] == "run boot"
        assert restored.mtd_partitions[1].name == "rootfs"
        assert restored.mtd_partitions[1].offset is None

    def test_no_uboot_header_round_trip(self):
        original = FirmwareImageMetadata(file_size=1024)
        service = FirmwareMetadataService()
        restored = service._from_cache(service._to_cache(original))
        assert restored.uboot_header is None
        assert restored.sections == []
        assert restored.uboot_env == {}
        assert restored.mtd_partitions == []


# ===========================================================================
# scan_firmware_image — orchestrator with cache
# ===========================================================================


class TestScanFirmwareImageOrchestration:
    @pytest.mark.asyncio
    async def test_cache_hit_short_circuits_no_parsers(self, tmp_path: Path):
        """When ``_cache.get_cached`` returns a payload, none of the four
        parsers fires — the cached dict is reconstructed and returned."""
        fw_path = tmp_path / "fw.bin"
        fw_path.write_bytes(b"\x00" * 1024)

        cached_payload = {
            "file_size": 999,
            "sections": [{"offset": 0, "size": 64, "type": "X", "description": "X"}],
            "uboot_header": None,
            "uboot_env": {"bootcmd": "from-cache"},
            "mtd_partitions": [],
        }

        # Patch every parser to detect any unintended invocation.
        with patch.object(
            fms_mod._cache, "get_cached", new=AsyncMock(return_value=cached_payload),
        ), patch.object(
            FirmwareMetadataService, "_run_binwalk_scan",
            new=AsyncMock(side_effect=AssertionError("binwalk should NOT run on cache hit")),
        ), patch.object(
            FirmwareMetadataService, "_detect_uboot_header",
            side_effect=AssertionError("_detect_uboot_header should NOT run on cache hit"),
        ), patch.object(
            FirmwareMetadataService, "_extract_uboot_env",
            side_effect=AssertionError("_extract_uboot_env should NOT run on cache hit"),
        ), patch.object(
            FirmwareMetadataService, "_parse_mtd_partitions",
            side_effect=AssertionError("_parse_mtd_partitions should NOT run on cache hit"),
        ):
            db = AsyncMock()
            service = FirmwareMetadataService()
            result = await service.scan_firmware_image(
                firmware_storage_path=str(fw_path),
                firmware_id=uuid.uuid4(),
                db=db,
            )

        assert result.file_size == 999
        assert result.uboot_env == {"bootcmd": "from-cache"}
        assert len(result.sections) == 1


# ===========================================================================
# Rule #30 INVERSE-CONSUMER-PATCH discipline
# ===========================================================================


class TestRule30InverseConsumerPatch:
    """Rule #30 inverse case (per Wave 1 ``test_assessment_service.py:200``
    documentation + Wave 6 generalisation).

    ``firmware_metadata_service.py`` imports ``_cache`` at MODULE scope
    (line 18: ``from app.services import _cache``). Patches MUST hit the
    CONSUMER-module reference (``fms_mod._cache.get_cached``); patching
    the SOURCE module ``app.services._cache.get_cached`` AFTER the module
    has already imported the symbol would have NO effect on a name bound
    at module-load time IF the consumer module had bound a sub-attribute.
    Because Python modules are objects and ``from app.services import
    _cache`` binds the MODULE OBJECT ``_cache`` (not a single attribute),
    both patch targets in fact alias the same module — but the canonical
    discipline (per the campaign Decision Log) is to patch the consumer
    module's local binding.
    """

    @pytest.mark.asyncio
    async def test_cache_hit_via_consumer_module_patch(self, tmp_path: Path):
        """The CONSUMER-module patch target is the canonical shape."""
        fw_path = tmp_path / "fw.bin"
        fw_path.write_bytes(b"\x00" * 1024)

        cached = {
            "file_size": 1,
            "sections": [],
            "uboot_header": None,
            "uboot_env": {},
            "mtd_partitions": [],
        }

        # Patch on `fms_mod._cache.get_cached` — the consumer-module
        # binding. This is the canonical Wave 6 inverse-Rule-30 shape.
        with patch.object(
            fms_mod._cache, "get_cached", new=AsyncMock(return_value=cached),
        ):
            service = FirmwareMetadataService()
            result = await service.scan_firmware_image(
                firmware_storage_path=str(fw_path),
                firmware_id=uuid.uuid4(),
                db=AsyncMock(),
            )
        assert result.file_size == 1


# ===========================================================================
# Rule #35b LIVE-CANARY — full cache round-trip with stamped JSONB result
# ===========================================================================


class TestScanFirmwareImageLiveCanary:
    """Rule #35b live canary: real SQLite session + real ``analysis_cache``
    row + the ``_stamp_analysis_cache_result`` schema_version contract.

    The first ``scan_firmware_image`` call writes ONE cache row keyed by
    (firmware_id, operation='firmware_metadata', binary_sha256 IS NULL)
    via ``_cache.store_cached``, which stamps the result JSONB with
    ``schema_version`` per the audit-2026-05-04 boundary-normaliser
    sweep (Rule #35c).

    Assertions follow the triage-pattern-#4 pop-and-assert shape:
    pop ``schema_version``, assert it equals the current constant
    (forward-compatibility — a future bump fails LOUDLY rather than
    producing a confusing structural diff), then verify the
    writer-supplied payload survived the round-trip with all 5 fields
    intact (file_size, sections, uboot_header, uboot_env, mtd_partitions).

    Mock-only tests of ``mock_cache.store_cached.assert_called`` cannot
    fail on:
    * the stamp drift (the stamper is invoked inside
      ``_cache.store_cached`` — mocking it bypasses the contract);
    * the ``binary_sha256 IS NULL`` discriminator (a typo to
      ``binary_sha256=""`` would produce a stale per-binary row that
      coexists with the firmware-wide row, silently doubling cache
      storage);
    * the ``operation='firmware_metadata'`` literal.
    """

    @pytest.mark.asyncio
    async def test_first_scan_persists_stamped_cache_row(self, tmp_path: Path):
        # Real on-disk firmware shaped just enough to drive each parser.
        fw_path = tmp_path / "firmware.bin"
        # Pad the file out to ~64KB so size math is meaningful.
        prefix = b"\xff" * 1024
        # Embed a valid uImage header so _detect_uboot_header returns non-None.
        uboot = _build_uboot_header(name="canary-kernel")
        # Embed an env block (bootcmd + bootargs + bootdelay = 3 patterns,
        # enough to trip the density threshold).
        env = _build_env_block({
            "bootcmd": "bootm 0x80000000",
            "bootargs": "console=ttyS0",
            "bootdelay": "3",
            "ipaddr": "10.0.0.1",
        })
        # Embed an mtdparts= string.
        mtd = b"mtdparts=mtd0:128k(boot),256k(env),-(rootfs)\x00"
        body = prefix + uboot + b"\xff" * 512 + env + b"\xff" * 512 + mtd + b"\xff" * 8192
        fw_path.write_bytes(body)

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="metadata-canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="m" * 64,
            )
            db.add(firmware)
            await db.flush()
            await db.commit()

            # Stub binwalk3 so the test doesn't depend on the host tool.
            with patch.object(
                fms_mod.asyncio, "create_subprocess_exec",
                new=_make_subprocess_mock(),
            ):
                service = FirmwareMetadataService()
                metadata = await service.scan_firmware_image(
                    firmware_storage_path=str(fw_path),
                    firmware_id=firmware.id,
                    db=db,
                )
                await db.commit()

            # The returned dataclass shape.
            assert metadata.file_size == len(body)
            assert metadata.uboot_header is not None
            assert metadata.uboot_header.name == "canary-kernel"
            assert metadata.uboot_env["bootcmd"] == "bootm 0x80000000"
            assert any(p.name == "boot" for p in metadata.mtd_partitions)

            # Real SELECT — Rule #35b. The cache row is keyed by
            # (firmware_id, operation='firmware_metadata', binary_sha256 IS NULL).
            stmt = (
                select(AnalysisCache)
                .where(AnalysisCache.firmware_id == firmware.id)
                .where(AnalysisCache.operation == "firmware_metadata")
                .where(AnalysisCache.binary_sha256.is_(None))
            )
            row = (await db.execute(stmt)).scalar_one()
            assert row.binary_path is None  # firmware-wide entry, not per-binary

            # Triage pattern #4 pop-and-assert: schema_version stamp survives.
            persisted = dict(row.result)
            stamp = persisted.pop("schema_version")
            assert stamp == ANALYSIS_CACHE_RESULT_SCHEMA_VERSION, (
                f"schema_version stamp mismatch (expected "
                f"{ANALYSIS_CACHE_RESULT_SCHEMA_VERSION}, got {stamp}). "
                f"If the schema bumped, update the assertion + audit "
                f"consumers per Rule #35c."
            )

            # Writer-supplied payload survived the round-trip.
            assert persisted["file_size"] == len(body)
            assert isinstance(persisted["sections"], list)
            assert persisted["uboot_header"]["name"] == "canary-kernel"
            assert persisted["uboot_env"]["bootcmd"] == "bootm 0x80000000"
            mtd_names = [p["name"] for p in persisted["mtd_partitions"]]
            assert "boot" in mtd_names
            assert "rootfs" in mtd_names

    @pytest.mark.asyncio
    async def test_second_scan_hits_cache_no_subprocess_invocation(
        self, tmp_path: Path,
    ):
        """First call MISS → stores. Second call HIT → no subprocess call.

        The cache HIT contract is load-bearing: a regression where the
        cache key drifted (e.g. ``binary_sha256=""`` vs ``IS NULL``)
        would silently re-run the parsers on every request. The
        subprocess mock asserts call_count == 1 across the two calls.
        """
        fw_path = tmp_path / "firmware.bin"
        fw_path.write_bytes(b"\x00" * 1024)  # No uImage / env / mtd content.

        # Counting wrapper around the binwalk3 subprocess.
        call_count = 0

        async def counting_create_subprocess(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            proc = MagicMock()
            proc.returncode = 0
            proc.communicate = AsyncMock(return_value=(b"", b""))
            return proc

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="cache-hit-canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(), project_id=pid, sha256="c" * 64,
            )
            db.add(firmware)
            await db.flush()
            await db.commit()

            with patch.object(
                fms_mod.asyncio, "create_subprocess_exec",
                new=counting_create_subprocess,
            ):
                service = FirmwareMetadataService()
                # Cache MISS → all parsers run, cache row is stored.
                _ = await service.scan_firmware_image(
                    firmware_storage_path=str(fw_path),
                    firmware_id=firmware.id,
                    db=db,
                )
                await db.commit()
                assert call_count == 1, (
                    f"first scan should invoke binwalk3, got {call_count}"
                )

                # Cache HIT → no parser fires (call_count stays 1).
                _ = await service.scan_firmware_image(
                    firmware_storage_path=str(fw_path),
                    firmware_id=firmware.id,
                    db=db,
                )
                await db.commit()
                assert call_count == 1, (
                    f"second scan should HIT cache (call_count==1), got "
                    f"{call_count} — cache key may be drifting."
                )
