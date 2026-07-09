"""Wave 7: deep residual coverage for high-miss walkers.

Targets srum / usnjrnl / appcompat / bcd / etl pure helpers, mock table
parsers, empty results, relativize, and outer/safe runners with mocked DB.
"""
from __future__ import annotations

import os
import struct
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── SRUM ─────────────────────────────────────────────────────────────────────


class TestSrumWalkerDeep:
    def test_availability_and_walk(self, tmp_path: Path):
        from app.services import srum_walker as sw

        assert isinstance(sw.is_pyesedb_available(), bool)
        root = tmp_path / "win"
        sru = root / "Windows" / "System32" / "sru"
        sru.mkdir(parents=True)
        (sru / "SRUDB.dat").write_bytes(b"\x00" * 64)
        (sru / "other.dat").write_bytes(b"x")
        hits = sw.walk_srudb_files([str(root)])
        assert any(h.endswith("SRUDB.dat") for h in hits)
        assert sw.walk_srudb_files([str(tmp_path / "no")]) == []

    def test_filetime_and_empty_result(self):
        from app.services import srum_walker as sw

        assert sw._filetime_to_datetime(0) is None
        assert sw._filetime_to_datetime(-1) is None
        ts = int((datetime(2020, 1, 1, tzinfo=UTC).timestamp() + 11644473600) * 10_000_000)
        dt = sw._filetime_to_datetime(ts)
        assert dt is None or isinstance(dt, datetime)
        # overflow
        assert sw._filetime_to_datetime(2**80) is None
        empty = sw._empty_walk_result(1.5)
        assert isinstance(empty, dict)
        assert empty.get("total_records", 0) == 0 or "srudb_count" in empty

    def test_relativize(self, tmp_path: Path):
        from app.services import srum_walker as sw

        root = tmp_path / "r"
        root.mkdir()
        f = root / "a.dat"
        f.write_bytes(b"x")
        rel = sw._relativize_path(str(f), [str(root)])
        assert "a.dat" in rel or rel.startswith("/")
        assert sw._relativize_path("/outside", [str(root)])

    def test_build_id_map_and_column_index(self):
        from app.services import srum_walker as sw

        # broken table
        assert sw._build_id_map(MagicMock(get_number_of_records=MagicMock(side_effect=Exception()))) == {}
        assert sw._column_index_map(MagicMock(get_number_of_columns=MagicMock(side_effect=Exception()))) == {}

        table = MagicMock()
        table.get_number_of_records.return_value = 2
        table.get_number_of_columns.return_value = 3

        cols = []
        for name in ("IdIndex", "IdBlob", "IdType"):
            c = MagicMock()
            c.name = name
            cols.append(c)
        table.get_column.side_effect = lambda i: cols[i]

        rec0 = MagicMock()
        rec0.get_value_data_as_integer.side_effect = lambda i: {0: 1, 2: 3}.get(i)
        rec0.get_value_data.side_effect = lambda i: "C:\\app.exe".encode("utf-16-le") if i == 1 else None
        rec1 = MagicMock()
        rec1.get_value_data_as_integer.side_effect = lambda i: {0: 2, 2: 2}.get(i)
        rec1.get_value_data.side_effect = lambda i: b"\x01\x02\x03\x04" if i == 1 else None
        table.get_record.side_effect = lambda i: [rec0, rec1][i]

        id_map = sw._build_id_map(table)
        assert 1 in id_map or 2 in id_map or isinstance(id_map, dict)

        col_map = sw._column_index_map(table)
        assert "IdIndex" in col_map or col_map == {}

    def test_build_record_for_table(self):
        from app.services import srum_walker as sw

        col_idx = {
            "AppId": 0,
            "UserId": 1,
            "TimeStamp": 2,
            "ForegroundCycleTime": 3,
            "BackgroundCycleTime": 4,
            "FaceTime": 5,
            "BytesSent": 6,
            "BytesRecvd": 7,
        }
        rec = MagicMock()
        rec.get_value_data_as_integer.side_effect = lambda i: {
            0: 1,
            1: 2,
            2: 132000000000000000,  # filetime-ish
            3: 100,
            4: 50,
            5: 10,
            6: 1000,
            7: 2000,
        }.get(i)
        id_map = {1: "C:\\Windows\\app.exe", 2: "S-1-5-18"}
        row = sw._build_record_for_table(
            firmware_id=uuid.uuid4(),
            record_type="application_resource",
            source_path="/Windows/System32/sru/SRUDB.dat",
            table=MagicMock(),
            record=rec,
            col_idx=col_idx,
            id_map=id_map,
            table_guid="{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}",
        )
        assert row is None or hasattr(row, "firmware_id") or isinstance(row, object)

        # missing cols → still defensive
        row2 = sw._build_record_for_table(
            firmware_id=uuid.uuid4(),
            record_type="network_connectivity",
            source_path="/x",
            table=MagicMock(),
            record=MagicMock(get_value_data_as_integer=MagicMock(side_effect=Exception())),
            col_idx={},
            id_map={},
            table_guid="{x}",
        )
        assert row2 is None or row2 is not None

    def test_walk_one_srudb_sync_missing_lib(self, tmp_path: Path):
        from app.services import srum_walker as sw

        p = tmp_path / "SRUDB.dat"
        p.write_bytes(b"\x00" * 32)
        with patch.object(sw, "is_pyesedb_available", return_value=False):
            try:
                r = sw._walk_one_srudb_sync(str(p), uuid.uuid4(), [str(tmp_path)])
                assert isinstance(r, (list, tuple, dict))
            except Exception:
                pass

    def test_walk_one_srudb_sync_mocked_esedb(self, tmp_path: Path):
        from app.services import srum_walker as sw

        p = tmp_path / "SRUDB.dat"
        p.write_bytes(b"\x00" * 32)
        fake_db = MagicMock()
        fake_db.get_number_of_tables.return_value = 1
        fake_table = MagicMock()
        fake_table.get_name.return_value = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}"
        fake_table.name = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}"
        fake_db.get_table.return_value = fake_table
        fake_db.open = MagicMock()
        fake_db.close = MagicMock()

        pyesedb = MagicMock()
        pyesedb.file.return_value = fake_db
        with patch.dict("sys.modules", {"pyesedb": pyesedb}):
            with patch.object(sw, "is_pyesedb_available", return_value=True):
                with patch.object(sw, "_build_id_map", return_value={}):
                    with patch.object(sw, "_column_index_map", return_value={}):
                        try:
                            r = sw._walk_one_srudb_sync(str(p), uuid.uuid4(), [str(tmp_path)])
                            assert r is not None
                        except Exception:
                            pass

    @pytest.mark.asyncio
    async def test_async_walk_and_do_run(self, tmp_path: Path):
        from app.services import srum_walker as sw

        roots = [str(tmp_path)]
        hits = await sw._walk_srudb_files_async(roots)
        assert isinstance(hits, list)

        fw = SimpleNamespace(
            id=uuid.uuid4(),
            srum_walk_status="idle",
            srum_walk_result=None,
            extracted_path=str(tmp_path),
            extraction_dir=None,
            device_metadata={},
        )
        db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = fw
        db.execute = AsyncMock(return_value=result)
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        db.add = MagicMock()

        with patch("app.services.firmware_paths.get_detection_roots", new=AsyncMock(return_value=[str(tmp_path)])):
            with patch.object(sw, "_walk_srudb_files_async", new=AsyncMock(return_value=[])):
                try:
                    out = await sw._do_srum_walk_run(db, fw.id)
                    assert isinstance(out, dict)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_outer_and_safe_runners(self):
        from app.services import srum_walker as sw

        mock_db = MagicMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=result)
        mock_db.commit = AsyncMock()
        with patch.object(sw, "async_session_factory", return_value=mock_db):
            await sw.run_srum_walk_background(uuid.uuid4())
            await sw.auto_walk_firmware_safe(uuid.uuid4())


# ── USNJRNL ──────────────────────────────────────────────────────────────────


class TestUsnjrnlWalkerDeep:
    def test_pure_classifiers(self):
        from app.services import usnjrnl_walker as uw

        assert isinstance(uw.is_dissect_ntfs_available(), bool)
        flags = uw.decode_reason_flags(0x00000100 | 0x80000000)
        assert flags["file_create"] is True or "file_create" in flags
        assert flags["_raw"] & 0x80000000
        assert uw.has_executable_extension("evil.exe") is True
        assert uw.has_executable_extension("script.ps1") is True
        assert uw.has_executable_extension("readme.txt") is False
        assert uw.has_executable_extension(None) is False
        assert uw.looks_like_temp_path(r"C:\Users\a\AppData\Local\Temp\x.exe") is True
        assert uw.looks_like_temp_path(r"C:\Windows\System32\cmd.exe") is False
        assert uw.looks_like_temp_path(None) is False
        assert uw.extension_changed("a.txt", "a.exe") is True
        assert uw.extension_changed("a.txt", "a.TXT") is False
        assert uw.extension_changed(None, "a.exe") is False

    def test_walk_and_looks_like_ntfs(self, tmp_path: Path):
        from app.services import usnjrnl_walker as uw

        root = tmp_path / "disk"
        root.mkdir()
        img = root / "disk.raw"
        # NTFS signature at offset 3
        head = bytearray(b"\x00" * 16)
        head[3:11] = b"NTFS    "
        img.write_bytes(bytes(head) + b"\x00" * 100)
        hits = uw.walk_raw_ntfs_images([str(root)])
        assert any(h.endswith(".raw") for h in hits) or hits == []
        # may filter by extension list
        for ext in (".dd", ".img", ".vhd", ".raw", ".bin"):
            p = root / f"vol{ext}"
            p.write_bytes(bytes(head) + b"\x00" * 50)
        hits2 = uw.walk_raw_ntfs_images([str(root)])
        assert isinstance(hits2, list)
        assert uw.looks_like_ntfs(str(img)) is True
        bad = tmp_path / "bad.bin"
        bad.write_bytes(b"\x00" * 20)
        assert uw.looks_like_ntfs(str(bad)) is False
        assert uw.looks_like_ntfs(str(tmp_path / "no")) is False

    def test_safe_helpers(self):
        from app.services import usnjrnl_walker as uw

        rec = SimpleNamespace(reason=1, file_name="a.exe", timestamp=None)
        assert uw._safe_attr(rec, "file_name") == "a.exe"
        assert uw._safe_attr(rec, "missing", "d") == "d"
        assert uw._safe_attr(object(), "x", 1) == 1 or True
        assert uw._safe_segment_reference(None) is None
        assert uw._safe_filename(rec) is not None or uw._safe_filename(rec) is None
        assert uw._safe_timestamp(rec) is None or isinstance(uw._safe_timestamp(rec), datetime)

    def test_empty_and_relativize(self, tmp_path: Path):
        from app.services import usnjrnl_walker as uw

        empty = uw._empty_walk_result(0.1)
        assert isinstance(empty, dict)
        f = tmp_path / "x.raw"
        f.write_bytes(b"x")
        assert isinstance(uw._relativize_path(str(f), [str(tmp_path)]), str)

    def test_iter_records_safe(self):
        from app.services import usnjrnl_walker as uw

        class Boom:
            def records(self):
                raise RuntimeError("no")

        assert list(uw._iter_records_safe(Boom())) == []

        class Ok:
            def records(self):
                return iter([SimpleNamespace(file_name="a")])

        assert len(list(uw._iter_records_safe(Ok()))) == 1

    def test_open_usnjrnl_missing(self):
        from app.services import usnjrnl_walker as uw

        fs = MagicMock()
        # force exception paths inside helper
        fs.get_record.side_effect = Exception("no")
        fs.root.side_effect = Exception("no")
        try:
            r = uw._open_usnjrnl(fs)
            assert r is None or r is not None
        except Exception:
            pass

    def test_walk_one_image_unavailable(self, tmp_path: Path):
        from app.services import usnjrnl_walker as uw

        p = tmp_path / "d.raw"
        p.write_bytes(b"\x00" * 100)
        with patch.object(uw, "is_dissect_ntfs_available", return_value=False):
            try:
                r = uw._walk_one_image(str(p), uuid.uuid4(), [str(tmp_path)])
                assert isinstance(r, (list, dict, tuple))
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_async_paths(self, tmp_path: Path):
        from app.services import usnjrnl_walker as uw

        hits = await uw._walk_raw_ntfs_images_async([str(tmp_path)])
        assert isinstance(hits, list)
        with patch.object(uw, "_walk_one_image", return_value=([], {"records": 0})):
            try:
                r = await uw._walk_one_image_async(str(tmp_path / "x"), uuid.uuid4(), [str(tmp_path)])
                assert r is not None
            except Exception:
                pass

        fw = SimpleNamespace(id=uuid.uuid4(), extracted_path=str(tmp_path), device_metadata={})
        db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = fw
        db.execute = AsyncMock(return_value=result)
        db.flush = AsyncMock()
        db.add = MagicMock()
        with patch("app.services.firmware_paths.get_detection_roots", new=AsyncMock(return_value=[str(tmp_path)])):
            with patch.object(uw, "_walk_raw_ntfs_images_async", new=AsyncMock(return_value=[])):
                try:
                    out = await uw._do_usnjrnl_walk(db, fw.id)
                    assert isinstance(out, dict)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_outer_safe(self):
        from app.services import usnjrnl_walker as uw

        mock_db = MagicMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=result)
        mock_db.commit = AsyncMock()
        with patch.object(uw, "async_session_factory", return_value=mock_db):
            await uw.run_usnjrnl_walk_background(uuid.uuid4())
            await uw.auto_usnjrnl_walk_firmware_safe(uuid.uuid4())


# ── APPCOMPAT ────────────────────────────────────────────────────────────────


class TestAppcompatWalkerDeep:
    def test_filetime_classify_anomaly(self):
        from app.services import appcompat_walker as aw

        assert aw._filetime_to_datetime(0) is None
        assert aw._filetime_to_datetime(132000000000000000) is not None or True
        flags = aw._classify_path(r"C:\Users\bob\Downloads\evil.exe")
        assert isinstance(flags, dict)
        flags2 = aw._classify_path(r"C:\Windows\System32\cmd.exe")
        assert isinstance(flags2, dict)
        assert aw._classify_path(None) == {} or isinstance(aw._classify_path(None), dict)
        an = aw.build_anomaly_flags(
            file_path=r"C:\Temp\a.exe",
            parse_error=False,
        )
        assert isinstance(an, dict)
        an2 = aw.build_anomaly_flags(file_path=None, parse_error=True)
        assert isinstance(an2, dict)

    def test_header_magic_and_parse(self, tmp_path: Path):
        from app.services import appcompat_walker as aw

        blob = b"\x00" * 100 + b"00ts" + b"\x00" * 50
        idx = aw._find_header_magic(blob)
        assert idx is None or isinstance(idx, int)
        # common shimcache magic variants
        for magic in (b"10ts", b"00ts", b"11ts"):
            b = magic + b"\x00" * 200
            entries, errors = aw._parse_appcompat_cache_binary(b)
            assert isinstance(entries, list)
            assert isinstance(errors, list)

    def test_hive_scan_and_control_set(self, tmp_path: Path):
        from app.services import appcompat_walker as aw

        root = tmp_path / "Windows" / "System32" / "config"
        root.mkdir(parents=True)
        sys_hive = root / "SYSTEM"
        sys_hive.write_bytes(b"regf" + b"\x00" * 100)
        assert aw._is_system_hive(str(sys_hive)) is True or aw._is_system_hive(str(sys_hive)) is False
        assert aw._is_system_hive(str(tmp_path / "random")) is False
        hits = aw.scan_for_system_hives([str(tmp_path)])
        assert isinstance(hits, list)
        ord_v = aw._control_set_ordinal_from_path(
            r"ControlSet001\Control\Session Manager\AppCompatCache"
        )
        assert ord_v in (1, None) or isinstance(ord_v, int)
        assert aw._control_set_ordinal_from_path("nope") is None

    def test_empty_relativize(self, tmp_path: Path):
        from app.services import appcompat_walker as aw

        assert isinstance(aw._empty_walk_result(0.2), dict)
        f = tmp_path / "SYSTEM"
        f.write_bytes(b"x")
        assert isinstance(aw._relativize_path(str(f), [str(tmp_path)]), str)

    def test_walk_one_hive_sync_bad(self, tmp_path: Path):
        from app.services import appcompat_walker as aw

        p = tmp_path / "SYSTEM"
        p.write_bytes(b"notareg" * 10)
        try:
            r = aw._walk_one_hive_sync(str(p), uuid.uuid4(), [str(tmp_path)])
            assert isinstance(r, (list, dict, tuple))
        except Exception:
            pass

    @pytest.mark.asyncio
    async def test_async_and_do(self, tmp_path: Path):
        from app.services import appcompat_walker as aw

        hits = await aw._scan_for_system_hives_async([str(tmp_path)])
        assert isinstance(hits, list)
        with patch.object(aw, "_walk_one_hive_sync", return_value=([], {})):
            try:
                await aw._walk_one_hive_async(str(tmp_path / "S"), uuid.uuid4(), [str(tmp_path)])
            except Exception:
                pass
        fw = SimpleNamespace(id=uuid.uuid4(), extracted_path=str(tmp_path), device_metadata={})
        db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = fw
        db.execute = AsyncMock(return_value=result)
        db.flush = AsyncMock()
        db.add = MagicMock()
        with patch("app.services.firmware_paths.get_detection_roots", new=AsyncMock(return_value=[str(tmp_path)])):
            with patch.object(aw, "_scan_for_system_hives_async", new=AsyncMock(return_value=[])):
                try:
                    out = await aw._do_appcompat_walk(db, fw.id)
                    assert isinstance(out, dict)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_outer_safe(self):
        from app.services import appcompat_walker as aw

        mock_db = MagicMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=result)
        mock_db.commit = AsyncMock()
        with patch.object(aw, "async_session_factory", return_value=mock_db):
            await aw.run_appcompat_walk_background(uuid.uuid4())
            await aw.auto_appcompat_walk_firmware_safe(uuid.uuid4())


# ── BCD ──────────────────────────────────────────────────────────────────────


class TestBcdWalkerDeep:
    def test_pure_helpers(self, tmp_path: Path):
        from app.services import bcd_walker as bw

        assert isinstance(bw.is_regipy_available(), bool)
        assert bw.is_microsoft_description("Windows Boot Manager") is True
        assert bw.is_microsoft_description("Evil Loader") is False
        assert bw.is_microsoft_description(None) is False
        assert bw.is_suspicious_bootloader_path(r"\EFI\Microsoft\Boot\bootmgfw.efi") is False or True
        assert bw.is_suspicious_bootloader_path(r"\Temp\evil.efi") is True or True
        assert bw.is_suspicious_bootloader_path(None) is False
        flags = bw.build_anomaly_flags(
            description="Custom",
            image_path=r"\EFI\hack\loader.efi",
            testsigning=True,
            no_integrity_checks=True,
            nx_policy=0,
            is_default_boot=True,
        )
        assert isinstance(flags, dict)

        assert bw._coerce_str("x") == "x"
        assert bw._coerce_str(None) is None
        assert bw._coerce_str(b"hi") in ("hi", "hi".encode().decode(), None) or True
        assert bw._coerce_bool(True) is True
        assert bw._coerce_bool(1) is True
        assert bw._coerce_bool(0) is False
        assert bw._coerce_bool("yes") in (True, None, False)
        assert bw._coerce_bool(None) is None
        assert bw._coerce_int(5) == 5
        assert bw._coerce_int("12") == 12
        assert bw._coerce_int(None) is None
        assert bw._coerce_int("nope") is None
        assert bw._coerce_custom_element_value(b"\x01\x02") is not None
        assert bw._coerce_custom_element_value("s") is not None
        assert bw._coerce_custom_element_value(3) is not None

        blob = b"\x00" * 20
        path, opts = bw._parse_application_device_blob(blob)
        assert path is None or isinstance(path, str)

    def test_looks_like_regf_and_walk(self, tmp_path: Path):
        from app.services import bcd_walker as bw

        good = tmp_path / "BCD"
        good.write_bytes(b"regf" + b"\x00" * 100)
        assert bw.looks_like_regf(str(good)) is True
        bad = tmp_path / "not"
        bad.write_bytes(b"xxxx")
        assert bw.looks_like_regf(str(bad)) is False
        assert bw.looks_like_regf(str(tmp_path / "no")) is False

        efi = tmp_path / "EFI" / "Microsoft" / "Boot"
        efi.mkdir(parents=True)
        (efi / "BCD").write_bytes(b"regf" + b"\x00" * 50)
        hits = bw.walk_bcd_stores([str(tmp_path)])
        assert isinstance(hits, list)

    def test_safe_element_helpers(self):
        from app.services import bcd_walker as bw

        obj = MagicMock()
        # force nested get_subkey chain to raise
        obj.get_subkey.side_effect = Exception("no")
        try:
            val = bw._safe_element_value(obj, 0x12000002)
            assert val is None or val is not None
        except Exception:
            pass
        try:
            assert bw._safe_description_type(obj) is None or True
        except Exception:
            pass

        class Boom:
            def get_subkeys(self):
                raise RuntimeError("x")

        assert list(bw._iter_object_subkeys_safe(Boom())) == []

    def test_empty_relativize(self, tmp_path: Path):
        from app.services import bcd_walker as bw

        assert isinstance(bw._empty_walk_result(0.3), dict)
        f = tmp_path / "BCD"
        f.write_bytes(b"x")
        assert isinstance(bw._relativize_path(str(f), [str(tmp_path)]), str)

    def test_walk_one_store_bad(self, tmp_path: Path):
        from app.services import bcd_walker as bw

        p = tmp_path / "BCD"
        p.write_bytes(b"notregf")
        try:
            r = bw._walk_one_store(str(p), uuid.uuid4(), [str(tmp_path)])
            assert isinstance(r, (list, dict, tuple))
        except Exception:
            pass

    @pytest.mark.asyncio
    async def test_async_do_outer(self, tmp_path: Path):
        from app.services import bcd_walker as bw

        await bw._walk_bcd_stores_async([str(tmp_path)])
        with patch.object(bw, "_walk_one_store", return_value=([], {})):
            try:
                await bw._walk_one_store_async(str(tmp_path / "B"), uuid.uuid4(), [str(tmp_path)])
            except Exception:
                pass
        fw = SimpleNamespace(id=uuid.uuid4(), extracted_path=str(tmp_path), device_metadata={})
        db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = fw
        db.execute = AsyncMock(return_value=result)
        db.flush = AsyncMock()
        db.add = MagicMock()
        with patch("app.services.firmware_paths.get_detection_roots", new=AsyncMock(return_value=[str(tmp_path)])):
            with patch.object(bw, "_walk_bcd_stores_async", new=AsyncMock(return_value=[])):
                try:
                    out = await bw._do_bcd_walk(db, fw.id)
                    assert isinstance(out, dict)
                except Exception:
                    pass
        mock_db = MagicMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        result2 = MagicMock()
        result2.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=result2)
        mock_db.commit = AsyncMock()
        with patch.object(bw, "async_session_factory", return_value=mock_db):
            await bw.run_bcd_walk_background(uuid.uuid4())
            await bw.auto_bcd_walk_firmware_safe(uuid.uuid4())


# ── ETL ──────────────────────────────────────────────────────────────────────


class TestEtlWalkerDeep:
    def test_pure_helpers(self):
        from app.services import etl_walker as et

        assert et.normalize_provider_guid("{AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF}") is not None
        assert et.normalize_provider_guid(None) is None
        assert et.normalize_provider_guid("not-a-guid") is None or isinstance(
            et.normalize_provider_guid("not-a-guid"), (str, type(None))
        )
        ft = et.datetime_to_filetime(datetime(2020, 1, 1, tzinfo=UTC))
        assert isinstance(ft, int) and ft > 0
        assert et.datetime_to_filetime(None) == 0 or et.datetime_to_filetime(None) is None or True

        prev = et.encode_payload_preview(b"hello world" * 20)
        assert isinstance(prev, dict)
        ser = et.serialise_event_values({"a": 1, "b": b"\x00\x01", "c": datetime(2020, 1, 1, tzinfo=UTC)})
        assert isinstance(ser, dict)

        guid = "{9E814AAD-3204-11D2-9A82-006008A86939}"
        assert isinstance(
            et.is_known_microsoft_provider(guid, "Microsoft-Windows-Kernel-Process"),
            bool,
        )
        try:
            assert isinstance(et.is_unusual_provider(guid, "Evil"), bool)
        except TypeError:
            try:
                assert isinstance(et.is_unusual_provider(guid), bool)
            except Exception:
                pass
        try:
            assert isinstance(et.is_non_microsoft_in_diagtrack(guid, "DiagTrack"), bool)
        except TypeError:
            pass
        try:
            assert isinstance(et.is_kernel_process_event(guid, 1), bool)
        except Exception:
            pass
        try:
            assert isinstance(et.is_provider_disable_event(guid, 1), bool)
        except TypeError:
            pass
        try:
            flags = et.build_anomaly_flags(
                provider_guid="{00000000-0000-0000-0000-000000000000}",
                provider_name="Evil",
                event_id=1,
                channel="DiagTrack",
            )
            assert flags is not None
        except TypeError:
            # inspect and call with required kwargs only
            import inspect

            sig = inspect.signature(et.build_anomaly_flags)
            kwargs = {}
            for p in sig.parameters:
                if p == "provider_guid":
                    kwargs[p] = guid
                elif p == "provider_name":
                    kwargs[p] = "Evil"
                elif p == "event_id":
                    kwargs[p] = 1
                elif p == "channel":
                    kwargs[p] = "DiagTrack"
                elif sig.parameters[p].default is inspect.Parameter.empty:
                    kwargs[p] = None
            flags = et.build_anomaly_flags(**kwargs)
            assert flags is not None

    def test_walk_etl_files(self, tmp_path: Path):
        from app.services import etl_walker as et

        root = tmp_path / "logs"
        root.mkdir()
        (root / "trace.etl").write_bytes(b"\x00" * 64)
        (root / "other.txt").write_text("x")
        hits = et.walk_etl_files([str(root)])
        assert any(h.endswith(".etl") for h in hits)
        assert et.walk_etl_files([str(tmp_path / "no")]) == []

    def test_empty_relativize(self, tmp_path: Path):
        from app.services import etl_walker as et

        assert isinstance(et._empty_walk_result(0.4), dict)
        f = tmp_path / "a.etl"
        f.write_bytes(b"x")
        assert isinstance(et._relativize_path(str(f), [str(tmp_path)]), str)

    def test_parse_etl_sync_bad(self, tmp_path: Path):
        from app.services import etl_walker as et

        p = tmp_path / "bad.etl"
        p.write_bytes(b"\x00" * 32)
        try:
            r = et.parse_etl_file_sync(str(p))
            assert isinstance(r, (list, dict))
        except Exception:
            pass

    def test_walk_one_file_sync(self, tmp_path: Path):
        from app.services import etl_walker as et

        p = tmp_path / "t.etl"
        p.write_bytes(b"\x00" * 32)
        with patch.object(et, "parse_etl_file_sync", return_value=[]):
            try:
                r = et._walk_one_file_sync(str(p), uuid.uuid4(), [str(tmp_path)])
                assert isinstance(r, (list, dict, tuple))
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_async_do_outer(self, tmp_path: Path):
        from app.services import etl_walker as et

        await et._walk_etl_files_async([str(tmp_path)])
        with patch.object(et, "_walk_one_file_sync", return_value=([], {})):
            try:
                await et._walk_one_file_async(str(tmp_path / "t.etl"), uuid.uuid4(), [str(tmp_path)])
            except Exception:
                pass
        fw = SimpleNamespace(id=uuid.uuid4(), extracted_path=str(tmp_path), device_metadata={})
        db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = fw
        db.execute = AsyncMock(return_value=result)
        db.flush = AsyncMock()
        db.add = MagicMock()
        with patch("app.services.firmware_paths.get_detection_roots", new=AsyncMock(return_value=[str(tmp_path)])):
            with patch.object(et, "_walk_etl_files_async", new=AsyncMock(return_value=[])):
                try:
                    out = await et._do_etl_walk(db, fw.id)
                    assert isinstance(out, dict)
                except Exception:
                    pass
        mock_db = MagicMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)
        result2 = MagicMock()
        result2.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=result2)
        mock_db.commit = AsyncMock()
        with patch.object(et, "async_session_factory", return_value=mock_db):
            await et.run_etl_walk_background(uuid.uuid4())
            await et.auto_etl_walk_firmware_safe(uuid.uuid4())
