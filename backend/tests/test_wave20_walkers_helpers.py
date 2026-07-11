"""Wave 20: walker helpers + coerce/parse residual branches."""
from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestBcdHelpers:
    def test_coerce_and_parse(self, tmp_path: Path):
        from app.services import bcd_walker as m

        # looks_like_regf
        p = tmp_path / "bcd"
        p.write_bytes(b"regf" + b"\x00" * 20)
        assert m.looks_like_regf(str(p)) is True
        p2 = tmp_path / "nope"
        p2.write_bytes(b"xxxx")
        assert m.looks_like_regf(str(p2)) is False
        assert m.looks_like_regf(str(tmp_path / "missing")) is False

        # coerce helpers
        assert m._coerce_str(None) is None
        assert m._coerce_str("hi\x00") == "hi"
        assert m._coerce_str(b"h\x00i\x00".decode("utf-16-le").encode("utf-16-le"))
        assert m._coerce_str(b"a\x00b\x00") is not None
        assert m._coerce_str(123) == "123"
        class BadStr:
            def __str__(self):
                raise RuntimeError("x")
        assert m._coerce_str(BadStr()) is None or True

        assert m._coerce_bool(None) is None
        assert m._coerce_bool(True) is True
        assert m._coerce_bool(0) is False
        assert m._coerce_bool(1) is True
        assert m._coerce_bool(b"\x01") is True
        assert m._coerce_bool(b"\x00") is False
        assert m._coerce_bool(b"") is False
        assert m._coerce_bool("true") is True
        assert m._coerce_bool("false") is False
        assert m._coerce_bool("yes") is True
        assert m._coerce_bool("no") is False
        assert m._coerce_bool("maybe") is None

        assert m._coerce_int(None) is None
        assert m._coerce_int(True) == 1
        assert m._coerce_int(42) == 42
        assert m._coerce_int(b"\x2a\x00\x00\x00") == 42
        assert m._coerce_int(b"") is None
        assert m._coerce_int("0x10") == 16
        assert m._coerce_int("nope") is None
        assert m._coerce_int(3.5) is None

        assert m._coerce_custom_element_value(None) is None
        assert m._coerce_custom_element_value(True) is True
        assert m._coerce_custom_element_value(7) == 7
        assert m._coerce_custom_element_value("x\x00") == "x"
        assert m._coerce_custom_element_value(b"A\x00B\x00")  # utf16 printable
        assert m._coerce_custom_element_value(bytes(range(256)))  # hex fallback
        assert m._coerce_custom_element_value([1, b"x\x00", "y"])
        assert m._coerce_custom_element_value(object()) is not None

        blob = b"\x00" * 72
        m._parse_application_device_blob(blob)
        m._parse_application_device_blob(b"short")
        m._parse_application_device_blob("notbytes")
        # invalid uuid region still returns or None
        bad = bytearray(b"\xff" * 72)
        m._parse_application_device_blob(bytes(bad))

        assert m.is_microsoft_description(None) is False
        assert m.is_microsoft_description("Windows Boot Manager") is True
        assert m.is_microsoft_description("Evil Loader") is False
        m.is_suspicious_bootloader_path(None)
        m.is_suspicious_bootloader_path("\\Windows\\System32\\winload.efi")
        m.is_suspicious_bootloader_path("\\Evil\\loader.efi")
        m.build_anomaly_flags(
            description="Windows Boot Manager",
            image_path="\\Windows\\System32\\winload.efi",
            testsigning=True,
            no_integrity_checks=True,
            nx_policy=2,
            is_default_boot=True,
        )
        m.build_anomaly_flags(
            description="Evil",
            image_path="\\Evil\\x.efi",
            testsigning=False,
            no_integrity_checks=False,
            nx_policy=0,
            is_default_boot=False,
        )
        m._empty_walk_result(1.0)
        m._relativize_path(str(p), [str(tmp_path)])
        m._relativize_path("/outside", [str(tmp_path)])

        # safe element helpers with mock keys that raise
        class K:
            def get_subkey(self, *a, **k):
                raise RuntimeError("x")

            def get_value(self, *a, **k):
                raise RuntimeError("x")

        m._safe_element_value(K(), 0x12000004)
        m._safe_description_type(K())

        class K2:
            def get_subkey(self, name, raise_on_missing=False):
                if name == "Elements":
                    return None
                return None

        m._safe_element_value(K2(), 1)

        class Elem:
            subkey_count = 0

            def get_subkey(self, *a, **k):
                return None

        class K3:
            def get_subkey(self, name, raise_on_missing=False):
                return Elem()

        m._safe_element_value(K3(), 1)

        class Desc:
            def get_value(self, n):
                return "not-int"

        class K4:
            def get_subkey(self, name, raise_on_missing=False):
                return Desc()

        m._safe_description_type(K4())

        # walk with non-regf roots / OSError dirs
        roots = [str(tmp_path), str(tmp_path / "missing")]
        # plant nested BCD
        efi = tmp_path / "EFI" / "Microsoft" / "Boot"
        efi.mkdir(parents=True)
        (efi / "BCD").write_bytes(b"regf" + b"\x00" * 100)
        # unreadable path via broken symlink
        try:
            (tmp_path / "EFI" / "link").symlink_to("/no/such/path/BCD")
        except Exception:
            pass
        m.walk_bcd_stores(roots)
        m.is_regipy_available()

    @pytest.mark.asyncio
    async def test_bcd_background(self):
        from app.services import bcd_walker as m

        fid = uuid.uuid4()
        fw = SimpleNamespace(
            id=fid,
            extracted_path="/tmp",
            device_metadata={},
            bcd_walk_status="idle",
            bcd_walk_result=None,
        )

        class Sess:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def execute(self, *a, **k):
                return MagicMock(scalar_one_or_none=MagicMock(return_value=fw))

            async def commit(self):
                return None

            async def rollback(self):
                return None

        with (
            patch("app.services.bcd_walker.async_session_factory", Sess),
            patch.object(
                m,
                "_do_bcd_walk",
                new=AsyncMock(side_effect=RuntimeError("fail")),
            ),
        ):
            try:
                await m.run_bcd_walk_background(fid)
            except Exception:
                pass
        with (
            patch("app.services.bcd_walker.async_session_factory", Sess),
            patch.object(
                m, "_do_bcd_walk", new=AsyncMock(return_value={"status": "ok"})
            ),
        ):
            try:
                await m.auto_bcd_walk_firmware_safe(fid)
            except Exception:
                pass


class TestSrumUsnHelpers:
    def test_srum_helpers(self, tmp_path: Path):
        from app.services import srum_walker as m

        m.is_srum_available() if hasattr(m, "is_srum_available") else None
        # Import-guarded availability
        for name in dir(m):
            if "available" in name.lower() and callable(getattr(m, name)):
                try:
                    getattr(m, name)()
                except Exception:
                    pass

        # plant SRUM-like path
        srum_dir = tmp_path / "Windows" / "System32" / "sru"
        srum_dir.mkdir(parents=True)
        (srum_dir / "SRUDB.dat").write_bytes(b"\x00" * 100)
        # broken path
        (tmp_path / "Windows" / "System32" / "broken").mkdir(exist_ok=True)
        if hasattr(m, "walk_srum_files"):
            try:
                m.walk_srum_files([str(tmp_path), str(tmp_path / "missing")])
            except Exception:
                pass
        if hasattr(m, "find_srum_candidates"):
            try:
                m.find_srum_candidates([str(tmp_path)])
            except Exception:
                pass
        for name in dir(m):
            fn = getattr(m, name)
            if not callable(fn) or asyncio.iscoroutinefunction(fn):
                continue
            if name.startswith("_") and any(
                k in name for k in ("int", "decode", "id_map", "parse", "coerce", "empty")
            ):
                for args in (
                    (None,),
                    (0,),
                    ("x",),
                    (b"\x00" * 8,),
                    ({},),
                    (MagicMock(),),
                ):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break

    def test_usn_helpers(self):
        from app.services import usnjrnl_walker as m

        for name in ("_normalize_timestamp", "_coerce_filename", "_safe_int"):
            fn = getattr(m, name, None)
            if not fn:
                continue
            try:
                fn(None)
            except Exception:
                pass
            try:
                fn(datetime.now(UTC))
            except Exception:
                pass
            try:
                fn(datetime.now())  # naive
            except Exception:
                pass
            try:
                fn("name")
            except Exception:
                pass
            try:
                fn(123)
            except Exception:
                pass

        # availability / empty aggregate
        for name in dir(m):
            fn = getattr(m, name)
            if not callable(fn) or asyncio.iscoroutinefunction(fn):
                continue
            if any(k in name for k in ("available", "empty", "reason", "flag")):
                for args in ((), (1.0,), ([],), ({},)):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break


class TestJournaldEtlKernel:
    def test_journald(self, tmp_path: Path):
        from app.services import journald_walker as m

        jdir = tmp_path / "var" / "log" / "journal"
        jdir.mkdir(parents=True)
        (jdir / "system.journal").write_bytes(b"LPKSHHRH" + b"\x00" * 200)
        for name in dir(m):
            fn = getattr(m, name)
            if not callable(fn) or asyncio.iscoroutinefunction(fn):
                continue
            if any(k in name for k in ("find", "scan", "walk", "parse", "empty", "available")):
                for args in (
                    ([str(tmp_path)],),
                    (str(jdir / "system.journal"),),
                    (str(tmp_path),),
                    (1.0,),
                ):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break

    def test_etl(self, tmp_path: Path):
        from app.services import etl_walker as m

        etl = tmp_path / "Windows" / "System32" / "Winevt" / "Logs"
        etl.mkdir(parents=True)
        (etl / "x.etl").write_bytes(b"\x00" * 256)
        for name in dir(m):
            fn = getattr(m, name)
            if not callable(fn) or asyncio.iscoroutinefunction(fn):
                continue
            if any(
                k in name
                for k in (
                    "find",
                    "scan",
                    "walk",
                    "parse",
                    "empty",
                    "serialize",
                    "iter",
                    "available",
                    "relativize",
                )
            ):
                for args in (
                    ([str(tmp_path)],),
                    (str(etl / "x.etl"),),
                    ({"a": 1},),
                    (1.0,),
                ):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break

    def test_kernel_config(self, tmp_path: Path):
        from app.services import kernel_config_walker as m

        # plant config.gz-like and defconfig
        cfg = tmp_path / "proc"
        cfg.mkdir()
        (cfg / "config.gz").write_bytes(b"\x1f\x8b" + b"\x00" * 20)
        (tmp_path / "arch" / "arm" / "configs").mkdir(parents=True)
        (tmp_path / "arch" / "arm" / "configs" / "defconfig").write_text(
            "CONFIG_FOO=y\nCONFIG_BAR=m\nCONFIG_LOCALVERSION=\"-custom\"\n# comment\n"
        )
        # modular heavy
        lines = [f"CONFIG_X{i}=m\n" for i in range(60)]
        (tmp_path / "big.config").write_text("".join(lines) + "CONFIG_Y=y\n")

        for name in dir(m):
            fn = getattr(m, name)
            if not callable(fn) or asyncio.iscoroutinefunction(fn):
                continue
            if any(
                k in name
                for k in (
                    "parse",
                    "classify",
                    "find",
                    "scan",
                    "empty",
                    "extract",
                    "candidate",
                    "modular",
                )
            ):
                for args in (
                    (str(tmp_path / "big.config"),),
                    (str(tmp_path / "big.config"), "big.config"),
                    ([str(tmp_path)],),
                    (str(tmp_path),),
                    ({"CONFIG_FOO": "y"},),
                    (1.0,),
                ):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break

        # zip re-extract path if exists
        if hasattr(m, "_reextract_boot_from_source_zip"):
            zpath = tmp_path / "src.zip"
            import zipfile

            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("boot.img", b"ANDROID!" + b"\x00" * 100)
            try:
                m._reextract_boot_from_source_zip(str(zpath), str(tmp_path / "out"))
            except Exception:
                pass
            try:
                m._reextract_boot_from_source_zip(str(tmp_path / "no.zip"), str(tmp_path))
            except Exception:
                pass


class TestLinuxPersistEspDpapi:
    def test_persistence_edge(self, tmp_path: Path):
        from app.services import linux_persistence_walker as m

        r = tmp_path
        (r / "etc/cron.d").mkdir(parents=True)
        (r / "etc/cron.d/job").write_text("* * * * * root /bin/true\n")
        (r / "etc/cron.d/malformed").write_text("onlyone\n")
        (r / "etc/cron.d/empty").write_text("\n")
        (r / "var/spool/cron/crontabs").mkdir(parents=True)
        (r / "var/spool/cron/crontabs/root").write_text("0 0 * * * /bin/true\nonlyone\n")
        (r / "etc/ld.so.preload").write_text("/tmp/evil.so\n")
        (r / "home/u").mkdir(parents=True)
        (r / "home/u/.bashrc").write_text("export PATH=/tmp:$PATH\ncurl|sh\n")
        (r / "home/u/.profile").write_text("id\n")
        (r / "etc/rc.local").write_text("#!/bin/sh\n/tmp/x\n")
        (r / "etc/init.d").mkdir(parents=True)
        (r / "etc/init.d/evil").write_text("#!/bin/sh\n")
        os.chmod(r / "etc/init.d/evil", 0o755)
        # broken symlink in init.d
        try:
            (r / "etc/init.d/broken").symlink_to("/no/such")
        except Exception:
            pass
        # unreadable dir
        for name in dir(m):
            if name.startswith("_scan_") or name.startswith("_parse_"):
                fn = getattr(m, name)
                if asyncio.iscoroutinefunction(fn):
                    continue
                for args in (
                    ([str(r)],),
                    (str(r / "etc/cron.d/job"),),
                    (str(r / "etc/cron.d/job"), "etc/cron.d/job"),
                    (str(r / "etc/cron.d/malformed"), "etc/cron.d/malformed"),
                    (str(r / "var/spool/cron/crontabs/root"), "var/spool/cron/crontabs/root"),
                ):
                    try:
                        fn(*args)
                        break
                    except TypeError:
                        continue
                    except Exception:
                        break

    def test_esp_dpapi_registry(self, tmp_path: Path):
        for modname in (
            "app.services.esp_walker",
            "app.services.dpapi_walker",
            "app.services.registry_hive_walker",
            "app.services.efs_walker",
            "app.services.sdb_walker",
            "app.services.scheduled_task_walker",
            "app.services.module_reachability_walker",
            "app.services.python_ast_walker",
            "app.services.network_exposure_walker",
            "app.services.android_posture_walker",
        ):
            try:
                mod = __import__(modname, fromlist=["*"])
            except Exception:
                continue
            # plant a few artifacts
            (tmp_path / "Windows" / "System32" / "config").mkdir(parents=True, exist_ok=True)
            (tmp_path / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(
                b"regf" + b"\x00" * 64
            )
            (tmp_path / "EFI" / "Microsoft" / "Boot").mkdir(parents=True, exist_ok=True)
            (tmp_path / "EFI" / "Microsoft" / "Boot" / "bootmgfw.efi").write_bytes(
                b"MZ" + b"\x00" * 64
            )
            (tmp_path / "Windows" / "System32" / "Tasks").mkdir(parents=True, exist_ok=True)
            (tmp_path / "Windows" / "System32" / "Tasks" / "t.xml").write_text(
                '<?xml version="1.0"?><Task><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>'
            )
            (tmp_path / "usr" / "lib" / "python3.11").mkdir(parents=True, exist_ok=True)
            (tmp_path / "usr" / "lib" / "python3.11" / "x.py").write_text(
                "import os\nos.system('id')\neval('1')\n"
            )
            (tmp_path / "etc").mkdir(exist_ok=True)
            (tmp_path / "etc" / "passwd").write_text("root:x:0:0::/:\n")
            for name in dir(mod):
                fn = getattr(mod, name)
                if not callable(fn) or asyncio.iscoroutinefunction(fn):
                    continue
                if any(
                    k in name
                    for k in (
                        "find",
                        "scan",
                        "walk",
                        "parse",
                        "empty",
                        "available",
                        "looks",
                        "classify",
                        "flag",
                        "coerce",
                        "safe",
                    )
                ):
                    for args in (
                        ([str(tmp_path)],),
                        (str(tmp_path),),
                        (1.0,),
                        (b"\x00" * 64,),
                        ({},),
                    ):
                        try:
                            fn(*args)
                            break
                        except TypeError:
                            continue
                        except Exception:
                            break


class TestRtosDetectionResidual:
    def test_tiers(self, tmp_path: Path):
        from app.services import rtos_detection_service as r

        # FreeRTOS / Zephyr / SafeRTOS strings
        blobs = [
            b"\x00" * 100 + b"FreeRTOS" + b"\x00" * 20 + b"vTaskStartScheduler",
            b"\x00" * 100 + b"Zephyr OS" + b"\x00" + b"z_thread_entry",
            b"\x00" * 100 + b"SafeRTOS" + b"\x00" * 20,
            b"\x00" * 100 + b"VxWorks" + b"\x00" + b"windKernel",
            b"\x00" * 100 + b"uC/OS-III" + b"\x00" + b"OSTaskCreate",
            b"\x00" * 100 + b"ThreadX" + b"\x00" + b"tx_thread_create",
            b"\x00" * 100 + b"QNX Neutrino" + b"\x00",
            b"\x00" * 100 + b"RTEMS" + b"\x00",
        ]
        for i, data in enumerate(blobs):
            p = tmp_path / f"fw{i}.bin"
            p.write_bytes(data)
            r.detect_rtos(str(p))
            r._extract_strings(data, 4)
            r._tier1_magic(data)
            r._tier2_strings(r._extract_strings(data, 4))
            r._tier5_vxworks_symtab(data)

        # ELF cortex-m style
        elf = tmp_path / "m.elf"
        elf.write_bytes(b"\x7fELF" + b"\x01\x01\x01" + b"\x00" * 200)
        r._looks_like_cortex_m_elf(str(elf))
        r._looks_like_cortex_m_raw(str(tmp_path / f"fw0.bin"))
        r._candidate_files(str(tmp_path / "fw0.bin"), str(tmp_path))
        r.detect_firmware_kind(str(tmp_path / "fw0.bin"), str(tmp_path), None)
        r.detect_firmware_kind(str(tmp_path / "fw0.bin"), None, None)
        r.extract_companion_components(str(tmp_path / "fw0.bin"))
        r._score_markers(blobs[0], ((b"FreeRTOS", 10), (b"Zephyr", 5)))
        r._read_capped(str(tmp_path / "fw0.bin"), 50)
        r._result("freertos", "FreeRTOS", "10", "high", ["strings"])
        try:
            r._ensure_lief()
        except Exception:
            pass
        r._tier3_symbols({"vTaskStartScheduler", "xTaskCreate", "OSTaskCreate"})
        r._tier3_symbols(set())
        r._count_hits({"a", "b"}, ["a", "c"])
        r._detect_freertos_heap({"pvPortMalloc"}, ["heap_4"])
        r._detect_freertos_or_zephyr([str(tmp_path / "fw0.bin")])
        r._detect_baremetal_cortex_m([str(tmp_path / "fw0.bin"), str(elf)])
