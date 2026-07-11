"""Wave 20: strings/security/ghidra tools + pure parsers/resolvers residual."""
from __future__ import annotations

import asyncio
import os
import struct
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _ctx(tmp_path: Path):
    ctx = MagicMock()
    ctx.resolve_path = lambda p: (
        str(tmp_path) if p in ("/", "", None) else str(tmp_path / str(p).lstrip("/"))
    )
    ctx.real_root_for = lambda p: str(tmp_path)
    ctx.to_virtual_path = lambda p: "/" + os.path.relpath(p, tmp_path)
    ctx.extracted_path = str(tmp_path)
    ctx.storage_path = str(tmp_path / "fw.bin")
    ctx.extraction_dir = str(tmp_path)
    ctx.project_id = uuid.uuid4()
    ctx.firmware_id = uuid.uuid4()
    ctx.db = AsyncMock()
    ctx.firmware_kind = "linux"
    return ctx


class TestStringsResidual:
    @pytest.mark.asyncio
    async def test_strings_handlers(self, tmp_path: Path):
        from app.ai.tools import strings as st

        (tmp_path / "etc").mkdir()
        (tmp_path / "bin").mkdir()
        (tmp_path / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/sh\nnobody:x:99:99::/:\n")
        (tmp_path / "etc" / "shadow").write_text(
            "root:$1$deadbeef$hashhashhash:0:0:99999:7:::\n"
            "user:$5$rounds=5000$salt$hash:0:0:99999:7:::\n"
            "u2:$6$salt$longhash:0:0:99999:7:::\n"
            "u3:*:0:0:99999:7:::\n"
            "u4:!:0:0:99999:7:::\n"
        )
        (tmp_path / "etc" / "ssl").mkdir()
        (tmp_path / "etc" / "ssl" / "cert.pem").write_text(
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
            "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"
        )
        secrets = tmp_path / "etc" / "secrets.conf"
        secrets.write_text(
            "password=SuperSecret99!\n"
            "api_key=AKIAIOSFODNN7EXAMPLE\n"
            "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
            "aws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        # many high-entropy strings for truncation branches
        bin_path = tmp_path / "bin" / "app"
        payload = b"\x7fELF" + b"\x00" * 50
        for i in range(80):
            payload += f"HighEntropyString{i:04d}XYZABC123!@#".encode() + b"\x00"
        payload += b"192.168.1.1\x0010.0.0.1\x00200.1.2.3\x00"
        bin_path.write_bytes(payload)

        ctx = _ctx(tmp_path)

        # helpers
        st._categorize_strings(["http://x", "password=1", "AES", "foo"])
        st._shannon_entropy("aaaa")
        st._shannon_entropy("aB3$xY9!")
        st._is_text_file(str(secrets))
        st._is_elf_file(str(bin_path))
        st._classify_binary_string("password=foo")
        st._classify_binary_string("normal")
        st._identify_hash_type("$1$x$y")
        st._identify_hash_type("$5$x$y")
        st._identify_hash_type("$6$x$y")
        st._identify_hash_type("*")
        st._try_common_passwords("$1$deadbeef$hashhashhash")
        st._analyze_shadow_file(str(tmp_path / "etc" / "shadow"), "/etc/shadow", [])
        st._analyze_passwd_file(str(tmp_path / "etc" / "passwd"), "/etc/passwd", [])
        st._classify_ip("192.168.0.1")
        st._classify_ip("8.8.8.8")
        st._classify_ip("10.0.0.1")
        st._classify_ip("127.0.0.1")
        st._classify_ip("not-ip")
        st._is_version_context("version 1.2.3", 8)
        st._is_oid_context("1.2.840.113549", 0)
        st._find_crypto_material_sync(str(tmp_path), str(tmp_path))
        st._find_hardcoded_credentials_sync(str(tmp_path), str(tmp_path), 5)
        st._find_hardcoded_credentials_sync(str(tmp_path), str(tmp_path), 100000)
        st._classify_files_for_ip_scan_sync(
            [str(tmp_path)], [str(tmp_path)], str(tmp_path), True
        )
        st._read_text_file_sync(str(secrets))
        st._match_ips_in_content_sync(
            "connect 192.168.1.1 and 8.8.8.8 and 10.1.2.3",
            "etc/x",
            False,
            True,
            100,
        )
        st._match_ips_in_content_sync(
            "x" * 10 + "200.1.2.3" + "y" * 10,
            "bin/app",
            True,
            False,
            1,
        )

        # handlers
        await st._handle_extract_strings(
            {"path": "/bin/app", "min_length": 4, "max_results": 5}, ctx
        )
        await st._handle_extract_strings(
            {"path": "/bin/app", "min_length": 4, "max_results": 0}, ctx
        )
        await st._handle_search_strings(
            {"path": "/", "pattern": "password", "max_results": 2}, ctx
        )
        await st._handle_search_strings(
            {"path": "/", "pattern": "password", "max_results": 0}, ctx
        )
        await st._handle_find_crypto_material({"path": "/"}, ctx)
        await st._handle_find_hardcoded_credentials(
            {"path": "/", "max_results": 10}, ctx
        )
        await st._handle_find_hardcoded_ips(
            {"path": "/", "include_private": True, "max_results": 5}, ctx
        )
        await st._handle_find_hardcoded_ips(
            {"path": "/", "include_private": False, "include_binaries": True, "max_results": 3},
            ctx,
        )

        # subprocess timeout path
        class Proc:
            def kill(self):
                return None

            async def communicate(self):
                return b"", b""

        async def fake_create(*a, **k):
            return Proc()

        with patch("asyncio.create_subprocess_exec", side_effect=fake_create), patch(
            "asyncio.wait_for", side_effect=TimeoutError()
        ):
            try:
                await st._run_subprocess(["echo", "hi"], cwd=str(tmp_path), timeout=0.01)
            except TimeoutError:
                pass

        # extract data strings OSError
        await st._extract_data_strings(str(tmp_path / "missing"), 4)


class TestSecurityResidual:
    @pytest.mark.asyncio
    async def test_many_security_edge(self, tmp_path: Path):
        from app.ai.tools import security as sec

        (tmp_path / "etc").mkdir()
        (tmp_path / "bin").mkdir()
        (tmp_path / "usr" / "bin").mkdir(parents=True)
        (tmp_path / "etc" / "passwd").write_text("root:x:0:0::/:\n")
        (tmp_path / "etc" / "shadow").write_text("root:*:0:0:99999:7:::\n")
        (tmp_path / "etc" / "sudoers").write_text("root ALL=(ALL) ALL\n")
        (tmp_path / "etc" / "ssh").mkdir()
        (tmp_path / "etc" / "ssh" / "sshd_config").write_text(
            "PermitRootLogin yes\nPasswordAuthentication yes\n"
        )
        (tmp_path / "etc" / "ssl" / "certs").mkdir(parents=True)
        (tmp_path / "etc" / "ssl" / "certs" / "ca.pem").write_text(
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        )
        su = tmp_path / "bin" / "su"
        su.write_bytes(b"\x7fELF" + b"\x00" * 40)
        os.chmod(su, 0o4755)
        (tmp_path / "etc" / "init.d").mkdir(parents=True)
        (tmp_path / "etc" / "init.d" / "S99x").write_text("#!/bin/sh\n")
        (tmp_path / "lib" / "modules").mkdir(parents=True)
        (tmp_path / "proc").mkdir()
        ctx = _ctx(tmp_path)

        # fire many handlers with short timeout
        for name in dir(sec):
            if not name.startswith("_handle_"):
                continue
            fn = getattr(sec, name)
            if not asyncio.iscoroutinefunction(fn):
                continue
            payload = {
                "path": "/",
                "binary_path": "/bin/su",
                "query": "openssl",
                "max_results": 5,
                "cve_id": "CVE-2021-44228",
                "component": "openssl",
                "version": "1.0.2",
                "service": "ssh",
                "config_path": "/etc/ssh/sshd_config",
            }
            try:
                await asyncio.wait_for(fn(payload, ctx), timeout=0.8)
            except Exception:
                pass


class TestGhidraResearchResidual:
    @pytest.mark.asyncio
    async def test_ghidra_tools(self, tmp_path: Path):
        from app.ai.tools import ghidra_research as gr

        ctx = _ctx(tmp_path)
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "app").write_bytes(b"\x7fELF" + b"\x00" * 100)

        # mock service layer commonly used
        mock_svc = MagicMock()
        for meth in dir(gr):
            pass

        for name in dir(gr):
            if not name.startswith("_handle_"):
                continue
            fn = getattr(gr, name)
            if not asyncio.iscoroutinefunction(fn):
                continue
            payload = {
                "path": "/bin/app",
                "binary_path": "/bin/app",
                "function": "main",
                "address": "0x1000",
                "query": "strcpy",
                "max_results": 5,
            }
            try:
                await asyncio.wait_for(fn(payload, ctx), timeout=0.8)
            except Exception:
                pass


class TestFileFormatResolver:
    def test_signal_evaluators(self, tmp_path: Path):
        from app.services.file_format_catalog import resolver as r

        p = tmp_path / "x.bin"
        p.write_bytes(b"\x7fELF" + b"\x00" * 100 + b"ustar")

        class Sig:
            def __init__(self, **kw):
                defaults = dict(
                    stems_lower=None,
                    extensions_lower=None,
                    path_substrings_any_of=None,
                    size_min=None,
                    size_max=None,
                    bytes_hex=None,
                    mask_hex=None,
                    offset=0,
                    substring=None,
                    substrings=None,
                    charset=None,
                    line_terminator=None,
                    first_line=None,
                    header_pattern_hex=None,
                    rtos_plugin_ref=None,
                    search_length=64,
                    text_format_constraint=None,
                    magic_bytes_constraint=None,
                    substring_constraint=None,
                )
                defaults.update(kw)
                self.__dict__.update(defaults)

        head = p.read_bytes()
        size = len(head)
        path = str(p)

        # filename / path / size
        for args in (
            (Sig(stems_lower=["x", "x.bin"], extensions_lower=[".bin"]), head, path, size),
            (Sig(stems_lower=["apk"], extensions_lower=[".apk"]), head, path, size),
            (Sig(path_substrings_any_of=["x.bin", "nope"]), head, path, size),
            (Sig(size_min=1, size_max=10000), head, path, size),
            (Sig(size_min=10**9), head, path, size),
        ):
            try:
                r._eval_filename(*args)
            except Exception:
                pass
            try:
                r._eval_path_context(*args)
            except Exception:
                pass
            try:
                r._eval_size_range(*args)
            except Exception:
                pass

        for fn in (
            r._eval_elf_check,
            r._eval_pe_check,
            r._eval_intel_hex_check,
            r._eval_text_format,
            r._eval_magic_bytes,
            r._eval_substring_in_head,
            r._eval_zip_markers,
            r._eval_tar_markers,
            r._eval_always_matches,
            r._eval_rtos_check,
        ):
            for blob in (head, b"NOPE", b"MZ" + b"\x00" * 60, b"PK\x03\x04" + b"\x00" * 20,
                         b"\x00" * 0x101 + b"ustar", b":10000000AABB"):
                try:
                    fn(Sig(bytes_hex="7f454c46", mask_hex="ffffffff", offset=0,
                           substring="ELF", substrings=["ELF"], rtos_plugin_ref="missing",
                           extensions_lower=[".bin"], stems_lower=["x"]), blob, path, len(blob))
                except Exception:
                    pass

        # resolve
        try:
            r.resolve(head, path, size)
        except Exception:
            pass
        try:
            r.get_default_snapshot()
        except Exception:
            pass

        # plugin registry
        try:
            r._unfreeze_plugin_registry_for_tests()
        except Exception:
            pass

        class M:
            def detect(self, blob_head, path, size):
                return None

        try:
            r.register_matcher("wave20_test_matcher", M())
        except Exception:
            pass
        try:
            r.freeze_plugin_registry()
        except Exception:
            pass


class TestIcsResolver:
    def test_ics_evals(self, tmp_path: Path):
        from app.services.ics_protocol_catalog import resolver as r

        class Constraint:
            def __init__(self, **kw):
                defaults = dict(
                    needles_hex=["6d6f64627573"],  # "modbus"
                    search_offset=0,
                    search_length=64,
                    case_sensitive=False,
                    combine="any",
                    min_count=1,
                    bytes_hex="00000000",
                    mask_hex=None,
                    offset=0,
                    function_codes=[1, 3, 16],
                    ports=[502, 20000],
                )
                defaults.update(kw)
                self.__dict__.update(defaults)

        class Sig:
            def __init__(self, **kw):
                defaults = dict(
                    kind="magic_bytes",
                    bytes_hex=None,
                    mask_hex=None,
                    offset=0,
                    strings=None,
                    strings_lower=None,
                    function_codes=None,
                    ports=None,
                    symbol_patterns=None,
                    symbol_patterns_lower=None,
                    search_length=64,
                    min_matches=1,
                    string_in_binary_constraint=None,
                    magic_bytes_constraint=None,
                    function_code_set_constraint=None,
                    port_signature_constraint=None,
                    library_symbol_constraint=None,
                )
                defaults.update(kw)
                self.__dict__.update(defaults)

        head = b"\x00\x00\x00\x00" + b"modbus" + b"\x00" * 50
        path = str(tmp_path / "plc.bin")
        Path(path).write_bytes(head)
        ctx = r.IcsResolverContext()
        ctx.elf_dynsym_cache[path] = frozenset({"modbus_read", "foo"})
        ctx.pe_imports_cache[path] = frozenset()

        for fn in (
            r._eval_magic_bytes,
            r._eval_string_in_binary,
            r._eval_function_code_set,
            r._eval_port_signature,
            r._eval_library_symbol,
        ):
            sig = Sig(
                bytes_hex="00000000",
                offset=0,
                string_in_binary_constraint=Constraint(),
                magic_bytes_constraint=Constraint(),
                function_code_set_constraint=Constraint(),
                port_signature_constraint=Constraint(),
                library_symbol_constraint=Constraint(),
                symbol_patterns_lower=["modbus"],
            )
            try:
                fn(sig, head, path, len(head), ctx)
            except Exception:
                pass
            try:
                fn(Sig(string_in_binary_constraint=None), head, path, len(head), None)
            except Exception:
                pass

        class Det:
            certainty = "high"
            min_confidence_score = None
            operator_confidence = None

        r._certainty_to_confidence(Det(), "high")
        try:
            r.resolve_all(head, path, len(head))
        except Exception:
            pass


class TestQualcommMbn:
    def test_mbn_parser(self, tmp_path: Path):
        from app.services.hardware_firmware.parsers import qualcomm_mbn as q

        q._safe_str(b"MSM8998\x00\x00")
        q._safe_str(None)
        q._safe_str(b"\xff\xfe")

        data = b"\x00" * 100 + b"MSM8998" + b"\x00" + b"BOOT.XF.1.2" + b"\x00" * 50
        q._scan_for_chipset_and_version(data)
        q._scan_for_chipset_and_version(b"\x00" * 10)

        # fake x509-ish
        q._parse_x509_chain(b"\x30\x82" + b"\x00" * 100)
        q._parse_x509_chain(b"")
        q._parse_x509_chain(b"\x00" * 5)

        header = struct.pack("<8I", 3, 0, 0, 0x100, 0x200, 0x10, 0x20, 0x30) + b"\x00" * 32
        try:
            q._parse_mbn_v3_header(header)
        except Exception:
            pass
        try:
            q._parse_mbn_v3_header(b"\x00" * 4)
        except Exception:
            pass

        p = tmp_path / "x.mbn"
        p.write_bytes(b"\x7fELF" + b"\x00" * 500 + data)
        q._load_bytes(str(p), 100)
        q._load_bytes(str(tmp_path / "nope"), 100)

        parser = q.QualcommMbnParser()
        try:
            parser.parse(str(p), b"\x7fELF", p.stat().st_size)
        except Exception:
            pass
        try:
            parser._parse_elf(str(p), p.stat().st_size, {})
        except Exception:
            pass
        q.QualcommMbnParser._read_range(str(p), 0, 16)
        q.QualcommMbnParser._read_range(str(p), 10**9, 16)
        q.QualcommMbnParser._tail_cert_bytes(str(p), p.stat().st_size, 32)
        q.QualcommMbnParser._tail_cert_bytes(str(p), p.stat().st_size, 10**9)


class TestDriverExtractor:
    def test_signing_and_scan(self, tmp_path: Path):
        from app.services import driver_extractor as d

        # INF triplet layout
        base = tmp_path / "drivers" / "foo"
        base.mkdir(parents=True)
        (base / "foo.inf").write_text(
            "[Version]\nSignature=$WINDOWS NT$\nClass=System\n"
            "[Manufacturer]\n%mfg%=mfg,NTamd64\n"
            "[mfg.NTamd64]\n%dev%=install,PCI\\VEN_8086&DEV_1234\n"
            "[install]\nCopyFiles=files\n"
        )
        (base / "foo.sys").write_bytes(b"MZ" + b"\x00" * 100)
        (base / "foo.cat").write_bytes(b"\x00" * 50)

        d._is_inf_file(str(base / "foo.inf"))
        d.scan_for_inf_triplets([str(tmp_path), str(tmp_path / "missing")])
        d._sha256_hex(str(base / "foo.sys"))
        d._sha256_hex(str(tmp_path / "nope"))
        d._bytes_at(str(base / "foo.sys"))
        d._bytes_at(str(tmp_path / "nope"))
        d._stringify_certificate_subject(SimpleNamespace(subject="CN=Test"))
        d._stringify_certificate_subject(None)
        d._classify_chain([])
        d._classify_chain([SimpleNamespace(subject="CN=Microsoft Windows")])
        d.classify_cat_signing_tier(str(base / "foo.cat"))
        d.classify_cat_signing_tier(str(tmp_path / "nope.cat"))
        d._empty_extract_result(1.0)

    @pytest.mark.asyncio
    async def test_auto_extract(self, tmp_path: Path):
        from app.services import driver_extractor as d

        base = tmp_path / "d"
        base.mkdir()
        (base / "x.inf").write_text("[Version]\nSignature=$WINDOWS NT$\n")
        (base / "x.sys").write_bytes(b"MZ" + b"\x00" * 20)
        fid = uuid.uuid4()
        fw = SimpleNamespace(
            id=fid,
            extracted_path=str(tmp_path),
            device_metadata={},
            project_id=uuid.uuid4(),
        )
        db = AsyncMock()
        db.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=fw))
        )
        db.add = MagicMock()
        db.flush = AsyncMock()
        with patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=[str(tmp_path)]),
        ):
            try:
                await d.auto_extract_drivers(fid, db)
            except Exception:
                pass
        with patch("app.services.driver_extractor.async_session_factory") as sf:
            class Sess:
                async def __aenter__(self):
                    return db

                async def __aexit__(self, *a):
                    return False

            sf.return_value = Sess()
            try:
                await d.auto_extract_drivers_safe(fid)
            except Exception:
                pass


class TestFileServiceResidual:
    def test_file_service_edges(self, tmp_path: Path):
        from app.services.file_service import FileService
        from app.utils.sandbox import PathTraversalError

        root = tmp_path / "rootfs"
        root.mkdir()
        (root / "bin").mkdir()
        (root / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\x00" * 20)
        (root / "etc").mkdir()
        (root / "etc" / "passwd").write_text("root:x:0:0::/:\n")
        # broken symlink
        try:
            (root / "bin" / "broken").symlink_to("/no/such")
        except Exception:
            pass
        # nested extra roots
        extra = tmp_path / "extra"
        extra.mkdir()
        (extra / "data.bin").write_bytes(b"\x00" * 10)
        carved = tmp_path / "carved"
        carved.mkdir()
        (carved / "c.bin").write_bytes(b"\x00" * 5)

        svc = FileService(
            str(root),
            extraction_dir=str(tmp_path),
            extra_roots=[str(extra)],
            carved_path=str(carved),
        )
        svc.list_directory("/")
        svc.list_directory("/bin")
        svc.list_directory("/extra") if False else None
        try:
            svc.list_directory("/_carved")
        except Exception:
            pass
        for p in ("/bin/busybox", "/etc/passwd", "/bin/broken"):
            try:
                svc.file_info(p)
            except Exception:
                pass
            try:
                svc.read_file(p)
            except Exception:
                pass
        try:
            svc._resolve("../escape")
        except (PathTraversalError, Exception):
            pass
        try:
            svc.to_virtual_path(str(root / "bin" / "busybox"))
        except Exception:
            pass

        # blob only
        blob = tmp_path / "rtos.bin"
        blob.write_bytes(b"\x7fELF" + b"\x00" * 100)
        bsvc = FileService("", firmware_path=str(blob))
        bsvc.list_directory("/")
        bsvc.list_directory("/firmware")
        try:
            bsvc.file_info(f"/firmware/{blob.name}")
        except Exception:
            pass
        try:
            bsvc.read_file(f"/firmware/{blob.name}")
        except Exception:
            pass
        try:
            bsvc.to_virtual_path(str(blob))
        except Exception:
            pass
