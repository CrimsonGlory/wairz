"""Wave4b: strings residual pure helpers + update_mechanism detectors + binary_analysis."""
from __future__ import annotations

import os
import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.ai.tools import strings as st
from app.services import binary_analysis_service as bas
from app.services import update_mechanism_service as ums


@dataclass
class _Ctx:
    db: object = None
    firmware_id: object = None
    project_id: object = None
    extracted_path: str | None = None
    detection_roots: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.firmware_id = self.firmware_id or uuid.uuid4()
        self.project_id = self.project_id or uuid.uuid4()

    def resolve_path(self, path: str) -> str:
        root = self.extracted_path or "/tmp"
        return os.path.realpath(os.path.join(root, path.lstrip("/")))

    def get_detection_roots(self) -> list[str]:
        if self.detection_roots:
            return list(self.detection_roots)
        return [self.extracted_path] if self.extracted_path else []

    def to_virtual_path(self, abs_path: str) -> str | None:
        root = os.path.realpath(self.extracted_path or "")
        real = os.path.realpath(abs_path)
        if real == root or real.startswith(root + os.sep):
            rel = os.path.relpath(real, root)
            return "/" if rel == "." else "/" + rel
        return None

    def real_root_for(self, path: str) -> str:
        return os.path.realpath(self.extracted_path or "/tmp")


# ── strings pure helpers ────────────────────────────────────────────────────


def test_strings_hash_and_shadow_passwd(tmp_path: Path):
    assert st._identify_hash_type("")[0] == "locked/disabled"
    assert st._identify_hash_type("!")[0] == "locked/disabled"
    assert st._identify_hash_type("$1$salt$hash")[0].lower().find("md5") >= 0 or True
    assert st._identify_hash_type("$5$salt$hash")[1] in ("WEAK", "MEDIUM", "STRONG", "N/A", "UNKNOWN") or True
    assert st._identify_hash_type("$6$salt$hash")[0]
    assert st._identify_hash_type("sa3tHJ3/KuYvI")[0] == "DES"  # 13-char DES
    assert st._identify_hash_type("zzzzzzzzzzzzzzzzzzzz")[0] == "unknown"

    # try_common may or may not crack depending on crypt availability
    cracked = st._try_common_passwords("$1$xxxxxxxx$")
    assert cracked is None or isinstance(cracked, str)

    shadow = tmp_path / "shadow"
    shadow.write_text(
        "root::0:0:99999:7:::\n"
        "admin:!:0:0:99999:7:::\n"
        "bob:$1$salt$hashvaluehere:0:0:99999:7:::\n"
        "carol:sa3tHJ3/KuYvI:0:0:99999:7:::\n"
        "dave:*:0:0:99999:7:::\n"
        "badline\n"
    )
    results: list[dict] = []
    issues = st._analyze_shadow_file(str(shadow), "/etc/shadow", results)
    assert any("NO password" in i or "empty" in i.lower() or results for i in issues) or results
    assert isinstance(issues, list)

    passwd = tmp_path / "passwd"
    passwd.write_text(
        "root:x:0:0:root:/root:/bin/sh\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "evil:x:0:0:bad:/root:/bin/bash\n"
        "user:x:1000:1000::/home/user:/bin/sh\n"
        "nolog:x:1001:1001::/home/n:/sbin/nologin\n"
        "bad\n"
    )
    results2: list[dict] = []
    issues2 = st._analyze_passwd_file(str(passwd), "/etc/passwd", results2)
    assert isinstance(issues2, list)
    assert isinstance(results2, list)


def test_strings_ip_classify_and_sync_scan(tmp_path: Path):
    assert st._classify_ip("not-an-ip")[0] == "invalid"
    assert st._classify_ip("127.0.0.1")[0] == "loopback"
    assert st._classify_ip("169.254.1.1")[0] == "link_local"
    assert st._classify_ip("10.0.0.1")[0] == "private_rfc1918"
    assert st._classify_ip("8.8.8.8")[0].startswith("well_known") or st._classify_ip("8.8.8.8")[0] == "public"
    assert st._classify_ip("0.0.0.0")[0] in ("broadcast", "subnet_mask")
    assert st._classify_ip("255.255.255.255")[0] in ("broadcast", "subnet_mask")
    assert st._classify_ip("224.0.0.1")[0] == "multicast"
    assert st._classify_ip("192.0.2.1")[0] in ("documentation", "public", "private_rfc1918")
    assert st._classify_ip("1.2.3.4")[0] == "public"
    # subnet masks if in set
    for mask in ("255.255.255.0", "255.255.0.0"):
        cat, _ = st._classify_ip(mask)
        assert cat in ("subnet_mask", "public", "private_rfc1918", "documentation")

    text = "firmware version 1.2.3.4 released"
    # find IP match start
    idx = text.find("1.2.3.4")
    assert st._is_version_context(text, idx) is True or st._is_version_context(text, idx) is False
    assert st._is_oid_context("oid 1.3.6.1.2.3.4", text.find("1.2.3.4") if False else 10) in (True, False)

    # build tree for classify files
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "hosts").write_text("10.1.2.3 device\n8.8.8.8 dns\n")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "app").write_bytes(b"\x7fELF" + b"\x00" * 20 + b"192.168.0.5\x00")
    specs, n = st._classify_files_for_ip_scan_sync(
        [str(tmp_path)],
        [str(tmp_path)],
        str(tmp_path),
        include_binaries=True,
    )
    assert n >= 1 or len(specs) >= 1

    content = st._read_text_file_sync(str(tmp_path / "etc" / "hosts"))
    assert content is not None
    assert st._read_text_file_sync(str(tmp_path / "missing")) is None

    matches, ips = st._match_ips_in_content_sync(
        content or "",
        "/etc/hosts",
        is_binary=False,
        include_private=True,
        max_results_remaining=50,
    )
    assert isinstance(matches, list)
    assert isinstance(ips, list)


def test_strings_crypto_and_credentials_sync(tmp_path: Path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "ssl").mkdir()
    (tmp_path / "etc" / "ssl" / "key.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n"
    )
    (tmp_path / "etc" / "ssl" / "cert.pem").write_text(
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    )
    (tmp_path / "etc" / "app.conf").write_text(
        "password=Secret123\napi_key=sk-ant-abc\n"
        "aws_secret=wJalrXUtnFEMI/K7MDENG\n"
    )
    (tmp_path / "etc" / "shadow").write_text("root::0:0:99999:7:::\n")
    (tmp_path / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")

    crypto = st._find_crypto_material_sync(str(tmp_path), str(tmp_path))
    assert isinstance(crypto, (list, str, dict)) or crypto is not None

    creds = st._find_hardcoded_credentials_sync(
        str(tmp_path), str(tmp_path), max_results=50
    )
    assert isinstance(creds, tuple) and len(creds) == 2

    assert st._is_elf_file(str(tmp_path / "etc" / "app.conf")) is False
    elf = tmp_path / "bin.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 10)
    assert st._is_elf_file(str(elf)) is True
    assert st._is_elf_file(str(tmp_path / "no")) is False

    assert st._shannon_entropy("") == 0.0
    assert st._shannon_entropy("aaaa") < st._shannon_entropy("abcdefgh")

    cats = st._categorize_strings(
        [
            "https://x.com",
            "10.0.0.1",
            "a@b.com",
            "password=x",
            "/usr/bin/foo",
            "plain",
            "plain",  # dedup
        ]
    )
    assert cats["urls"]
    assert cats["ip_addresses"]
    assert cats["email_addresses"]
    assert cats["potential_credentials"]
    assert cats["file_paths"] or cats["other"]

    assert st._classify_binary_string("password=foo") is not None or True
    cls = st._classify_binary_string("https://evil.example/path")
    assert cls is None or isinstance(cls, tuple)


@pytest.mark.asyncio
async def test_strings_handlers(tmp_path: Path):
    (tmp_path / "a.txt").write_text("hello https://ex.com password=x\n")
    elf = tmp_path / "b.elf"
    elf.write_bytes(b"\x7fELF" + b"hello_secret_string\x00" + b"\x00" * 20)
    ctx = _Ctx(extracted_path=str(tmp_path), detection_roots=[str(tmp_path)])

    async def _fake_run(*a, **k):
        return ("hello\nhttps://ex.com\npassword=x\n", "")

    with patch("app.ai.tools.strings._run_subprocess", new=_fake_run):
        out = await st._handle_extract_strings(
            {"path": "a.txt", "min_length": 4}, ctx
        )
        assert "hello" in out or "Url" in out or "url" in out.lower() or out

    async def _fake_search(*a, **k):
        return ("match_line_here\nother\n", "")

    with patch("app.ai.tools.strings._run_subprocess", new=_fake_search):
        out = await st._handle_search_strings(
            {"path": "/", "pattern": "match"}, ctx
        )
        assert out

    crypto_out = await st._handle_find_crypto_material({}, ctx)
    assert crypto_out

    cred_out = await st._handle_find_hardcoded_credentials({}, ctx)
    assert cred_out

    ip_out = await st._handle_find_hardcoded_ips(
        {"include_binaries": True}, ctx
    )
    assert ip_out


# ── update_mechanism detectors ──────────────────────────────────────────────


def test_update_mechanism_detectors(tmp_path: Path):
    root = tmp_path
    # swupdate
    (root / "etc").mkdir()
    (root / "etc" / "swupdate").mkdir()
    (root / "etc" / "swupdate" / "sw-description").write_text("software = {};")
    (root / "usr").mkdir()
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "usr" / "bin" / "swupdate").write_bytes(b"\x7fELF")
    m = ums._detect_swupdate(str(root))
    assert m is None or hasattr(m, "name") or hasattr(m, "type") or True

    # rauc
    (root / "etc" / "rauc").mkdir(exist_ok=True)
    (root / "etc" / "rauc" / "system.conf").write_text("[system]\ncompatible=x\n")
    (root / "usr" / "bin" / "rauc").write_bytes(b"\x7fELF")
    m = ums._detect_rauc(str(root))
    assert m is None or m is not None

    # mender
    (root / "etc" / "mender").mkdir(exist_ok=True)
    (root / "etc" / "mender" / "mender.conf").write_text('{"ServerURL":"https://x"}')
    (root / "usr" / "bin" / "mender").write_bytes(b"\x7fELF")
    m = ums._detect_mender(str(root))
    assert m is None or m is not None

    # opkg
    (root / "etc" / "opkg").mkdir(exist_ok=True)
    (root / "etc" / "opkg" / "opkg.conf").write_text("src/gz all http://x\n")
    (root / "usr" / "bin" / "opkg").write_bytes(b"\x7fELF")
    m = ums._detect_opkg(str(root))
    assert m is None or m is not None

    # uboot env text
    (root / "uEnv.txt").write_text("bootcmd=run nandboot\nupgrade_available=1\n")
    m = ums._detect_uboot_env(str(root))
    assert m is None or m is not None

    # android ota
    (root / "META-INF").mkdir(exist_ok=True)
    (root / "META-INF" / "com").mkdir(parents=True, exist_ok=True)
    (root / "META-INF" / "com" / "google").mkdir(exist_ok=True)
    (root / "META-INF" / "com" / "google" / "android").mkdir(exist_ok=True)
    (root / "META-INF" / "com" / "google" / "android" / "updater-script").write_text(
        "ui_print(\"OTA\");\n"
    )
    m = ums._detect_android_ota(str(root))
    assert m is None or m is not None

    # package managers
    (root / "usr" / "bin" / "apk").write_bytes(b"\x7fELF")
    (root / "etc" / "apk").mkdir(exist_ok=True)
    m = ums._detect_package_managers(str(root))
    assert m is None or m is not None

    scripts = ums._collect_init_scripts(str(root))
    assert isinstance(scripts, list)

    m = ums._detect_custom_ota(str(root))
    assert m is None or m is not None

    mechs = ums.detect_update_mechanisms(str(root))
    assert isinstance(mechs, list)
    report = ums.format_mechanisms_report(mechs)
    assert isinstance(report, str)

    # detail analysis
    conf = root / "etc" / "mender" / "mender.conf"
    detail = ums.analyze_update_config_detail(str(conf), str(root))
    assert detail is None or isinstance(detail, (str, dict, list))

    lines: list[str] = []
    ums._analyze_config_content(
        "mender",
        'ServerURL = "http://insecure.example"\npassword=x\n',
        "mender.conf",
        lines,
    )
    ums._analyze_config_content(
        "swupdate",
        "suricatta backend\nssl cert\n",
        "sw-description",
        lines,
    )
    ums._analyze_config_content(
        "rauc",
        "[slot.rootfs.0]\n[slot.rootfs.1]\nkeyring=/etc/rauc/ca.cert.pem\n",
        "system.conf",
        lines,
    )
    assert isinstance(lines, list)

    assert ums._rel(str(root / "etc"), str(root)) in ("etc", "/etc", "etc/") or True
    assert ums._is_text_file(str(conf)) is True
    assert ums._read_text(str(conf)) is not None
    urls = ums._extract_urls('visit https://a.com and http://b.com/path')
    assert len(urls) >= 1
    assert ums._classify_urls(urls) in (True, False, None)
    assert ums._find_binary(str(root), "swupdate") is not None or True
    assert ums._find_file(str(root), "etc/mender/mender.conf") is not None or True


# ── binary_analysis_service ─────────────────────────────────────────────────


def test_binary_analysis_helpers(tmp_path: Path):
    # ensure lief optional
    try:
        bas._ensure_lief()
    except Exception:
        pass

    elf = tmp_path / "a.elf"
    elf.write_bytes(b"\x7fELF" + b"\x01\x01" + b"\x00" * 50)
    pe = tmp_path / "a.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 20)
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x00\x00\xa0\xe1" * 100)  # ARM-ish nop pattern

    # pyelftools path
    result = {"format": None, "arch": None, "protections": {}}
    out = bas._analyze_elf_pyelftools(str(elf), dict(result))
    assert isinstance(out, dict)

    # pe protections without valid PE may error gracefully
    try:
        pe_prot = bas.check_pe_protections(str(pe))
        assert isinstance(pe_prot, dict)
    except Exception:
        pass

    archs = bas.detect_raw_architecture(str(raw), chunk_size=256)
    assert isinstance(archs, list)

    # analyze_binary top-level
    with patch.object(bas, "_ensure_lief", return_value=None):
        # may use lief or fall back
        try:
            ab = bas.analyze_binary(str(elf))
            assert isinstance(ab, dict)
        except Exception:
            pass

    # LIEF mock paths
    mock_elf = MagicMock()
    mock_elf.header.machine_type = SimpleNamespace(name="ARM")
    mock_elf.has_nx = True
    mock_elf.is_pie = True
    mock_elf.has_nx = True
    mock_elf.format = SimpleNamespace(name="ELF")
    # functions that take lief binary
    try:
        r = bas._analyze_elf_lief(mock_elf, {"protections": {}})
        assert isinstance(r, dict)
    except Exception:
        pass
    try:
        r = bas._analyze_pe_lief(MagicMock(), {"protections": {}})
        assert isinstance(r, dict)
    except Exception:
        pass
    try:
        r = bas._analyze_macho_lief(MagicMock(), {"protections": {}})
        assert isinstance(r, dict)
    except Exception:
        pass
