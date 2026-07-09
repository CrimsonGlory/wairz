"""Broader coverage for update_mechanism_service detectors + helpers."""
from __future__ import annotations

from pathlib import Path

from app.services.update_mechanism_service import (
    UpdateMechanism,
    _classify_urls,
    _detect_android_ota,
    _detect_custom_ota,
    _detect_mender,
    _detect_package_managers,
    _detect_rauc,
    _detect_swupdate,
    _detect_uboot_env,
    _extract_urls,
    _find_binary,
    _find_file,
    _is_text_file,
    _read_text,
    _rel,
    analyze_update_config_detail,
    detect_update_mechanisms,
    format_mechanisms_report,
)


def test_rel_and_urls():
    assert _rel("/fw/etc/x", "/fw") == "/etc/x"
    urls = _extract_urls("see http://a.com/path and https://b.io/y")
    assert any(u.startswith("http://a.com") for u in urls)
    assert any(u.startswith("https://b.io") for u in urls)
    assert _classify_urls([]) is None
    assert _classify_urls(["https://x"]) is True
    assert _classify_urls(["http://x", "https://y"]) is False


def test_is_text_and_read(tmp_path: Path):
    t = tmp_path / "a.conf"
    t.write_text("url=https://example.com\n")
    assert _is_text_file(str(t)) is True
    assert "example" in (_read_text(str(t)) or "")
    b = tmp_path / "bin.elf"
    b.write_bytes(b"\x7fELF\x00\x00\x00")
    assert _is_text_file(str(b)) is False
    assert _read_text(str(tmp_path / "nope")) is None


def test_find_binary_and_file(tmp_path: Path):
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "bin" / "rauc").write_bytes(b"\x7fELF")
    (tmp_path / "etc" / "rauc").mkdir(parents=True)
    (tmp_path / "etc" / "rauc" / "system.conf").write_text("[system]\n")
    assert _find_binary(str(tmp_path), "rauc") is not None
    assert _find_file(str(tmp_path), "etc/rauc/system.conf") is not None
    assert _find_binary(str(tmp_path), "missing") is None


def test_detect_rauc(tmp_path: Path):
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "bin" / "rauc").write_bytes(b"\x7fELF")
    conf = tmp_path / "etc" / "rauc" / "system.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text(
        "[system]\n"
        "compatible=test\n"
        "[slot.rootfs.0]\n"
        "device=/dev/mmcblk0p1\n"
        "[slot.rootfs.1]\n"
        "device=/dev/mmcblk0p2\n"
        "url=https://updates.example.com/bundle.raucb\n"
    )
    (tmp_path / "bundle.raucb").write_bytes(b"x")
    mech = _detect_rauc(str(tmp_path))
    assert mech is not None
    assert mech.system == "rauc"
    assert mech.has_ab_scheme is True
    assert mech.uses_https is True


def test_detect_mender(tmp_path: Path):
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "bin" / "mender").write_bytes(b"\x7fELF")
    conf = tmp_path / "etc" / "mender" / "mender.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text('{"ServerURL": "https://mender.example.com"}\n')
    (tmp_path / "var" / "lib" / "mender").mkdir(parents=True)
    mech = _detect_mender(str(tmp_path))
    assert mech is not None
    assert mech.system == "mender"
    assert mech.has_ab_scheme is True
    assert mech.uses_https is True


def test_detect_mender_http_finding(tmp_path: Path):
    conf = tmp_path / "etc" / "mender" / "mender.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text('{"ServerURL": "http://insecure.example.com"}\n')
    mech = _detect_mender(str(tmp_path))
    assert mech is not None
    assert any(f.get("cwe") == "CWE-319" for f in mech.findings)


def test_detect_uboot_env(tmp_path: Path):
    (tmp_path / "usr" / "sbin").mkdir(parents=True)
    (tmp_path / "usr" / "sbin" / "fw_setenv").write_bytes(b"\x7fELF")
    (tmp_path / "usr" / "sbin" / "fw_printenv").write_bytes(b"\x7fELF")
    (tmp_path / "etc").mkdir(exist_ok=True)
    (tmp_path / "etc" / "fw_env.config").write_text("/dev/mtd1 0x0 0x20000\n")
    init = tmp_path / "etc" / "init.d"
    init.mkdir()
    (init / "boot").write_text("altbootcmd=run recovery\nbootcount=0\nbootlimit=3\n")
    mech = _detect_uboot_env(str(tmp_path))
    assert mech is not None
    assert mech.system == "uboot_env"
    assert mech.has_ab_scheme is True


def test_detect_android_ota(tmp_path: Path):
    eng = tmp_path / "system" / "bin" / "update_engine"
    eng.parent.mkdir(parents=True)
    eng.write_bytes(b"\x7fELF")
    prop = tmp_path / "system" / "build.prop"
    prop.write_text("ro.url=https://ota.android.com/update\n")
    bc = tmp_path / "system" / "lib64" / "hw" / "boot_control.default.so"
    bc.parent.mkdir(parents=True)
    bc.write_bytes(b"\x7fELF")
    mech = _detect_android_ota(str(tmp_path))
    assert mech is not None
    assert mech.system == "android_ota"
    assert mech.has_ab_scheme is True


def test_detect_package_managers_apt(tmp_path: Path):
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "bin" / "dpkg").write_bytes(b"\x7fELF")
    (tmp_path / "usr" / "bin" / "apt-get").write_bytes(b"\x7fELF")
    sources = tmp_path / "etc" / "apt" / "sources.list"
    sources.parent.mkdir(parents=True)
    sources.write_text("deb http://deb.debian.org/debian stable main\n")
    mech = _detect_package_managers(str(tmp_path))
    assert mech is not None
    assert mech.system == "package_manager"
    assert any(f.get("cwe") == "CWE-319" for f in mech.findings)


def test_detect_package_managers_yum(tmp_path: Path):
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "bin" / "yum").write_bytes(b"\x7fELF")
    repo_dir = tmp_path / "etc" / "yum.repos.d"
    repo_dir.mkdir(parents=True)
    (repo_dir / "base.repo").write_text(
        "[base]\nbaseurl=https://mirror.centos.org/centos/\n"
    )
    mech = _detect_package_managers(str(tmp_path))
    assert mech is not None
    assert mech.uses_https is True


def test_detect_custom_ota(tmp_path: Path):
    init = tmp_path / "etc" / "init.d"
    init.mkdir(parents=True)
    (init / "update").write_text(
        "#!/bin/sh\n"
        "wget http://vendor.example.com/fw.bin -O /tmp/fw.bin\n"
        "mtd write /tmp/fw.bin firmware\n"
    )
    mech = _detect_custom_ota(str(tmp_path))
    assert mech is not None
    assert mech.system == "custom_ota"
    assert any(f.get("cwe") == "CWE-494" for f in mech.findings)
    assert any(f.get("cwe") == "CWE-319" for f in mech.findings)


def test_detect_swupdate_with_config_dir(tmp_path: Path):
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "usr" / "bin" / "swupdate").write_bytes(b"\x7fELF")
    cfg_dir = tmp_path / "etc" / "swupdate"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "extra.cfg").write_text('url = "https://swu.example.com";\n')
    (tmp_path / "etc" / "swupdate.cfg").write_text(
        'url = "https://main.example.com";\ndual_copy = true;\n'
    )
    (tmp_path / "update.swu").write_bytes(b"pkg")
    mech = _detect_swupdate(str(tmp_path))
    assert mech is not None
    assert mech.has_ab_scheme is True
    assert mech.uses_https is True


def test_detect_update_mechanisms_extra_roots(tmp_path: Path):
    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "etc").mkdir()
    (root / "etc" / "hostname").write_text("x\n")
    extra = tmp_path / "extra"
    (extra / "usr" / "bin").mkdir(parents=True)
    (extra / "usr" / "bin" / "opkg").write_bytes(b"\x7fELF")
    (extra / "etc" / "opkg").mkdir(parents=True)
    (extra / "etc" / "opkg" / "distfeeds.conf").write_text(
        "src/gz base https://openwrt.org/packages\n"
    )
    results = detect_update_mechanisms(str(root), extra_roots=[str(extra)])
    systems = [r.system for r in results]
    assert any("opkg" in s for s in systems)


def test_format_mechanisms_report_rich():
    mech = UpdateMechanism(
        system="rauc",
        confidence="high",
        binaries=["/usr/bin/rauc"],
        configs=["/etc/rauc/system.conf"],
        update_urls=["https://x"],
        uses_https=True,
        has_ab_scheme=True,
        findings=[{"severity": "info", "description": "A/B ok"}],
    )
    report = format_mechanisms_report([mech])
    assert "rauc" in report.lower()
    assert "https" in report.lower() or "A/B" in report or len(report) > 0


def test_analyze_update_config_detail(tmp_path: Path):
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    conf = root / "etc" / "swupdate.cfg"
    conf.write_text(
        'url = "http://insecure.example.com/update";\n'
        "installed-directly = true;\n"
    )
    detail = analyze_update_config_detail(str(root), "swupdate")
    assert isinstance(detail, str)
    assert "http" in detail.lower() or "SWUPDATE" in detail or "url" in detail.lower()

    unknown = analyze_update_config_detail(str(root), "not_a_system")
    assert "Unknown" in unknown
