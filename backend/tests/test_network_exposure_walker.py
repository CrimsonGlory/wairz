"""C3 network-exposure REACHABILITY-EVIDENCE walker tests (Rule #39 triplet +
Rule #45/#46 parse-only canary + Rule #35b live canary + THE BIND-SCOPE
over-read-guard fixtures).

C3 is the RISKIEST collector — its bind-scope evidence feeds the L4 listener
discriminator; an over-read (loopback mis-read as 0.0.0.0) could FALSELY
promote a CVE to initial_entry. The consumer-side guard is ALREADY BUILT
(the framework caps config_inferred remote binds at chainable + reads BOTH
host AND address keys). These tests assert C3 EMITS the evidence correctly so
that guard works.

Coverage axes:

* **Rule #39 triplet exports** — inner / outer / safe runners exported.
* **Rule #36 + Rule #45 no-execute + no-decrypt + Rule #46 paired
  META-CANARY** — token-scan over ``network_exposure_walker.py`` asserting
  NO subprocess / daemon-start / decrypt / eval / exec. Paired META-CANARY
  confirms the gate fires on a synthetic violation.
* **THE BIND-SCOPE FIXTURES (the converged over-read guard):**
  - loopback ``127.0.0.1`` config → host=127.0.0.1 + NOT remote.
  - unknown / defaulted bind → host=0.0.0.0 + bind_confidence=config_inferred.
  - explicit ``0.0.0.0`` config → host=0.0.0.0 + bind_confidence=config_high
    + remote.
  - an ``address``-keyed listener round-trips (DUAL-KEY: host == address).
  - the over-read guard confirmed: no inferred bind becomes a
    confirmed-remote (runtime_confirmed) listener.
* **Rule #35b LIVE CANARY** — round-trip through the real ORM: run the inner
  runner against a fixture rootfs carrying sshd_config + a systemd .socket +
  a loopback nginx listen, commit, SELECT, assert the listener set + dual
  keys + bind_confidence are populated.
* **Stamp-helper-used** — source scan that the walker writes the JSONB only
  via ``_stamp_firmware_network_exposure_walk_result``.
* **Empty / no-roots** — stable empty-aggregate shape.
"""
from __future__ import annotations

import io
import re
import tokenize
import uuid
from pathlib import Path

import pytest

from app.services import network_exposure_walker
from tests._live_db import make_live_db

# ───────────────────────────────────────────────────────────────────────
# Rule #39 triplet exports.
# ───────────────────────────────────────────────────────────────────────


def test_walker_triplet_exports_all_three_runners():
    assert hasattr(network_exposure_walker, "_do_network_exposure_run")
    assert hasattr(
        network_exposure_walker, "run_network_exposure_walk_background"
    )
    assert hasattr(
        network_exposure_walker, "auto_network_exposure_walk_firmware_safe"
    )


# ───────────────────────────────────────────────────────────────────────
# Rule #36 + Rule #45 no-execute / no-decrypt token-scan + Rule #46
# paired META-CANARY.
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


def _tokens_stripped(src_bytes: bytes) -> str:
    """Tokenize; drop comment + string + structural tokens; join with single
    spaces (so ``subprocess.run`` appears as ``subprocess . run (``).
    Stripping STRING tokens means regex literals + error-message strings
    don't trigger; the gate fires only on actual calls."""
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
    """Rule #36 + Rule #45 gate — token-scan over the walker asserts NO
    forbidden tokens. The walker reads sshd_config / nginx.conf / .socket
    units AS DATA; it NEVER starts a daemon / spawns / decrypts."""
    src_path = Path(network_exposure_walker.__file__)
    with open(src_path, "rb") as fh:
        src_repr = _tokens_stripped(fh.read())
    matches = [
        (p, m.group(0))
        for p in _FORBIDDEN_PATTERNS
        if (m := re.search(p, src_repr))
    ]
    assert not matches, (
        f"Rule #36 + Rule #45 no-execute / no-decrypt gate FIRED on "
        f"network_exposure_walker — forbidden tokens: {matches!r}. The C3 "
        f"network-exposure walker MUST be PARSE-ONLY (reads configs AS DATA; "
        f"never starts a daemon / spawns / decrypts)."
    )


def test_walker_no_execute_gate_actually_fires():
    """Rule #46 paired META-CANARY — synthesize a forbidden-token violation
    IN MEMORY (concatenated string, NOT f-string — tokenize strips f-string
    contents) and confirm the gate WOULD reject it. Without this, the gate
    is a Rule #17 silent-pass instance."""
    synthetic_violation_lines = [
        "import subprocess",
        "result = subprocess.run(['nginx', '-s', 'reload'])",
        "import asyncio",
        "x = asyncio.create_subprocess_exec('sshd')",
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
    """The walker MUST write network_exposure_walk_result only via
    _stamp_firmware_network_exposure_walk_result (Rule #35c)."""
    src = Path(network_exposure_walker.__file__).read_text()
    assigns = re.findall(r"\.network_exposure_walk_result\s*=\s*(.+)", src)
    for rhs in assigns:
        rhs = rhs.strip()
        assert (
            rhs == "("
            or rhs.startswith("None")
            or "_stamp_firmware_network_exposure_walk_result" in src
        ), (
            f"network_exposure_walk_result assigned via {rhs!r} — must use "
            f"_stamp_firmware_network_exposure_walk_result or be a None-clear."
        )
    assert "_stamp_firmware_network_exposure_walk_result" in src


# ───────────────────────────────────────────────────────────────────────
# THE BIND-SCOPE classifier unit table (THE OVER-READ GUARD — pure fns).
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw_host,expected_host,expected_remote,expected_explicit",
    [
        # (a) loopback → host=127.0.0.1, NEVER remote, explicit.
        ("127.0.0.1", "127.0.0.1", False, True),
        ("127.0.0.53", "127.0.0.1", False, True),  # 127.0.0.0/8
        ("::1", "127.0.0.1", False, True),
        ("localhost", "127.0.0.1", False, True),
        # (c) explicit all_interfaces → host=0.0.0.0, remote, explicit.
        ("0.0.0.0", "0.0.0.0", True, True),
        ("*", "0.0.0.0", True, True),
        ("::", "0.0.0.0", True, True),
        # explicit concrete LAN address → kept verbatim, remote, explicit.
        ("192.168.1.1", "192.168.1.1", True, True),
        ("10.0.0.5", "10.0.0.5", True, True),
        # (b) unknown / defaulted → host=0.0.0.0, remote, NOT explicit.
        (None, "0.0.0.0", True, False),
        ("", "0.0.0.0", True, False),
    ],
)
def test_classify_bind_host_over_read_guard(
    raw_host, expected_host, expected_remote, expected_explicit
):
    host, is_remote, is_explicit = network_exposure_walker._classify_bind_host(
        raw_host
    )
    assert host == expected_host
    assert is_remote is expected_remote
    assert is_explicit is expected_explicit


@pytest.mark.parametrize(
    "raw_host,source_runtime,expected_confidence",
    [
        # loopback (explicit) → config_high (config source).
        ("127.0.0.1", False, "config_high"),
        # explicit 0.0.0.0 → config_high.
        ("0.0.0.0", False, "config_high"),
        # unknown / defaulted → config_inferred (THE GUARD).
        (None, False, "config_inferred"),
        # any host from a runtime capture → runtime_confirmed.
        ("0.0.0.0", True, "runtime_confirmed"),
        ("127.0.0.1", True, "runtime_confirmed"),
    ],
)
def test_make_listener_bind_confidence(
    raw_host, source_runtime, expected_confidence
):
    """The 3-way bind_confidence axis (the converged over-read guard):
    runtime_confirmed (live capture) > config_high (explicit directive) >
    config_inferred (inferred/defaulted)."""
    ln = network_exposure_walker._make_listener(
        raw_host=raw_host,
        port=22,
        protocol="tcp",
        owning_process="sshd",
        source_is_runtime=source_runtime,
    )
    assert ln["bind_confidence"] == expected_confidence
    # DUAL-KEY (R51.2 BLOCKING #2): host AND address present + equal.
    assert ln["host"] == ln["address"], "host and address keys must match"


def test_over_read_guard_inferred_never_becomes_runtime_confirmed():
    """THE OVER-READ GUARD, asserted directly: a defaulted/unknown bind
    (raw_host=None, config source) is host=0.0.0.0 (guilty-open for the
    surface) BUT bind_confidence=config_inferred — it MUST NOT carry
    runtime_confirmed (which is the only confidence that lets the framework
    promote toward a confirmed-remote initial_entry HEAD). No inferred bind
    becomes a confirmed remote."""
    ln = network_exposure_walker._make_listener(
        raw_host=None,
        port=8080,
        protocol="tcp",
        owning_process="httpd",
        source_is_runtime=False,
    )
    assert ln["host"] == "0.0.0.0", "unknown bind defaults guilty-open"
    assert ln["address"] == "0.0.0.0"
    assert ln["bind_confidence"] == "config_inferred", (
        "an inferred bind MUST be config_inferred — never runtime_confirmed "
        "(the framework caps config_inferred remote binds at chainable, so an "
        "inferred 0.0.0.0 NEVER mints a confirmed-remote initial_entry HEAD)."
    )
    assert ln["bind_confidence"] != "runtime_confirmed"


# ───────────────────────────────────────────────────────────────────────
# host:port splitter table.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected_host,expected_port",
    [
        ("0.0.0.0:80", "0.0.0.0", 80),
        ("127.0.0.1:8080", "127.0.0.1", 8080),
        ("[::1]:443", "::1", 443),
        ("[::]:443", "::", 443),
        ("80", None, 80),
        ("192.168.1.1", "192.168.1.1", None),
        ("/run/foo.sock", None, None),  # unix socket → not a network listener
    ],
)
def test_split_host_port(value, expected_host, expected_port):
    host, port = network_exposure_walker._split_host_port(value)
    assert host == expected_host
    assert port == expected_port


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
        result = await network_exposure_walker._do_network_exposure_run(
            db, firmware.id
        )
        assert result["listeners"] == []
        assert result["listener_count"] == 0
        assert result["remote_listener_count"] == 0
        assert result["capture_source"] == "config"
        assert any("detection_roots" in e for e in result["errors"])


# ───────────────────────────────────────────────────────────────────────
# THE 3 BIND-SCOPE FIXTURES — end-to-end through the inner runner against a
# real rootfs (the converged over-read-guard fixtures the task mandates).
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_loopback_bind_is_not_remote(tmp_path):
    """FIXTURE 1 — a loopback bind (127.0.0.1) MUST yield host=127.0.0.1 and
    MUST NOT be counted remote. nginx `listen 127.0.0.1:8080;` is the
    canonical loopback-only daemon (the fluent-bit/exporter:7887 worked
    reference). Without this, a loopback daemon would falsely open the REMOTE
    surface → false initial_entry."""
    from app.models.firmware import Firmware

    root = tmp_path / "rootfs"
    (root / "etc" / "nginx").mkdir(parents=True)
    (root / "etc" / "nginx" / "nginx.conf").write_text(
        "http {\n  server {\n    listen 127.0.0.1:8080;\n  }\n}\n"
    )

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="1" * 64,
            original_filename="router.bin",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await network_exposure_walker._do_network_exposure_run(
            db, firmware.id
        )

    listeners = result["listeners"]
    assert len(listeners) == 1
    ln = listeners[0]
    assert ln["host"] == "127.0.0.1", "loopback bind MUST stay 127.0.0.1"
    assert ln["address"] == "127.0.0.1", "dual-key: address mirrors host"
    assert ln["port"] == 8080
    assert ln["owning_process"] == "nginx"
    # The load-bearing guard: a loopback listener is NOT counted remote.
    assert result["remote_listener_count"] == 0, (
        "a loopback-only listener MUST NOT count as a remote bind — else the "
        "framework opens the REMOTE surface and over-claims initial_entry."
    )


@pytest.mark.asyncio
async def test_unknown_bind_defaults_to_all_interfaces_config_inferred(tmp_path):
    """FIXTURE 2 — an UNKNOWN / defaulted bind (sshd_config with a Port but
    NO ListenAddress; dropbear binary present) MUST default to host=0.0.0.0
    (guilty-open, Axiom 1 at the parser seam) BUT carry
    bind_confidence=config_inferred so the framework caps it at chainable
    (never mints a confirmed-remote HEAD from an inferred bind)."""
    from app.models.firmware import Firmware

    root = tmp_path / "rootfs"
    (root / "etc" / "ssh").mkdir(parents=True)
    # Port set, but NO ListenAddress → sshd defaults 0.0.0.0 but NOT stated.
    (root / "etc" / "ssh" / "sshd_config").write_text(
        "# sshd config\nPort 2222\nPermitRootLogin no\n"
    )

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="2" * 64,
            original_filename="device.bin",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await network_exposure_walker._do_network_exposure_run(
            db, firmware.id
        )

    listeners = result["listeners"]
    assert len(listeners) == 1
    ln = listeners[0]
    assert ln["host"] == "0.0.0.0", (
        "an unknown/defaulted bind MUST default to 0.0.0.0 (guilty-open)"
    )
    assert ln["address"] == "0.0.0.0"
    assert ln["port"] == 2222
    assert ln["owning_process"] == "sshd"
    assert ln["bind_confidence"] == "config_inferred", (
        "a sshd Port with NO explicit ListenAddress is config_inferred — the "
        "framework caps it at chainable, NOT initial_entry."
    )
    # It IS counted remote (0.0.0.0 is non-loopback) — surface stays guilty-OPEN.
    assert result["remote_listener_count"] == 1
    assert result["capture_source"] == "config"


@pytest.mark.asyncio
async def test_explicit_zero_bind_is_config_high_remote(tmp_path):
    """FIXTURE 3 — an EXPLICIT 0.0.0.0 bind from a config (sshd_config
    `ListenAddress 0.0.0.0`) MUST carry bind_confidence=config_high + be
    counted remote. config_high is the higher confidence that lets the
    framework promote toward initial_entry (an explicit all-interfaces bind
    is a genuine remote surface, not a parse artefact)."""
    from app.models.firmware import Firmware

    root = tmp_path / "rootfs"
    (root / "etc" / "ssh").mkdir(parents=True)
    (root / "etc" / "ssh" / "sshd_config").write_text(
        "Port 22\nListenAddress 0.0.0.0\n"
    )

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="3" * 64,
            original_filename="exposed.bin",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await network_exposure_walker._do_network_exposure_run(
            db, firmware.id
        )

    listeners = result["listeners"]
    assert len(listeners) == 1
    ln = listeners[0]
    assert ln["host"] == "0.0.0.0"
    assert ln["address"] == "0.0.0.0"
    assert ln["port"] == 22
    assert ln["owning_process"] == "sshd"
    assert ln["bind_confidence"] == "config_high", (
        "an EXPLICIT `ListenAddress 0.0.0.0` is config_high — the framework "
        "may promote it toward initial_entry (genuine remote surface)."
    )
    assert result["remote_listener_count"] == 1


@pytest.mark.asyncio
async def test_address_keyed_listener_round_trips_through_orm(tmp_path):
    """FIXTURE 4 — an address-keyed listener round-trips through the ORM with
    BOTH host AND address keys equal (DUAL-KEY, R51.2 BLOCKING #2). The Linux
    adapter reads host; the Android adapter reads address. Stamp + commit +
    SELECT and assert both keys survive on every listener."""
    from sqlalchemy import select

    from app.models.firmware import Firmware
    from app.services.jsonb_normalizers import (
        _stamp_firmware_network_exposure_walk_result,
    )

    root = tmp_path / "rootfs"
    (root / "etc" / "ssh").mkdir(parents=True)
    (root / "etc" / "ssh" / "sshd_config").write_text(
        "Port 22\nListenAddress 192.168.1.1\n"
    )

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="4" * 64,
            original_filename="ap.bin",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await network_exposure_walker._do_network_exposure_run(
            db, firmware.id
        )
        firmware.network_exposure_walk_result = (
            _stamp_firmware_network_exposure_walk_result(result)
        )
        await db.commit()

        reread = (
            await db.execute(select(Firmware).where(Firmware.id == firmware.id))
        ).scalar_one()
        walk = reread.network_exposure_walk_result
        assert walk is not None
        assert walk["provenance"] == "walker"
        assert walk["schema_version"] == 1
        assert walk["listener_count"] == 1
        ln = walk["listeners"][0]
        # DUAL-KEY survives the JSONB round-trip.
        assert "host" in ln and "address" in ln
        assert ln["host"] == "192.168.1.1"
        assert ln["address"] == "192.168.1.1", (
            "the Android adapter reads `address` — it MUST be present + equal "
            "to host, else Android defaults to 0.0.0.0 → false-remote on every "
            "listener (R51.2 BLOCKING #2)."
        )
        # 192.168.1.1 is a LAN AP-subnet (non-loopback) → remote, config_high.
        assert ln["bind_confidence"] == "config_high"
        assert walk["remote_listener_count"] == 1


# ───────────────────────────────────────────────────────────────────────
# Rule #35b LIVE CANARY — multi-source 3-way exposure round-trip.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_live_canary_multi_source_exposure(tmp_path):
    """Run the inner runner against a fixture rootfs carrying THREE listener
    sources at once — a systemd .socket (+ paired .service for the owning
    daemon), a remote sshd, and a loopback nginx. Round-trip through the ORM
    (stamp + commit + SELECT) and assert the merged listener set + dual keys
    + bind_confidence + remote count are correct."""
    from sqlalchemy import select

    from app.models.firmware import Firmware
    from app.services.jsonb_normalizers import (
        _stamp_firmware_network_exposure_walk_result,
    )

    root = tmp_path / "rootfs"
    # systemd .socket on 0.0.0.0:9100 owned by node_exporter (via .service).
    sysd = root / "etc" / "systemd" / "system"
    sysd.mkdir(parents=True)
    (sysd / "node_exporter.socket").write_text(
        "[Socket]\nListenStream=0.0.0.0:9100\n[Install]\nWantedBy=sockets.target\n"
    )
    (sysd / "node_exporter.service").write_text(
        "[Service]\nExecStart=/usr/bin/node_exporter --web.listen-address\n"
    )
    # sshd on a LAN address (config_high remote).
    (root / "etc" / "ssh").mkdir(parents=True)
    (root / "etc" / "ssh" / "sshd_config").write_text(
        "Port 22\nListenAddress 192.168.1.1\n"
    )
    # nginx loopback-only (NOT remote).
    (root / "etc" / "nginx").mkdir(parents=True)
    (root / "etc" / "nginx" / "nginx.conf").write_text(
        "http { server { listen 127.0.0.1:8080; } }\n"
    )

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="5" * 64,
            original_filename="linux-rootfs.bin",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await network_exposure_walker._do_network_exposure_run(
            db, firmware.id
        )
        firmware.network_exposure_walk_result = (
            _stamp_firmware_network_exposure_walk_result(result)
        )
        await db.commit()

        reread = (
            await db.execute(select(Firmware).where(Firmware.id == firmware.id))
        ).scalar_one()
        walk = reread.network_exposure_walk_result

    by_proc = {ln["owning_process"]: ln for ln in walk["listeners"]}
    assert "node_exporter" in by_proc, (
        "systemd .socket→.service owning-daemon join failed"
    )
    assert by_proc["node_exporter"]["host"] == "0.0.0.0"
    assert by_proc["node_exporter"]["port"] == 9100
    assert by_proc["node_exporter"]["bind_confidence"] == "config_high"

    assert by_proc["sshd"]["host"] == "192.168.1.1"
    assert by_proc["sshd"]["bind_confidence"] == "config_high"

    assert by_proc["nginx"]["host"] == "127.0.0.1"

    # 3 listeners total; 2 remote (node_exporter 0.0.0.0 + sshd LAN), 1 loopback.
    assert walk["listener_count"] == 3
    assert walk["remote_listener_count"] == 2
    # Every listener carries BOTH keys equal (DUAL-KEY invariant).
    for ln in walk["listeners"]:
        assert ln["host"] == ln["address"]


# ───────────────────────────────────────────────────────────────────────
# Runtime-capture source → runtime_confirmed.
# (The Rule #47 registry-membership + ordering tests live in
# test_network_exposure_walker_ordering.py — they land green in the Piece 5
# registration commit so each commit stays bisect-clean.)
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_runtime_capture_yields_runtime_confirmed(tmp_path):
    """A captured `ss -tlnp` dump dropped into the tree is the ONLY source
    that yields runtime_confirmed — the highest confidence the framework can
    promote toward initial_entry without caveat. capture_source flips to
    'runtime'."""
    from app.models.firmware import Firmware

    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "ss.txt").write_text(
        "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        'tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*  users:(("sshd",pid=1,fd=3))\n'
        'tcp   LISTEN 0      128    127.0.0.1:6379     0.0.0.0:*  users:(("redis-server",pid=2,fd=6))\n'
    )

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="6" * 64,
            original_filename="live.bin",
            extracted_path=str(root),
        )
        db.add(firmware)
        await db.flush()
        result = await network_exposure_walker._do_network_exposure_run(
            db, firmware.id
        )

    assert result["capture_source"] == "runtime"
    by_proc = {ln["owning_process"]: ln for ln in result["listeners"]}
    assert by_proc["sshd"]["host"] == "0.0.0.0"
    assert by_proc["sshd"]["bind_confidence"] == "runtime_confirmed"
    assert by_proc["sshd"]["port"] == 22
    # redis on loopback → NOT remote even from a runtime capture.
    assert by_proc["redis-server"]["host"] == "127.0.0.1"
    assert by_proc["redis-server"]["bind_confidence"] == "runtime_confirmed"
    assert result["remote_listener_count"] == 1  # only sshd
