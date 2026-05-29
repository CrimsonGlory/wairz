"""C3 generic network-exposure / attack-surface REACHABILITY-EVIDENCE collector.

This walker synthesizes, per firmware, the listener → bind-scope →
owning-daemon exposure map the cve-assessment-framework L4 kill-chain
classifier needs to discriminate a kill-chain HEAD (a daemon bound to a
remote interface — an AV:N CVE owned by it can be initial_entry) from a
post-foothold link (a loopback-only daemon — the CVE stays chainable).

C3 is the RISKIEST of the generic collectors. Its bind-scope evidence feeds
the L4 listener discriminator (#2), and an INCORRECT bind-scope is WORSE
than a missing one: a config that binds loopback but is mis-read as
``0.0.0.0`` would FALSELY promote a CVE to ``initial_entry`` — an over-claim
the L4 guilty default CANNOT catch (the classifier trusts the adapter's
measured posture as ground truth). The converged R51.2 over-read guard
(BLOCKING-2/B2/B3) is baked into the EMITTED evidence so the framework
consumer — ALREADY BUILT to cap config_inferred remote binds at chainable
and to read BOTH host AND address keys — can act on it:

  * **THE OVER-READ GUARD (3 cases):**
    (a) A loopback bind (``127.0.0.1`` / ``::1`` / ``localhost`` /
        ``127.0.0.0/8``) → host = ``127.0.0.1``, NEVER classified remote.
    (b) An UNKNOWN / unparseable / DEFAULTED bind → default host =
        ``0.0.0.0`` (all_interfaces, GUILTY per Axiom 1 at the parser seam)
        BUT ``bind_confidence = "config_inferred"`` (so the consumer caps it
        at chainable, NOT initial_entry — never silently mint a
        confirmed-remote HEAD from an inferred bind).
    (c) Only an EXPLICIT remote bind from a config (``config_high``) or a
        live capture (``runtime_confirmed``) carries the higher confidence
        that lets the consumer promote toward initial_entry.

  * **DUAL-KEY EMISSION:** every listener row carries BOTH ``host`` AND
    ``address`` keys (same value). The framework's Linux adapter reads
    ``host``; the Android adapter reads ``address``. The single shared
    ``network/listeners.json`` cannot satisfy two adapter keys without
    emitting both — without ``address`` the Android adapter defaults every
    row to ``0.0.0.0`` (non-loopback) → a false-remote over-claim on EVERY
    listener (the framework-consumer critique's BLOCKING #2).

Listener sources (all PARSE-ONLY, read as DATA across get_detection_roots
per Rule #16):

  * **systemd ``.socket`` units** — ``ListenStream`` / ``ListenDatagram``
    bind+port, joined to the paired ``.service`` ``ExecStart`` for the
    owning daemon (reuses :func:`systemd_walker.parse_systemd_unit_text` +
    :func:`systemd_walker._extract_port`).
  * **sshd_config** — ``Port`` / ``ListenAddress`` (owning: sshd).
  * **dropbear** — default ssh on 22 (owning: dropbear).
  * **nginx** — ``listen`` directives (owning: nginx).
  * **dnsmasq** — ``interface=`` / ``listen-address`` / ``port`` +
    ``bind-interfaces`` (owning: dnsmasq).
  * **inetd / xinetd** — ``inetd.conf`` service lines + ``xinetd.d/*``
    ``bind`` / ``port`` (owning: the service binary named in the line).
  * **captured ss/netstat output** — a ``runtime_confirmed`` source when an
    operator dropped a ``ss -tlnp`` / ``netstat -tlnp`` capture into the
    tree (the only source that yields ``runtime_confirmed``).

Cross-platform: Linux rootfs (systemd / sshd / nginx / dnsmasq) + Android
(``init*.rc`` ``socket`` stanzas — surfaced as config_inferred). RTOS /
bare-metal → no listener sources found → empty aggregate (guilty-safe no-op;
a missed listener stays chainable, never over-claims).

Three functions per CLAUDE.md Rule #39 (inner/outer/safe triplet):

  - :func:`_do_network_exposure_run` — INNER pure-logic orchestrator.
    Caller owns the session + transaction. Resolves detection roots
    (Rule #16). Walks every listener source, resolves the owning daemon +
    bind-scope + confidence per listener, emits BOTH host AND address keys.
    Returns the result aggregate UNSTAMPED (caller stamps via
    ``_stamp_firmware_network_exposure_walk_result``). Clears stale
    ``network_exposure_walk_result`` at entry.

  - :func:`run_network_exposure_walk_background` — OUTER Rule #33 .a state
    machine. Owns its own ``async_session_factory()``. Cycles
    ``queued → running → completed | failed``. Failure persistence on a
    FRESH session (the inner session rolled back).

  - :func:`auto_network_exposure_walk_firmware_safe` — SAFE
    unpack-post-detection hook. Owns own session. Stamps the result so
    operators see the last-known result. Does NOT mutate
    ``network_exposure_walk_status`` (leaves it ``idle`` so an
    operator-triggered re-walk via ``trigger_network_exposure_walk`` MCP
    tool works without a 409 conflict).

**Rule #36 + Rule #45 PARSE-ONLY contract.** The walker reads sshd_config /
nginx.conf / dnsmasq.conf / ``.socket`` units / inetd.conf / captured
ss output AS DATA. It NEVER passes any path to a spawn primitive
(``subprocess`` / ``os.system`` / ``exec`` / ``runpy`` / etc.) — it NEVER
STARTS a daemon — and NEVER decrypts anything. Test gate
``test_network_exposure_walker.py::test_walker_no_execute_no_decrypt``
enforces via tokenize-walk; Rule #46 paired META-CANARY confirms the gate
fires on a synthetic violation.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os
import re
import traceback
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_network_exposure_walk_result,
)
from app.services.systemd_walker import _extract_port, parse_systemd_unit_text

logger = logging.getLogger(__name__)


# ── Bounds (Rule #5). ───────────────────────────────────────────────────────
# Per-walk hard cap on listeners emitted — a pathological config must not
# blow the JSONB past the 30 KB MCP truncation ceiling.
_MAX_LISTENERS_PER_WALK = 2000
# A daemon config file (sshd_config / nginx.conf / dnsmasq.conf) is small;
# cap the read defensively.
_MAX_CONFIG_TEXT_BYTES = 4 * 1024 * 1024
# A captured ss/netstat dump is small; cap defensively.
_MAX_CAPTURE_TEXT_BYTES = 8 * 1024 * 1024
# Per-walk hard cap on candidate files scanned (the os.walk envelope) so a
# huge tree doesn't stall even when few are config files.
_MAX_CANDIDATES_PER_WALK = 300_000


# ── Bind-scope grammar (closed; no eval). ───────────────────────────────────
#
# THE OVER-READ GUARD lives here. The classifier is conservative:
#   - An EXPLICIT loopback bind → host="127.0.0.1", remote=False.
#   - An EXPLICIT non-loopback bind → host=<that addr>, remote=True.
#   - A wildcard / all-interfaces bind → host="0.0.0.0", remote=True.
#   - An UNKNOWN / unparseable bind → host="0.0.0.0", remote=True BUT the
#     CALLER stamps bind_confidence="config_inferred" so the framework caps
#     it at chainable. (Guilty for the surface-OPEN question — Axiom 1 — but
#     NOT a confident initial_entry HEAD.)

# Loopback host literals (IPv4 + IPv6 + the localhost name). The /8 check is
# done numerically below for 127.0.0.0/8.
_LOOPBACK_LITERALS: frozenset[str] = frozenset({
    "127.0.0.1",
    "::1",
    "[::1]",
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
})

# Wildcard / all-interfaces host literals → host normalised to "0.0.0.0".
_WILDCARD_LITERALS: frozenset[str] = frozenset({
    "0.0.0.0",
    "*",
    "::",
    "[::]",
    "0000:0000:0000:0000:0000:0000:0000:0000",
})

# The canonical guilty default host for an unknown / wildcard / missing bind.
_DEFAULT_HOST = "0.0.0.0"
_LOOPBACK_HOST = "127.0.0.1"


def _is_loopback_host(host: str) -> bool:
    """True iff ``host`` resolves to the loopback scope (the NEVER-remote
    case). PURE — no DNS, no I/O. Handles the 127.0.0.0/8 IPv4 block + the
    IPv6 ::1 + the localhost name."""
    if not host:
        return False
    h = host.strip().strip("[]").lower()
    if h in _LOOPBACK_LITERALS:
        return True
    # 127.0.0.0/8 — any 127.x.y.z is loopback.
    parts = h.split(".")
    if len(parts) == 4 and parts[0] == "127":
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return True
        except ValueError:
            return False
    return False


def _classify_bind_host(raw_host: str | None) -> tuple[str, bool, bool]:
    """Classify a raw bind-host string into ``(host, is_remote, is_explicit)``.

    THE OVER-READ GUARD (closed grammar; PURE — no I/O):

      * ``raw_host`` is None / empty → ``(_DEFAULT_HOST, True, False)`` —
        unknown / defaulted; guilty-open for the surface but NOT explicit, so
        the caller stamps ``config_inferred`` (consumer caps at chainable).
      * loopback literal / 127.0.0.0/8 / ::1 / localhost →
        ``(_LOOPBACK_HOST, False, True)`` — EXPLICIT loopback; NEVER remote.
      * wildcard / all-interfaces literal → ``(_DEFAULT_HOST, True, True)`` —
        EXPLICIT all_interfaces; remote + explicit.
      * any other parseable address → ``(<that addr>, True, True)`` —
        EXPLICIT non-loopback (e.g. a LAN AP-subnet ``192.168.1.1``); remote
        + explicit.

    ``is_explicit`` distinguishes a parsed-from-config bind (→ config_high)
    from a defaulted/unknown bind (→ config_inferred). It NEVER upgrades a
    runtime capture — the runtime_confirmed confidence is set by the CALLER
    based on the SOURCE, not the host string.
    """
    if raw_host is None:
        return _DEFAULT_HOST, True, False
    h = raw_host.strip()
    if not h:
        return _DEFAULT_HOST, True, False
    low = h.strip("[]").lower()
    if low in _WILDCARD_LITERALS or h in _WILDCARD_LITERALS:
        return _DEFAULT_HOST, True, True
    if _is_loopback_host(h):
        return _LOOPBACK_HOST, False, True
    # An explicitly-parsed concrete address (LAN / public). Keep it verbatim
    # so the framework's loopback-set membership test is exact; it is remote
    # (non-loopback) and explicit.
    return h, True, True


def _split_host_port(value: str) -> tuple[str | None, int | None]:
    """Split a ``host:port`` / ``[ipv6]:port`` / bare-port / bare-host bind
    string into ``(host, port)``. PURE — no I/O.

    Examples::

        "0.0.0.0:80"        → ("0.0.0.0", 80)
        "127.0.0.1:8080"    → ("127.0.0.1", 8080)
        "[::1]:443"         → ("::1", 443)
        "80"                → (None, 80)        # bare port → host unknown
        "192.168.1.1"       → ("192.168.1.1", None)  # bare host → port unknown
        "/run/foo.sock"     → (None, None)      # unix socket → not a network listener
    """
    if not value:
        return None, None
    v = value.strip()
    if v.startswith("/"):
        return None, None  # unix domain socket — not a network listener
    # Bracketed IPv6 [host]:port or [host].
    if v.startswith("["):
        end = v.find("]")
        if end != -1:
            host = v[1 : end]
            rest = v[end + 1 :]
            port = None
            if rest.startswith(":"):
                port = _extract_port(rest[1:])
            return (host or None), port
    # Bare port (all digits)?
    if v.isdigit():
        return None, _extract_port(v)
    # host:port — but an unbracketed IPv6 has many colons; only treat the
    # LAST colon as the port separator when the tail is numeric.
    if ":" in v:
        host_part, _, port_part = v.rpartition(":")
        port = _extract_port(port_part)
        if port is not None and host_part:
            return host_part, port
        # tail not numeric → whole thing is a host (e.g. a bare IPv6).
        return v, None
    # Bare host, no port.
    return v, None


# ── A single emitted listener (pre-stamp dict builder). ─────────────────────


def _make_listener(
    *,
    raw_host: str | None,
    port: int | None,
    protocol: str,
    owning_process: str | None,
    source_is_runtime: bool,
) -> dict:
    """Build one canonical listener dict with the dual-key + bind_confidence
    over-read guard applied. PURE — no I/O.

    bind_confidence resolution:
      * source_is_runtime          → "runtime_confirmed"
      * explicit config bind        → "config_high"
      * inferred / unknown bind     → "config_inferred"
    """
    host, _is_remote, is_explicit = _classify_bind_host(raw_host)
    if source_is_runtime:
        bind_confidence = "runtime_confirmed"
    elif is_explicit:
        bind_confidence = "config_high"
    else:
        bind_confidence = "config_inferred"
    return {
        # DUAL-KEY (R51.2 BLOCKING #2): host for the Linux adapter, address
        # for the Android adapter — SAME value.
        "host": host,
        "address": host,
        "port": port,
        "protocol": protocol,
        "owning_process": owning_process,
        "bind_confidence": bind_confidence,
    }


# ── Sync filesystem helpers (Rule #5 — wrapped in run_in_executor). ─────────


def _read_text_file_sync(path: str, cap: int) -> str | None:
    """Read up to ``cap`` bytes of a text file (sync), decode best-effort."""
    try:
        with open(path, "rb") as fh:  # noqa: ASYNC240 — sync helper run via executor
            data = fh.read(cap)
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


# systemd .socket / .service unit-search dirs (mirror systemd_walker).
_SYSTEMD_DIRS: tuple[str, ...] = (
    "etc/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
    "run/systemd/system",
)

# A captured ss/netstat dump file (operator-dropped); these names signal a
# runtime_confirmed source.
_CAPTURE_FILENAMES: frozenset[str] = frozenset({
    "ss.txt",
    "ss-tlnp.txt",
    "netstat.txt",
    "netstat-tlnp.txt",
    "listeners.txt",
    "ss_output.txt",
})

# All ListenStream / ListenDatagram-style [Socket] keys (TCP vs UDP).
_SOCKET_TCP_KEYS = ("ListenStream", "ListenSequentialPacket")
_SOCKET_UDP_KEYS = ("ListenDatagram",)

# sshd_config directive matchers (whitespace-delimited, case-insensitive).
_SSHD_PORT_RE = re.compile(r"^\s*Port\s+(\d+)\s*$", re.IGNORECASE)
_SSHD_LISTENADDR_RE = re.compile(r"^\s*ListenAddress\s+(\S+)\s*$", re.IGNORECASE)

# nginx `listen` directive (inside server{}); strips a trailing `;` + flags.
# nginx config is `;`-and-`{}`-delimited, NOT line-delimited — a `listen`
# directive may appear mid-line (e.g. `server { listen 80; }`). Anchor on a
# `listen` token preceded by a statement boundary (start / `;` / `{` / `}` /
# whitespace) so both own-line and inline forms are caught. The capture stops
# at the terminating `;`.
_NGINX_LISTEN_RE = re.compile(
    r"(?:^|[;{}\s])listen\s+([^;{}]+);", re.IGNORECASE
)

# dnsmasq directives.
_DNSMASQ_PORT_RE = re.compile(r"^\s*port\s*=\s*(\d+)\s*$", re.IGNORECASE)
_DNSMASQ_LISTEN_RE = re.compile(
    r"^\s*listen-address\s*=\s*(\S+)\s*$", re.IGNORECASE
)

# A captured `ss -tlnp` / `netstat -tlnp` line. We extract proto + local
# address:port. Example ss line:
#   tcp   LISTEN 0  128  0.0.0.0:22   0.0.0.0:*  users:(("sshd",pid=1,fd=3))
_SS_LINE_RE = re.compile(
    r"^\s*(tcp6?|udp6?)\b.*?\bLISTEN\b\s+\S+\s+\S+\s+(\S+)\s+\S+(.*)$",
    re.IGNORECASE,
)
# A netstat line: Proto Recv-Q Send-Q Local-Address Foreign-Address State PID/Program
_NETSTAT_LINE_RE = re.compile(
    r"^\s*(tcp6?|udp6?)\s+\d+\s+\d+\s+(\S+)\s+\S+\s+(?:LISTEN\b)?(.*)$",
    re.IGNORECASE,
)
# Pull the program name out of an ss/netstat process column.
_SS_PROC_RE = re.compile(r'\("([^"]+)"')
_NETSTAT_PROC_RE = re.compile(r"\d+/(\S+)")


def _parse_socket_unit_listen(text: str) -> list[tuple[str | None, int | None, str]]:
    """Parse every ListenStream/ListenDatagram from a .socket unit body.

    Returns ``[(raw_host, port, protocol), ...]``. A .socket can declare
    MULTIPLE ListenStream lines, so we re-scan the raw text (the shared
    parse_systemd_unit_text keeps only the last scalar for non-list keys).
    PURE — no I/O.
    """
    out: list[tuple[str | None, int | None, str]] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()
        if not value:
            continue
        if key in _SOCKET_TCP_KEYS:
            proto = "tcp"
        elif key in _SOCKET_UDP_KEYS:
            proto = "udp"
        else:
            continue
        host, port = _split_host_port(value)
        if port is None and host is None:
            # A unix-domain ListenStream (path) — not a network listener.
            continue
        out.append((host, port, proto))
    return out


def _service_exec_binary(service_text: str) -> str | None:
    """Resolve the owning daemon name from a .service ExecStart. PURE."""
    sections = parse_systemd_unit_text(service_text)
    svc = sections.get("Service", {})
    exec_start = svc.get("ExecStart")
    if isinstance(exec_start, list):
        exec_start = exec_start[-1] if exec_start else None
    if not exec_start:
        return None
    # Strip leading systemd exec prefixes (-, @, +, !, !!).
    cmd = str(exec_start).lstrip("-@+!").strip()
    if not cmd:
        return None
    first = cmd.split()[0]
    return os.path.basename(first) or None


def _collect_systemd_socket_listeners_sync(
    root_path: str,
) -> tuple[list[dict], list[str]]:
    """Walk one detection root's systemd dirs for .socket listeners.

    Joins each .socket to its paired .service (same basename, or the
    Socket=/Service= directive) for the owning-daemon name. Returns
    ``(listeners, errors)``. PARSE-ONLY (reads unit text AS DATA).
    """
    listeners: list[dict] = []
    errors: list[str] = []
    for sysdir in _SYSTEMD_DIRS:
        base = os.path.join(root_path, sysdir)
        if not os.path.isdir(base):
            continue
        try:
            entries = sorted(os.listdir(base))
        except OSError:
            continue
        for entry in entries:
            if not entry.endswith(".socket"):
                continue
            sock_path = os.path.join(base, entry)
            if not os.path.isfile(sock_path):
                continue
            text = _read_text_file_sync(sock_path, _MAX_CONFIG_TEXT_BYTES)
            if not text:
                continue
            listen_rows = _parse_socket_unit_listen(text)
            if not listen_rows:
                continue
            # Owning daemon: paired .service (same basename) ExecStart, or the
            # [Socket] Service= directive's basename.
            unit_base = entry[: -len(".socket")]
            owning = None
            svc_name = f"{unit_base}.service"
            svc_path = os.path.join(base, svc_name)
            if os.path.isfile(svc_path):
                svc_text = _read_text_file_sync(
                    svc_path, _MAX_CONFIG_TEXT_BYTES
                )
                if svc_text:
                    owning = _service_exec_binary(svc_text)
            if owning is None:
                # Fall back to the socket unit's own [Socket] Service= name.
                sections = parse_systemd_unit_text(text)
                svc_directive = sections.get("Socket", {}).get("Service")
                if isinstance(svc_directive, str) and svc_directive:
                    owning = svc_directive.removesuffix(".service")
                else:
                    owning = unit_base
            for raw_host, port, proto in listen_rows:
                listeners.append(
                    _make_listener(
                        raw_host=raw_host,
                        port=port,
                        protocol=proto,
                        owning_process=owning,
                        source_is_runtime=False,
                    )
                )
    return listeners, errors


def _collect_sshd_listeners_sync(root_path: str) -> list[dict]:
    """Parse sshd_config Port / ListenAddress (owning: sshd). PARSE-ONLY.

    sshd defaults: if NO ListenAddress, sshd binds 0.0.0.0 (+ ::) on each
    Port. We surface one listener per (ListenAddress × Port) cross-product;
    a bare Port with no ListenAddress → 0.0.0.0 with config_inferred (the
    default IS 0.0.0.0 but it was not explicitly stated)."""
    candidates = (
        os.path.join(root_path, "etc", "ssh", "sshd_config"),
        os.path.join(root_path, "etc", "sshd_config"),
    )
    listeners: list[dict] = []
    for cfg_path in candidates:
        if not os.path.isfile(cfg_path):
            continue
        text = _read_text_file_sync(cfg_path, _MAX_CONFIG_TEXT_BYTES)
        if not text:
            continue
        ports: list[int] = []
        addrs: list[str] = []
        for line in text.splitlines():
            m = _SSHD_PORT_RE.match(line)
            if m:
                p = _extract_port(m.group(1))
                if p is not None:
                    ports.append(p)
                continue
            m = _SSHD_LISTENADDR_RE.match(line)
            if m:
                addrs.append(m.group(1).strip())
        if not ports:
            ports = [22]  # sshd default port
        if addrs:
            # EXPLICIT ListenAddress → config_high.
            for addr in addrs:
                host_only, addr_port = _split_host_port(addr)
                for p in ports:
                    listeners.append(
                        _make_listener(
                            raw_host=host_only if host_only else addr,
                            port=addr_port or p,
                            protocol="tcp",
                            owning_process="sshd",
                            source_is_runtime=False,
                        )
                    )
        else:
            # NO ListenAddress → sshd defaults to 0.0.0.0, but it was NOT
            # explicitly stated → config_inferred (the guilty-but-not-HEAD
            # case). raw_host=None drives the config_inferred branch.
            for p in ports:
                listeners.append(
                    _make_listener(
                        raw_host=None,
                        port=p,
                        protocol="tcp",
                        owning_process="sshd",
                        source_is_runtime=False,
                    )
                )
    return listeners


def _collect_dropbear_listeners_sync(root_path: str) -> list[dict]:
    """Surface a dropbear SSH listener when the dropbear binary / its
    init.d service is present (owning: dropbear). dropbear's bind is set on
    its command line at runtime, not in a config file, so it is
    config_inferred (default 0.0.0.0:22). PARSE-ONLY — only PRESENCE is
    checked; no execution."""
    present = False
    for rel in (
        os.path.join("usr", "sbin", "dropbear"),
        os.path.join("sbin", "dropbear"),
        os.path.join("usr", "bin", "dropbear"),
        os.path.join("etc", "init.d", "dropbear"),
        os.path.join("etc", "default", "dropbear"),
    ):
        if os.path.exists(os.path.join(root_path, rel)):
            present = True
            break
    if not present:
        return []
    return [
        _make_listener(
            raw_host=None,  # bind set on cmdline → inferred default 0.0.0.0
            port=22,
            protocol="tcp",
            owning_process="dropbear",
            source_is_runtime=False,
        )
    ]


def _collect_nginx_listeners_sync(root_path: str) -> list[dict]:
    """Parse nginx `listen` directives (owning: nginx). PARSE-ONLY.

    Scans nginx.conf + conf.d/*.conf + sites-enabled/*. A `listen 80;` (no
    address) → bare port → host unknown → config_inferred default 0.0.0.0.
    A `listen 127.0.0.1:8080;` → explicit loopback → NOT remote. A
    `listen 0.0.0.0:80;` → explicit all_interfaces → config_high remote."""
    conf_paths: list[str] = []
    for rel in (
        os.path.join("etc", "nginx", "nginx.conf"),
        os.path.join("usr", "local", "nginx", "conf", "nginx.conf"),
    ):
        full = os.path.join(root_path, rel)
        if os.path.isfile(full):
            conf_paths.append(full)
    for confd_rel in (
        os.path.join("etc", "nginx", "conf.d"),
        os.path.join("etc", "nginx", "sites-enabled"),
    ):
        confd = os.path.join(root_path, confd_rel)
        if os.path.isdir(confd):
            try:
                for name in sorted(os.listdir(confd)):
                    full = os.path.join(confd, name)
                    if os.path.isfile(full):
                        conf_paths.append(full)
            except OSError:
                continue
    listeners: list[dict] = []
    seen: set[tuple[str, int | None, str]] = set()
    for cfg_path in conf_paths:
        text = _read_text_file_sync(cfg_path, _MAX_CONFIG_TEXT_BYTES)
        if not text:
            continue
        # nginx config is `;`/`{}`-delimited (not line-delimited), so scan the
        # WHOLE text with finditer — a `listen` directive may sit inline
        # (`server { listen 80; }`). Comments (`#` to EOL) are dropped first so
        # a commented-out `listen` doesn't match.
        decommented = "\n".join(
            ln.split("#", 1)[0] for ln in text.splitlines()
        )
        for m in _NGINX_LISTEN_RE.finditer(decommented):
            spec = m.group(1).strip()
            # First token is the address/port; remaining tokens are flags
            # (ssl, http2, default_server, ...).
            first = spec.split()[0] if spec.split() else spec
            proto = "tcp"
            host, port = _split_host_port(first)
            if host is None and port is None:
                continue
            listener = _make_listener(
                raw_host=host,
                port=port,
                protocol=proto,
                owning_process="nginx",
                source_is_runtime=False,
            )
            key = (listener["host"], listener["port"], proto)
            if key in seen:
                continue
            seen.add(key)
            listeners.append(listener)
    return listeners


def _collect_dnsmasq_listeners_sync(root_path: str) -> list[dict]:
    """Parse dnsmasq listen-address / port (owning: dnsmasq). PARSE-ONLY.

    dnsmasq defaults to binding all interfaces on port 53 unless
    listen-address is set. A bare `port=5353` with no listen-address →
    config_inferred default 0.0.0.0. An explicit `listen-address=127.0.0.1`
    → explicit loopback → NOT remote."""
    cfg_paths: list[str] = []
    for rel in (
        os.path.join("etc", "dnsmasq.conf"),
    ):
        full = os.path.join(root_path, rel)
        if os.path.isfile(full):
            cfg_paths.append(full)
    confd = os.path.join(root_path, "etc", "dnsmasq.d")
    if os.path.isdir(confd):
        try:
            for name in sorted(os.listdir(confd)):
                full = os.path.join(confd, name)
                if os.path.isfile(full):
                    cfg_paths.append(full)
        except OSError:
            pass
    if not cfg_paths:
        return []
    port = 53
    addrs: list[str] = []
    for cfg_path in cfg_paths:
        text = _read_text_file_sync(cfg_path, _MAX_CONFIG_TEXT_BYTES)
        if not text:
            continue
        for line in text.splitlines():
            m = _DNSMASQ_PORT_RE.match(line)
            if m:
                p = _extract_port(m.group(1))
                if p is not None:
                    port = p
                continue
            m = _DNSMASQ_LISTEN_RE.match(line)
            if m:
                addrs.append(m.group(1).strip())
    if port == 0:
        return []  # dnsmasq port=0 disables DNS
    listeners: list[dict] = []
    if addrs:
        for addr in addrs:
            host_only, _ = _split_host_port(addr)
            listeners.append(
                _make_listener(
                    raw_host=host_only if host_only else addr,
                    port=port,
                    protocol="udp",
                    owning_process="dnsmasq",
                    source_is_runtime=False,
                )
            )
    else:
        # No listen-address → dnsmasq binds all interfaces, but not stated →
        # config_inferred.
        listeners.append(
            _make_listener(
                raw_host=None,
                port=port,
                protocol="udp",
                owning_process="dnsmasq",
                source_is_runtime=False,
            )
        )
    return listeners


def _parse_capture_line(line: str) -> dict | None:
    """Parse one ss/netstat LISTEN line → a runtime_confirmed listener dict.
    PURE. Returns None for non-LISTEN / non-matching lines."""
    proto = None
    local = None
    tail = ""
    m = _SS_LINE_RE.match(line)
    if m:
        proto, local, tail = m.group(1), m.group(2), m.group(3)
    else:
        m = _NETSTAT_LINE_RE.match(line)
        if m and "LISTEN" in line.upper():
            proto, local, tail = m.group(1), m.group(2), m.group(3)
    if not proto or not local:
        return None
    protocol = "udp" if proto.lower().startswith("udp") else "tcp"
    host, port = _split_host_port(local)
    if host is None and port is None:
        return None
    # Owning process from the trailing column.
    owning = None
    pm = _SS_PROC_RE.search(tail)
    if pm:
        owning = pm.group(1)
    else:
        pm = _NETSTAT_PROC_RE.search(tail)
        if pm:
            owning = pm.group(1)
    return _make_listener(
        raw_host=host,
        port=port,
        protocol=protocol,
        owning_process=owning,
        source_is_runtime=True,  # ss/netstat → runtime_confirmed
    )


def _collect_runtime_capture_listeners_sync(root_path: str) -> list[dict]:
    """Find a captured ss/netstat dump at a well-known top-level name and
    parse it → runtime_confirmed listeners. PARSE-ONLY."""
    listeners: list[dict] = []
    try:
        top = sorted(os.listdir(root_path))
    except OSError:
        return []
    for name in top:
        if name.lower() not in _CAPTURE_FILENAMES:
            continue
        full = os.path.join(root_path, name)
        if not os.path.isfile(full):
            continue
        text = _read_text_file_sync(full, _MAX_CAPTURE_TEXT_BYTES)
        if not text:
            continue
        for line in text.splitlines():
            entry = _parse_capture_line(line)
            if entry is not None:
                listeners.append(entry)
    return listeners


def _collect_all_listeners_sync(root_path: str) -> tuple[list[dict], list[str]]:
    """Run every listener source against one detection root (sync, bounded).

    Returns ``(listeners, errors)``. PARSE-ONLY across the board.
    """
    listeners: list[dict] = []
    errors: list[str] = []

    sock_listeners, sock_errors = _collect_systemd_socket_listeners_sync(
        root_path
    )
    listeners.extend(sock_listeners)
    errors.extend(sock_errors)
    listeners.extend(_collect_sshd_listeners_sync(root_path))
    listeners.extend(_collect_dropbear_listeners_sync(root_path))
    listeners.extend(_collect_nginx_listeners_sync(root_path))
    listeners.extend(_collect_dnsmasq_listeners_sync(root_path))
    listeners.extend(_collect_runtime_capture_listeners_sync(root_path))
    return listeners, errors


def _dedup_listeners(listeners: list[dict]) -> list[dict]:
    """De-duplicate listeners on (host, port, protocol, owning_process),
    preferring the HIGHEST-confidence row (runtime_confirmed > config_high >
    config_inferred). PURE."""
    rank = {"runtime_confirmed": 3, "config_high": 2, "config_inferred": 1}
    best: dict[tuple, dict] = {}
    for ln in listeners:
        key = (
            ln["host"],
            ln["port"],
            ln["protocol"],
            ln["owning_process"],
        )
        cur = best.get(key)
        if cur is None or rank.get(ln["bind_confidence"], 0) > rank.get(
            cur["bind_confidence"], 0
        ):
            best[key] = ln
    out = list(best.values())
    out.sort(
        key=lambda m: (
            m["host"],
            m["port"] if m["port"] is not None else 0,
            m["protocol"],
            m["owning_process"] or "",
        )
    )
    return out


# ---------------------------------------------------------------------------
# INNER pure-logic walker (Rule #39).
# ---------------------------------------------------------------------------


async def _do_network_exposure_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict:
    """INNER pure-logic orchestrator.

    Caller owns the session + transaction. Resolves detection roots
    (Rule #16). Walks every listener source (systemd .socket / sshd /
    dropbear / nginx / dnsmasq / captured ss output), resolves the owning
    daemon + bind-scope + bind_confidence per listener (THE OVER-READ GUARD),
    emits BOTH host AND address keys. Returns the result aggregate UNSTAMPED.
    Clears stale ``network_exposure_walk_result`` at entry.
    """
    walked_at = dt.datetime.now(dt.UTC).isoformat()

    firmware = await db.get(Firmware, firmware_id)
    if firmware is None:
        return _empty_aggregate(walked_at, [f"firmware {firmware_id} not found"])

    # Clear stale JSONB at entry (mirrors C1 / C2 + the ICS δ-mitigation).
    firmware.network_exposure_walk_result = None

    detection_roots = await get_detection_roots(firmware, db=db)
    if not detection_roots:
        return _empty_aggregate(
            walked_at,
            ["no detection_roots for firmware (extraction may have failed)"],
        )

    loop = asyncio.get_running_loop()
    errors: list[str] = []
    all_listeners: list[dict] = []
    candidates_total = 0

    for root_path in detection_roots:
        if candidates_total >= _MAX_CANDIDATES_PER_WALK:
            errors.append(
                f"reached _MAX_CANDIDATES_PER_WALK={_MAX_CANDIDATES_PER_WALK}; "
                f"later roots skipped"
            )
            break
        candidates_total += 1
        listeners, root_errors = await loop.run_in_executor(
            None, _collect_all_listeners_sync, root_path
        )
        all_listeners.extend(listeners)
        errors.extend(root_errors)
        if len(all_listeners) >= _MAX_LISTENERS_PER_WALK:
            errors.append(
                f"reached _MAX_LISTENERS_PER_WALK={_MAX_LISTENERS_PER_WALK}; "
                f"some listeners not emitted (listener_count is a lower bound)"
            )
            all_listeners = all_listeners[:_MAX_LISTENERS_PER_WALK]
            break

    listeners_final = _dedup_listeners(all_listeners)

    # capture_source: "runtime" iff ANY listener is runtime_confirmed.
    any_runtime = any(
        ln["bind_confidence"] == "runtime_confirmed" for ln in listeners_final
    )
    capture_source = "runtime" if any_runtime else "config"

    # remote_listener_count: a listener is remote iff its host is NOT loopback.
    remote_count = sum(
        1 for ln in listeners_final if not _is_loopback_host(ln["host"])
    )

    return {
        "walked_at": walked_at,
        "capture_source": capture_source,
        "listeners": listeners_final,
        "listener_count": len(listeners_final),
        "remote_listener_count": remote_count,
        "errors": errors,
    }


def _empty_aggregate(walked_at: str, errors: list[str]) -> dict:
    """Stable empty-result shape (firmware missing / no detection roots)."""
    return {
        "walked_at": walked_at,
        "capture_source": "config",
        "listeners": [],
        "listener_count": 0,
        "remote_listener_count": 0,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# OUTER state-machine wrapper (Rule #33 .a + Rule #39).
# ---------------------------------------------------------------------------


async def run_network_exposure_walk_background(firmware_id: uuid.UUID) -> None:
    """OUTER wrapper — owns the Rule #33 .a state machine + outer guard.

    Transitions ``firmware.network_exposure_walk_status``:
        queued (set by caller via MCP trigger)
          → running (this fn, on entry)
          → completed | failed (this fn, on exit)

    Failure persistence on a FRESH session (the inner session rolled back on
    the exception). On failure, ``network_exposure_walk_result`` is cleared.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                logger.warning(
                    "network_exposure_walk: firmware %s not found", firmware_id,
                )
                return
            firmware.network_exposure_walk_status = "running"
            firmware.network_exposure_walk_started_at = dt.datetime.now(dt.UTC)
            firmware.network_exposure_walk_error = None
            await db.commit()
            try:
                result = await _do_network_exposure_run(db, firmware_id)
                firmware.network_exposure_walk_status = "completed"
                firmware.network_exposure_walk_finished_at = dt.datetime.now(
                    dt.UTC
                )
                firmware.network_exposure_walk_result = (
                    _stamp_firmware_network_exposure_walk_result(result)
                )
                await db.commit()
            except Exception as exc:
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.network_exposure_walk_status = "failed"
                        fail_row.network_exposure_walk_finished_at = (
                            dt.datetime.now(dt.UTC)
                        )
                        fail_row.network_exposure_walk_error = err
                        fail_row.network_exposure_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "network_exposure_walk: inner runner failed for %s",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "network_exposure_walk: unrecoverable outer failure for %s",
            firmware_id,
        )


# ---------------------------------------------------------------------------
# SAFE unpack-post-detection hook (Rule #39 — never raises).
# ---------------------------------------------------------------------------


async def auto_network_exposure_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Auto-triggered post-detection hook (Rule #39 .safe contract).

    Owns own session. Runs the inner walker to populate the
    ``network_exposure_walk_result`` JSONB so operators see the last-known
    result even on the first upload. DOES NOT mutate
    ``network_exposure_walk_status`` — leaves it ``idle`` so an
    operator-triggered re-walk via ``trigger_network_exposure_walk`` MCP tool
    works without a 409 conflict.

    ORDERING (Rule #47): order-independent of C1/C2 — C3 reads no other
    walker's output. Registered near the systemd walker in
    walker_registry.WALKER_AUTO_TRIGGERS.

    Swallows exceptions silently with structured ``logger.exception``.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                return
            try:
                result = await _do_network_exposure_run(db, firmware_id)
                firmware.network_exposure_walk_result = (
                    _stamp_firmware_network_exposure_walk_result(result)
                )
                # No status flip per Rule #39 .safe.
                await db.commit()
            except Exception:
                await db.rollback()
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.network_exposure_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "auto_network_exposure_walk_firmware_safe: inner failed "
                    "for %s",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "auto_network_exposure_walk_firmware_safe: unrecoverable for %s",
            firmware_id,
        )


__all__ = [
    "_do_network_exposure_run",
    "auto_network_exposure_walk_firmware_safe",
    "run_network_exposure_walk_background",
]
