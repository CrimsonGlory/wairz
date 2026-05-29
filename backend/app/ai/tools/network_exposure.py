"""MCP tools for the C3 network-exposure REACHABILITY-EVIDENCE walker.

This is a NEW, DISTINCT tool namespace (R51.2 SHOULD-FIX S1) — C3's tools live
HERE, NOT in the existing pcap-analysis ``network.py`` (which holds
``analyze_pcap`` / ``get_network_conversations`` / etc.).
``ToolRegistry.register`` SILENTLY OVERWRITES (no dup guard, the Rule
#10-class MCP-layer gap), so a clean separate file lowers the collision risk;
the registry-uniqueness META-CANARY in ``test_kernel_config_mcp.py`` + the C3
canary in ``test_network_exposure_mcp.py`` close the gap.

Tool surface:

  - ``trigger_network_exposure_walk`` — operator-trigger the C3 walker
    (Rule #33 .a; project-scope guarded; 409-shaped conflict on in-flight
    rerun). Flips ``network_exposure_walk_status`` idle → queued + dispatches
    the background runner.
  - ``get_network_exposure`` — reads ``firmware.network_exposure_walk_result``
    (the listener → bind-scope → owning-daemon map the
    cve-assessment-framework L4 kill-chain classifier consumes via
    ``ListenerEntry`` + ``network/listeners.json``). Provenance-gated
    (schema_version==1 + provenance=="walker"). Each listener carries BOTH
    ``host`` AND ``address`` keys (Linux adapter reads host; Android adapter
    reads address) + ``bind_confidence`` (runtime_confirmed / config_high /
    config_inferred — the over-read guard).
  - ``lookup_network_listener_across_firmwares`` — **Rule #44 mandatory
    cross-firmware aggregator**. "Which firmware expose the SAME daemon on
    0.0.0.0?" / "Which firmware bind port 23 (telnet) remote?" —
    grouped-by-firmware with ``supply_chain_signal`` flag (true when ≥2
    firmware expose the same daemon remotely — the fleet-wide exposure
    query).

Per Rule #36/#45 the walker neither decrypts nor starts any daemon; these MCP
tools only surface parse-only artefacts (the walk-result JSONB aggregate).
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.jsonb_normalizers import (
    _normalize_firmware_network_exposure_walk_result,
)
from app.services.network_exposure_walker import (
    run_network_exposure_walk_background,
)

logger = logging.getLogger(__name__)

_OUTPUT_CAP_BYTES = 30 * 1024

# A listener whose host is in this set is loopback-only — NOT a remote
# exposure (mirrors the framework's _LOOPBACK_ADDRS + the walker's
# _is_loopback_host). Used by the cross-firmware tool to flag remote exposure.
_LOOPBACK_HOSTS: frozenset[str] = frozenset({
    "127.0.0.1",
    "::1",
    "localhost",
})


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    """Truncate an MCP tool payload to the 30 KB ceiling (Rule: tool outputs
    must stay small or MCP clients break)."""
    if len(text) <= cap:
        return text
    return text[: cap - 80] + '\n... [truncated — narrow the query/scope] ...'


def _is_remote_host(host: str | None) -> bool:
    """True iff ``host`` is a non-loopback bind (a remote exposure). Handles
    the 127.0.0.0/8 block + ::1 + localhost. PURE."""
    if not host:
        return False
    h = host.strip().strip("[]").lower()
    if h in _LOOPBACK_HOSTS:
        return False
    parts = h.split(".")
    if len(parts) == 4 and parts[0] == "127":
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return False
        except ValueError:
            return True
    return True


# ---------------------------------------------------------------------------
# Handlers.
# ---------------------------------------------------------------------------


async def _handle_trigger_network_exposure_walk(
    input: dict, context: ToolContext
) -> str:
    """Operator-trigger the C3 network-exposure walker (Rule #33 .a).

    Synthesizes the listener → bind-scope → owning-daemon exposure map across
    the firmware's detection roots so the cve-assessment-framework L4
    classifier can tell a kill-chain HEAD (a daemon on a remote interface)
    from a post-foothold link (a loopback-only daemon). Project-scope guarded;
    409-shaped conflict on in-flight rerun.
    """
    firmware_id_str = input.get("firmware_id") or context.firmware_id
    if not firmware_id_str:
        return json.dumps({"error": "firmware_id required"})
    try:
        firmware_id = (
            uuid.UUID(firmware_id_str)
            if isinstance(firmware_id_str, str)
            else firmware_id_str
        )
    except ValueError:
        return json.dumps({"error": f"invalid firmware_id: {firmware_id_str!r}"})

    # Project-scope guard — operator-A in P1 cannot trigger against
    # operator-B's firmware in P2 via switch_project.
    if not context.project_id:
        return json.dumps({
            "error": (
                "no active project — call switch_project before "
                "trigger_network_exposure_walk"
            ),
        })
    project_id = (
        uuid.UUID(context.project_id)
        if isinstance(context.project_id, str)
        else context.project_id
    )
    firmware = (
        await context.db.execute(
            select(Firmware).where(
                Firmware.id == firmware_id,
                Firmware.project_id == project_id,
            )
        )
    ).scalar_one_or_none()
    if firmware is None:
        return json.dumps({
            "error": (
                f"firmware {firmware_id} not found in active project "
                f"{project_id} (either wrong id OR belongs to a different "
                f"project — tenancy scope guard)"
            ),
        })

    if firmware.network_exposure_walk_status in ("queued", "running"):
        return json.dumps({
            "status": "conflict",
            "network_exposure_walk_status": (
                firmware.network_exposure_walk_status
            ),
            "message": (
                f"network_exposure_walk is already "
                f"{firmware.network_exposure_walk_status} — wait for "
                f"completion before re-triggering."
            ),
        })

    firmware.network_exposure_walk_status = "queued"
    firmware.network_exposure_walk_started_at = None
    firmware.network_exposure_walk_finished_at = None
    firmware.network_exposure_walk_error = None
    firmware.network_exposure_walk_result = None
    await context.db.flush()  # Rule #3 — flush, not commit, in MCP handlers.
    # Background runner opens its own session; commit BEFORE spawning so it
    # sees `queued`.
    await context.db.commit()
    asyncio.create_task(run_network_exposure_walk_background(firmware_id))

    return json.dumps({
        "status": "queued",
        "firmware_id": str(firmware_id),
        "message": (
            "Network-exposure walker enqueued. Poll "
            "firmware.network_exposure_walk_status through running → "
            "completed | failed; harvest via get_network_exposure. The result "
            "carries the listener → bind-scope → owning-daemon map (with the "
            "bind_confidence over-read guard) the cve-assessment-framework L4 "
            "kill-chain classifier consumes."
        ),
    })


async def _handle_get_network_exposure(
    input: dict, context: ToolContext
) -> str:
    """Read the C3 network-exposure walk aggregate for one firmware.

    Returns firmware.network_exposure_walk_result — the listeners[] map (each
    {host, address, port, protocol, owning_process, bind_confidence}) +
    capture_source + listener_count + remote_listener_count. This is the
    evidence shape the cve-assessment-framework reads (ListenerEntry +
    network/listeners.json — Linux adapter reads `host`, Android adapter reads
    `address`; both keys present per R51.2 BLOCKING #2). Provenance-gated:
    schema_version==1 + provenance=="walker" before trusting the evidence.
    """
    firmware_id_str = input.get("firmware_id") or context.firmware_id
    if not firmware_id_str:
        return json.dumps({"error": "firmware_id required"})
    try:
        firmware_id = (
            uuid.UUID(firmware_id_str)
            if isinstance(firmware_id_str, str)
            else firmware_id_str
        )
    except ValueError:
        return json.dumps({"error": f"invalid firmware_id: {firmware_id_str!r}"})

    firmware = await context.db.get(Firmware, firmware_id)
    if firmware is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    result = _normalize_firmware_network_exposure_walk_result(
        firmware.network_exposure_walk_result
    )
    out: dict = {
        "firmware_id": str(firmware_id),
        "network_exposure_walk_status": (
            firmware.network_exposure_walk_status
        ),
    }
    if result is None:
        out["result"] = None
        out["hint"] = (
            f"no network-exposure walk result yet (status="
            f"{firmware.network_exposure_walk_status}); trigger via "
            f"trigger_network_exposure_walk and poll until completed."
        )
        return _truncate(json.dumps(out, indent=2, default=str))

    # Provenance gate — refuse to surface a non-walker / legacy result.
    if result.get("schema_version") != 1 or result.get("provenance") != "walker":
        out["result"] = result
        out["consumer_warning"] = (
            f"walker result REJECTED by provenance gate "
            f"(schema_version={result.get('schema_version')!r}, "
            f"provenance={result.get('provenance')!r}). Downstream L4 "
            f"consumers MUST NOT trust the listener bind-scope evidence — "
            f"re-trigger via trigger_network_exposure_walk."
        )
        return _truncate(json.dumps(out, indent=2, default=str))

    out["result"] = result
    return _truncate(json.dumps(out, indent=2, default=str))


async def _handle_lookup_network_listener_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """Rule #44 mandatory cross-firmware aggregator for network exposure.

    Given a daemon NAME (e.g. ``sshd``, ``dropbear``, ``telnetd``) and/or a
    ``port``, return every firmware whose network-exposure walk found a
    matching listener. The headline fleet query: "which firmware expose the
    SAME daemon on 0.0.0.0?" (the remote-attack-surface fleet sweep).

    Returns one row per matching firmware with:
      - firmware_id, project_id, project_name, original_filename
      - matched listeners (host/address/port/protocol/owning_process/
        bind_confidence)
      - any_remote_bind (true when at least one matched listener is
        non-loopback)
    plus a top-level ``supply_chain_signal`` (True when ≥2 firmware expose the
    SAME daemon REMOTELY — the strongest "same exposed surface across the
    fleet" signal).
    """
    daemon_name = input.get("daemon_name") or input.get("owning_process")
    port = input.get("port")
    if not daemon_name and port is None:
        return json.dumps({
            "error": "At least one of daemon_name or port is required.",
        })
    if isinstance(daemon_name, str):
        daemon_name = daemon_name.strip().lower()
    if port is not None:
        try:
            port = int(port)
        except (TypeError, ValueError):
            return json.dumps({"error": f"port must be an integer, got {port!r}"})

    scope = input.get("scope", "project")
    if scope not in ("project", "global"):
        return json.dumps({
            "error": f"scope must be 'project' or 'global', got {scope!r}",
        })
    limit = int(input.get("limit", 100))
    limit = max(1, min(limit, 500))

    stmt = (
        select(Firmware, Project)
        .join(Project, Firmware.project_id == Project.id)
        .where(Firmware.network_exposure_walk_status == "completed")
        .order_by(Firmware.created_at)
    )
    if scope == "project":
        if not context.project_id:
            return json.dumps({
                "error": (
                    "scope='project' requires an active project — call "
                    "switch_project first or use scope='global'."
                ),
            })
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = stmt.where(Firmware.project_id == project_id)

    rows = (await context.db.execute(stmt)).all()

    matches: list[dict] = []
    # daemon_name -> set of firmware ids that expose it REMOTELY.
    remote_daemon_owners: dict[str, set[str]] = {}
    for firmware, project in rows:
        result = _normalize_firmware_network_exposure_walk_result(
            firmware.network_exposure_walk_result
        )
        if result is None or result.get("schema_version") != 1:
            continue

        listeners = result.get("listeners") or []
        matched: list[dict] = []
        any_remote = False
        for entry in listeners:
            if not isinstance(entry, dict):
                continue
            ename = (entry.get("owning_process") or "").lower()
            eport = entry.get("port")
            name_match = bool(daemon_name) and daemon_name in ename
            port_match = port is not None and eport == port
            # When BOTH filters are supplied, require BOTH; when one, require it.
            if daemon_name and port is not None:
                hit = name_match and port_match
            else:
                hit = name_match or port_match
            if not hit:
                continue
            matched.append(entry)
            if _is_remote_host(entry.get("host") or entry.get("address")):
                any_remote = True
                if ename:
                    remote_daemon_owners.setdefault(ename, set()).add(
                        str(firmware.id)
                    )

        if not matched:
            continue

        matches.append({
            "firmware_id": str(firmware.id),
            "project_id": str(project.id),
            "project_name": project.name,
            "original_filename": firmware.original_filename,
            "any_remote_bind": any_remote,
            "matched_listeners": matched,
        })
        if len(matches) >= limit:
            break

    # supply_chain_signal: the SAME daemon is exposed REMOTELY in ≥2 firmware
    # (the strongest "identical exposed surface across the fleet" signal).
    shared_remote = {
        d: sorted(fws)
        for d, fws in remote_daemon_owners.items()
        if len(fws) >= 2
    }
    supply_chain_signal = bool(shared_remote) or (
        sum(1 for m in matches if m["any_remote_bind"]) >= 2
    )

    out: dict = {
        "daemon_name": daemon_name,
        "port": port,
        "scope": scope,
        "match_firmware_count": len(matches),
        "supply_chain_signal": supply_chain_signal,
        "shared_remote_daemons": shared_remote,
        "matches": matches,
    }
    if not matches:
        out["message"] = (
            "No matching firmwares found. Ensure the C3 walker has run on the "
            "relevant firmwares (trigger_network_exposure_walk + poll). "
            "schema_version must equal 1; rows with a NULL "
            "network_exposure_walk_result or status != 'completed' are "
            "skipped."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ---------------------------------------------------------------------------
# Registration.
# ---------------------------------------------------------------------------


def register_network_exposure_tools(registry: ToolRegistry) -> None:
    """Register the C3 network-exposure MCP tools (DISTINCT namespace)."""
    registry.register(
        name="trigger_network_exposure_walk",
        description=(
            "Trigger the C3 network-exposure REACHABILITY-EVIDENCE walker on "
            "one firmware. Synthesizes the listener → bind-scope → "
            "owning-daemon exposure map across systemd .socket units + "
            "sshd_config + dropbear + nginx + dnsmasq + any captured "
            "ss/netstat output — the evidence the cve-assessment-framework "
            "L4 kill-chain classifier consumes to tell a kill-chain HEAD (a "
            "daemon on a remote interface → an AV:N CVE owned by it can be "
            "initial_entry) from a post-foothold link (a loopback-only daemon "
            "→ chainable). THE OVER-READ GUARD: a loopback bind is NEVER "
            "remote; an unknown/defaulted bind defaults to 0.0.0.0 BUT carries "
            "bind_confidence=config_inferred (the consumer caps it at "
            "chainable — never mints a confirmed-remote HEAD from an inferred "
            "bind). Idempotent — 409-shaped conflict if already running. Poll "
            "firmware.network_exposure_walk_status; harvest via "
            "get_network_exposure. PARSE-ONLY (Rule #45) — reads configs AS "
            "DATA; never starts a daemon / spawns."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": (
                        "UUID of the firmware to walk; defaults to "
                        "context.firmware_id."
                    ),
                },
            },
        },
        handler=_handle_trigger_network_exposure_walk,
    )
    registry.register(
        name="get_network_exposure",
        description=(
            "Read the C3 network-exposure walk aggregate for one firmware "
            "(firmware.network_exposure_walk_result). Returns the listeners[] "
            "map — each {host, address, port, protocol, owning_process, "
            "bind_confidence}. Each listener carries BOTH host AND address "
            "keys (the framework's Linux adapter reads host; the Android "
            "adapter reads address — both present per R51.2 BLOCKING #2). "
            "bind_confidence is the over-read guard: runtime_confirmed (live "
            "ss/netstat) > config_high (explicit bind directive) > "
            "config_inferred (inferred/defaulted — capped at chainable by the "
            "consumer). Plus capture_source (config|runtime), listener_count, "
            "remote_listener_count. This is the evidence the "
            "cve-assessment-framework reads for the L4 listener bind-scope "
            "discriminator (ListenerEntry + network/listeners.json). "
            "Provenance-gated (schema_version==1 + provenance=='walker')."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "firmware_id": {
                    "type": "string",
                    "description": (
                        "UUID of the firmware; defaults to "
                        "context.firmware_id."
                    ),
                },
            },
        },
        handler=_handle_get_network_exposure,
    )
    registry.register(
        name="lookup_network_listener_across_firmwares",
        description=(
            "Rule #44 CROSS-FIRMWARE AGGREGATION — given a daemon name "
            "(e.g. 'sshd', 'dropbear', 'telnetd') and/or a port, return every "
            "firmware whose network-exposure walk found a matching listener. "
            "The headline fleet query: 'which firmware expose the SAME daemon "
            "on 0.0.0.0?' Returns one row per matching firmware with the "
            "matched listeners + an any_remote_bind flag; supply_chain_signal="
            "True when >=2 firmware expose the SAME daemon REMOTELY (or, with "
            "a port filter, when >=2 firmware bind it remotely). scope='global' "
            "searches all projects."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "daemon_name": {
                    "type": "string",
                    "description": (
                        "Owning-daemon name substring to look up "
                        "(case-insensitive). Either this or port is required. "
                        "Example: 'sshd', 'dropbear', 'telnetd', 'nginx'."
                    ),
                },
                "port": {
                    "type": "integer",
                    "description": (
                        "Listener port to look up across the fleet. Either "
                        "this or daemon_name is required. When both are "
                        "supplied, BOTH must match."
                    ),
                },
                "scope": {
                    "type": "string",
                    "enum": ["project", "global"],
                    "description": (
                        "Search scope. 'project' (default) restricts to "
                        "firmwares in the active project; 'global' searches "
                        "across all projects."
                    ),
                    "default": "project",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "description": (
                        "Maximum number of distinct firmwares to return "
                        "(default 100, max 500)."
                    ),
                },
            },
        },
        handler=_handle_lookup_network_listener_across_firmwares,
    )


__all__ = ["register_network_exposure_tools"]
