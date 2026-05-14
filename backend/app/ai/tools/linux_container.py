"""Linux container runtime artefact MCP tools — Phase ι.E.E (THIRD LINUX MCP).

Surfaces the Phase ι.E.C container-runtime artefact walk results to the
MCP layer (FIFTH ι MCP category overall; THIRD LINUX MCP after ι.A
journald + ι.B systemd):

- ``list_container_artifacts`` — paginate the linux_container_artifacts
  table for the active firmware with filters (artifact_type, privileged,
  anomaly_only / anomaly_bit).
- ``lookup_container_artifact`` — fetch one artifact row by ID with
  full detail (mounts, capabilities, env keys, anomaly_flags).
- ``search_container_images`` — substring search across image_name /
  image_id / image_repository (find every container instance for an
  image of interest).
- ``trigger_container_walk`` — trigger the 202+polling container walk
  background runner (Rule #33 .a idempotent POST + 409-on-conflict).
- ``container_walk_status`` — Rule #33 status reader for the
  firmware-row container_walk_* state machine.
- ``lookup_container_image_across_firmwares`` — **CROSS-FIRMWARE
  AGGREGATION** (wairz competitive differentiator). Given an
  image_id (sha256:...) OR image_repository:tag, return all firmware
  images that ship that container image. **Supply-chain indicator** —
  same vendor-pushed container image across multiple firmware images
  is a strong fingerprint for shared dependencies / shared infections.
  FOURTH application of the cross-firmware aggregation pattern at
  walker-stream time (ι.B systemd → ι.C ETL → ι.D EFS → THIS ι.E
  container — Rule-of-Three → Rule-of-Four; **pattern is durable
  BEYOND DEBATE**).

Persona-E container forensics relevance (Scout 3 "modest engineering
cost" ship — T1610 Deploy Container / T1611 Escape to Host / T1612
Build Image on Host). 2025 CVE cluster (3 runc CVEs + Docker
CVE-2025-9074) all exploit inspectable container-state artefacts.

Rule #36 no-execute reminder: these MCP tools surface METADATA only —
never invoke any extracted container, never exec into one, never pull
images. The walker that populates this table parses JSON via stdlib
json with the same discipline.

Output truncation (Rule #29): tool outputs ≤ 30 KB.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid

from sqlalchemy import func as sa_func
from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.firmware import Firmware
from app.models.linux_container_artifacts import LinuxContainerArtifact
from app.models.project import Project
from app.services.jsonb_normalizers import (
    _normalize_firmware_container_walk_result,
    _normalize_linux_container_artifacts_anomaly_flags,
    _normalize_linux_container_artifacts_capabilities_add,
    _normalize_linux_container_artifacts_capabilities_drop,
    _normalize_linux_container_artifacts_env_vars,
    _normalize_linux_container_artifacts_mounts,
)

logger = logging.getLogger(__name__)


# 30 KB output cap (Rule #29).
_OUTPUT_CAP_BYTES = 30 * 1024

# Substantive anomaly bits (the 9 bits that warrant operator review).
_SUBSTANTIVE_ANOMALY_BITS = (
    "privileged_mode",
    "host_pid_namespace",
    "host_network_namespace",
    "host_ipc_namespace",
    "dangerous_capability",
    "unconfined_seccomp",
    "unconfined_apparmor",
    "unsafe_mount",
    "unknown_registry",
)


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    if len(text.encode("utf-8")) <= cap:
        return text
    encoded = text.encode("utf-8")[: cap - 200]
    truncated = encoded.decode("utf-8", errors="ignore")
    return (
        truncated
        + "\n\n[output truncated to 30KB — narrow filters or use offset+limit "
        "to paginate]"
    )


def _row_has_substantive_anomaly(record: LinuxContainerArtifact) -> bool:
    """True iff at least one of the 9 substantive anomaly bits is True."""
    flags = _normalize_linux_container_artifacts_anomaly_flags(
        record.anomaly_flags
    )
    return any(bool(flags.get(k)) for k in _SUBSTANTIVE_ANOMALY_BITS)


def _row_summary(record: LinuxContainerArtifact) -> dict:
    """Construct the per-row summary dict surfaced by list / search /
    lookup tools."""
    return {
        "id": str(record.id),
        "artifact_path": record.artifact_path,
        "artifact_type": record.artifact_type,
        "container_id": record.container_id,
        "image_id": record.image_id,
        "image_name": record.image_name,
        "image_repository": record.image_repository,
        "image_tag": record.image_tag,
        "runtime": record.runtime,
        "state": record.state,
        "privileged": record.privileged,
        "network_mode": record.network_mode,
        "seccomp_profile": record.seccomp_profile,
        "apparmor_profile": record.apparmor_profile,
        "anomaly_flags": _normalize_linux_container_artifacts_anomaly_flags(
            record.anomaly_flags
        ),
        "has_anomaly": _row_has_substantive_anomaly(record),
        "parse_error": record.parse_error,
    }


def _row_detail(record: LinuxContainerArtifact) -> dict:
    """Like _row_summary but also includes mounts + capabilities + env."""
    out = _row_summary(record)
    out["mounts"] = _normalize_linux_container_artifacts_mounts(record.mounts)
    out["capabilities_add"] = (
        _normalize_linux_container_artifacts_capabilities_add(
            record.capabilities_add
        )
    )
    out["capabilities_drop"] = (
        _normalize_linux_container_artifacts_capabilities_drop(
            record.capabilities_drop
        )
    )
    out["env_vars"] = _normalize_linux_container_artifacts_env_vars(
        record.env_vars
    )
    out["command"] = record.command
    out["entrypoint"] = record.entrypoint
    out["working_dir"] = record.working_dir
    out["selinux_label"] = record.selinux_label
    out["raw_state"] = record.raw_state
    return out


# ── list_container_artifacts ────────────────────────────────────────────────


async def _handle_list_container_artifacts(
    input: dict, context: ToolContext
) -> str:
    """Paginate linux_container_artifacts by artifact_type / privileged /
    anomaly filters."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    artifact_type_filter = input.get("artifact_type")
    privileged_filter = input.get("privileged")
    anomaly_only = bool(input.get("anomaly_only", False))
    anomaly_bit = input.get("anomaly_bit")
    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))

    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    base_where = [LinuxContainerArtifact.firmware_id == firmware_id]
    if artifact_type_filter:
        base_where.append(
            LinuxContainerArtifact.artifact_type == artifact_type_filter
        )
    if privileged_filter is not None:
        base_where.append(
            LinuxContainerArtifact.privileged == bool(privileged_filter)
        )

    if anomaly_only or anomaly_bit:
        # Python-side filtering since anomaly_flags is JSONB.
        page_q = (
            select(LinuxContainerArtifact)
            .where(*base_where)
            .order_by(LinuxContainerArtifact.artifact_path)
        )
        rows = (await context.db.execute(page_q)).scalars().all()
        if anomaly_bit:
            filtered = [
                r for r in rows
                if (
                    _normalize_linux_container_artifacts_anomaly_flags(
                        r.anomaly_flags
                    ).get(anomaly_bit)
                )
            ]
        elif anomaly_only:
            filtered = [
                r for r in rows if _row_has_substantive_anomaly(r)
            ]
        else:
            filtered = list(rows)
        total = len(filtered)
        rows = filtered[offset : offset + limit]
    else:
        total_q = select(sa_func.count(LinuxContainerArtifact.id)).where(
            *base_where
        )
        total = (await context.db.execute(total_q)).scalar_one()

        page_q = (
            select(LinuxContainerArtifact)
            .where(*base_where)
            .order_by(LinuxContainerArtifact.artifact_path)
            .limit(limit)
            .offset(offset)
        )
        rows = (await context.db.execute(page_q)).scalars().all()

    artifacts = [_row_summary(r) for r in rows]

    out: dict = {
        "firmware_id": str(firmware_id),
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "container_artifacts": artifacts,
        "filters": {
            "artifact_type": artifact_type_filter,
            "privileged": privileged_filter,
            "anomaly_only": anomaly_only,
            "anomaly_bit": anomaly_bit,
        },
    }
    if total == 0:
        out["message"] = (
            "No container artefacts match. The walker may not have run "
            "yet (call trigger_container_walk and poll "
            "container_walk_status), or this firmware may have no "
            "container runtime installed, or your filters may be too "
            "narrow."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── lookup_container_artifact ───────────────────────────────────────────────


async def _handle_lookup_container_artifact(
    input: dict, context: ToolContext
) -> str:
    """Fetch one container artifact by ID with full detail."""
    artifact_id_raw = input.get("artifact_id")
    if not artifact_id_raw:
        return json.dumps({"error": "artifact_id is required"})
    try:
        artifact_id = uuid.UUID(str(artifact_id_raw))
    except (TypeError, ValueError):
        return json.dumps(
            {
                "error": (
                    f"artifact_id {artifact_id_raw!r} is not a valid UUID"
                ),
            }
        )

    row = (
        await context.db.execute(
            select(LinuxContainerArtifact).where(
                LinuxContainerArtifact.id == artifact_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps(
            {"error": f"container artifact {artifact_id} not found"}
        )

    return _truncate(json.dumps(_row_detail(row), indent=2, default=str))


# ── search_container_images ─────────────────────────────────────────────────


async def _handle_search_container_images(
    input: dict, context: ToolContext
) -> str:
    """Substring search across image_name / image_id / image_repository."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )

    query = input.get("query")
    if not query:
        return json.dumps({"error": "query (substring) is required"})

    limit = int(input.get("limit", 50))
    offset = int(input.get("offset", 0))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1
    if offset < 0:
        offset = 0

    pattern = f"%{query}%"
    where_clauses = [
        LinuxContainerArtifact.firmware_id == firmware_id,
        (
            LinuxContainerArtifact.image_name.ilike(pattern)
            | LinuxContainerArtifact.image_id.ilike(pattern)
            | LinuxContainerArtifact.image_repository.ilike(pattern)
        ),
    ]

    total_q = select(sa_func.count(LinuxContainerArtifact.id)).where(
        *where_clauses
    )
    total = (await context.db.execute(total_q)).scalar_one()

    page_q = (
        select(LinuxContainerArtifact)
        .where(*where_clauses)
        .order_by(LinuxContainerArtifact.image_name)
        .limit(limit)
        .offset(offset)
    )
    rows = (await context.db.execute(page_q)).scalars().all()

    out = {
        "firmware_id": str(firmware_id),
        "query": query,
        "total_count": total,
        "limit": limit,
        "offset": offset,
        "matches": [_row_summary(r) for r in rows],
    }
    return _truncate(json.dumps(out, indent=2, default=str))


# ── container_walk_status ───────────────────────────────────────────────────


async def _handle_container_walk_status(
    input: dict, context: ToolContext
) -> str:
    """Rule #33 status reader for firmware.container_walk_* state machine."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )
    row = (
        await context.db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    out = {
        "firmware_id": str(firmware_id),
        "status": row.container_walk_status,
        "started_at": (
            row.container_walk_started_at.isoformat()
            if row.container_walk_started_at
            else None
        ),
        "finished_at": (
            row.container_walk_finished_at.isoformat()
            if row.container_walk_finished_at
            else None
        ),
        "error": row.container_walk_error,
        "result": _normalize_firmware_container_walk_result(
            row.container_walk_result
        ),
    }
    return _truncate(json.dumps(out, indent=2))


# ── trigger_container_walk ──────────────────────────────────────────────────


async def _handle_trigger_container_walk(
    input: dict, context: ToolContext
) -> str:
    """Trigger the 202+polling container walk background runner.
    Rule #33 .a idempotent POST + 409-on-conflict."""
    firmware_id = (
        uuid.UUID(context.firmware_id)
        if isinstance(context.firmware_id, str)
        else context.firmware_id
    )
    row = (
        await context.db.execute(
            select(Firmware).where(Firmware.id == firmware_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return json.dumps({"error": f"firmware {firmware_id} not found"})

    if row.container_walk_status in ("queued", "running"):
        return json.dumps(
            {
                "conflict": True,
                "status": row.container_walk_status,
                "started_at": (
                    row.container_walk_started_at.isoformat()
                    if row.container_walk_started_at
                    else None
                ),
                "message": (
                    f"container walk already {row.container_walk_status} "
                    f"for firmware {firmware_id}. Poll "
                    "container_walk_status."
                ),
            }
        )

    row.container_walk_status = "queued"
    row.container_walk_started_at = None
    row.container_walk_finished_at = None
    row.container_walk_error = None
    row.container_walk_result = None
    await context.db.flush()

    from app.services.container_walker import run_container_walk_background

    asyncio.create_task(run_container_walk_background(firmware_id))

    return json.dumps(
        {
            "scheduled": True,
            "status": "queued",
            "firmware_id": str(firmware_id),
            "message": (
                "container walk scheduled. Poll container_walk_status "
                "until status=='completed' to harvest the result. "
                "Rule #36 no-execute: wairz NEVER invokes any extracted "
                "container, NEVER exec's into one, NEVER pulls images "
                "— the walker parses JSON state files only."
            ),
        }
    )


# ── lookup_container_image_across_firmwares (CROSS-FIRMWARE AGG) ──────────


async def _handle_lookup_container_image_across_firmwares(
    input: dict, context: ToolContext
) -> str:
    """**CROSS-FIRMWARE AGGREGATION** — given an image_id (sha256:...)
    OR image_repository:tag, return ALL firmware images in the active
    project (or globally, if requested) that ship that container image.

    **STRONG SUPPLY-CHAIN INDICATOR** — if the SAME image_id appears
    across multiple supposedly-independent customer firmware images,
    the implication is either:

    (a) A shared vendor-pushed image — legitimate vendor base image
        deployed across the product line (verify against operator's
        documented vendor inventory).
    (b) A shared infection — same compromised image deployed by the
        adversary across multiple targets (T1612 Build Image on Host
        + supply-chain spread).
    (c) Vendor default-image-with-CVE — vulnerable image baseline that
        wasn't updated; same CVE-bearing image across the fleet.

    FOURTH application of the cross-firmware aggregation pattern at
    walker-stream time (ι.B systemd → ι.C ETL → ι.D EFS → THIS ι.E
    container — Rule-of-Three → Rule-of-Four; **the pattern is now
    durable BEYOND debate** — applies cleanly across persistence
    (systemd), trace logs (ETW), cryptographic recovery (EFS DRF), and
    container images).

    Filters by either image_id OR image_repository (at least one is
    required). Optional image_tag refinement when image_repository is
    supplied. Returns one row per matching firmware (deduplicated by
    firmware_id), with project + firmware metadata + match count.
    """
    image_id_filter = input.get("image_id")
    repo_filter = input.get("image_repository")
    tag_filter = input.get("image_tag")
    if not image_id_filter and not repo_filter:
        return json.dumps({
            "error": (
                "Either image_id OR image_repository is required."
            )
        })

    scope = input.get("scope", "project")
    if scope not in ("project", "global"):
        scope = "project"
    limit = int(input.get("limit", 100))
    if limit > 500:
        limit = 500
    if limit < 1:
        limit = 1

    where_clauses = []
    if image_id_filter:
        where_clauses.append(
            LinuxContainerArtifact.image_id == image_id_filter
        )
    if repo_filter:
        where_clauses.append(
            LinuxContainerArtifact.image_repository == repo_filter
        )
    if tag_filter:
        where_clauses.append(
            LinuxContainerArtifact.image_tag == tag_filter
        )

    if scope == "project":
        if not context.project_id:
            return json.dumps({
                "error": (
                    "scope='project' requires an active project — call "
                    "switch_project first or use scope='global'."
                )
            })
        project_id = (
            uuid.UUID(context.project_id)
            if isinstance(context.project_id, str)
            else context.project_id
        )
        stmt = (
            select(LinuxContainerArtifact, Firmware, Project)
            .join(Firmware, LinuxContainerArtifact.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(Project.id == project_id, *where_clauses)
            .order_by(Firmware.created_at)
        )
    else:
        stmt = (
            select(LinuxContainerArtifact, Firmware, Project)
            .join(Firmware, LinuxContainerArtifact.firmware_id == Firmware.id)
            .join(Project, Firmware.project_id == Project.id)
            .where(*where_clauses)
            .order_by(Firmware.created_at)
        )

    rows = (await context.db.execute(stmt)).all()

    # Group matches by firmware_id (dedupe — same image may appear in
    # multiple artefacts per firmware).
    per_firmware: dict[uuid.UUID, dict] = {}

    for artifact, firmware, project in rows:
        bucket = per_firmware.setdefault(firmware.id, {
            "project_id": str(project.id),
            "project_name": project.name,
            "firmware_id": str(firmware.id),
            "firmware_sha256": firmware.sha256,
            "firmware_original_filename": firmware.original_filename,
            "firmware_version_label": firmware.version_label,
            "match_count": 0,
            "sample_artifact": {
                "artifact_path": artifact.artifact_path,
                "artifact_type": artifact.artifact_type,
                "container_id": artifact.container_id,
                "image_id": artifact.image_id,
                "image_name": artifact.image_name,
                "image_repository": artifact.image_repository,
                "image_tag": artifact.image_tag,
                "anomaly_flags": (
                    _normalize_linux_container_artifacts_anomaly_flags(
                        artifact.anomaly_flags
                    )
                ),
            },
        })
        bucket["match_count"] += 1

    matches = list(per_firmware.values())[:limit]

    out: dict = {
        "image_id": image_id_filter,
        "image_repository": repo_filter,
        "image_tag": tag_filter,
        "scope": scope,
        "match_count": len(matches),
        "matches": matches,
    }
    if not matches:
        filter_desc = []
        if image_id_filter:
            filter_desc.append(f"image_id={image_id_filter!r}")
        if repo_filter:
            filter_desc.append(f"image_repository={repo_filter!r}")
        if tag_filter:
            filter_desc.append(f"image_tag={tag_filter!r}")
        out["message"] = (
            f"No firmware in scope '{scope}' has a container artefact "
            f"matching " + " AND ".join(filter_desc)
            + ". Run the walker against more firmwares (call "
            "trigger_container_walk on each), then re-query."
        )
    elif len(matches) >= 2:
        out["supply_chain_signal"] = (
            f"Container image appears across {len(matches)} firmware "
            "images — possible shared vendor base image (legitimate; "
            "verify against operator's documented vendor inventory), "
            "shared infection (T1612 Build Image on Host + supply-chain "
            "spread), OR vendor-default-with-CVE (same vulnerable "
            "image baseline across the fleet without updates). Compare "
            "sample_artifact.anomaly_flags across matches to "
            "characterise the signal."
        )
    return _truncate(json.dumps(out, indent=2, default=str))


# ── Registration ───────────────────────────────────────────────────────────


def register_linux_container_tools(registry: ToolRegistry) -> None:
    """Register all Phase ι.E.E Linux container runtime MCP tools.
    THIRD LINUX MCP tool category in wairz (ι.A.E journald + ι.B.E
    systemd shipped Linux); FIFTH ι MCP category overall (ι.C.E ETW +
    ι.D.E EFS shipped Windows). Brings MCP tool count 275 → 281.

    Includes the FOURTH application of the cross-firmware aggregation
    pattern at walker-stream time
    (``lookup_container_image_across_firmwares``) — wairz competitive
    differentiator surfacing supply-chain / shared-infection signal
    across firmware captures. Rule-of-One (ι.B) → Rule-of-Two (ι.C) →
    Rule-of-Three (ι.D) → Rule-of-Four (this stream — **pattern is
    durable BEYOND DEBATE**; applies across persistence + trace logs +
    cryptographic recovery + container images).

    Rule #36 no-execute reminder: all tools surface METADATA only;
    the walker that populates the table parses JSON state files via
    stdlib json — never invokes any container, never pulls images.
    """

    registry.register(
        name="list_container_artifacts",
        description=(
            "Phase ι.E.E — paginate the per-artifact "
            "linux_container_artifacts table for the active firmware. "
            "Surfaces Linux container runtime metadata extracted from "
            "Docker (config.v2.json + hostconfig.json), containerd "
            "(state.json + OCI runtime config.json), podman (state.json "
            "+ OCI config.json), OCI image-spec (manifest.json + "
            "repositories.json), and runtime configs (daemon.json + "
            "storage.conf + registries.conf). THIRD LINUX MCP tool "
            "category in wairz (ι.A + ι.B shipped Linux journald + "
            "systemd; ι.C + ι.D shipped Windows ETW + EFS). FIFTH ι MCP "
            "category overall. Container forensics Persona-E coverage: "
            "T1610 (Deploy Container — privileged-deploy signal), "
            "T1611 (Escape to Host — host-namespace shares + dangerous "
            "capabilities + unsafe bind mounts), T1612 (Build Image on "
            "Host — unknown_registry signal). 2025 CVE cluster: 3 runc "
            "CVEs (CVE-2025-31133 / -52565 / -52881) + Docker "
            "CVE-2025-9074 all exploit inspectable container-state "
            "artefacts. Filters: artifact_type (docker_container_state "
            "/ containerd_state / containerd_config / podman_state / "
            "podman_config / oci_manifest / docker_repositories / "
            "daemon_config / runtime_config / docker_hostconfig), "
            "privileged (filter to privileged-deploy candidates), "
            "anomaly_only (filter to artefacts with at least one "
            "substantive anomaly bit), anomaly_bit (specific bit name). "
            "Returns up to `limit` rows per page (default 50, max 500) "
            "ordered by artifact_path. Rule #36 no-execute reminder: "
            "wairz NEVER invokes any extracted container, NEVER exec's "
            "into one, NEVER pulls images."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "artifact_type": {
                    "type": "string",
                    "description": (
                        "Exact match on artifact_type "
                        "(docker_container_state / containerd_state / "
                        "containerd_config / podman_state / podman_config "
                        "/ oci_manifest / docker_repositories / "
                        "daemon_config / runtime_config / "
                        "docker_hostconfig)."
                    ),
                },
                "privileged": {
                    "type": "boolean",
                    "description": (
                        "Filter to containers running with the "
                        "--privileged flag (T1610 / T1611 highest-risk "
                        "candidates)."
                    ),
                },
                "anomaly_only": {
                    "type": "boolean",
                    "description": (
                        "If true, return only artefacts with at least "
                        "one substantive anomaly flag raised."
                    ),
                },
                "anomaly_bit": {
                    "type": "string",
                    "description": (
                        "Filter to artefacts with this specific anomaly "
                        "bit set (privileged_mode / host_pid_namespace "
                        "/ host_network_namespace / host_ipc_namespace "
                        "/ dangerous_capability / unconfined_seccomp / "
                        "unconfined_apparmor / unsafe_mount / "
                        "unknown_registry)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": "Page size (default 50, min 1, max 500).",
                    "minimum": 1,
                    "maximum": 500,
                },
                "offset": {
                    "type": "integer",
                    "description": "Page offset for pagination (default 0).",
                    "minimum": 0,
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_list_container_artifacts,
    )

    registry.register(
        name="lookup_container_artifact",
        description=(
            "Phase ι.E.E — fetch one container artifact row by its "
            "UUID with full detail (incl. full mounts list with "
            "source/destination/mode/type, full capabilities lists "
            "added + dropped, environment variable KEYS only — values "
            "dropped for security since secrets often in env vars, "
            "command + entrypoint + working_dir, seccomp + apparmor + "
            "selinux profiles, raw_state JSON content)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "artifact_id": {
                    "type": "string",
                    "description": (
                        "UUID of the LinuxContainerArtifact row. Get "
                        "from list_container_artifacts or "
                        "search_container_images."
                    ),
                },
            },
            "required": ["artifact_id"],
            "additionalProperties": False,
        },
        handler=_handle_lookup_container_artifact,
    )

    registry.register(
        name="search_container_images",
        description=(
            "Phase ι.E.E — case-insensitive substring search across "
            "image_name / image_id / image_repository for the active "
            "firmware. Use this to find containers by partial image "
            "name ('nginx'), image hash, or repository ('docker.io/"
            "library'). Returns up to `limit` matching rows per page "
            "(default 50, max 500) ordered by image_name."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Substring to search for in image_name / "
                        "image_id / image_repository (case-insensitive)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": "Page size (default 50, min 1, max 500).",
                    "minimum": 1,
                    "maximum": 500,
                },
                "offset": {
                    "type": "integer",
                    "description": "Page offset (default 0).",
                    "minimum": 0,
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        handler=_handle_search_container_images,
    )

    registry.register(
        name="container_walk_status",
        description=(
            "Rule #33 status reader for the firmware-row "
            "container_walk_* state machine. Returns status (idle / "
            "queued / running / completed / failed), started_at, "
            "finished_at, error, and the last-known-result aggregate "
            "(artifacts_scanned, artifacts_persisted, containers_count, "
            "images_count, configs_count, privileged_count, "
            "host_namespace_count, dangerous_capability_count, "
            "unsafe_mount_count, unconfined_security_count, "
            "unknown_registry_count, anomaly_total, parse_errors, "
            "oversize_skipped, errors, per_root)."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_container_walk_status,
    )

    registry.register(
        name="trigger_container_walk",
        description=(
            "Trigger the 202+polling Linux container-runtime artefact "
            "walk background runner. Walks every detection root per "
            "Rule #16 (var/lib/docker/containers/ + "
            "var/run/containerd/.../state.json + "
            "var/lib/containers/storage/overlay-containers/.../userdata "
            "+ var/lib/docker/image/overlay2/repositories.json + "
            "var/lib/containers/storage/overlay-images/.../manifest + "
            "etc/docker/daemon.json + etc/containers/storage.conf + "
            "etc/containers/registries.conf), parses each JSON via "
            "Python's stdlib json (ZERO new dependency), discriminates "
            "by path + content shape (Docker config.v2.json + "
            "hostconfig.json merged; containerd OCI runtime-spec; "
            "podman state + config; OCI image-spec manifest), extracts "
            "container forensic METADATA (image_id, mounts, "
            "capabilities, seccomp + apparmor profiles, network mode, "
            "env var KEYS only, command + entrypoint + working_dir), "
            "persists per-artefact rows into linux_container_artifacts "
            "with anomaly_flags (9 bits: privileged_mode / "
            "host_*_namespace / dangerous_capability / unconfined_* / "
            "unsafe_mount / unknown_registry). Idempotent (Rule #33 "
            ".a) — returns conflict=true if a run is already queued or "
            "running. Schedules run_container_walk_background via "
            "asyncio.create_task. Poll container_walk_status until "
            "status=='completed' to harvest the result. Anomaly "
            "classifier covers Persona-E container TTPs: T1610 Deploy "
            "Container (privileged_mode), T1611 Escape to Host "
            "(host-namespace shares + dangerous_capability + "
            "unsafe_mount), T1612 Build Image on Host (unknown_registry). "
            "Rule #36 no-execute: walker NEVER invokes any extracted "
            "container, NEVER exec's into one, NEVER pulls images. "
            "THIRD LINUX walker in wairz's portfolio (ι.A journald + "
            "ι.B systemd shipped Linux); FIFTH ι walker overall."
        ),
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        handler=_handle_trigger_container_walk,
    )

    registry.register(
        name="lookup_container_image_across_firmwares",
        description=(
            "**CROSS-FIRMWARE AGGREGATION** — given an image_id "
            "(sha256:abc...) OR image_repository (e.g. "
            "'docker.io/library/nginx') OR both (AND-combined), "
            "return ALL firmware images in the active project (default) "
            "OR globally that ship that container image. Optional "
            "image_tag refinement for repo-based queries. "
            "**STRONG SUPPLY-CHAIN INDICATOR** — same image_id across "
            "multiple supposedly-independent customer firmware images "
            "may mean: (a) shared vendor base image (legitimate; verify "
            "against operator's documented vendor inventory), (b) "
            "shared infection (T1612 Build Image on Host + supply-chain "
            "spread), (c) vendor-default-with-CVE (vulnerable image "
            "baseline never updated across the fleet). FOURTH "
            "application of the cross-firmware aggregation pattern at "
            "walker-stream time (ι.B systemd Rule-of-One → ι.C ETL "
            "Rule-of-Two → ι.D EFS Rule-of-Three → THIS ι.E container "
            "Rule-of-Four; **pattern is now DURABLE BEYOND DEBATE** — "
            "applies across persistence + trace logs + cryptographic "
            "recovery + container images). Wairz competitive "
            "differentiator — no other forensic tool surfaces this "
            "cross-corpus container fingerprint signal. match_count "
            ">=2 triggers supply_chain_signal in the output. "
            "scope='project' (default) restricts to the active "
            "project's firmwares; scope='global' searches every "
            "project."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "image_id": {
                    "type": "string",
                    "description": (
                        "Image hash to match (typically 'sha256:abc...' "
                        "format; up to 128 chars). Either image_id OR "
                        "image_repository is required."
                    ),
                },
                "image_repository": {
                    "type": "string",
                    "description": (
                        "Image repository to match (e.g. "
                        "'docker.io/library/nginx', 'gcr.io/foo/bar', "
                        "or bare 'nginx' for docker.io implicit). "
                        "Either image_id OR image_repository is "
                        "required. Both can be supplied to AND-combine."
                    ),
                },
                "image_tag": {
                    "type": "string",
                    "description": (
                        "Optional image tag refinement (e.g. '1.21', "
                        "'latest'). Only used when image_repository is "
                        "supplied."
                    ),
                },
                "scope": {
                    "type": "string",
                    "enum": ["project", "global"],
                    "description": (
                        "'project' (default) restricts to the active "
                        "project's firmwares; 'global' searches every "
                        "project."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": (
                        "Max firmware matches to return (default 100, "
                        "min 1, max 500)."
                    ),
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "additionalProperties": False,
        },
        handler=_handle_lookup_container_image_across_firmwares,
    )
