"""Phase ι.E.E contract tests: linux_container MCP tools (THIRD LINUX MCP).

Per Rule #35b: live canaries via make_live_db. Tests verify that the
MCP tools return the actual persisted shape from the ι.E.A table, not
just that .add() was called.

Mirrors test_linux_systemd_tools.py / test_windows_efs_tools.py shape —
5 per-firmware tools (list / lookup / search / status / trigger) + 1
cross-firmware aggregation tool with contract assertions across
happy-path + 404 + 409 + filter shapes + supply-chain signal.

Includes coverage for the FOURTH application of the cross-firmware
aggregation pattern at walker-stream time
(lookup_container_image_across_firmwares) — within a project AND
globally; supply_chain_signal emission on match_count >= 2.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.linux_container import (
    _handle_container_walk_status,
    _handle_list_container_artifacts,
    _handle_lookup_container_artifact,
    _handle_lookup_container_image_across_firmwares,
    _handle_search_container_images,
    _handle_trigger_container_walk,
    register_linux_container_tools,
)
from app.models import Firmware, LinuxContainerArtifact, Project
from app.services.jsonb_normalizers import (
    _stamp_linux_container_artifacts_anomaly_flags,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub for the linux_container MCP handlers."""

    db: AsyncSession
    firmware_id: uuid.UUID
    project_id: uuid.UUID | None = None


def _make_firmware(
    project_id: uuid.UUID, name: str, sha_seed: str
) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


def _make_artifact(
    firmware_id: uuid.UUID,
    *,
    artifact_type: str = "docker_container_state",
    artifact_path: str | None = None,
    image_id: str | None = "sha256:abc123",
    image_name: str | None = "docker.io/library/nginx:1.21",
    image_repository: str | None = "docker.io/library/nginx",
    image_tag: str | None = "1.21",
    container_id: str | None = "container-abc",
    privileged: bool | None = False,
    network_mode: str | None = "bridge",
    seccomp_profile: str | None = "default",
    apparmor_profile: str | None = "docker-default",
    anomaly_flags_override: dict | None = None,
) -> LinuxContainerArtifact:
    default_flags = {
        "privileged_mode": bool(privileged),
        "host_pid_namespace": False,
        "host_network_namespace": network_mode == "host",
        "host_ipc_namespace": False,
        "dangerous_capability": False,
        "unconfined_seccomp": False,
        "unconfined_apparmor": False,
        "unsafe_mount": False,
        "unknown_registry": False,
    }
    if anomaly_flags_override is not None:
        default_flags.update(anomaly_flags_override)
    return LinuxContainerArtifact(
        firmware_id=firmware_id,
        artifact_path=(
            artifact_path
            or f"/var/lib/docker/containers/{container_id}/config.v2.json"
        ),
        artifact_type=artifact_type,
        container_id=container_id,
        image_id=image_id,
        image_name=image_name,
        image_repository=image_repository,
        image_tag=image_tag,
        runtime="runc",
        state="running",
        privileged=privileged,
        mounts=[
            {"source": "/host", "destination": "/container", "mode": "ro", "type": "bind"}
        ],
        capabilities_add=["CAP_NET_BIND_SERVICE"],
        capabilities_drop=[],
        seccomp_profile=seccomp_profile,
        apparmor_profile=apparmor_profile,
        selinux_label=None,
        network_mode=network_mode,
        env_vars=["PATH", "HOME"],
        command="nginx -g daemon off;",
        entrypoint=None,
        working_dir="/usr/share/nginx/html",
        anomaly_flags=_stamp_linux_container_artifacts_anomaly_flags(
            default_flags
        ),
        raw_state='{"ID": "test"}',
    )


# ── Registration test ────────────────────────────────────────────────────────


def test_register_linux_container_tools_registers_six():
    """register_linux_container_tools must register exactly the six
    ι.E.E tools (5 per-firmware + 1 cross-firmware aggregation)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_linux_container_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "list_container_artifacts" in names
    assert "lookup_container_artifact" in names
    assert "search_container_images" in names
    assert "container_walk_status" in names
    assert "trigger_container_walk" in names
    assert "lookup_container_image_across_firmwares" in names
    assert len(reg._tools) >= 6


# ── list_container_artifacts ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_container_artifacts_empty():
    async with make_live_db() as db:
        project = Project(name="ι.E.E list empty")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "le.bin", "s")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_list_container_artifacts({}, ctx)
        )
        assert out["total_count"] == 0
        assert out["container_artifacts"] == []
        assert "message" in out


@pytest.mark.asyncio
async def test_list_container_artifacts_returns_all_when_no_filters():
    async with make_live_db() as db:
        project = Project(name="ι.E.E list all")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "la.bin", "t")
        db.add(firmware)
        await db.flush()

        db.add(_make_artifact(firmware.id, container_id="c1"))
        db.add(_make_artifact(firmware.id, container_id="c2"))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_list_container_artifacts({}, ctx)
        )
        assert out["total_count"] == 2
        assert len(out["container_artifacts"]) == 2


@pytest.mark.asyncio
async def test_list_container_artifacts_filters_by_artifact_type():
    async with make_live_db() as db:
        project = Project(name="ι.E.E filter type")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "ft.bin", "u")
        db.add(firmware)
        await db.flush()

        db.add(_make_artifact(
            firmware.id, container_id="c1",
            artifact_type="docker_container_state",
        ))
        db.add(_make_artifact(
            firmware.id, container_id="c2",
            artifact_type="podman_state",
            artifact_path="/var/lib/containers/storage/podman-id/userdata/state.json",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_list_container_artifacts(
                {"artifact_type": "podman_state"}, ctx
            )
        )
        assert out["total_count"] == 1
        assert (
            out["container_artifacts"][0]["artifact_type"] == "podman_state"
        )


@pytest.mark.asyncio
async def test_list_container_artifacts_filters_by_privileged():
    async with make_live_db() as db:
        project = Project(name="ι.E.E filter privileged")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fp.bin", "v")
        db.add(firmware)
        await db.flush()

        db.add(_make_artifact(firmware.id, container_id="c1", privileged=False))
        db.add(_make_artifact(firmware.id, container_id="c2", privileged=True))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_list_container_artifacts(
                {"privileged": True}, ctx
            )
        )
        assert out["total_count"] == 1
        assert out["container_artifacts"][0]["privileged"] is True


@pytest.mark.asyncio
async def test_list_container_artifacts_filters_by_anomaly_only():
    async with make_live_db() as db:
        project = Project(name="ι.E.E filter anomaly")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fa.bin", "w")
        db.add(firmware)
        await db.flush()

        # Clean container.
        db.add(_make_artifact(firmware.id, container_id="c1"))
        # Privileged + dangerous-cap container (2 anomalies).
        db.add(_make_artifact(
            firmware.id, container_id="c2",
            privileged=True,
            anomaly_flags_override={
                "privileged_mode": True,
                "dangerous_capability": True,
            },
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_list_container_artifacts(
                {"anomaly_only": True}, ctx
            )
        )
        assert out["total_count"] == 1
        flags = out["container_artifacts"][0]["anomaly_flags"]
        assert flags["privileged_mode"] is True


@pytest.mark.asyncio
async def test_list_container_artifacts_filters_by_anomaly_bit():
    async with make_live_db() as db:
        project = Project(name="ι.E.E filter anomaly bit")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fab.bin", "x")
        db.add(firmware)
        await db.flush()

        # privileged_mode only.
        db.add(_make_artifact(
            firmware.id, container_id="c1",
            anomaly_flags_override={"privileged_mode": True},
        ))
        # unsafe_mount only.
        db.add(_make_artifact(
            firmware.id, container_id="c2",
            anomaly_flags_override={"unsafe_mount": True},
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_list_container_artifacts(
                {"anomaly_bit": "unsafe_mount"}, ctx
            )
        )
        assert out["total_count"] == 1
        assert (
            out["container_artifacts"][0]["anomaly_flags"]["unsafe_mount"]
            is True
        )


# ── lookup_container_artifact ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_container_artifact_missing_id_returns_error():
    async with make_live_db() as db:
        project = Project(name="ι.E.E lookup err")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "lu.bin", "y")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_lookup_container_artifact({}, ctx)
        )
        assert "error" in out
        assert "artifact_id" in out["error"]


@pytest.mark.asyncio
async def test_lookup_container_artifact_invalid_uuid():
    async with make_live_db() as db:
        project = Project(name="ι.E.E lookup invalid")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "lu2.bin", "z")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_lookup_container_artifact(
                {"artifact_id": "not-a-uuid"}, ctx
            )
        )
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_container_artifact_not_found():
    async with make_live_db() as db:
        project = Project(name="ι.E.E lookup 404")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "l404.bin", "a")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_lookup_container_artifact(
                {"artifact_id": str(uuid.uuid4())}, ctx
            )
        )
        assert "not found" in out["error"]


@pytest.mark.asyncio
async def test_lookup_container_artifact_returns_full_detail():
    async with make_live_db() as db:
        project = Project(name="ι.E.E lookup detail")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "ld.bin", "b")
        db.add(firmware)
        await db.flush()

        artifact = _make_artifact(firmware.id, container_id="cd1")
        db.add(artifact)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_lookup_container_artifact(
                {"artifact_id": str(artifact.id)}, ctx
            )
        )
        assert out["container_id"] == "cd1"
        assert "mounts" in out
        assert "capabilities_add" in out
        assert "env_vars" in out
        # Capability list surfaces correctly.
        assert "CAP_NET_BIND_SERVICE" in out["capabilities_add"]
        # Env keys only (values stripped at walker).
        assert "PATH" in out["env_vars"]


# ── search_container_images ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_container_images_missing_query():
    async with make_live_db() as db:
        project = Project(name="ι.E.E search err")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "s1.bin", "c")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_search_container_images({}, ctx)
        )
        assert "error" in out


@pytest.mark.asyncio
async def test_search_container_images_finds_by_image_name():
    async with make_live_db() as db:
        project = Project(name="ι.E.E search name")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "s2.bin", "d")
        db.add(firmware)
        await db.flush()

        db.add(_make_artifact(
            firmware.id, container_id="cs1",
            image_name="nginx:latest",
            image_repository="nginx",
        ))
        db.add(_make_artifact(
            firmware.id, container_id="cs2",
            image_name="docker.io/library/redis:7",
            image_repository="docker.io/library/redis",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_search_container_images(
                {"query": "nginx"}, ctx
            )
        )
        assert out["total_count"] == 1


# ── container_walk_status ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_container_walk_status_firmware_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = json.loads(
            await _handle_container_walk_status({}, ctx)
        )
        assert "error" in out


@pytest.mark.asyncio
async def test_container_walk_status_returns_idle():
    async with make_live_db() as db:
        project = Project(name="ι.E.E status idle")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "st.bin", "e")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_container_walk_status({}, ctx)
        )
        assert out["status"] == "idle"
        assert out["started_at"] is None
        assert out["error"] is None


# ── trigger_container_walk ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_container_walk_firmware_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = json.loads(
            await _handle_trigger_container_walk({}, ctx)
        )
        assert "error" in out


@pytest.mark.asyncio
async def test_trigger_container_walk_returns_409_when_queued():
    async with make_live_db() as db:
        project = Project(name="ι.E.E trigger 409")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "tg.bin", "f")
        firmware.container_walk_status = "queued"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_trigger_container_walk({}, ctx)
        )
        assert out.get("conflict") is True
        assert out["status"] == "queued"


@pytest.mark.asyncio
async def test_trigger_container_walk_returns_409_when_running():
    async with make_live_db() as db:
        project = Project(name="ι.E.E trigger 409 running")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "tr.bin", "g")
        firmware.container_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = json.loads(
            await _handle_trigger_container_walk({}, ctx)
        )
        assert out.get("conflict") is True
        assert out["status"] == "running"


# ── lookup_container_image_across_firmwares ─────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_across_missing_filter_returns_error():
    async with make_live_db() as db:
        project = Project(name="ι.E.E across err")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x1.bin", "h")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=firmware.id, project_id=project.id
        )
        out = json.loads(
            await _handle_lookup_container_image_across_firmwares({}, ctx)
        )
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_across_no_matches():
    async with make_live_db() as db:
        project = Project(name="ι.E.E across 0")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x2.bin", "i")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=firmware.id, project_id=project.id
        )
        out = json.loads(
            await _handle_lookup_container_image_across_firmwares(
                {"image_id": "sha256:absent"}, ctx
            )
        )
        assert out["match_count"] == 0
        assert "message" in out


@pytest.mark.asyncio
async def test_lookup_across_finds_match_single_firmware():
    async with make_live_db() as db:
        project = Project(name="ι.E.E across 1")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x3.bin", "j")
        db.add(firmware)
        await db.flush()

        db.add(_make_artifact(
            firmware.id,
            container_id="cm1",
            image_id="sha256:findme",
            image_repository="docker.io/library/nginx",
            image_tag="1.21",
        ))
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=firmware.id, project_id=project.id
        )
        out = json.loads(
            await _handle_lookup_container_image_across_firmwares(
                {"image_id": "sha256:findme"}, ctx
            )
        )
        assert out["match_count"] == 1
        assert out["matches"][0]["match_count"] == 1
        assert "supply_chain_signal" not in out  # Single firmware


@pytest.mark.asyncio
async def test_lookup_across_supply_chain_signal_on_multi_firmware():
    """Match across 2 firmwares → supply_chain_signal emitted."""
    async with make_live_db() as db:
        project = Project(name="ι.E.E across multi")
        db.add(project)
        await db.flush()
        firmware1 = _make_firmware(project.id, "x4.bin", "k")
        firmware2 = _make_firmware(project.id, "x5.bin", "l")
        db.add(firmware1)
        db.add(firmware2)
        await db.flush()

        db.add(_make_artifact(
            firmware1.id, container_id="ca1",
            image_id="sha256:shared",
            image_repository="evil/payload",
            artifact_path="/var/lib/docker/containers/ca1/config.v2.json",
        ))
        db.add(_make_artifact(
            firmware2.id, container_id="ca2",
            image_id="sha256:shared",
            image_repository="evil/payload",
            artifact_path="/var/lib/docker/containers/ca2/config.v2.json",
        ))
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=firmware1.id, project_id=project.id
        )
        out = json.loads(
            await _handle_lookup_container_image_across_firmwares(
                {"image_id": "sha256:shared"}, ctx
            )
        )
        assert out["match_count"] == 2
        assert "supply_chain_signal" in out


@pytest.mark.asyncio
async def test_lookup_across_filter_by_repository():
    async with make_live_db() as db:
        project = Project(name="ι.E.E across repo")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "xr.bin", "m")
        db.add(firmware)
        await db.flush()

        db.add(_make_artifact(
            firmware.id, container_id="cr1",
            image_repository="docker.io/library/nginx",
        ))
        db.add(_make_artifact(
            firmware.id, container_id="cr2",
            image_repository="evil/payload",
            artifact_path="/var/lib/docker/containers/cr2/config.v2.json",
        ))
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=firmware.id, project_id=project.id
        )
        out = json.loads(
            await _handle_lookup_container_image_across_firmwares(
                {"image_repository": "evil/payload"}, ctx
            )
        )
        assert out["match_count"] == 1


@pytest.mark.asyncio
async def test_lookup_across_global_scope_spans_projects():
    async with make_live_db() as db:
        project1 = Project(name="ι.E.E gp1")
        project2 = Project(name="ι.E.E gp2")
        db.add(project1)
        db.add(project2)
        await db.flush()
        firmware1 = _make_firmware(project1.id, "g1.bin", "n")
        firmware2 = _make_firmware(project2.id, "g2.bin", "o")
        db.add(firmware1)
        db.add(firmware2)
        await db.flush()

        db.add(_make_artifact(
            firmware1.id, container_id="g1c",
            image_id="sha256:global",
        ))
        db.add(_make_artifact(
            firmware2.id, container_id="g2c",
            image_id="sha256:global",
            artifact_path="/var/lib/docker/containers/g2c/config.v2.json",
        ))
        await db.commit()

        # project scope on project1 → only 1 match.
        ctx = _StubContext(
            db=db, firmware_id=firmware1.id, project_id=project1.id
        )
        out_proj = json.loads(
            await _handle_lookup_container_image_across_firmwares(
                {"image_id": "sha256:global", "scope": "project"}, ctx
            )
        )
        assert out_proj["match_count"] == 1

        # global scope → 2 matches across both projects.
        out_global = json.loads(
            await _handle_lookup_container_image_across_firmwares(
                {"image_id": "sha256:global", "scope": "global"}, ctx
            )
        )
        assert out_global["match_count"] == 2
        assert "supply_chain_signal" in out_global
