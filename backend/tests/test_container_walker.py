"""Tier-1 tests for the Phase ι.E.C Linux container-runtime artefact walker.

Walker is the FIFTH ι walker, THIRD Linux walker after ι.A journald +
ι.B systemd. Pure-function tests cover the anomaly detector + parsers
for Docker, containerd, podman, OCI manifest, and the cross-format
helpers. Rule #35b live canary drives the full ``_do_container_walk``
pipeline against an ORM-backed test session. Rule #36 no-execute test
gate enforces walker source has no spawn primitive against extracted
artefacts.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest
from sqlalchemy import select

from app.models.firmware import Firmware
from app.models.linux_container_artifacts import LinuxContainerArtifact
from app.models.project import Project
from app.services.container_walker import (
    _do_container_walk,
    build_anomaly_flags,
    find_container_artifacts,
    has_dangerous_capability,
    is_known_registry,
    is_unsafe_mount,
    normalize_capability,
    parse_containerd_state,
    parse_docker_container_state,
    parse_docker_repositories,
    parse_image_repository_tag,
    parse_oci_manifest,
    parse_oci_runtime_spec,
)
from tests._live_db import make_live_db

# ── normalize_capability + has_dangerous_capability ─────────────────────────


def test_normalize_capability_strips_cap_prefix():
    assert normalize_capability("CAP_SYS_ADMIN") == "SYS_ADMIN"
    assert normalize_capability("cap_sys_ptrace") == "SYS_PTRACE"


def test_normalize_capability_lowercase_input():
    assert normalize_capability("sys_admin") == "SYS_ADMIN"


def test_normalize_capability_no_prefix():
    assert normalize_capability("SYS_ADMIN") == "SYS_ADMIN"


def test_has_dangerous_capability_sys_admin():
    assert has_dangerous_capability(["CAP_SYS_ADMIN"]) is True


def test_has_dangerous_capability_sys_ptrace():
    assert has_dangerous_capability(["CAP_SYS_PTRACE"]) is True


def test_has_dangerous_capability_sys_module():
    assert has_dangerous_capability(["CAP_SYS_MODULE"]) is True


def test_has_dangerous_capability_dac_read_search():
    assert has_dangerous_capability(["CAP_DAC_READ_SEARCH"]) is True


def test_has_dangerous_capability_net_admin():
    assert has_dangerous_capability(["CAP_NET_ADMIN"]) is True


def test_has_dangerous_capability_safe_caps():
    assert (
        has_dangerous_capability(["CAP_NET_BIND_SERVICE", "CAP_KILL"]) is False
    )


def test_has_dangerous_capability_empty():
    assert has_dangerous_capability([]) is False


def test_has_dangerous_capability_lowercase():
    """Accept lower-case / no-prefix forms via normalization."""
    assert has_dangerous_capability(["sys_admin"]) is True


# ── is_unsafe_mount ─────────────────────────────────────────────────────────


def test_is_unsafe_mount_docker_sock():
    assert is_unsafe_mount("/var/run/docker.sock") is True


def test_is_unsafe_mount_containerd_sock():
    assert is_unsafe_mount("/var/run/containerd/containerd.sock") is True


def test_is_unsafe_mount_etc():
    assert is_unsafe_mount("/etc") is True


def test_is_unsafe_mount_etc_subdir():
    assert is_unsafe_mount("/etc/passwd") is True


def test_is_unsafe_mount_proc():
    assert is_unsafe_mount("/proc") is True


def test_is_unsafe_mount_sys():
    assert is_unsafe_mount("/sys") is True


def test_is_unsafe_mount_dev():
    assert is_unsafe_mount("/dev") is True


def test_is_unsafe_mount_root():
    assert is_unsafe_mount("/") is True


def test_is_unsafe_mount_home():
    assert is_unsafe_mount("/home/alice/data") is True


def test_is_unsafe_mount_safe_path():
    assert is_unsafe_mount("/opt/myapp/data") is False


def test_is_unsafe_mount_empty():
    assert is_unsafe_mount(None) is False
    assert is_unsafe_mount("") is False


def test_is_unsafe_mount_etcetera_not_etc():
    """/etcetera should NOT match /etc (prefix-with-slash gate)."""
    assert is_unsafe_mount("/etcetera/data") is False


# ── is_known_registry ───────────────────────────────────────────────────────


def test_is_known_registry_docker_io():
    assert is_known_registry("docker.io/library/nginx") is True


def test_is_known_registry_gcr_io():
    assert is_known_registry("gcr.io/foo/bar") is True


def test_is_known_registry_mcr_microsoft():
    assert is_known_registry("mcr.microsoft.com/dotnet/aspnet:6.0") is True


def test_is_known_registry_quay_io():
    assert is_known_registry("quay.io/coreos/etcd") is True


def test_is_known_registry_bare_name():
    """Bare image name implicitly resolves to docker.io."""
    assert is_known_registry("nginx") is True


def test_is_known_registry_library_prefix():
    """library/nginx is docker.io library namespace."""
    assert is_known_registry("library/nginx") is True


def test_is_known_registry_unknown():
    assert is_known_registry("evil-registry.attacker.com/payload") is False


def test_is_known_registry_empty():
    assert is_known_registry(None) is False
    assert is_known_registry("") is False


# ── parse_image_repository_tag ──────────────────────────────────────────────


def test_parse_image_repository_tag_simple():
    repo, tag = parse_image_repository_tag("nginx:1.21")
    assert repo == "nginx"
    assert tag == "1.21"


def test_parse_image_repository_tag_with_registry():
    repo, tag = parse_image_repository_tag("docker.io/library/nginx:latest")
    assert repo == "docker.io/library/nginx"
    assert tag == "latest"


def test_parse_image_repository_tag_with_port():
    repo, tag = parse_image_repository_tag("registry:5000/foo/bar:v1")
    assert repo == "registry:5000/foo/bar"
    assert tag == "v1"


def test_parse_image_repository_tag_no_tag():
    repo, tag = parse_image_repository_tag("gcr.io/foo/bar")
    assert repo == "gcr.io/foo/bar"
    assert tag is None


def test_parse_image_repository_tag_sha_addressed():
    repo, tag = parse_image_repository_tag("nginx@sha256:abc123def456")
    assert repo == "nginx"
    assert tag == "sha256:abc123def456"


def test_parse_image_repository_tag_empty():
    assert parse_image_repository_tag(None) == (None, None)
    assert parse_image_repository_tag("") == (None, None)


# ── build_anomaly_flags ─────────────────────────────────────────────────────


def test_build_anomaly_flags_all_clean():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode="bridge",
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile="default",
        apparmor_profile="docker-default",
        mounts=[],
        image_name="docker.io/library/nginx:latest",
    )
    assert flags["privileged_mode"] is False
    assert flags["host_pid_namespace"] is False
    assert flags["host_network_namespace"] is False
    assert flags["host_ipc_namespace"] is False
    assert flags["dangerous_capability"] is False
    assert flags["unconfined_seccomp"] is False
    assert flags["unconfined_apparmor"] is False
    assert flags["unsafe_mount"] is False
    assert flags["unknown_registry"] is False


def test_build_anomaly_flags_privileged():
    flags = build_anomaly_flags(
        privileged=True,
        pid_mode=None,
        network_mode=None,
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile=None,
        apparmor_profile=None,
        mounts=[],
        image_name=None,
    )
    assert flags["privileged_mode"] is True


def test_build_anomaly_flags_host_network():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode="host",
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile=None,
        apparmor_profile=None,
        mounts=[],
        image_name=None,
    )
    assert flags["host_network_namespace"] is True


def test_build_anomaly_flags_host_pid():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode="host",
        network_mode=None,
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile=None,
        apparmor_profile=None,
        mounts=[],
        image_name=None,
    )
    assert flags["host_pid_namespace"] is True


def test_build_anomaly_flags_host_ipc():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode=None,
        ipc_mode="host",
        capabilities_add=[],
        seccomp_profile=None,
        apparmor_profile=None,
        mounts=[],
        image_name=None,
    )
    assert flags["host_ipc_namespace"] is True


def test_build_anomaly_flags_dangerous_capability():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode=None,
        ipc_mode=None,
        capabilities_add=["CAP_SYS_ADMIN"],
        seccomp_profile=None,
        apparmor_profile=None,
        mounts=[],
        image_name=None,
    )
    assert flags["dangerous_capability"] is True


def test_build_anomaly_flags_unconfined_seccomp():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode=None,
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile="unconfined",
        apparmor_profile=None,
        mounts=[],
        image_name=None,
    )
    assert flags["unconfined_seccomp"] is True


def test_build_anomaly_flags_unconfined_apparmor():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode=None,
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile=None,
        apparmor_profile="unconfined",
        mounts=[],
        image_name=None,
    )
    assert flags["unconfined_apparmor"] is True


def test_build_anomaly_flags_unsafe_mount_docker_sock():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode=None,
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile=None,
        apparmor_profile=None,
        mounts=[{
            "source": "/var/run/docker.sock",
            "destination": "/var/run/docker.sock",
            "type": "bind",
        }],
        image_name=None,
    )
    assert flags["unsafe_mount"] is True


def test_build_anomaly_flags_unsafe_mount_etc():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode=None,
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile=None,
        apparmor_profile=None,
        mounts=[{
            "source": "/etc",
            "destination": "/host_etc",
            "type": "bind",
        }],
        image_name=None,
    )
    assert flags["unsafe_mount"] is True


def test_build_anomaly_flags_safe_mount():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode=None,
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile=None,
        apparmor_profile=None,
        mounts=[{
            "source": "/opt/myapp/data",
            "destination": "/data",
            "type": "bind",
        }],
        image_name=None,
    )
    assert flags["unsafe_mount"] is False


def test_build_anomaly_flags_volume_mount_not_unsafe():
    """Volume mounts (vs bind) are NOT flagged unsafe."""
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode=None,
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile=None,
        apparmor_profile=None,
        mounts=[{
            "source": "/var/lib/docker/volumes/foo",
            "destination": "/data",
            "type": "volume",
        }],
        image_name=None,
    )
    assert flags["unsafe_mount"] is False


def test_build_anomaly_flags_unknown_registry():
    flags = build_anomaly_flags(
        privileged=False,
        pid_mode=None,
        network_mode=None,
        ipc_mode=None,
        capabilities_add=[],
        seccomp_profile=None,
        apparmor_profile=None,
        mounts=[],
        image_name="evil-registry.attacker.com/payload:v1",
    )
    assert flags["unknown_registry"] is True


# ── parse_docker_container_state ────────────────────────────────────────────


def test_parse_docker_container_state_basic():
    config_v2 = {
        "ID": "abc123" * 10,
        "Image": "docker.io/library/nginx:1.21",
        "ImageID": "sha256:" + "0" * 64,
        "Config": {
            "Image": "nginx:1.21",
            "Cmd": ["nginx", "-g", "daemon off;"],
            "Entrypoint": ["/docker-entrypoint.sh"],
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin", "NGINX_VERSION=1.21"],
            "WorkingDir": "/usr/share/nginx/html",
        },
        "State": {"Running": True},
        "MountPoints": {},
    }
    hostconfig = {
        "Privileged": False,
        "NetworkMode": "bridge",
        "CapAdd": [],
        "CapDrop": [],
        "Binds": ["/host/log:/container/log:ro"],
        "Runtime": "runc",
        "PidMode": "",
        "IpcMode": "private",
    }
    parsed = parse_docker_container_state(config_v2, hostconfig)
    assert parsed["container_id"] == "abc123" * 10
    assert parsed["image_name"] == "docker.io/library/nginx:1.21"
    assert parsed["image_id"] == "sha256:" + "0" * 64
    assert parsed["image_repository"] == "docker.io/library/nginx"
    assert parsed["image_tag"] == "1.21"
    assert parsed["state"] == "running"
    assert parsed["privileged"] is False
    assert parsed["network_mode"] == "bridge"
    assert parsed["runtime"] == "runc"
    assert "PATH" in parsed["env_vars"]
    assert "NGINX_VERSION" in parsed["env_vars"]
    # Env VALUES dropped for security.
    assert "/usr/local/sbin:/usr/local/bin" not in parsed["env_vars"]
    assert "nginx -g daemon off;" == parsed["command"]
    assert parsed["entrypoint"] == "/docker-entrypoint.sh"
    assert parsed["working_dir"] == "/usr/share/nginx/html"
    # Bind mount parsed.
    assert any(
        m["source"] == "/host/log" and m["destination"] == "/container/log"
        for m in parsed["mounts"]
    )


def test_parse_docker_container_state_privileged():
    config_v2 = {"ID": "x", "Image": "nginx", "Config": {}}
    hostconfig = {"Privileged": True, "CapAdd": ["CAP_SYS_ADMIN"]}
    parsed = parse_docker_container_state(config_v2, hostconfig)
    assert parsed["privileged"] is True
    assert "CAP_SYS_ADMIN" in parsed["capabilities_add"]


def test_parse_docker_container_state_host_network():
    config_v2 = {"ID": "x", "Image": "nginx", "Config": {}}
    hostconfig = {"NetworkMode": "host", "Privileged": False}
    parsed = parse_docker_container_state(config_v2, hostconfig)
    assert parsed["network_mode"] == "host"


def test_parse_docker_container_state_security_opt_seccomp():
    config_v2 = {"ID": "x", "Image": "nginx", "Config": {}}
    hostconfig = {
        "SecurityOpt": ["seccomp=unconfined", "apparmor=docker-default"],
    }
    parsed = parse_docker_container_state(config_v2, hostconfig)
    assert parsed["seccomp_profile"] == "unconfined"
    assert parsed["apparmor_profile"] == "docker-default"


# ── parse_oci_runtime_spec ──────────────────────────────────────────────────


def test_parse_oci_runtime_spec_basic():
    state = {
        "process": {
            "args": ["/bin/sh", "-c", "echo hello"],
            "env": ["PATH=/usr/bin", "DEBUG=1"],
            "cwd": "/app",
            "capabilities": {
                "bounding": ["CAP_NET_BIND_SERVICE"],
                "effective": ["CAP_NET_BIND_SERVICE"],
            },
        },
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "network"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"},
            ],
        },
        "mounts": [
            {
                "source": "/proc",
                "destination": "/proc",
                "type": "proc",
            },
        ],
    }
    parsed = parse_oci_runtime_spec(state)
    assert "CAP_NET_BIND_SERVICE" in parsed["capabilities_add"]
    assert parsed["working_dir"] == "/app"
    assert parsed["command"] == "/bin/sh -c echo hello"
    assert "PATH" in parsed["env_vars"]
    # Both pid and network declared as namespaces → NOT host.
    assert parsed["_pid_mode"] is None
    assert parsed["network_mode"] is None
    assert parsed["_ipc_mode"] is None


def test_parse_oci_runtime_spec_host_namespaces():
    """Missing namespace declaration = container shares host namespace."""
    state = {
        "process": {"args": ["sh"]},
        "linux": {
            "namespaces": [
                {"type": "mount"},
                # No pid / network / ipc — adversary shares host namespaces.
            ],
        },
    }
    parsed = parse_oci_runtime_spec(state)
    assert parsed["_pid_mode"] == "host"
    assert parsed["network_mode"] == "host"
    assert parsed["_ipc_mode"] == "host"


def test_parse_oci_runtime_spec_dangerous_caps():
    state = {
        "process": {
            "capabilities": {
                "bounding": ["CAP_SYS_ADMIN", "CAP_NET_BIND_SERVICE"],
            },
        },
        "linux": {"namespaces": []},
    }
    parsed = parse_oci_runtime_spec(state)
    assert "CAP_SYS_ADMIN" in parsed["capabilities_add"]


# ── parse_containerd_state ──────────────────────────────────────────────────


def test_parse_containerd_state_basic():
    state = {
        "ID": "abc123",
        "Runtime": {"name": "io.containerd.runc.v2"},
    }
    parsed = parse_containerd_state(state)
    assert parsed["container_id"] == "abc123"
    assert parsed["runtime"] == "io.containerd.runc.v2"


# ── parse_oci_manifest ──────────────────────────────────────────────────────


def test_parse_oci_manifest_basic():
    state = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "annotations": {
            "org.opencontainers.image.ref.name": "library/nginx:1.21",
        },
        "config": {
            "digest": "sha256:abc123",
        },
    }
    parsed = parse_oci_manifest(state)
    assert parsed["image_name"] == "library/nginx:1.21"
    assert parsed["image_id"] == "sha256:abc123"


# ── parse_docker_repositories ───────────────────────────────────────────────


def test_parse_docker_repositories_basic():
    state = {
        "Repositories": {
            "nginx": {
                "latest": "sha256:abc",
                "1.21": "sha256:def",
            },
        },
    }
    out = parse_docker_repositories(state)
    assert len(out) == 2
    assert any(o["image_name"] == "nginx:latest" for o in out)
    assert any(o["image_name"] == "nginx:1.21" for o in out)


# ── find_container_artifacts ────────────────────────────────────────────────


def _make_fake_firmware_tree(
    tmp_path: pathlib.Path,
    *,
    docker_container_id: str = "a" * 64,
) -> pathlib.Path:
    """Build a synthetic Linux firmware extract with docker / podman /
    containerd artifacts."""
    # Docker container state.
    docker_dir = (
        tmp_path / "var" / "lib" / "docker" / "containers" / docker_container_id
    )
    docker_dir.mkdir(parents=True, exist_ok=True)
    (docker_dir / "config.v2.json").write_text(
        json.dumps({
            "ID": docker_container_id,
            "Image": "docker.io/library/nginx:1.21",
            "Config": {"Cmd": ["nginx"], "Env": ["PATH=/usr/bin"]},
            "State": {"Running": True},
        })
    )
    (docker_dir / "hostconfig.json").write_text(
        json.dumps({
            "Privileged": False,
            "NetworkMode": "bridge",
            "CapAdd": [],
            "Binds": ["/host:/container:ro"],
        })
    )

    # Docker daemon config.
    docker_etc = tmp_path / "etc" / "docker"
    docker_etc.mkdir(parents=True, exist_ok=True)
    (docker_etc / "daemon.json").write_text(
        json.dumps({"insecure-registries": []})
    )

    # Podman state.
    podman_dir = (
        tmp_path / "var" / "lib" / "containers" / "storage"
        / "overlay-containers" / "podman-id-1" / "userdata"
    )
    podman_dir.mkdir(parents=True, exist_ok=True)
    (podman_dir / "state.json").write_text(
        json.dumps({"ID": "podman-id-1", "State": {"Status": "exited"}})
    )

    return tmp_path


def test_find_container_artifacts_docker(tmp_path):
    fw_root = _make_fake_firmware_tree(tmp_path)
    hits = find_container_artifacts([str(fw_root)])
    types = {t for _, t, _ in hits}
    assert "docker_container_state" in types
    assert "docker_hostconfig" in types
    assert "daemon_config" in types
    assert "podman_state" in types


def test_find_container_artifacts_empty_root(tmp_path):
    """No container artifacts in a bare directory."""
    hits = find_container_artifacts([str(tmp_path)])
    assert hits == []


# ── Rule #35b live canaries — end-to-end against real ORM/DB ────────────────


@pytest.mark.asyncio
async def test_do_container_walk_no_artifacts_returns_empty(tmp_path):
    """Empty extracted tree → empty aggregate."""
    async with make_live_db() as db:
        project = Project(name="iota-e-empty", description="ι.E.C empty canary")
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

        result = await _do_container_walk(db, firmware.id)
        assert result["artifacts_scanned"] == 0
        assert result["artifacts_persisted"] == 0
        assert result["containers_count"] == 0
        assert result["anomaly_total"] == 0


@pytest.mark.asyncio
async def test_do_container_walk_persists_docker_state(tmp_path):
    """Rule #35b — full pipeline against a synthetic Docker container."""
    fw_root = _make_fake_firmware_tree(tmp_path)

    async with make_live_db() as db:
        project = Project(name="iota-e-docker", description="ι.E.C docker canary")
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="firmware.bin",
            storage_path="/tmp/firmware",
            file_size=512,
            sha256="1" * 64,
            extracted_path=str(fw_root),
        )
        db.add(firmware)
        await db.flush()

        result = await _do_container_walk(db, firmware.id)
        await db.commit()

        # Should have found at least:
        # - 1 docker_container_state
        # - 1 daemon_config
        # - 1 podman_state
        assert result["artifacts_persisted"] >= 3
        assert result["containers_count"] >= 1
        assert result["configs_count"] >= 1

        rows = (
            await db.execute(
                select(LinuxContainerArtifact).where(
                    LinuxContainerArtifact.firmware_id == firmware.id,
                )
            )
        ).scalars().all()
        assert len(rows) >= 3

        # Verify the docker_container_state row has parsed metadata.
        docker_rows = [
            r for r in rows if r.artifact_type == "docker_container_state"
        ]
        assert len(docker_rows) == 1
        docker_row = docker_rows[0]
        assert docker_row.image_name == "docker.io/library/nginx:1.21"
        assert docker_row.image_repository == "docker.io/library/nginx"
        assert docker_row.privileged is False
        assert docker_row.network_mode == "bridge"
        # anomaly_flags includes schema_version sentinel.
        assert docker_row.anomaly_flags is not None
        assert docker_row.anomaly_flags.get("schema_version") == 1
        # Bind mount /host:/container is NOT under any unsafe prefix.
        assert docker_row.anomaly_flags.get("unsafe_mount") is False


@pytest.mark.asyncio
async def test_do_container_walk_detects_privileged(tmp_path):
    """Privileged container should set anomaly_flags.privileged_mode."""
    container_id = "b" * 64
    docker_dir = (
        tmp_path / "var" / "lib" / "docker" / "containers" / container_id
    )
    docker_dir.mkdir(parents=True, exist_ok=True)
    (docker_dir / "config.v2.json").write_text(
        json.dumps({
            "ID": container_id,
            "Image": "evil-registry.attacker.com/payload:v1",
            "Config": {"Cmd": ["bash"]},
            "State": {"Running": True},
        })
    )
    (docker_dir / "hostconfig.json").write_text(
        json.dumps({
            "Privileged": True,
            "NetworkMode": "host",
            "PidMode": "host",
            "IpcMode": "host",
            "CapAdd": ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"],
            "SecurityOpt": ["seccomp=unconfined"],
            "AppArmorProfile": "unconfined",
            "Binds": ["/var/run/docker.sock:/var/run/docker.sock:rw"],
        })
    )

    async with make_live_db() as db:
        project = Project(name="iota-e-priv", description="ι.E.C privileged canary")
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="pwn.bin",
            storage_path="/tmp/pwn",
            file_size=512,
            sha256="2" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.flush()

        result = await _do_container_walk(db, firmware.id)
        await db.commit()

        rows = (
            await db.execute(
                select(LinuxContainerArtifact).where(
                    LinuxContainerArtifact.firmware_id == firmware.id,
                    LinuxContainerArtifact.artifact_type
                    == "docker_container_state",
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        row = rows[0]
        flags = row.anomaly_flags
        assert flags["privileged_mode"] is True
        assert flags["host_network_namespace"] is True
        assert flags["host_pid_namespace"] is True
        assert flags["host_ipc_namespace"] is True
        assert flags["dangerous_capability"] is True
        assert flags["unconfined_seccomp"] is True
        assert flags["unconfined_apparmor"] is True
        assert flags["unsafe_mount"] is True  # docker.sock
        assert flags["unknown_registry"] is True  # evil-registry.attacker.com

        # Aggregate counts.
        assert result["privileged_count"] == 1
        assert result["host_namespace_count"] == 1
        assert result["dangerous_capability_count"] == 1
        assert result["unsafe_mount_count"] == 1
        assert result["unconfined_security_count"] == 1
        assert result["unknown_registry_count"] == 1
        assert result["anomaly_total"] == 1


@pytest.mark.asyncio
async def test_do_container_walk_oversize_skipped(tmp_path):
    """Oversize JSON > 10MB → oversize_skipped counter incremented."""
    from app.services import container_walker as cw_module

    container_id = "c" * 64
    docker_dir = (
        tmp_path / "var" / "lib" / "docker" / "containers" / container_id
    )
    docker_dir.mkdir(parents=True, exist_ok=True)

    # Monkey-patch the size cap to a small value so we don't write a 10MB file.
    original_cap = cw_module._DEFAULT_MAX_ARTIFACT_BYTES
    try:
        cw_module._DEFAULT_MAX_ARTIFACT_BYTES = 64

        (docker_dir / "config.v2.json").write_text(
            json.dumps({"ID": container_id, "Image": "x", "Config": {}, "State": {}})
            # > 64 chars even after json formatting
        )

        async with make_live_db() as db:
            project = Project(name="iota-e-oversize", description="ι.E.C oversize")
            db.add(project)
            await db.flush()
            firmware = Firmware(
                project_id=project.id,
                original_filename="big.bin",
                storage_path="/tmp/big",
                file_size=512,
                sha256="3" * 64,
                extracted_path=str(tmp_path),
            )
            db.add(firmware)
            await db.flush()

            result = await _do_container_walk(db, firmware.id)
            await db.commit()

            assert result["oversize_skipped"] >= 1
    finally:
        cw_module._DEFAULT_MAX_ARTIFACT_BYTES = original_cap


@pytest.mark.asyncio
async def test_do_container_walk_malformed_json_records_parse_error(tmp_path):
    """Malformed JSON → row persisted with parse_error field set."""
    container_id = "d" * 64
    docker_dir = (
        tmp_path / "var" / "lib" / "docker" / "containers" / container_id
    )
    docker_dir.mkdir(parents=True, exist_ok=True)
    (docker_dir / "config.v2.json").write_text("not valid json at all")
    (docker_dir / "hostconfig.json").write_text("{}")

    async with make_live_db() as db:
        project = Project(name="iota-e-mal", description="ι.E.C malformed")
        db.add(project)
        await db.flush()
        firmware = Firmware(
            project_id=project.id,
            original_filename="bad.bin",
            storage_path="/tmp/bad",
            file_size=512,
            sha256="4" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.flush()

        result = await _do_container_walk(db, firmware.id)
        await db.commit()

        assert result["parse_errors"] >= 1

        rows = (
            await db.execute(
                select(LinuxContainerArtifact).where(
                    LinuxContainerArtifact.firmware_id == firmware.id,
                )
            )
        ).scalars().all()
        assert any(r.parse_error is not None for r in rows)


# ── Rule #36 no-execute test gate ──────────────────────────────────────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Remove docstrings, # comments, and string literals from Python
    source so we can scan for ACTUAL code references without false
    positives from prose that MENTIONS forbidden primitives.
    """
    import io
    import tokenize

    out_tokens = []
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


def test_container_walker_no_execute_no_container_invocation():
    """Rule #36 — the container_walker.py CODE (not docstrings/comments)
    MUST NOT invoke any spawn primitive against extracted artefacts AND
    MUST NOT shell out to docker / containerd / podman / runc / kubectl.

    The walker is a pure metadata parser; nothing should exec / spawn
    against the parsed data, AND nothing should invoke the container
    runtimes whose state files we're reading.
    """
    raw_source = (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "container_walker.py"
    ).read_text()
    source = _strip_docstrings_and_comments(raw_source)

    # Rule #36 standard forbidden-spawn tokens.
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
            f"Rule #36 violation in container_walker.py CODE — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke spawn primitives against extracted artefacts."
        )

    # Container-runtime CLI invocations — wairz must not run docker /
    # containerd / podman / runc / kubectl directly.
    forbidden_container_cli = (
        r"['\"](?:docker|containerd-ctr|ctr|podman|runc|kubectl|crictl|nerdctl)['\"]",
    )
    for pattern in forbidden_container_cli:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in container_walker.py CODE — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "invoke container runtimes against extracted state."
        )

    # Belt-and-braces: assert no image-pull primitives.
    image_pull_anti_tokens = (
        r"\bpull_image\b",
        r"\bdocker_pull\b",
        r"image_pull\(",
    )
    for pattern in image_pull_anti_tokens:
        matches = re.findall(pattern, raw_source)
        assert not matches, (
            f"Rule #36 violation in container_walker.py — found "
            f"{matches} matching {pattern!r}; the walker MUST NOT "
            "pull container images."
        )
