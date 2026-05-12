"""Phase ι.E.C — Linux container runtime artefact walker (THIRD LINUX, FIFTH ι).

Walks every container-runtime state / image-spec / config artefact
under detection roots (per Rule #16). Discriminates by file path +
content shape (Docker config.v2.json + hostconfig.json; containerd
state.json + config.json; podman state.json + config.json; OCI
manifest.json + repositories.json; daemon.json + storage.conf +
registries.conf). Surfaces T1610 (Deploy Container), T1611 (Escape to
Host), T1612 (Build Image on Host) persistence + privilege indicators.

Real-world Persona-E container forensics relevance (Phase ι Scout 3
"modest engineering cost" ship):

- **T1610 (Deploy Container)** — privileged-deploy + dangerous-capability
  signals via per-row anomaly bits (``privileged_mode`` /
  ``dangerous_capability``). Adversary deploys a privileged container
  to gain a foothold on the host.
- **T1611 (Escape to Host)** — host-namespace shares (PID/Network/IPC)
  + unsafe bind mounts (``/var/run/docker.sock``, ``/proc``, ``/sys``,
  ``/etc``, ``/dev``, ``/``) surfaced via ``host_*_namespace`` /
  ``unsafe_mount``. Dangerous capabilities (``CAP_SYS_ADMIN``,
  ``CAP_SYS_PTRACE``, ``CAP_SYS_MODULE``, ``CAP_DAC_READ_SEARCH``,
  ``CAP_NET_ADMIN``) flagged via ``dangerous_capability``.
- **T1612 (Build Image on Host)** — surfaces via the OCI manifest +
  image_repository fields.

**2025 CVE cluster:** 3 runc CVEs (CVE-2025-31133 unsafe symlink mount,
CVE-2025-52565 mishandling /dev/console, CVE-2025-52881 procfs write
redirect) + Docker CVE-2025-9074 (internal API exposure via embedded
Engine API). All exploit chains start from inspectable container-state
artefacts that wairz now surfaces.

**Rule #19 evidence-first OSS-library probe**:

- All container state files are JSON. Python stdlib ``json`` handles
  them. NO new dependency.
- Container state file formats are well-documented:
  - Docker config.v2.json + hostconfig.json: Moby project source.
  - OCI runtime-spec config.json: github.com/opencontainers/runtime-spec.
  - OCI image-spec manifest.json: github.com/opencontainers/image-spec.
  - containerd v2 task state: github.com/containerd/containerd.
  - podman storage overlay-containers: docs.podman.io.

**Rule #39 inner/outer/safe runner triplet** (Rule-of-Eighteen → Rule-
of-Nineteen with this stream):

- :func:`_do_container_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every container artefact under detection roots,
  discriminates by path + shape, parses each via stdlib json, persists
  per-artifact ``LinuxContainerArtifact`` rows, returns aggregate dict
  UNSTAMPED.
- :func:`run_container_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer guard
  catches escapes; failure persistence on a fresh session.
- :func:`auto_container_walk_firmware_safe` — UNPACK-POST-DETECTION
  hook. Runs the inner orchestrator but does NOT mutate
  ``container_walk_status`` (leaves ``idle`` so manual re-trigger
  works without 409).

**Rule #36 no-execute discipline.** This is a pure-Python JSON parser.
The walker NEVER:

- Invokes ``docker`` / ``containerd-ctr`` / ``podman`` against parsed
  artefacts.
- Executes any extracted container.
- Pulls images from registries.
- Sources or evaluates any ``Cmd`` / ``Entrypoint`` / ``Command`` value.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare ``firmware.extracted_path``)
so multi-rootfs Linux firmware (squashfs / ext / cramfs / erofs /
tar.xz) surfaces every container state file.

**Rule #43 noqa rationale (category 3, bounded loop over ≤8 detection
roots).** Sync filesystem operations inside the bounded outer loop
(over detection roots) are inline rather than executor-wrapped.

**Performance.** A typical Linux firmware extract carries 0-50
container state files. The walker completes in <1 s per firmware. We
cap per-firmware at 10K artefacts (defensive against attacker-planted
trees) and per-file size at 10 MB (defensive against attacker-planted
huge JSON).
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import glob
import json
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.linux_container_artifacts import LinuxContainerArtifact
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_container_walk_result,
    _stamp_linux_container_artifacts_anomaly_flags,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum artefacts persisted per firmware. Production Linux firmware
# usually has 0-50 container artefacts; bounding at 10K protects
# against attacker-planted trees with thousands of bogus state files.
_DEFAULT_MAX_ARTIFACTS_PER_FIRMWARE: int = 10_000

# Cap on per-file size. Real-world container state JSON files are
# <100 KB; bounding at 10 MB protects against attacker-planted huge
# files.
_DEFAULT_MAX_ARTIFACT_BYTES: int = 10 * 1024 * 1024

# Truncate raw_state content to this size for DB persistence.
_MAX_RAW_STATE_CHARS: int = 8192

# Truncate command / entrypoint to this size.
_MAX_EXEC_CHARS: int = 2048


# ── Artifact type discriminators ─────────────────────────────────────────────

# Docker container state lives at var/lib/docker/containers/<id>/config.v2.json
# Glob pattern relative to each detection root.
_DOCKER_CONTAINER_GLOB: str = "var/lib/docker/containers/*/config.v2.json"
_DOCKER_HOSTCONFIG_GLOB: str = "var/lib/docker/containers/*/hostconfig.json"

# containerd state lives at var/run/containerd/io.containerd.runtime.v2.task/.../state.json
_CONTAINERD_STATE_GLOB: str = (
    "var/run/containerd/io.containerd.runtime.v2.task/*/*/state.json"
)
_CONTAINERD_CONFIG_GLOB: str = (
    "var/run/containerd/io.containerd.runtime.v2.task/*/*/config.json"
)

# podman state lives at var/lib/containers/storage/overlay-containers/<id>/userdata/
_PODMAN_STATE_GLOB: str = (
    "var/lib/containers/storage/overlay-containers/*/userdata/state.json"
)
_PODMAN_CONFIG_GLOB: str = (
    "var/lib/containers/storage/overlay-containers/*/userdata/config.json"
)

# Docker image registry
_DOCKER_REPOSITORIES_GLOB: str = (
    "var/lib/docker/image/overlay2/repositories.json"
)
# podman image manifests
_PODMAN_MANIFEST_GLOB: str = (
    "var/lib/containers/storage/overlay-images/*/manifest"
)

# Runtime config files
_DAEMON_CONFIG_PATHS: tuple[str, ...] = (
    "etc/docker/daemon.json",
)
_RUNTIME_CONFIG_PATHS: tuple[str, ...] = (
    "etc/containers/storage.conf",
    "etc/containers/registries.conf",
)


# ── Anomaly classifier constants ─────────────────────────────────────────────

# Dangerous Linux capabilities that signal T1611 escape-pathway risk.
# Names normalised without the CAP_ prefix (some configs use plain
# "SYS_ADMIN", others "CAP_SYS_ADMIN").
_DANGEROUS_CAPS: frozenset[str] = frozenset({
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
    "NET_ADMIN",
    "NET_RAW",
    "SETUID",
    "SETGID",
    "MKNOD",
    "AUDIT_WRITE",
})

# Host-sensitive bind mount source prefixes that signal T1611 escape risk.
_UNSAFE_MOUNT_PREFIXES: tuple[str, ...] = (
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/var/run/docker.sock",
    "/var/run/containerd",
    "/var/run/crio",
    "/run/containerd",
    "/run/docker.sock",
    "/home",
    "/root",
)

# Major container registries — anything else triggers unknown_registry.
# Substring match (e.g. "gcr.io" matches "us-docker.pkg.dev/gcr.io/...").
_KNOWN_REGISTRIES: tuple[str, ...] = (
    "docker.io",
    "gcr.io",
    "mcr.microsoft.com",
    "quay.io",
    "public.ecr.aws",
    "registry.access.redhat.com",
    "registry.redhat.io",
    "ghcr.io",
    "registry.k8s.io",
    "k8s.gcr.io",
    "nvcr.io",
)


# ── Helper functions (pure, no I/O) ──────────────────────────────────────────


def normalize_capability(cap: str) -> str:
    """Strip CAP_ prefix and uppercase the capability name."""
    s = str(cap).strip().upper()
    if s.startswith("CAP_"):
        s = s[4:]
    return s


def has_dangerous_capability(caps_add: list[str]) -> bool:
    """True iff CapAdd contains at least one dangerous capability."""
    if not caps_add:
        return False
    for cap in caps_add:
        if normalize_capability(cap) in _DANGEROUS_CAPS:
            return True
    return False


def is_unsafe_mount(source: str | None) -> bool:
    """True iff bind mount source matches a host-sensitive prefix."""
    if not source:
        return False
    src = str(source).strip()
    # Check the docker.sock special case first (it's a file, not a
    # directory).
    if "/docker.sock" in src or "/containerd" in src or "/crio" in src:
        return True
    # Exact match or prefix match with trailing slash to avoid /etcetera
    # matching /etc.
    for prefix in _UNSAFE_MOUNT_PREFIXES:
        if src == prefix or src.startswith(prefix + "/"):
            return True
    # Special bare "/" check — mounting / as anything is unsafe.
    if src == "/":
        return True
    return False


def is_known_registry(image_name: str | None) -> bool:
    """True iff the image name starts with a known major registry."""
    if not image_name:
        return False
    img = str(image_name).strip().lower()
    # Strip optional sha256: hash suffix.
    if "@sha256:" in img:
        img = img.split("@sha256:")[0]
    for registry in _KNOWN_REGISTRIES:
        if img.startswith(registry):
            return True
    # docker.io implicit prefix — names like "nginx:latest" or
    # "library/nginx" implicitly resolve to docker.io.
    if "/" not in img or img.startswith("library/"):
        # Looks like a bare docker.io name (no registry prefix).
        return True
    return False


def parse_image_repository_tag(
    image_name: str | None,
) -> tuple[str | None, str | None]:
    """Split an image name into (repository, tag).

    Examples:
        nginx:1.21 → ("nginx", "1.21")
        docker.io/library/nginx:latest → ("docker.io/library/nginx", "latest")
        gcr.io/foo/bar → ("gcr.io/foo/bar", "latest" — implicit)
        nginx@sha256:abc → ("nginx", "sha256:abc" — content-addressed)
    """
    if not image_name:
        return None, None
    img = str(image_name).strip()
    if not img:
        return None, None
    # Handle @sha256:... content-addressed form.
    if "@sha256:" in img:
        repo, _, sha = img.partition("@")
        return repo[:255], f"sha256:{sha.split(':', 1)[-1]}"[:64]
    # Find the LAST colon that's after the LAST slash — that's the tag
    # separator (registry:port has colons before the path).
    last_slash = img.rfind("/")
    last_colon = img.rfind(":")
    if last_colon > last_slash:
        return img[:last_colon][:255], img[last_colon + 1:][:64]
    return img[:255], None


# ── Anomaly classifier ───────────────────────────────────────────────────────


def build_anomaly_flags(
    *,
    privileged: bool | None,
    pid_mode: str | None,
    network_mode: str | None,
    ipc_mode: str | None,
    capabilities_add: list[str] | None,
    seccomp_profile: str | None,
    apparmor_profile: str | None,
    mounts: list[dict] | None,
    image_name: str | None,
) -> dict[str, Any]:
    """Construct the anomaly_flags payload from extracted fields.

    Pure function — same inputs always produce the same output. Caller
    stamps the schema_version via
    ``_stamp_linux_container_artifacts_anomaly_flags``.

    Anomaly bits:
    - privileged_mode: HostConfig.Privileged = true.
    - host_pid_namespace: PidMode = "host" (joins host PID namespace).
    - host_network_namespace: NetworkMode = "host".
    - host_ipc_namespace: IpcMode = "host".
    - dangerous_capability: CapAdd contains SYS_ADMIN / SYS_PTRACE / etc.
    - unconfined_seccomp: SecurityOpt contains seccomp=unconfined OR
      profile is "unconfined".
    - unconfined_apparmor: AppArmorProfile is "unconfined".
    - unsafe_mount: bind mount source under /, /etc, /proc, /sys, /dev,
      /var/run/docker.sock, /home — host-mount escape pathway.
    - unknown_registry: image_repository not in major registry set.
    """
    has_unsafe = False
    if mounts:
        for mount in mounts:
            if not isinstance(mount, dict):
                continue
            mount_type = str(mount.get("type", "")).lower()
            # Only flag bind mounts (volumes / tmpfs are typically safe).
            if mount_type and mount_type != "bind":
                continue
            if is_unsafe_mount(mount.get("source")):
                has_unsafe = True
                break

    return {
        "privileged_mode": bool(privileged),
        "host_pid_namespace": (pid_mode == "host" if pid_mode else False),
        "host_network_namespace": (
            network_mode == "host" if network_mode else False
        ),
        "host_ipc_namespace": (ipc_mode == "host" if ipc_mode else False),
        "dangerous_capability": has_dangerous_capability(
            capabilities_add or []
        ),
        "unconfined_seccomp": (
            seccomp_profile == "unconfined" if seccomp_profile else False
        ),
        "unconfined_apparmor": (
            apparmor_profile == "unconfined" if apparmor_profile else False
        ),
        "unsafe_mount": has_unsafe,
        "unknown_registry": (
            (not is_known_registry(image_name)) if image_name else False
        ),
    }


# ── Per-format parsers ───────────────────────────────────────────────────────


def _extract_env_keys(env_list: Any) -> list[str]:
    """Extract KEY names from Docker-style env list ['KEY=value', ...].

    Drops the values for security (secrets often in env vars). Defensive:
    returns empty list on non-list input.
    """
    if not isinstance(env_list, list):
        return []
    keys: list[str] = []
    for item in env_list:
        if not isinstance(item, str):
            continue
        key = item.split("=", 1)[0].strip()
        if key:
            keys.append(key)
    return keys


def _extract_command_list(cmd: Any) -> str | None:
    """Join a Docker-style command list into a single string."""
    if isinstance(cmd, list):
        return " ".join(str(c) for c in cmd if c is not None)[:_MAX_EXEC_CHARS]
    if isinstance(cmd, str):
        return cmd[:_MAX_EXEC_CHARS]
    return None


def _parse_docker_mounts(state: dict) -> list[dict]:
    """Extract mount specifications from Docker config.v2.json + hostconfig.json.

    Docker mounts appear in two places:
    - ``MountPoints`` (config.v2.json) — declared mount points.
    - ``HostConfig.Binds`` (hostconfig.json) — colon-separated bind specs.
    """
    mounts: list[dict] = []
    # config.v2.json MountPoints
    mountpoints = state.get("MountPoints", {})
    if isinstance(mountpoints, dict):
        for dest, mp in mountpoints.items():
            if not isinstance(mp, dict):
                continue
            mounts.append({
                "source": str(mp.get("Source", ""))[:512],
                "destination": str(dest)[:512],
                "mode": "rw" if mp.get("RW") else "ro",
                "type": str(mp.get("Type", "bind")),
            })
    # HostConfig.Binds: "/host:/container:ro"
    host_config = state.get("HostConfig", {})
    if isinstance(host_config, dict):
        binds = host_config.get("Binds")
        if isinstance(binds, list):
            for bind in binds:
                if not isinstance(bind, str):
                    continue
                parts = bind.split(":", 2)
                if len(parts) >= 2:
                    mounts.append({
                        "source": parts[0][:512],
                        "destination": parts[1][:512],
                        "mode": parts[2][:32] if len(parts) > 2 else "rw",
                        "type": "bind",
                    })
    return mounts[:256]  # Cap defensively


def _parse_oci_mounts(state: dict) -> list[dict]:
    """Extract mount specifications from OCI runtime-spec config.json.

    OCI spec mounts: ``mounts: [{source, destination, type, options}]``.
    """
    mounts: list[dict] = []
    raw_mounts = state.get("mounts", [])
    if not isinstance(raw_mounts, list):
        return []
    for mount in raw_mounts:
        if not isinstance(mount, dict):
            continue
        options = mount.get("options", [])
        mode = "rw"
        if isinstance(options, list):
            if "ro" in options or "readonly" in options:
                mode = "ro"
        mounts.append({
            "source": str(mount.get("source", ""))[:512],
            "destination": str(mount.get("destination", ""))[:512],
            "mode": mode,
            "type": str(mount.get("type", "bind"))[:32],
        })
    return mounts[:256]


def parse_docker_container_state(
    config_v2: dict,
    hostconfig: dict | None,
) -> dict[str, Any]:
    """Extract container metadata from Docker config.v2.json + hostconfig.json.

    Returns a flat dict with the per-artifact fields ready for ORM
    construction. Defensive: missing keys yield None.
    """
    # Merge hostconfig into the state dict for unified parsing.
    state = dict(config_v2)
    if hostconfig:
        state["HostConfig"] = hostconfig

    host_config = state.get("HostConfig", {}) if isinstance(
        state.get("HostConfig"), dict
    ) else {}
    config_section = state.get("Config", {}) if isinstance(
        state.get("Config"), dict
    ) else {}

    container_id = state.get("ID") or state.get("Id")
    image_name = state.get("Image") or config_section.get("Image")
    image_id = state.get("ImageID") or state.get("ImageDigest")
    repo, tag = parse_image_repository_tag(image_name)

    # SecurityOpt parsing for seccomp + apparmor.
    seccomp = None
    apparmor = host_config.get("AppArmorProfile")
    selinux = None
    security_opts = host_config.get("SecurityOpt") or []
    if isinstance(security_opts, list):
        for opt in security_opts:
            if not isinstance(opt, str):
                continue
            if opt.startswith("seccomp="):
                seccomp = opt[len("seccomp="):]
            elif opt.startswith("apparmor="):
                apparmor = apparmor or opt[len("apparmor="):]
            elif opt.startswith("label="):
                selinux = opt[len("label="):]

    state_section = state.get("State", {}) if isinstance(
        state.get("State"), dict
    ) else {}
    lifecycle_state = None
    if isinstance(state_section, dict):
        if state_section.get("Running"):
            lifecycle_state = "running"
        elif state_section.get("Paused"):
            lifecycle_state = "paused"
        elif state_section.get("ExitCode") is not None:
            lifecycle_state = "exited"
        else:
            lifecycle_state = str(state_section.get("Status", ""))[:32] or None

    runtime = host_config.get("Runtime")
    if runtime is None and isinstance(state.get("Driver"), str):
        runtime = state.get("Driver")

    caps_add = host_config.get("CapAdd") or []
    caps_drop = host_config.get("CapDrop") or []

    env_vars = _extract_env_keys(config_section.get("Env"))
    command = _extract_command_list(config_section.get("Cmd"))
    entrypoint = _extract_command_list(config_section.get("Entrypoint"))
    working_dir = config_section.get("WorkingDir")

    mounts = _parse_docker_mounts(state)

    return {
        "container_id": (str(container_id)[:64] if container_id else None),
        "image_id": (str(image_id)[:128] if image_id else None),
        "image_name": (str(image_name)[:255] if image_name else None),
        "image_repository": repo,
        "image_tag": tag,
        "runtime": (str(runtime)[:64] if runtime else None),
        "state": lifecycle_state,
        "privileged": bool(host_config.get("Privileged", False)),
        "mounts": mounts,
        "capabilities_add": [
            str(c)[:64] for c in caps_add if c is not None
        ][:64],
        "capabilities_drop": [
            str(c)[:64] for c in caps_drop if c is not None
        ][:64],
        "seccomp_profile": (str(seccomp)[:255] if seccomp else None),
        "apparmor_profile": (str(apparmor)[:255] if apparmor else None),
        "selinux_label": (str(selinux)[:255] if selinux else None),
        "network_mode": (
            str(host_config.get("NetworkMode", ""))[:64] or None
        ),
        "env_vars": env_vars[:256],
        "command": command,
        "entrypoint": entrypoint,
        "working_dir": (str(working_dir)[:1024] if working_dir else None),
        # Inputs for build_anomaly_flags
        "_pid_mode": str(host_config.get("PidMode", "")) or None,
        "_ipc_mode": str(host_config.get("IpcMode", "")) or None,
    }


def parse_oci_runtime_spec(state: dict) -> dict[str, Any]:
    """Extract container metadata from an OCI runtime-spec config.json.

    Used by containerd + podman OCI config artefacts.
    """
    process = state.get("process", {}) if isinstance(
        state.get("process"), dict
    ) else {}
    linux = state.get("linux", {}) if isinstance(
        state.get("linux"), dict
    ) else {}

    # Capabilities live at process.capabilities.{bounding,permitted,...}.
    caps_section = process.get("capabilities", {}) if isinstance(
        process.get("capabilities"), dict
    ) else {}
    caps_bounding = caps_section.get("bounding", []) or []
    caps_effective = caps_section.get("effective", []) or []
    # Union of all granted caps (defensive).
    caps_add: list[str] = []
    seen_caps: set[str] = set()
    for caps_list in (caps_bounding, caps_effective):
        if isinstance(caps_list, list):
            for cap in caps_list:
                if cap not in seen_caps:
                    seen_caps.add(cap)
                    caps_add.append(str(cap))

    seccomp_section = linux.get("seccomp")
    seccomp_profile = None
    if isinstance(seccomp_section, dict):
        # The presence of a seccomp block means a profile IS applied.
        # The "unconfined" case happens when there's NO seccomp block.
        seccomp_profile = str(
            seccomp_section.get("defaultAction", "configured")
        )[:255]

    apparmor = process.get("apparmorProfile")
    selinux = process.get("selinuxLabel")

    # Namespaces — host_pid / host_network / host_ipc flags. OCI uses
    # the absence of a namespace block (or explicit type without path)
    # to indicate "share host namespace".
    namespaces = linux.get("namespaces", []) if isinstance(
        linux.get("namespaces"), list
    ) else []
    declared_namespaces: set[str] = set()
    for ns in namespaces:
        if isinstance(ns, dict) and ns.get("type"):
            declared_namespaces.add(ns["type"])

    # If a namespace isn't declared, the container shares the host's.
    pid_mode = "host" if "pid" not in declared_namespaces else None
    network_mode = "host" if "network" not in declared_namespaces else None
    ipc_mode = "host" if "ipc" not in declared_namespaces else None

    # OCI runtime-spec doesn't carry "privileged" directly — the
    # equivalent shape is host-namespace + dropped-caps absent. We
    # treat None (unknown) for OCI runtime configs.
    args = process.get("args", []) or []
    if isinstance(args, list):
        command = " ".join(
            str(a) for a in args if a is not None
        )[:_MAX_EXEC_CHARS] or None
    else:
        command = None

    env_vars = _extract_env_keys(process.get("env"))
    working_dir = process.get("cwd")

    # Mounts.
    mounts = _parse_oci_mounts(state)

    return {
        "container_id": None,  # OCI runtime config doesn't carry ID
        "image_id": None,
        "image_name": None,
        "image_repository": None,
        "image_tag": None,
        "runtime": None,
        "state": None,
        "privileged": None,
        "mounts": mounts,
        "capabilities_add": [c[:64] for c in caps_add][:64],
        "capabilities_drop": [],
        "seccomp_profile": seccomp_profile,
        "apparmor_profile": (str(apparmor)[:255] if apparmor else None),
        "selinux_label": (str(selinux)[:255] if selinux else None),
        "network_mode": network_mode,
        "env_vars": env_vars[:256],
        "command": command,
        "entrypoint": None,
        "working_dir": (str(working_dir)[:1024] if working_dir else None),
        "_pid_mode": pid_mode,
        "_ipc_mode": ipc_mode,
    }


def parse_containerd_state(state: dict) -> dict[str, Any]:
    """Extract metadata from containerd task state.json.

    containerd state files are lightweight — they reference the
    OCI runtime config by bundle path; the container metadata lives
    in the OCI config (parsed by parse_oci_runtime_spec).
    """
    container_id = state.get("ID") or state.get("id")
    runtime = state.get("Runtime") or state.get("runtime")
    if isinstance(runtime, dict):
        runtime = runtime.get("name") or runtime.get("Name")

    return {
        "container_id": (str(container_id)[:64] if container_id else None),
        "image_id": None,
        "image_name": None,
        "image_repository": None,
        "image_tag": None,
        "runtime": (str(runtime)[:64] if runtime else None),
        "state": None,
        "privileged": None,
        "mounts": [],
        "capabilities_add": [],
        "capabilities_drop": [],
        "seccomp_profile": None,
        "apparmor_profile": None,
        "selinux_label": None,
        "network_mode": None,
        "env_vars": [],
        "command": None,
        "entrypoint": None,
        "working_dir": None,
        "_pid_mode": None,
        "_ipc_mode": None,
    }


def parse_podman_state(state: dict) -> dict[str, Any]:
    """Extract metadata from podman state.json.

    Podman state is similar to Docker — it carries State / Config /
    HostConfig-equivalent sections. Use Docker parser as a baseline,
    since podman tries to be Docker-API-compatible.
    """
    # Podman state.json has a "Config" section similar to Docker.
    # Reuse parse_docker_container_state with the state itself as both
    # config.v2 and hostconfig source.
    return parse_docker_container_state(state, state.get("HostConfig"))


def parse_oci_manifest(state: dict) -> dict[str, Any]:
    """Extract metadata from an OCI image-spec manifest.json.

    The manifest is image metadata only — no container instance. Has
    config + layers + annotations.
    """
    annotations = state.get("annotations", {}) if isinstance(
        state.get("annotations"), dict
    ) else {}
    # OCI spec annotations.
    image_name = (
        annotations.get("org.opencontainers.image.ref.name")
        or annotations.get("org.opencontainers.image.title")
    )
    config = state.get("config", {}) if isinstance(
        state.get("config"), dict
    ) else {}
    image_id = config.get("digest")

    repo, tag = parse_image_repository_tag(image_name)
    return {
        "container_id": None,
        "image_id": (str(image_id)[:128] if image_id else None),
        "image_name": (str(image_name)[:255] if image_name else None),
        "image_repository": repo,
        "image_tag": tag,
        "runtime": None,
        "state": None,
        "privileged": None,
        "mounts": [],
        "capabilities_add": [],
        "capabilities_drop": [],
        "seccomp_profile": None,
        "apparmor_profile": None,
        "selinux_label": None,
        "network_mode": None,
        "env_vars": [],
        "command": None,
        "entrypoint": None,
        "working_dir": None,
        "_pid_mode": None,
        "_ipc_mode": None,
    }


def parse_docker_repositories(state: dict) -> list[dict[str, Any]]:
    """Extract a list of image registry entries from repositories.json.

    Docker's overlay2/repositories.json shape:
        {"Repositories": {"<image-name>": {"<tag>": "sha256:abc...", ...}}}
    Returns one dict per (image, tag) pair.
    """
    results: list[dict[str, Any]] = []
    repos = state.get("Repositories", {}) if isinstance(
        state.get("Repositories"), dict
    ) else {}
    for image, tags in repos.items():
        if not isinstance(tags, dict):
            continue
        for tag, sha in tags.items():
            full_name = f"{image}:{tag}"
            repo, tag_part = parse_image_repository_tag(full_name)
            results.append({
                "container_id": None,
                "image_id": (str(sha)[:128] if sha else None),
                "image_name": full_name[:255],
                "image_repository": repo,
                "image_tag": tag_part,
                "runtime": None,
                "state": None,
                "privileged": None,
                "mounts": [],
                "capabilities_add": [],
                "capabilities_drop": [],
                "seccomp_profile": None,
                "apparmor_profile": None,
                "selinux_label": None,
                "network_mode": None,
                "env_vars": [],
                "command": None,
                "entrypoint": None,
                "working_dir": None,
                "_pid_mode": None,
                "_ipc_mode": None,
            })
    return results


# ── Filesystem helpers ───────────────────────────────────────────────────────


def find_container_artifacts(roots: Iterable[str]) -> list[tuple[str, str, str]]:
    """Find every container-runtime artefact under detection roots.

    Returns a list of (absolute_path, artifact_type, relative_root)
    tuples. Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots` — NEVER ``firmware.extracted_path``
    alone.
    """
    hits: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — bounded loop over ≤8 detection roots
        except OSError:
            continue
        if not os.path.isdir(real_root):  # noqa: ASYNC240 — bounded loop
            continue

        # Glob patterns — each artifact type.
        glob_pattern_table = (
            (_DOCKER_CONTAINER_GLOB, "docker_container_state"),
            (_DOCKER_HOSTCONFIG_GLOB, "docker_hostconfig"),
            (_CONTAINERD_STATE_GLOB, "containerd_state"),
            (_CONTAINERD_CONFIG_GLOB, "containerd_config"),
            (_PODMAN_STATE_GLOB, "podman_state"),
            (_PODMAN_CONFIG_GLOB, "podman_config"),
            (_DOCKER_REPOSITORIES_GLOB, "docker_repositories"),
            (_PODMAN_MANIFEST_GLOB, "oci_manifest"),
        )
        for pattern, artifact_type in glob_pattern_table:
            full_pattern = os.path.join(real_root, pattern)  # noqa: ASYNC240 — pure-string path math
            try:
                matches = glob.glob(full_pattern)  # noqa: ASYNC240 — bounded loop over detection roots
            except OSError:
                continue
            for full in matches:
                try:
                    real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                if real_full in seen:
                    continue
                seen.add(real_full)
                hits.append((real_full, artifact_type, root))

        # Direct-path config files (daemon.json, storage.conf, etc).
        for cfg in _DAEMON_CONFIG_PATHS:
            full = os.path.join(real_root, cfg)  # noqa: ASYNC240 — pure-string
            try:
                if os.path.isfile(full):  # noqa: ASYNC240 — bounded loop
                    real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string
                    if real_full.startswith(real_root) and real_full not in seen:
                        seen.add(real_full)
                        hits.append((real_full, "daemon_config", root))
            except OSError:
                continue
        for cfg in _RUNTIME_CONFIG_PATHS:
            full = os.path.join(real_root, cfg)  # noqa: ASYNC240 — pure-string
            try:
                if os.path.isfile(full):  # noqa: ASYNC240 — bounded loop
                    real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string
                    if real_full.startswith(real_root) and real_full not in seen:
                        seen.add(real_full)
                        hits.append((real_full, "runtime_config", root))
            except OSError:
                continue
    return hits


def read_artifact_file(path: str) -> str | None:
    """Read a container artifact file's contents as text. Returns None
    on read failure or oversize.

    SYNC I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > _DEFAULT_MAX_ARTIFACT_BYTES:
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    return raw.decode("utf-8", errors="replace")


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "artifacts_scanned": 0,
        "artifacts_persisted": 0,
        "containers_count": 0,
        "images_count": 0,
        "configs_count": 0,
        "privileged_count": 0,
        "host_namespace_count": 0,
        "dangerous_capability_count": 0,
        "unsafe_mount_count": 0,
        "unconfined_security_count": 0,
        "unknown_registry_count": 0,
        "anomaly_total": 0,
        "parse_errors": 0,
        "oversize_skipped": 0,
        "errors": [],
        "per_root": [],
    }


# ── Per-artifact row assembler ──────────────────────────────────────────────


def assemble_artifact_row(
    *,
    firmware_id: uuid.UUID,
    artifact_path: str,
    artifact_type: str,
    parsed: dict[str, Any],
    raw_state_text: str | None,
    parse_error: str | None,
) -> LinuxContainerArtifact:
    """Construct one LinuxContainerArtifact ORM row from parsed JSON +
    discriminator + metadata."""
    pid_mode = parsed.pop("_pid_mode", None)
    ipc_mode = parsed.pop("_ipc_mode", None)

    anomaly = build_anomaly_flags(
        privileged=parsed.get("privileged"),
        pid_mode=pid_mode,
        network_mode=parsed.get("network_mode"),
        ipc_mode=ipc_mode,
        capabilities_add=parsed.get("capabilities_add"),
        seccomp_profile=parsed.get("seccomp_profile"),
        apparmor_profile=parsed.get("apparmor_profile"),
        mounts=parsed.get("mounts"),
        image_name=parsed.get("image_name"),
    )
    stamped_anomaly = _stamp_linux_container_artifacts_anomaly_flags(anomaly)

    return LinuxContainerArtifact(
        firmware_id=firmware_id,
        artifact_path=artifact_path[:1024],
        artifact_type=artifact_type[:32],
        container_id=parsed.get("container_id"),
        image_id=parsed.get("image_id"),
        image_name=parsed.get("image_name"),
        image_repository=parsed.get("image_repository"),
        image_tag=parsed.get("image_tag"),
        runtime=parsed.get("runtime"),
        state=parsed.get("state"),
        privileged=parsed.get("privileged"),
        mounts=parsed.get("mounts") or None,
        capabilities_add=parsed.get("capabilities_add") or None,
        capabilities_drop=parsed.get("capabilities_drop") or None,
        seccomp_profile=parsed.get("seccomp_profile"),
        apparmor_profile=parsed.get("apparmor_profile"),
        selinux_label=parsed.get("selinux_label"),
        network_mode=parsed.get("network_mode"),
        env_vars=parsed.get("env_vars") or None,
        command=parsed.get("command"),
        entrypoint=parsed.get("entrypoint"),
        working_dir=parsed.get("working_dir"),
        anomaly_flags=stamped_anomaly,
        raw_state=(raw_state_text or "")[:_MAX_RAW_STATE_CHARS] or None,
        parse_error=parse_error,
    )


# ── Per-root walker ──────────────────────────────────────────────────────────


def _walk_one_root_sync(
    root: str,
    *,
    firmware_id: uuid.UUID,
    max_artifacts: int,
    persisted_so_far: int,
) -> tuple[list[LinuxContainerArtifact], dict]:
    """Walk all container artefacts under one detection root, build rows.

    SYNC I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    """
    aggregate: dict = {
        "root": root,
        "artifacts_scanned": 0,
        "artifacts_persisted": 0,
        "oversize_skipped": 0,
        "parse_errors": 0,
        "errors": [],
    }
    rows: list[LinuxContainerArtifact] = []

    hits = find_container_artifacts([root])
    persist_budget = max_artifacts - persisted_so_far

    # Group docker_container_state + docker_hostconfig pairs by directory.
    # Map dir → (config_path, hostconfig_path)
    docker_pairs: dict[str, dict] = {}
    standalone_hits: list[tuple[str, str, str]] = []
    for path, artifact_type, _root in hits:
        if artifact_type in ("docker_container_state", "docker_hostconfig"):
            container_dir = os.path.dirname(path)
            entry = docker_pairs.setdefault(
                container_dir, {"config": None, "hostconfig": None}
            )
            if artifact_type == "docker_container_state":
                entry["config"] = path
            else:
                entry["hostconfig"] = path
        else:
            standalone_hits.append((path, artifact_type, _root))

    # Process Docker pairs.
    for container_dir, paths in docker_pairs.items():
        if persist_budget <= 0:
            break
        config_path = paths["config"]
        hostconfig_path = paths["hostconfig"]
        # Anchor on config.v2.json — if missing, skip the pair.
        if not config_path:
            continue

        aggregate["artifacts_scanned"] += 1
        try:
            size = os.path.getsize(config_path)
        except OSError:
            aggregate["errors"].append(
                f"stat failed: {config_path}"
            )
            continue
        if size > _DEFAULT_MAX_ARTIFACT_BYTES:
            aggregate["oversize_skipped"] += 1
            continue

        config_text = read_artifact_file(config_path)
        if config_text is None:
            aggregate["errors"].append(
                f"read failed: {config_path}"
            )
            continue
        try:
            config_v2 = json.loads(config_text)
        except (json.JSONDecodeError, ValueError) as exc:
            aggregate["parse_errors"] += 1
            # Persist row with parse_error.
            try:
                row = assemble_artifact_row(
                    firmware_id=firmware_id,
                    artifact_path=config_path,
                    artifact_type="docker_container_state",
                    parsed={},
                    raw_state_text=config_text,
                    parse_error=f"json decode: {type(exc).__name__}: {exc}",
                )
                rows.append(row)
                persist_budget -= 1
                aggregate["artifacts_persisted"] += 1
            except Exception:  # noqa: BLE001 — defensive boundary
                pass
            continue

        hostconfig = None
        if hostconfig_path:
            hostconfig_text = read_artifact_file(hostconfig_path)
            if hostconfig_text is not None:
                try:
                    hostconfig = json.loads(hostconfig_text)
                except (json.JSONDecodeError, ValueError):
                    pass

        try:
            parsed = parse_docker_container_state(config_v2, hostconfig)
            row = assemble_artifact_row(
                firmware_id=firmware_id,
                artifact_path=config_path,
                artifact_type="docker_container_state",
                parsed=parsed,
                raw_state_text=config_text,
                parse_error=None,
            )
            rows.append(row)
            persist_budget -= 1
            aggregate["artifacts_persisted"] += 1
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            aggregate["errors"].append(
                f"assemble failed for {config_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )

    # Process standalone hits.
    for path, artifact_type, _root in standalone_hits:
        if persist_budget <= 0:
            break
        aggregate["artifacts_scanned"] += 1

        try:
            size = os.path.getsize(path)
        except OSError:
            aggregate["errors"].append(f"stat failed: {path}")
            continue
        if size > _DEFAULT_MAX_ARTIFACT_BYTES:
            aggregate["oversize_skipped"] += 1
            continue

        text = read_artifact_file(path)
        if text is None:
            aggregate["errors"].append(f"read failed: {path}")
            continue

        # runtime_config files (storage.conf / registries.conf) are TOML,
        # not JSON — store as raw_state with parse_error.
        if artifact_type == "runtime_config":
            try:
                row = assemble_artifact_row(
                    firmware_id=firmware_id,
                    artifact_path=path,
                    artifact_type=artifact_type,
                    parsed={},
                    raw_state_text=text,
                    parse_error=None,
                )
                rows.append(row)
                persist_budget -= 1
                aggregate["artifacts_persisted"] += 1
            except Exception as exc:  # noqa: BLE001
                aggregate["errors"].append(
                    f"assemble failed for {path}: "
                    f"{type(exc).__name__}: {str(exc)[:200]}"
                )
            continue

        try:
            state = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            aggregate["parse_errors"] += 1
            try:
                row = assemble_artifact_row(
                    firmware_id=firmware_id,
                    artifact_path=path,
                    artifact_type=artifact_type,
                    parsed={},
                    raw_state_text=text,
                    parse_error=f"json decode: {type(exc).__name__}: {exc}",
                )
                rows.append(row)
                persist_budget -= 1
                aggregate["artifacts_persisted"] += 1
            except Exception:  # noqa: BLE001
                pass
            continue

        try:
            if artifact_type == "containerd_state":
                parsed = parse_containerd_state(state)
            elif artifact_type == "containerd_config":
                parsed = parse_oci_runtime_spec(state)
                artifact_type = "containerd_config"
            elif artifact_type == "podman_state":
                parsed = parse_podman_state(state)
            elif artifact_type == "podman_config":
                parsed = parse_oci_runtime_spec(state)
            elif artifact_type == "oci_manifest":
                parsed = parse_oci_manifest(state)
            elif artifact_type == "daemon_config":
                # daemon.json is a config file — surface as data only.
                parsed = {}
            elif artifact_type == "docker_repositories":
                # Each image entry becomes its own row.
                multi_parsed = parse_docker_repositories(state)
                for sub_parsed in multi_parsed[:64]:  # Cap defensively
                    if persist_budget <= 0:
                        break
                    sub_row = assemble_artifact_row(
                        firmware_id=firmware_id,
                        artifact_path=path,
                        artifact_type="docker_repositories",
                        parsed=sub_parsed,
                        raw_state_text=text,
                        parse_error=None,
                    )
                    rows.append(sub_row)
                    persist_budget -= 1
                    aggregate["artifacts_persisted"] += 1
                continue
            else:
                parsed = {}

            row = assemble_artifact_row(
                firmware_id=firmware_id,
                artifact_path=path,
                artifact_type=artifact_type,
                parsed=parsed,
                raw_state_text=text,
                parse_error=None,
            )
            rows.append(row)
            persist_budget -= 1
            aggregate["artifacts_persisted"] += 1
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            aggregate["errors"].append(
                f"assemble failed for {path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )

    return rows, aggregate


async def _walk_one_root_async(
    root: str,
    *,
    firmware_id: uuid.UUID,
    max_artifacts: int,
    persisted_so_far: int,
) -> tuple[list[LinuxContainerArtifact], dict]:
    """Async wrapper around :func:`_walk_one_root_sync` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_root_sync(
            root,
            firmware_id=firmware_id,
            max_artifacts=max_artifacts,
            persisted_so_far=persisted_so_far,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ──────────────────────────


async def _do_container_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_artifacts: int = _DEFAULT_MAX_ARTIFACTS_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every container-runtime artefact under ``firmware_id``'s extracted
    tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. For each root, scan canonical container runtime paths.
    3. For each artefact: read text, discriminate by path + content shape,
       parse via stdlib json (or store as raw_state for TOML configs),
       build LinuxContainerArtifact row + anomaly_flags.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real
    test DB without DNS resolution issues from
    ``async_session_factory()``.
    """
    started = time.monotonic()

    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        return _empty_walk_result(0.0)

    roots = await get_detection_roots(firmware, db=db)
    if not roots:
        return _empty_walk_result(time.monotonic() - started)

    all_rows: list[LinuxContainerArtifact] = []
    per_root_aggregates: list[dict] = []
    errors: list[str] = []

    persisted_so_far = 0
    for root in roots:
        try:
            rows, agg = await _walk_one_root_async(
                root,
                firmware_id=firmware_id,
                max_artifacts=max_artifacts,
                persisted_so_far=persisted_so_far,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            errors.append(
                f"walk failed for root {root}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            per_root_aggregates.append({
                "root": root,
                "artifacts_scanned": 0,
                "artifacts_persisted": 0,
                "oversize_skipped": 0,
                "parse_errors": 0,
                "errors": [str(exc)[:200]],
            })
            continue
        all_rows.extend(rows)
        per_root_aggregates.append(agg)
        errors.extend(agg.get("errors", []))
        persisted_so_far += agg["artifacts_persisted"]

    # Write rows to DB.
    for row in all_rows:
        db.add(row)
    if all_rows:
        await db.flush()

    # Aggregate counts by artifact_type.
    containers_count = sum(
        1 for r in all_rows
        if r.artifact_type in (
            "docker_container_state",
            "containerd_state",
            "podman_state",
            "containerd_config",
            "podman_config",
        )
    )
    images_count = sum(
        1 for r in all_rows
        if r.artifact_type in ("oci_manifest", "docker_repositories")
    )
    configs_count = sum(
        1 for r in all_rows
        if r.artifact_type in ("daemon_config", "runtime_config")
    )
    privileged_count = sum(1 for r in all_rows if r.privileged)

    def _count_anomaly(rows: list[LinuxContainerArtifact], key: str) -> int:
        c = 0
        for r in rows:
            flags = r.anomaly_flags or {}
            if flags.get(key):
                c += 1
        return c

    host_namespace_count = sum(
        1 for r in all_rows
        if (r.anomaly_flags or {}).get("host_pid_namespace")
        or (r.anomaly_flags or {}).get("host_network_namespace")
        or (r.anomaly_flags or {}).get("host_ipc_namespace")
    )
    dangerous_capability_count = _count_anomaly(
        all_rows, "dangerous_capability"
    )
    unsafe_mount_count = _count_anomaly(all_rows, "unsafe_mount")
    unconfined_security_count = sum(
        1 for r in all_rows
        if (r.anomaly_flags or {}).get("unconfined_seccomp")
        or (r.anomaly_flags or {}).get("unconfined_apparmor")
    )
    unknown_registry_count = _count_anomaly(all_rows, "unknown_registry")

    # anomaly_total = rows with ≥1 substantive anomaly bit.
    substantive_keys = (
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
    anomaly_total = sum(
        1
        for r in all_rows
        if any((r.anomaly_flags or {}).get(k) for k in substantive_keys)
    )

    artifacts_scanned = sum(
        a["artifacts_scanned"] for a in per_root_aggregates
    )
    parse_errors = sum(
        a["parse_errors"] for a in per_root_aggregates
    )
    oversize_skipped = sum(
        a["oversize_skipped"] for a in per_root_aggregates
    )

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "artifacts_scanned": artifacts_scanned,
        "artifacts_persisted": len(all_rows),
        "containers_count": containers_count,
        "images_count": images_count,
        "configs_count": configs_count,
        "privileged_count": privileged_count,
        "host_namespace_count": host_namespace_count,
        "dangerous_capability_count": dangerous_capability_count,
        "unsafe_mount_count": unsafe_mount_count,
        "unconfined_security_count": unconfined_security_count,
        "unknown_registry_count": unknown_registry_count,
        "anomaly_total": anomaly_total,
        "parse_errors": parse_errors,
        "oversize_skipped": oversize_skipped,
        "errors": errors,
        "per_root": per_root_aggregates,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_container_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the container walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back.

    Status transitions: idle → running → completed | failed. The
    queued state belongs to the trigger router (idempotent POST +
    409-on-conflict per Rule #33 .a).
    """
    try:
        async with async_session_factory() as db:
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is None:
                logger.warning(
                    "container_walk: firmware %s not found", firmware_id
                )
                return

            row.container_walk_status = "running"
            row.container_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_container_walk(db, firmware_id)
                row.container_walk_status = "completed"
                row.container_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.container_walk_result = (
                    _stamp_firmware_container_walk_result(result)
                )
                await db.commit()

                logger.info(
                    "container_walk: firmware %s completed in %.2fs "
                    "(%d scanned, %d persisted, %d privileged, %d anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["artifacts_scanned"],
                    result["artifacts_persisted"],
                    result["privileged_count"],
                    result["anomaly_total"],
                )
            except Exception as exc:  # noqa: BLE001
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(
                        type(exc), exc, exc.__traceback__
                    )
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(
                                Firmware.id == firmware_id
                            )
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.container_walk_status = "failed"
                        fail_row.container_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.container_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "container_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "container_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_container_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as ι.A/B/C/D auto_walk_safe
    hooks.

    Distinct from :func:`run_container_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-triggered
    walks. The auto-walk-on-unpack flow runs the SAME orchestrator
    (``_do_container_walk``) but DOES NOT transition the status
    column — it stays ``idle`` so manual re-trigger works without 409.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_container_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.container_walk_result = (
                    _stamp_firmware_container_walk_result(result)
                )
                await db.commit()

            logger.info(
                "container_walk auto: firmware %s walked %d artefacts in %.2fs",
                firmware_id,
                result["artifacts_scanned"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "container_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_container_walk",
    "assemble_artifact_row",
    "auto_container_walk_firmware_safe",
    "build_anomaly_flags",
    "find_container_artifacts",
    "has_dangerous_capability",
    "is_known_registry",
    "is_unsafe_mount",
    "normalize_capability",
    "parse_containerd_state",
    "parse_docker_container_state",
    "parse_docker_repositories",
    "parse_image_repository_tag",
    "parse_oci_manifest",
    "parse_oci_runtime_spec",
    "parse_podman_state",
    "read_artifact_file",
    "run_container_walk_background",
]
