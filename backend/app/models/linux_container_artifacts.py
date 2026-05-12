"""Per-artifact Linux container runtime metadata row (Phase ι.E.A — FIFTH ι WALKER, THIRD LINUX WALKER).

One row per container-runtime configuration / state / image-spec artefact
located inside a Linux firmware extract. The Phase ι.E.C walker iterates
canonical container-runtime locations (Docker, containerd, podman) plus
OCI image-spec roots and runtime config files. Discriminated by
``artifact_type``.

Real-world Persona-E container forensics relevance (Phase ι Scout 3
"modest engineering cost" ship):

- **T1610 (Deploy Container)** — adversary deploys a privileged container
  to gain a foothold on the host. wairz surfaces ``HostConfig.Privileged``
  + ``HostConfig.PidMode=host`` / ``NetworkMode=host`` / ``IpcMode=host``
  via per-row anomaly bits.
- **T1611 (Escape to Host)** — host-namespace shares + dangerous
  capabilities (``CAP_SYS_ADMIN``, ``CAP_SYS_PTRACE``, ``CAP_SYS_MODULE``,
  ``CAP_DAC_READ_SEARCH``) + ``/var/run/docker.sock`` mounts open the
  escape pathway. Surfaced via the ``unsafe_mount`` /
  ``dangerous_capability`` / ``host_*_namespace`` anomaly bits.
- **T1612 (Build Image on Host)** — surfaces via the OCI manifest +
  image_repository fields (operator can correlate built-on-target images
  vs known-registry images).
- **2025 CVE cluster:** 3 runc CVEs (CVE-2025-31133 unsafe symlink mount
  / 2025-52565 mishandling /dev/console / 2025-52881 procfs write
  redirect) + Docker CVE-2025-9074 (internal API exposure via embedded
  ``Engine API``). All exploit chains start from inspectable
  container-state artefacts that wairz now surfaces.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. Container state files live at:

- ``var/lib/docker/containers/<id>/config.v2.json`` (Docker container state)
- ``var/lib/docker/containers/<id>/hostconfig.json`` (Docker hostconfig)
- ``var/run/containerd/io.containerd.runtime.v2.task/.../state.json``
- ``var/run/containerd/io.containerd.runtime.v2.task/.../config.json``
- ``var/lib/containers/storage/overlay-containers/<id>/userdata/state.json``
- ``var/lib/containers/storage/overlay-containers/<id>/userdata/config.json``
- ``var/lib/docker/image/overlay2/repositories.json`` (Docker image registry)
- ``etc/docker/daemon.json`` / ``etc/containers/storage.conf`` /
  ``etc/containers/registries.conf`` (runtime configs)

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker parses JSON state files via Python's stdlib ``json``
and surfaces command / entrypoint / env keys / mount paths as untrusted
strings. Nothing in wairz invokes any extracted container, exec's into
one, or pulls images.

Per CLAUDE.md Rule #35c JSONB discipline: every JSONB column carries
its own normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``. The list-shape columns (mounts /
capabilities_add / capabilities_drop / env_vars) canonicalize to
list[dict] or list[str]; the dict-shape anomaly_flags carries the
heuristic classifier output.

ι.E.D finding emit leverages the parsed metadata to flag the canonical
container-escape + privileged-deploy + unknown-registry TTPs above.

Reference for the formats:

- Docker config.v2.json + hostconfig.json — Docker daemon's per-container
  state files (Moby project source: ``daemon/containerd/container.go``).
- OCI runtime-spec config.json — https://github.com/opencontainers/runtime-spec/blob/main/config.md
- OCI image-spec manifest.json — https://github.com/opencontainers/image-spec/blob/main/manifest.md
- containerd runtime v2 task state — https://github.com/containerd/containerd/blob/main/runtime/v2/runc/manager.go
- podman storage overlay-containers — https://docs.podman.io/en/latest/markdown/podman.1.html
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class LinuxContainerArtifact(Base):
    """Per-artifact row from a walked Linux container-runtime tree."""

    __tablename__ = "linux_container_artifacts"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this container artefact was
    # parsed from. Cascade DELETE so removing a firmware row removes its
    # container artefacts.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Absolute path inside the firmware extract. E.g.
    # ``/var/lib/docker/containers/abc123.../config.v2.json``.
    artifact_path: Mapped[str] = mapped_column(
        String(1024), nullable=False
    )

    # Artifact discriminator — one of:
    # - docker_container_state (config.v2.json + hostconfig.json merged)
    # - containerd_state (containerd task state.json)
    # - containerd_config (OCI runtime-spec config.json)
    # - podman_state (podman state.json)
    # - podman_config (podman OCI config.json)
    # - oci_manifest (image-spec manifest.json)
    # - docker_repositories (overlay2/repositories.json image registry)
    # - daemon_config (etc/docker/daemon.json)
    # - runtime_config (etc/containers/storage.conf / registries.conf)
    artifact_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )

    # Container instance UUID / hash. Docker / containerd / podman each
    # use 64-char hex; NULL on image / config artefacts (which don't
    # carry a container instance).
    container_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Image hash (e.g. "sha256:abc123..."). Up to 128 chars to fit
    # legacy non-sha256 image IDs (some early Docker images use shorter
    # hashes). NULL when the artifact doesn't reference a specific image.
    image_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )

    # Image name in repo:tag form (e.g. "nginx:1.21"). NULL when the
    # artifact has no repo:tag (e.g. ad-hoc local-built images).
    image_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # Image repository portion (e.g. "docker.io/library/nginx").
    # Surfaced separately from image_name so cross-firmware aggregation
    # can filter on registry alone.
    image_repository: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # Image tag portion (e.g. "1.21" or "latest").
    image_tag: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Container runtime — "runc" / "kata" / "gvisor" / etc. NULL when
    # not specified in the artifact.
    runtime: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Container lifecycle state — "running" / "created" / "exited" /
    # "paused" / "stopped". NULL for image / config artefacts.
    state: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )

    # True iff container is configured with --privileged. The canonical
    # T1610 / T1611 indicator. Stored as nullable Boolean because image
    # / config artefacts don't carry a privileged flag.
    privileged: Mapped[bool | None] = mapped_column(
        Boolean, nullable=True
    )

    # List of mount specifications. Canonical shape:
    #   [
    #     {
    #       "source": "/host/path", "destination": "/container/path",
    #       "mode": "rw" | "ro", "type": "bind" | "volume" | "tmpfs",
    #     },
    #     ...
    #   ]
    # Anomaly: source under /, /etc, /proc, /sys, /dev,
    # /var/run/docker.sock, /home flags as unsafe_mount.
    mounts: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # Added Linux capabilities (e.g. "CAP_SYS_ADMIN"). Canonical list[str].
    # Anomaly: SYS_ADMIN / SYS_PTRACE / SYS_MODULE / DAC_READ_SEARCH /
    # NET_ADMIN / SETUID / SETGID flag as dangerous_capability.
    capabilities_add: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # Dropped Linux capabilities. Canonical list[str]. Default Docker
    # drops 18 capabilities; an empty CapDrop with no explicit allowlist
    # is a defensive-baseline concern.
    capabilities_drop: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # Seccomp profile — "default" / "unconfined" / custom path. The
    # "unconfined" value disables seccomp filtering entirely (escape risk).
    seccomp_profile: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # AppArmor profile — "unconfined" / "docker-default" / custom.
    apparmor_profile: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # SELinux label — type:role:user:level string. NULL on
    # non-SELinux systems.
    selinux_label: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # Network mode — "bridge" / "host" / "none" / custom network name.
    # The "host" value joins the container to the host network namespace
    # (T1611 escape pathway).
    network_mode: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Environment variable KEYS only (values dropped for security —
    # secrets often live in env vars). Canonical list[str].
    env_vars: Mapped[list | None] = mapped_column(
        JSONB, nullable=True
    )

    # Runtime command. Truncated to 2048 chars defensively.
    command: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )

    # Entrypoint command. Truncated to 2048 chars defensively.
    entrypoint: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )

    # Working directory.
    working_dir: Mapped[str | None] = mapped_column(
        String(1024), nullable=True
    )

    # Anomaly flags — heuristic detection summary for the ι.E.D
    # classifier. Canonical shape (boolean bits + schema_version):
    #   {
    #     "schema_version": 1,
    #     "privileged_mode": bool,            # --privileged flag
    #     "host_pid_namespace": bool,         # PidMode=host
    #     "host_network_namespace": bool,     # NetworkMode=host
    #     "host_ipc_namespace": bool,         # IpcMode=host
    #     "dangerous_capability": bool,       # CAP_SYS_ADMIN / etc.
    #     "unconfined_seccomp": bool,         # seccomp=unconfined
    #     "unconfined_apparmor": bool,        # apparmor=unconfined
    #     "unsafe_mount": bool,               # host-sensitive bind mount
    #     "unknown_registry": bool,           # image from non-major registry
    #   }
    # Rule #35c stamped envelope.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Original JSON content (truncated to ~8K at the walker boundary).
    # Surfaces for operator forensic review — the parsed columns above
    # are summary; the raw JSON carries everything the parser doesn't
    # enumerate.
    raw_state: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    # If the JSON couldn't be parsed (truncated, corrupted), record the
    # error so operators can review without losing the row. The walker
    # still emits the row rather than silently skipping.
    parse_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        # "All artefacts for firmware Y by type" — service-discriminator
        # filter.
        Index(
            "ix_linux_container_artifacts_firmware_type",
            "firmware_id",
            "artifact_type",
        ),
        # "All artefacts for firmware Y by image_id" — cross-correlation
        # with cross-firmware aggregation (ι.E.E supply-chain indicator).
        Index(
            "ix_linux_container_artifacts_firmware_image",
            "firmware_id",
            "image_id",
        ),
        # "All privileged containers for firmware Y" — operator's primary
        # T1610/T1611 hunt query.
        Index(
            "ix_linux_container_artifacts_firmware_privileged",
            "firmware_id",
            "privileged",
        ),
        # "All artefacts for firmware Y by container_id" — instance lookup.
        Index(
            "ix_linux_container_artifacts_firmware_container",
            "firmware_id",
            "container_id",
        ),
    )
