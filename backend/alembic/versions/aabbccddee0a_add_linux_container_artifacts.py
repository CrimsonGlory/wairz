"""add linux_container_artifacts table (Phase ι.E.A — FIFTH ι WALKER, THIRD LINUX)

Revision ID: aabbccddee0a
Revises: aabbccddee09
Create Date: 2026-05-12 16:42:00.000000

Phase ι.E.A — adds the per-artifact landing zone for the FIFTH ι walker
in wairz's portfolio (THIRD LINUX walker after ι.A journald + ι.B
systemd; ι.C ETW + ι.D EFS were Windows). The Phase ι.E.C walker
iterates canonical container-runtime locations (Docker, containerd,
podman) plus OCI image-spec roots, persists per-artifact rows
discriminated by ``artifact_type`` (docker_container_state /
containerd_state / podman_state / oci_manifest / daemon_config /
runtime_config / etc).

**Container forensics persona (Phase ι Scout 3 — "modest engineering
cost" ship).** Linux firmware often ships container runtime state +
OCI image specs. wairz surfaces the forensic METADATA (which images,
which mounts, which capabilities, which seccomp profiles) — NOT deep
layer FS contents (Trivy/Syft already do that well). Differentiation
= MCP-callable cross-firmware aggregation of image-hash + recovery
from JSON state files.

**Adversary lens — T1610 / T1611 / T1612:**

- T1610 (Deploy Container) — privileged-deploy + dangerous-capability
  signals via per-row anomaly bits (``privileged_mode`` /
  ``dangerous_capability``).
- T1611 (Escape to Host) — host-namespace shares (PID/Network/IPC) +
  unsafe bind mounts (``/var/run/docker.sock``, ``/proc``, ``/sys``,
  ``/etc``, ``/dev``) surfaced via ``host_*_namespace`` / ``unsafe_mount``.
- T1612 (Build Image on Host) — surfaces via the OCI manifest +
  image_repository / image_id columns.

**2025 CVE cluster:** 3 runc CVEs (CVE-2025-31133 unsafe symlink mount,
CVE-2025-52565 mishandling /dev/console, CVE-2025-52881 procfs write
redirect) + Docker CVE-2025-9074 (internal API exposure via embedded
Engine API). Each exploits inspectable container-state artefacts wairz
now surfaces.

Per CLAUDE.md Rule #16: the ι.E.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so multi-rootfs Linux firmware (squashfs / ext / cramfs /
erofs / tar.xz) surfaces every container state file. Path patterns
scanned:

- ``var/lib/docker/containers/*/config.v2.json`` + ``hostconfig.json``
- ``var/run/containerd/io.containerd.runtime.v2.task/*/*/state.json``
- ``var/run/containerd/io.containerd.runtime.v2.task/*/*/config.json``
- ``var/lib/containers/storage/overlay-containers/*/userdata/state.json``
- ``var/lib/containers/storage/overlay-containers/*/userdata/config.json``
- ``var/lib/docker/image/overlay2/repositories.json``
- ``var/lib/containers/storage/overlay-images/*/manifest``
- ``etc/docker/daemon.json``
- ``etc/containers/storage.conf`` + ``etc/containers/registries.conf``

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only. The walker parses JSON via Python's stdlib ``json``. Nothing in
wairz invokes any extracted container, exec's into one, or pulls
images. ι.E.C ships ``test_container_walker_no_execute`` to enforce.

Per CLAUDE.md Rule #35c JSONB discipline: each JSONB column gets a
dedicated normalizer + schema_version stamp helper in
``app.services.jsonb_normalizers`` (5 helpers for this table:
mounts / capabilities_add / capabilities_drop / env_vars /
anomaly_flags).

Indexes:

- ``ix_linux_container_artifacts_firmware_type`` — ``(firmware_id,
  artifact_type)`` covers the artifact-discriminator filter.
- ``ix_linux_container_artifacts_firmware_image`` — ``(firmware_id,
  image_id)`` covers cross-firmware aggregation (ι.E.E supply-chain).
- ``ix_linux_container_artifacts_firmware_privileged`` —
  ``(firmware_id, privileged)`` covers the T1610/T1611 hunt query.
- ``ix_linux_container_artifacts_firmware_container`` —
  ``(firmware_id, container_id)`` covers instance lookup.

Revision ID ``aabbccddee0a`` was pre-validated FREE in the versions
tree before authoring (grep returned 0 hits). Chains from ι.D.D head
``aabbccddee09``.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "aabbccddee0a"
down_revision: str | None = "aabbccddee09"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "linux_container_artifacts",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "firmware_id",
            UUID(as_uuid=True),
            sa.ForeignKey("firmware.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("artifact_path", sa.String(1024), nullable=False),
        sa.Column("artifact_type", sa.String(32), nullable=False),
        sa.Column("container_id", sa.String(64), nullable=True),
        sa.Column("image_id", sa.String(128), nullable=True),
        sa.Column("image_name", sa.String(255), nullable=True),
        sa.Column("image_repository", sa.String(255), nullable=True),
        sa.Column("image_tag", sa.String(64), nullable=True),
        sa.Column("runtime", sa.String(64), nullable=True),
        sa.Column("state", sa.String(32), nullable=True),
        sa.Column("privileged", sa.Boolean, nullable=True),
        sa.Column("mounts", JSONB, nullable=True),
        sa.Column("capabilities_add", JSONB, nullable=True),
        sa.Column("capabilities_drop", JSONB, nullable=True),
        sa.Column("seccomp_profile", sa.String(255), nullable=True),
        sa.Column("apparmor_profile", sa.String(255), nullable=True),
        sa.Column("selinux_label", sa.String(255), nullable=True),
        sa.Column("network_mode", sa.String(64), nullable=True),
        sa.Column("env_vars", JSONB, nullable=True),
        sa.Column("command", sa.String(2048), nullable=True),
        sa.Column("entrypoint", sa.String(2048), nullable=True),
        sa.Column("working_dir", sa.String(1024), nullable=True),
        sa.Column("anomaly_flags", JSONB, nullable=True),
        sa.Column("raw_state", sa.Text, nullable=True),
        sa.Column("parse_error", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_linux_container_artifacts_firmware_type",
        "linux_container_artifacts",
        ["firmware_id", "artifact_type"],
    )
    op.create_index(
        "ix_linux_container_artifacts_firmware_image",
        "linux_container_artifacts",
        ["firmware_id", "image_id"],
    )
    op.create_index(
        "ix_linux_container_artifacts_firmware_privileged",
        "linux_container_artifacts",
        ["firmware_id", "privileged"],
    )
    op.create_index(
        "ix_linux_container_artifacts_firmware_container",
        "linux_container_artifacts",
        ["firmware_id", "container_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_linux_container_artifacts_firmware_container",
        table_name="linux_container_artifacts",
    )
    op.drop_index(
        "ix_linux_container_artifacts_firmware_privileged",
        table_name="linux_container_artifacts",
    )
    op.drop_index(
        "ix_linux_container_artifacts_firmware_image",
        table_name="linux_container_artifacts",
    )
    op.drop_index(
        "ix_linux_container_artifacts_firmware_type",
        table_name="linux_container_artifacts",
    )
    op.drop_table("linux_container_artifacts")
