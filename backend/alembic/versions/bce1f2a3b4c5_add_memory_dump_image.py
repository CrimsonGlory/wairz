r"""add memory_dump_image table (Phase λ.α.A — first memory-forensic stream)

Revision ID: bce1f2a3b4c5
Revises: aabbccddee18
Create Date: 2026-05-13 01:30:00.000000

Phase λ.α.A — adds the per-firmware landing zone for memory-dump
images (RAM acquisitions), the foundation for Volatility 3 integration
in subsequent λ.β-ε streams. One row per ``.raw`` / ``.dmp`` /
``.vmem`` / ``.lime`` / ``.mem`` / ``.crash`` file discovered inside
a firmware's detection roots above the 100 MB threshold.

Mirrors ε.2.A's ``windows_event_records`` + ζ.2.A's ``windows_prefetch_records``
shape: per-row forensic record + composite indexes for the operator-MCP
filter shapes.

Indexes:

- ``ix_memory_dump_image_firmware_filename`` —
  ``(firmware_id, image_filename)`` covers "find image named X for
  firmware Y" filter.
- ``ix_memory_dump_image_firmware_os_family`` —
  ``(firmware_id, os_family)`` covers per-OS-family Vol3 walker
  dispatch (all Windows images / all Linux images for firmware Y).

Per CLAUDE.md Rule #19 generalised: this migration touches
infrastructure (alembic chain). Rule #8 extended rebuild (backend +
worker + migrator) runs after the λ.α.D cut-over. Pre-validated
revision ID: ``bce1f2a3b4c5`` confirmed FREE in the versions tree
at migration-authoring time (grep returned 0 hits).

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — memory images are read by Vol3's pure-Python framework
(read-only file open + struct unpack of underlying layers). Wairz
NEVER invokes any binary referenced inside a memory image, NEVER
shells out to ``qemu-system -hda <dump>``, NEVER resumes the image
as a VM. The no-execute rule extends to memory artefacts exactly
as it does to installer custom actions (Rule #36 original incidents)
and EFS / DPAPI walkers (Rule #45 metadata-walker promotion).

Per CLAUDE.md Rule #45 metadata-walker discipline: future Vol3 walkers
that extract credentials (``windows.hashdump`` / ``windows.lsadump``
/ ``windows.cachedump`` / ``windows.truecrypt``) are DEFERRED beyond
λ.δ pending explicit operator sign-off. The Vol3 chain wairz wires
in λ.β-ε is metadata-surfacing only (processes, network endpoints,
modules, persistence indicators) — same shape as the EFS / DPAPI
walkers Rule #45 governs.

Per CLAUDE.md Rule #37 offline-trust-anchor discipline: Vol3 ISF
symbol bundles MUST be baked into the worker image at build time
(``backend/vol3-symbols/`` directory under λ.α.C's ``ARG INCLUDE_VOL3=1``
gate, served at ``/opt/wairz/vol3-symbols`` runtime). The
``isf_profile_guess`` column records WHICH bundle ID matched at
walker-time so operators can confirm the offline-anchor discipline
held.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "bce1f2a3b4c5"
down_revision: str | None = "aabbccddee18"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "memory_dump_image",
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
        # Absolute path on the worker's view of the firmware tree.
        # Vol3 CLI takes an absolute -f argument; the runner passes
        # this verbatim. Cross-run stable identity is via
        # (firmware_id, image_filename, file_size) not by path —
        # the enumerator drops+readds image rows when it runs.
        sa.Column("image_path", sa.String(1024), nullable=False),
        # Basename of the image file (e.g. memory.raw, crash.dmp).
        # Drives the (firmware_id, image_filename) covering index.
        sa.Column("image_filename", sa.String(256), nullable=False),
        # File size in bytes — BigInteger because memory images
        # commonly run 4-128 GB. Used by the auto-detect threshold
        # (MIN_MEMORY_IMAGE_BYTES = 100 MB) and surfaces in the
        # firmware UI for capacity-planning hints.
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        # Magic-byte signature from a head probe — typically 4-16
        # bytes. Examples: MDMP (Windows minidump), PAGEDU64
        # (Windows kernel dump 64-bit), PAGEDUMP (Windows kernel
        # dump 32-bit), LiME (Linux LiME), raw (no recognisable
        # magic — Vol3 automagic LayerStacker handles).
        sa.Column("magic_detected", sa.String(48), nullable=False),
        # Coarse OS family guess: windows / linux / mac / unknown.
        # Full kernel-version fingerprint goes into kernel_hint
        # after the first walker pass (windows.info / linux.banners
        # / mac.kevents).
        sa.Column("os_family", sa.String(32), nullable=False),
        # Kernel version string from Vol3 windows.info /
        # linux.banners / mac.kevents after the first walker pass.
        # NULL pre-walker-pass.
        sa.Column("kernel_hint", sa.String(255), nullable=True),
        # ISF symbol bundle ID that Vol3's automagic matched
        # against this image — 16-char SHA1 prefix. NULL
        # pre-walker-pass; stamped after.
        sa.Column("isf_profile_guess", sa.String(64), nullable=True),
        # Most-recent timestamp when ANY Vol3 walker ran against
        # this image. Updated by each walker on success.
        sa.Column(
            "last_walked_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_memory_dump_image_firmware_filename",
        "memory_dump_image",
        ["firmware_id", "image_filename"],
    )
    op.create_index(
        "ix_memory_dump_image_firmware_os_family",
        "memory_dump_image",
        ["firmware_id", "os_family"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_memory_dump_image_firmware_os_family",
        table_name="memory_dump_image",
    )
    op.drop_index(
        "ix_memory_dump_image_firmware_filename",
        table_name="memory_dump_image",
    )
    op.drop_table("memory_dump_image")
