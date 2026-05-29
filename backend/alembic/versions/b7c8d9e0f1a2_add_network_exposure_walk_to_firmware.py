r"""add network_exposure_walk extraction walker state machine

Revision ID: b7c8d9e0f1a2
Revises: a6b7c8d9e0f1
Create Date: 2026-05-29 18:00:00.000000

DDL infrastructure for the C3 ``network_exposure_walker`` (the generic
attack-surface / network-exposure REACHABILITY-EVIDENCE collector) per
CLAUDE.md Rule #33 .a 5-state contract.

C3 produces the listener → bind-scope → owning-daemon evidence the
cve-assessment-framework L4 kill-chain classifier consumes (the framework
``ListenerEntry`` discriminator #2 + ``network/listeners.json``). A daemon
bound to ``0.0.0.0`` makes the REMOTE surface OPEN + ``has_remote_bind`` →
an AV:N CVE owned by that daemon → ``initial_entry`` (the kill-chain HEAD);
a loopback-only daemon → no remote bind → the CVE stays ``chainable``
(R51.1 C3 GAP-CLOSED).

C3 is the RISKIEST collector — its bind-scope evidence feeds the L4 listener
discriminator, and an INCORRECT bind-scope is worse than a missing one (a
config that binds loopback but is mis-read as ``0.0.0.0`` would FALSELY
promote a CVE to ``initial_entry`` — an over-claim the guilty default cannot
catch). The converged R51.2 mitigations (BLOCKING-2/B2/B3) bake the over-read
guard into the EMITTED evidence:

- Each listener carries BOTH ``host`` AND ``address`` keys (same value) so the
  framework's Linux ``host`` reader AND Android ``address`` reader both work
  (the framework-consumer critique's BLOCKING #2 — the single shared
  ``listeners.json`` cannot satisfy two adapter keys without emitting both).
- Each listener carries a ``bind_confidence`` Literal
  (``runtime_confirmed`` | ``config_high`` | ``config_inferred``) so the
  framework caps a ``config_inferred`` remote bind at ``chainable`` (never
  mints a confirmed-remote HEAD from an inferred bind — the only mitigation
  that is guilty-safe in BOTH directions).

C3 is DISTINCT from C1 ``kernel_config_walk_*`` (migration ``e3f4a5b6c7d8``)
and C2 ``module_reachability_walk_*`` (migration ``a6b7c8d9e0f1``): C1 extracts
the kernel ``.config``; C2 enumerates the on-disk loadable module set; C3
synthesizes the listener exposure map across systemd ``.socket`` units +
server-config bind directives (sshd / nginx / dnsmasq / dropbear /
inetd-xinetd) + any captured ss/netstat output.

New ``firmware`` columns:

- ``network_exposure_walk_status``
  (Literal[idle|queued|running|completed|failed]) +
  ``ck_firmware_network_exposure_walk_status`` CHECK
- ``network_exposure_walk_started_at`` /
  ``network_exposure_walk_finished_at`` timestamps
- ``network_exposure_walk_error`` text (failure trace)
- ``network_exposure_walk_result`` JSONB (per-run exposure aggregate;
  Rule #35c normaliser pair +
  ``FIRMWARE_NETWORK_EXPOSURE_WALK_RESULT_SCHEMA_VERSION`` lands in the
  jsonb_normalizers commit)

Mirrors ``e3f4a5b6c7d8`` (C1 kernel_config_walk state machine) +
``a6b7c8d9e0f1`` (C2 module_reachability_walk state machine). No new
table — the walker reads configs from the firmware extraction tree
(Rule #16 detection roots) and writes back only onto the existing
``firmware.network_exposure_walk_result`` JSONB column.

Chains from ``a6b7c8d9e0f1`` (C2 module-reachability — the single alembic
head verified 2026-05-29). Revision ID ``b7c8d9e0f1a2`` chosen distinct from
existing IDs to avoid the collision lesson in commit ``a51b15a``.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "b7c8d9e0f1a2"
down_revision: str | None = "a6b7c8d9e0f1"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "network_exposure_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.create_check_constraint(
        "ck_firmware_network_exposure_walk_status",
        "firmware",
        "network_exposure_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )
    op.add_column(
        "firmware",
        sa.Column(
            "network_exposure_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "network_exposure_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("network_exposure_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "network_exposure_walk_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("firmware", "network_exposure_walk_result")
    op.drop_column("firmware", "network_exposure_walk_error")
    op.drop_column("firmware", "network_exposure_walk_finished_at")
    op.drop_column("firmware", "network_exposure_walk_started_at")
    op.drop_constraint(
        "ck_firmware_network_exposure_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "network_exposure_walk_status")
