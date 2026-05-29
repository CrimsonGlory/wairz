r"""add android_posture_walk extraction walker state machine

Revision ID: c4a17052e000
Revises: b7c8d9e0f1a2
Create Date: 2026-05-29 19:30:00.000000

DDL infrastructure for the C4 ``android_posture_walker`` (the Android
DEPLOYMENT-POSTURE REACHABILITY-EVIDENCE collector) per CLAUDE.md Rule #33 .a
5-state contract.

C4 produces the ``gates_open`` deployment-posture evidence the
cve-assessment-framework L4 kill-chain ``LockdownGate`` consumes (Topic 2 +
``AndroidAdapter.get_security_posture()`` / ``get_entry_surfaces()``). The
static firmware image can SUPPORT a lockdown (a DPC / kiosk app present, a
telephony stack present) but CANNOT confirm THIS unit is enrolled / active —
that is provisioning + runtime, not an image property. So C4 emits
``runtime_confirmed=false`` for every image-inferred posture → the framework
consumer HOLDS THE GATE OPEN (guilty per Axiom 1, no reduction) and names the
live-capture command (``adb shell dumpsys device_policy`` / ``dpm
list-owners`` / ``getprop``). Only a live capture can set
``runtime_confirmed=true``.

THE HONEST GATING (the C4-defining contract):

- ``gates_open`` = {``cellular_active``, ``sideloading_allowed``, ``kiosk``}
  — each emitted from STATIC image evidence (telephony stack present;
  install-unknown-sources / ro.secure / adb-default build-prop+settings;
  Device-Policy-Controller / lockTask / custom-launcher app present).
- ``runtime_confirmed=false`` for ALL image-inferred posture → the consumer
  keeps the gate OPEN (guilty, no reduction) and surfaces
  ``settling_command``.
- Absence-in-extracted-partition is NOT proof of absence (C3 saw phones ship
  incomplete partitions) → an absent DPC yields ``kiosk`` inferred-FALSE at
  ``config_inferred`` confidence, NEVER ``runtime_confirmed``. The framework
  treats a config_inferred negative as a still-OPEN gate.

C4 is DISTINCT from C1 ``kernel_config_walk_*`` (migration ``e3f4a5b6c7d8``),
C2 ``module_reachability_walk_*`` (migration ``a6b7c8d9e0f1``), and C3
``network_exposure_walk_*`` (migration ``b7c8d9e0f1a2``): C1 extracts the
kernel ``.config``; C2 enumerates the loadable-module set; C3 synthesizes the
listener exposure map; C4 synthesizes the Android deployment-posture gates.

New ``firmware`` columns:

- ``android_posture_walk_status``
  (Literal[idle|queued|running|completed|failed]) +
  ``ck_firmware_android_posture_walk_status`` CHECK
- ``android_posture_walk_started_at`` /
  ``android_posture_walk_finished_at`` timestamps
- ``android_posture_walk_error`` text (failure trace)
- ``android_posture_walk_result`` JSONB (per-run posture aggregate;
  Rule #35c normaliser pair +
  ``FIRMWARE_ANDROID_POSTURE_WALK_RESULT_SCHEMA_VERSION`` lands in the
  jsonb_normalizers commit)

Mirrors ``e3f4a5b6c7d8`` (C1) + ``a6b7c8d9e0f1`` (C2) + ``b7c8d9e0f1a2``
(C3). No new table — the walker reads APK manifests / build.prop / settings
/ device_owner XML from the firmware extraction tree (Rule #16 detection
roots) and writes back only onto the existing
``firmware.android_posture_walk_result`` JSONB column.

Chains from ``b7c8d9e0f1a2`` (C3 network-exposure — the single alembic head
verified 2026-05-29). Revision ID ``c4a17052e000`` ("C4" + random tail) chosen
DISTINCT from every existing ID — the first-attempt ``c8d9e0f1a2b3`` collided
with ``c8d9e0f1a2b3_add_registry_hive_walk_status`` (the exact ``a51b15a``
revision-ID-collision lesson reproduced + corrected this session).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "c4a17052e000"
down_revision: str | None = "b7c8d9e0f1a2"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "android_posture_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.create_check_constraint(
        "ck_firmware_android_posture_walk_status",
        "firmware",
        "android_posture_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )
    op.add_column(
        "firmware",
        sa.Column(
            "android_posture_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "android_posture_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("android_posture_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "android_posture_walk_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("firmware", "android_posture_walk_result")
    op.drop_column("firmware", "android_posture_walk_error")
    op.drop_column("firmware", "android_posture_walk_finished_at")
    op.drop_column("firmware", "android_posture_walk_started_at")
    op.drop_constraint(
        "ck_firmware_android_posture_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "android_posture_walk_status")
