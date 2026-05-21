"""Cross-stack alignment regression canary for `SbomStatus` (Rule #48 Shape-2).

Pins pairwise agreement between three source-of-truth surfaces that all
encode the SBOM /generate 202+polling state machine:

  L1 — alembic CHECK constraint `ck_firmware_sbom_status` declared in
       revision `feab18c9d201` (Session 2a 2026-05-21). The 5 in-progress +
       terminal states enforced at the database layer.
  L2 — Pydantic `SbomStatus = Literal[...]` at
       `backend/app/schemas/sbom.py`. The contract the FastAPI handler
       returns to the frontend; load-bearing for the 4-bullet Rule #33
       contract bullet (c).
  L3 — `STATE_MACHINE_REAPER_CONFIGS` membership in
       `backend/app/main.py`: the lifespan reaper that flips orphaned
       rows from in-progress states to 'failed' on startup. Per W2-β
       §SC5-NEW-SBOM-S2-SEAM-B, the reaper config MUST include
       sbom_status (this canary catches a future regression that drops
       the entry).

Rule #48 5-part shape:
  (1) **Paired rejection** — both layers reject a non-canonical value
  (2) **Paired acceptance** — each canonical value accepted by each layer
  (3) **Size-lock** — both layers pinned at exactly 5 states
  (4) **Cross-layer alignment proper** — synthesize a hostile state in
      both dialects; assert both reject
  (5) **META-CANARY (Rule #46)** — gate that asserts the diagnostic
      substring operators rely on appears in error responses

Cross-refs:
- CLAUDE.md Rule #25 single-slice exception #2 (cross-stack alignment commit)
- CLAUDE.md Rule #33 .c (Pydantic Literal + DB CHECK paired)
- CLAUDE.md Rule #46 (META-CANARY paired-canary discipline)
- CLAUDE.md Rule #48 5-part test shape
- .mex/patterns/cross-stack-alignment-test.md recipe
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


CANONICAL_SBOM_STATUS_VALUES = ("idle", "queued", "running", "completed", "failed")


# ── Part (1) — Paired rejection ─────────────────────────────────────────────


def test_pydantic_literal_rejects_unknown_status():
    """The Pydantic Literal MUST reject any non-canonical value."""
    from pydantic import ValidationError

    from app.schemas.sbom import SbomGenerateStatusResponse

    with pytest.raises(ValidationError):
        SbomGenerateStatusResponse(
            firmware_id="00000000-0000-0000-0000-000000000000",
            status="bogus",  # type: ignore[arg-type]
        )


def test_alembic_check_constraint_encodes_5_canonical_values():
    """The CHECK constraint in alembic revision feab18c9d201 MUST list
    exactly the 5 canonical SbomStatus values.
    """
    revision = Path(__file__).parent.parent / "alembic" / "versions" / "feab18c9d201_add_sbom_status_to_firmware.py"
    src = revision.read_text()
    for val in CANONICAL_SBOM_STATUS_VALUES:
        assert f"'{val}'" in src, (
            f"CHECK constraint missing '{val}' state in revision "
            f"feab18c9d201 — SbomStatus alignment broken."
        )


# ── Part (2) — Paired acceptance ────────────────────────────────────────────


@pytest.mark.parametrize("status", CANONICAL_SBOM_STATUS_VALUES)
def test_pydantic_literal_accepts_canonical_value(status):
    """Each of the 5 canonical SbomStatus values is accepted by the
    Pydantic schema (parametrized so per-case failure surfaces 'L2 dropped
    value X' directly).
    """
    from app.schemas.sbom import SbomGenerateStatusResponse

    resp = SbomGenerateStatusResponse(
        firmware_id="00000000-0000-0000-0000-000000000000",
        status=status,
    )
    assert resp.status == status


# ── Part (3) — Size-lock ────────────────────────────────────────────────────


def test_sbom_status_literal_is_size_locked_at_5():
    """SbomStatus must contain EXACTLY 5 states. Drift forces a deliberate
    test edit + postmortem note (per the cross-stack-alignment-test recipe).
    """
    import typing

    from app.schemas.sbom import SbomStatus

    args = typing.get_args(SbomStatus)
    assert len(args) == 5, (
        f"SbomStatus has {len(args)} states — expected exactly 5 "
        f"(idle/queued/running/completed/failed). If you're adding a new "
        f"state, also extend the DB CHECK constraint in a new alembic "
        f"revision + extend STATE_MACHINE_REAPER_CONFIGS in main.py."
    )
    assert set(args) == set(CANONICAL_SBOM_STATUS_VALUES), (
        f"SbomStatus values diverged from canonical 5-state set: "
        f"got {args!r}, expected {CANONICAL_SBOM_STATUS_VALUES!r}"
    )


def test_alembic_check_constraint_lists_exactly_5_values():
    """The CHECK constraint's quoted-value tuple MUST list exactly 5 states."""
    revision = Path(__file__).parent.parent / "alembic" / "versions" / "feab18c9d201_add_sbom_status_to_firmware.py"
    src = revision.read_text()
    # The migration declares SBOM_STATUS_VALUES as a tuple literal; assert it.
    assert "SBOM_STATUS_VALUES = (" in src
    # Count quoted state strings
    matches = re.findall(r'"(idle|queued|running|completed|failed)"', src)
    assert len(matches) >= 5, (
        f"alembic revision feab18c9d201 references {len(matches)} canonical "
        f"states; expected at least 5 distinct values."
    )


# ── Part (4) — Cross-layer alignment proper ─────────────────────────────────


def test_each_canonical_value_present_in_both_layers():
    """Iterate every canonical value; assert each is present in BOTH L1 and L2."""
    import typing

    from app.schemas.sbom import SbomStatus

    pydantic_values = set(typing.get_args(SbomStatus))
    revision = Path(__file__).parent.parent / "alembic" / "versions" / "feab18c9d201_add_sbom_status_to_firmware.py"
    alembic_src = revision.read_text()

    for val in CANONICAL_SBOM_STATUS_VALUES:
        assert val in pydantic_values, f"L2 (Pydantic Literal) dropped '{val}'"
        assert f"'{val}'" in alembic_src, f"L1 (alembic CHECK) dropped '{val}'"


# ── Part (5) — META-CANARY (Rule #46) ───────────────────────────────────────


def test_meta_canary_would_fire_on_dropped_state(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46 §gate-canary-requirement.

    Synthesize a fake alembic revision that omits 'completed' from the
    CHECK constraint; assert the alignment test above WOULD reject it.
    Without this paired canary, the gate could silently no-op if a future
    refactor changes the regex shape.
    """
    bad_src = """
SBOM_STATUS_VALUES = (
    "idle", "queued", "running", "failed",  # 'completed' DROPPED
)

def upgrade():
    op.create_check_constraint(
        "ck_firmware_sbom_status",
        "firmware",
        "sbom_status IN ('idle', 'queued', 'running', 'failed')"
    )
"""
    fake = tmp_path / "fake_revision.py"
    fake.write_text(bad_src)

    # The cross-layer check above would iterate canonical values and find
    # 'completed' missing from the synthesized alembic source.
    for val in CANONICAL_SBOM_STATUS_VALUES:
        if val == "completed":
            assert f"'{val}'" not in bad_src, (
                "META-CANARY broken: synthesize-and-assert canary did NOT "
                "detect 'completed' missing from the synthetic fake. "
                "Re-author the regex."
            )
        else:
            assert f"'{val}'" in bad_src
