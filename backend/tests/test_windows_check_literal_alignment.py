"""Phase γ — Pydantic Literal ↔ DB CHECK alignment for new γ.1 + γ.2 columns.

Asserts that the per-column Pydantic Literals declared in
``app.schemas.hardware_firmware`` (the writer-side typo gates) agree
with the SQLAlchemy ``CheckConstraint`` IN-list values declared in the
matching model (the durable runtime gates per Rule #33 .c).

Out-of-sync state would silently allow a writer to push a value the DB
will then reject, OR allow a direct-SQL value the writer-Literal can't
emit (so neither layer guards both halves alone). This test catches the
drift at code-load time.

Pattern mirrors the existing ``test_finding_source_alignment.py``
discipline applied to a single-table column rather than the cross-stack
``ck_findings_source`` / TS-union / FE-config triple. Per Phase γ this
is "single-stack" — backend Literal + backend CHECK only — so a single
test file co-locates both checks (no FE surface to mirror).

When a future column adds another tri-state with the same shape, append
to ``_PAIRS`` rather than copying the helper.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import get_args

import pytest
from sqlalchemy import CheckConstraint

from app.models.windows_driver import WindowsDriver
from app.models.windows_registry_extract import WindowsRegistryExtract
from app.schemas.hardware_firmware import (
    WindowsDriverSigningTier,
    WindowsRegistryExtractWalkStatus,
)


@dataclass(frozen=True)
class _AlignmentPair:
    """One Literal ↔ CheckConstraint pair to verify."""
    literal: object  # ``typing.Literal[...]`` annotation alias
    model: type
    constraint_name: str
    column_name: str  # for error messages

    def literal_values(self) -> set[str]:
        return set(get_args(self.literal))

    def db_values(self) -> set[str]:
        for ta in self.model.__table_args__:
            if isinstance(ta, CheckConstraint) and ta.name == self.constraint_name:
                # CheckConstraint.sqltext is the SQL expression. Parse out
                # the IN ('a', 'b', ...) clause via regex — the constraint
                # text is ``<col> IN ('a', 'b', ...)``.
                expr = str(ta.sqltext)
                m = re.search(r"IN\s*\((.*?)\)", expr, re.IGNORECASE)
                if m is None:
                    pytest.fail(
                        f"could not parse IN-list from {self.constraint_name} "
                        f"sqltext: {expr!r}"
                    )
                return set(re.findall(r"'([^']+)'", m.group(1)))
        pytest.fail(
            f"CheckConstraint {self.constraint_name!r} not found in "
            f"{self.model.__tablename__}.__table_args__"
        )


_PAIRS: tuple[_AlignmentPair, ...] = (
    _AlignmentPair(
        literal=WindowsDriverSigningTier,
        model=WindowsDriver,
        constraint_name="ck_windows_drivers_signing_tier",
        column_name="signing_tier",
    ),
    _AlignmentPair(
        literal=WindowsRegistryExtractWalkStatus,
        model=WindowsRegistryExtract,
        constraint_name="ck_windows_registry_extracts_walk_status",
        column_name="walk_status",
    ),
)


@pytest.mark.parametrize("pair", _PAIRS, ids=lambda p: p.constraint_name)
def test_literal_matches_db_check(pair: _AlignmentPair) -> None:
    """Literal values must equal the DB CHECK IN-list values exactly."""
    literal_values = pair.literal_values()
    db_values = pair.db_values()

    missing_in_db = literal_values - db_values
    missing_in_literal = db_values - literal_values

    msgs: list[str] = []
    if missing_in_db:
        msgs.append(
            f"Literal values present but missing from CHECK "
            f"({pair.constraint_name}): {sorted(missing_in_db)} — "
            f"writer can emit values the DB will reject"
        )
    if missing_in_literal:
        msgs.append(
            f"CHECK values present but missing from Literal "
            f"({pair.constraint_name}): {sorted(missing_in_literal)} — "
            f"direct-SQL values exist that the writer-Literal can't produce"
        )

    if msgs:
        pytest.fail(
            f"Pydantic Literal ↔ DB CHECK drift on "
            f"{pair.model.__tablename__}.{pair.column_name}:\n  - "
            + "\n  - ".join(msgs)
        )
