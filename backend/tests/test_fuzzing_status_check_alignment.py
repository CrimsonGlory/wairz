"""DB ck_fuzzing_campaigns_status CHECK ↔ fuzzing service writes must agree.

Background: the Wave-1 β 202+polling refactor (commit `df30015`,
2026-04-20) added `campaign.status = "queued"` writes in
`backend/app/services/fuzzing_service.py` but did NOT ship the
companion CHECK-constraint widening.  Every `POST /fuzzing/campaigns/
{id}/start` raised `CheckViolationError` on flush against
`ck_fuzzing_campaigns_status`.  Migration `d8e9c4b5f7a2` widens the
allowlist; this test prevents the next drift from being silent.

Discovers all `campaign.status = "<lit>"` and `<row>.status = "<lit>"`
literal assignments in the fuzzing service via regex, then confronts
them with the latest CHECK migration's allowlist.  Mirrors the shape
of `test_finding_source_alignment.py` (alembic-chain walk, tuple
extraction, set comparison).
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest


_BACKEND_DIR = Path(__file__).parent.parent
_ALEMBIC_VERSIONS = _BACKEND_DIR / "alembic" / "versions"
_FUZZING_SERVICE = _BACKEND_DIR / "app" / "services" / "fuzzing_service.py"
_FUZZING_ROUTER = _BACKEND_DIR / "app" / "routers" / "fuzzing.py"


def _alembic_chain() -> dict[str, tuple[Path, str | None]]:
    chain: dict[str, tuple[Path, str | None]] = {}
    for path in _ALEMBIC_VERSIONS.glob("*.py"):
        if path.name.startswith("__"):
            continue
        text = path.read_text()
        rev_m = re.search(
            r'^revision(?:\s*:\s*[^=]+)?\s*=\s*[\'"]([^\'"]+)[\'"]',
            text,
            re.MULTILINE,
        )
        if not rev_m:
            continue
        down_m = re.search(
            r'^down_revision(?:\s*:\s*[^=]+)?\s*=\s*[\'"]([^\'"]+)[\'"]',
            text,
            re.MULTILINE,
        )
        chain[rev_m.group(1)] = (path, down_m.group(1) if down_m else None)
    return chain


def _alembic_heads(chain: dict[str, tuple[Path, str | None]]) -> list[str]:
    referenced_as_parent = {
        down for (_, down) in chain.values() if down is not None
    }
    return [rev for rev in chain if rev not in referenced_as_parent]


_CK_FUZZING_QUOTED = re.compile(
    r'["\']ck_fuzzing_campaigns_status["\']',
)


def _latest_status_check_migration_path() -> Path:
    chain = _alembic_chain()
    heads = _alembic_heads(chain)
    assert heads, "no alembic head found — script directory is empty"

    candidates: set[Path] = set()
    for head in heads:
        rev: str | None = head
        seen: set[str] = set()
        while rev and rev in chain and rev not in seen:
            seen.add(rev)
            path, down = chain[rev]
            text = path.read_text()
            # Require the constraint name in QUOTED form (excludes
            # markdown-backtick docstring references). Also require
            # that quoted name to appear as the FIRST positional arg
            # to create_check_constraint (not just anywhere in the
            # file). This prevents matching unrelated migrations that
            # cite the constraint as historical precedent in a
            # docstring (e.g. b0c1a2d3e4f5_add_device_dump_sessions.py
            # which creates ck_device_dump_sessions_status while
            # referencing ck_fuzzing_campaigns_status by name).
            if (
                _CK_FUZZING_QUOTED.search(text)
                and re.search(
                    r'create_check_constraint\s*\(\s*\n?\s*'
                    r'["\']ck_fuzzing_campaigns_status["\']',
                    text,
                )
            ):
                candidates.add(path)
                break
            rev = down

    assert candidates, (
        "no migration found that recreates ck_fuzzing_campaigns_status — "
        "did the constraint get renamed?"
    )
    assert len(candidates) == 1, (
        "alembic chain has multiple heads with diverging fuzzing CHECK "
        f"definitions: {sorted(p.name for p in candidates)}"
    )
    return next(iter(candidates))


def _load_db_status_values() -> set[str]:
    path = _latest_status_check_migration_path()
    spec = importlib.util.spec_from_file_location("_latest_fuzz_mig", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Original migration uses `FUZZING_STATUS_VALUES`; widening migration
    # exposes `FUZZING_STATUS_VALUES_V2` (and `_V1` for downgrade).  When
    # a future widening lands it should follow the same pattern; this
    # selector picks the largest tuple ending in `STATUS_VALUES_V2` or
    # `STATUS_VALUES` so the test keeps working without per-migration
    # edits.
    candidates: list[set[str]] = []
    for name in dir(mod):
        if not (
            name.endswith("STATUS_VALUES")
            or name.endswith("STATUS_VALUES_V2")
        ):
            continue
        val = getattr(mod, name)
        if (
            isinstance(val, tuple)
            and val
            and all(isinstance(v, str) for v in val)
        ):
            candidates.append(set(val))

    if not candidates:
        raise AssertionError(
            f"{path.name} touches ck_fuzzing_campaigns_status but exposes "
            "no tuple-of-strings ending in STATUS_VALUES — convention is "
            "to expose `FUZZING_STATUS_VALUES_V2` (current allowlist) "
            "AND `FUZZING_STATUS_VALUES_V1` (downgrade target)"
        )
    # Most permissive (largest) wins — that's the live constraint.
    return max(candidates, key=len)


_STATUS_WRITE_RE = re.compile(
    r"""(?:campaign|row|crash|c)\.status\s*=\s*['"]([^'"]+)['"]""",
)


def _service_status_writes() -> set[str]:
    text = _FUZZING_SERVICE.read_text()
    values = set(_STATUS_WRITE_RE.findall(text))
    # Also catch `status="…"` keyword in `Model(status=…)` constructor
    # calls within the service (e.g. campaign creation).
    for m in re.finditer(r"""\bstatus\s*=\s*['"]([^'"]+)['"]""", text):
        values.add(m.group(1))
    return values


def test_fuzzing_status_writes_satisfy_check_constraint():
    """Every literal status the service writes MUST be in the live
    `ck_fuzzing_campaigns_status` allowlist, otherwise the next call
    flushes a `CheckViolationError`.
    """
    db_values = _load_db_status_values()
    service_writes = _service_status_writes()

    illegal = service_writes - db_values
    if illegal:
        pytest.fail(
            f"fuzzing_service.py writes statuses not allowed by the live "
            f"ck_fuzzing_campaigns_status CHECK constraint "
            f"({len(illegal)}): {sorted(illegal)}.\n\n"
            f"Resolution: add a migration that recreates the constraint "
            f"with the new value (see "
            f"`d8e9c4b5f7a2_widen_fuzzing_campaigns_status_check.py` for "
            f"the shape — mirror its V2 tuple, append the new value, "
            f"drop+create the constraint, and bump the down_revision).  "
            f"Conversely if the literal is dead code, remove it from the "
            f"service.\n\n"
            f"Allowed: {sorted(db_values)}\n"
            f"Service writes: {sorted(service_writes)}"
        )


def test_fuzzing_status_check_includes_queued_post_2026_04_20():
    """Sanity check for the specific Wave-1 β regression: `queued` MUST
    appear in the live allowlist, otherwise the 202+polling refactor is
    broken at runtime."""
    db_values = _load_db_status_values()
    assert "queued" in db_values, (
        "`queued` not in ck_fuzzing_campaigns_status allowlist — the "
        "Wave-1 β 202+polling refactor (commit df30015) regressed "
        "without this value being permitted.  Confirm migration "
        "d8e9c4b5f7a2 (or its successor) is the head."
    )
