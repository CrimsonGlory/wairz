"""DB ck_findings_source CHECK ↔ frontend FindingSource union ↔
FINDING_SOURCE_CONFIG keys must agree.

Background: the frontend `?? FINDING_SOURCE_CONFIG.manual` fallback at
`FindingDetail.tsx` and `FindingsList.tsx` masks any drift between the
DB allowlist and the frontend type union — findings created with a
DB-only source render as "Manual", so operators can't tell.  This test
adds a discoverability gate.

The audit covers three artefacts:

1. The `ck_findings_source` CHECK on the `findings` table (DB-side
   allowlist, defined in alembic migrations).
2. The `FindingSource` TypeScript union in
   `frontend/src/types/index.ts`.
3. The `FINDING_SOURCE_CONFIG` keys in
   `frontend/src/constants/statusConfig.ts`.

If any of the three diverge, this test fails with a diff naming the
offending values.  Resolution depends on which side has the extra:

- DB-only:    add to `FindingSource` union and `FINDING_SOURCE_CONFIG`
              (the frontend has new sources to render), OR drop from
              the migration (the source is genuinely defunct, e.g. a
              legacy `fuzzing` rename).
- FE-only:    add a migration recreating `ck_findings_source` with the
              new value (CLAUDE.md Rule #33 design contract — same
              shape as `a9f4e9cdabe2_add_unpack_audit_source.py`),
              OR drop from the union if never written.
- config gap: `FINDING_SOURCE_CONFIG` is exhaustive per CLAUDE.md
              Rule #9 — every `FindingSource` value MUST have an entry,
              add the missing key.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

_BACKEND_DIR = Path(__file__).parent.parent
_REPO_ROOT = _BACKEND_DIR.parent
_FRONTEND_TYPES = _REPO_ROOT / "frontend" / "src" / "types" / "index.ts"
_FRONTEND_STATUS_CONFIG = _REPO_ROOT / "frontend" / "src" / "constants" / "statusConfig.ts"
_ALEMBIC_VERSIONS = _BACKEND_DIR / "alembic" / "versions"

# Cross-stack contract test: requires both backend/ AND frontend/ source
# trees. The backend container at /app/ has only `backend/` mounted (no
# `frontend/`), so the FRONTEND_TYPES + FRONTEND_STATUS_CONFIG paths
# don't resolve when pytest runs inside the container. Skip the entire
# module in that environment — host-side CI / dev runs still execute
# the alignment checks.
pytestmark = pytest.mark.skipif(
    not _FRONTEND_TYPES.exists() or not _FRONTEND_STATUS_CONFIG.exists(),
    reason=(
        "frontend/ source tree not accessible — this is a cross-stack "
        "alignment test that requires both backend/ and frontend/ "
        "checked out (host-side, not in the backend container)"
    ),
)


def _alembic_chain() -> dict[str, tuple[Path, str | None]]:
    """Map every revision to (file path, down_revision)."""
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


def _latest_source_check_migration_path() -> Path:
    """Walk the alembic chain from head backwards; return the path of
    the most recent migration that recreates `ck_findings_source`."""
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
            if (
                "ck_findings_source" in text
                and "create_check_constraint" in text
            ):
                candidates.add(path)
                break
            rev = down

    assert candidates, (
        "no migration found that recreates ck_findings_source — "
        "did the constraint get renamed?"
    )
    assert len(candidates) == 1, (
        "alembic chain has multiple heads with diverging source CHECK "
        f"definitions: {sorted(p.name for p in candidates)}"
    )
    return next(iter(candidates))


def _load_db_source_values() -> set[str]:
    """Load + exec the latest source-CHECK migration; return its source
    values tuple as a set."""
    path = _latest_source_check_migration_path()
    spec = importlib.util.spec_from_file_location("_latest_src_mig", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Migration files use either `FINDINGS_SOURCE_VALUES` (initial creator)
    # or `_NEW_SOURCE_VALUES` (subsequent recreators that extend the list).
    # Accept any module-level tuple-of-strings whose name ends in
    # `SOURCE_VALUES`.
    for name in dir(mod):
        if not name.endswith("SOURCE_VALUES"):
            continue
        val = getattr(mod, name)
        if (
            isinstance(val, tuple)
            and val
            and all(isinstance(v, str) for v in val)
        ):
            return set(val)

    raise AssertionError(
        f"{path.name} touches ck_findings_source but exposes no "
        "tuple-of-strings ending in SOURCE_VALUES — convention is to "
        "name the allowlist `FINDINGS_SOURCE_VALUES` or "
        "`_NEW_SOURCE_VALUES` so external code (this test) can import it"
    )


def _parse_finding_source_union() -> set[str]:
    text = _FRONTEND_TYPES.read_text()
    m = re.search(
        r"export\s+type\s+FindingSource\s*=\s*([^\n]+)",
        text,
    )
    assert m, (
        f"could not locate `export type FindingSource = ...` in "
        f"{_FRONTEND_TYPES} — was it renamed?"
    )
    raw = m.group(1)
    # Each member is a single-quoted string; strip trailing semicolon.
    return set(re.findall(r"'([^']+)'", raw))


def _balanced_object_body(text: str, start_after_open_brace: int) -> str:
    """Return the substring between the `{` at the given position+1 and
    its matching `}`, skipping over string literals."""
    depth = 1
    in_string: str | None = None
    end = start_after_open_brace
    while end < len(text):
        ch = text[end]
        if in_string:
            if ch == "\\":
                end += 2
                continue
            if ch == in_string:
                in_string = None
        elif ch in ("'", '"'):
            in_string = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start_after_open_brace:end]
        end += 1
    raise AssertionError("unbalanced braces — could not find matching '}'")


def _parse_finding_source_config_keys() -> set[str]:
    """Pull top-level keys from the `FINDING_SOURCE_CONFIG` object literal.

    Walks the body tracking brace depth so that nested entry literals
    (e.g. `manual: { icon: User, label: 'Manual', ... }`) don't fool the
    parser into grabbing the inner field names.
    """
    text = _FRONTEND_STATUS_CONFIG.read_text()
    m = re.search(
        r"export\s+const\s+FINDING_SOURCE_CONFIG\b[^{]*\{",
        text,
    )
    assert m, (
        f"could not locate `export const FINDING_SOURCE_CONFIG ...= {{` in "
        f"{_FRONTEND_STATUS_CONFIG} — was it renamed?"
    )
    body = _balanced_object_body(text, m.end())

    keys: set[str] = set()
    depth = 0
    in_string: str | None = None
    buf = ""
    for ch in body:
        if in_string:
            buf += ch
            if ch == "\\":
                # naive — buf will have an extra char but key parsing only
                # looks at the very start of an entry, so this is fine.
                continue
            if ch == in_string:
                in_string = None
            continue
        if ch in ("'", '"'):
            in_string = ch
            buf += ch
            continue
        if ch == "{":
            depth += 1
            buf += ch
            continue
        if ch == "}":
            depth -= 1
            buf += ch
            continue
        if ch == "," and depth == 0:
            key_m = re.match(r"^\s*['\"]?([\w\-]+)['\"]?\s*:", buf)
            if key_m:
                keys.add(key_m.group(1))
            buf = ""
            continue
        buf += ch

    # Final entry (file may have a trailing comma, but if not, this catches it).
    key_m = re.match(r"^\s*['\"]?([\w\-]+)['\"]?\s*:", buf)
    if key_m:
        keys.add(key_m.group(1))

    assert keys, "parsed FINDING_SOURCE_CONFIG body but found no keys"
    return keys


# ── Known pre-existing drift (baseline as of 2026-05-04) ──
#
# This intake (`findings-source-tag-drift-ci-2026-05-04`) explicitly
# scoped the close OUT — closing requires per-source classification
# (keep / rename / remove) which is a separate effort.  The GATE that
# this test provides is FORWARD-DRIFT detection: any value added to
# either side without being reflected on the other will fail the test
# in CI.
#
# When a baseline entry is closed (added to the missing side, or
# dropped from the offending side), remove it from the corresponding
# `_KNOWN_*_DRIFT` set — the test will then continue to enforce
# zero-drift on that value.
#
# Intake initially listed 8 DB-only / 2 FE-only based on a manual grep;
# this test surfaced reality as 7 / 3.  The intake mis-counted because
# (a) it treated `fuzzing` and `fuzzing_scan` as both DB-only, but
# `fuzzing` is also in the FE union (so it's NOT drifting); (b) it
# missed `security_review` on the FE-only side.  Classic Rule #31
# narrow-grep miscounting; corrected then.
#
# Closure landed 2026-05-06 in alembic revision
# `61b147189fcf_close_findings_source_drift.py` + matching frontend
# changes:
#   - DB ADD: `security_review` (assessment_service ASSESSMENT_SOURCE),
#     `ai_discovered` (MCP add_finding default).
#   - DB DROP: `fuzzing_scan` (legacy duplicate, 0 rows / 0 SET sites).
#   - FE ADD: `attack_surface`, `clamav_scan`, `cwe_checker`,
#     `hardware_firmware_graph`, `uefi_scan`, `vt_scan` (all already in
#     DB, missing from frontend union/config).
#   - FE DROP: `known_good_scan` (dead UI; `run_known_good_scan` in
#     `services/security_audit/hash_lookups.py` produces SecurityFinding
#     objects which `_persist_finding` writes with
#     `source='security_audit'`, never `'known_good_scan'`).
#
# Both baselines are now empty; the alignment tests act as a hard
# forward-drift gate.

_KNOWN_DB_ONLY_DRIFT: frozenset[str] = frozenset()

_KNOWN_FE_ONLY_DRIFT: frozenset[str] = frozenset()


def test_finding_source_config_is_exhaustive():
    """CLAUDE.md Rule #9: every `FindingSource` union value MUST have a
    `FINDING_SOURCE_CONFIG` entry, otherwise the lookup at the call
    site returns `undefined` and crashes React.  This is a STRICT
    invariant — no baseline tolerance — because a missing entry is a
    runtime crash, not just a UX mislabel."""
    fe_union = _parse_finding_source_union()
    fe_config = _parse_finding_source_config_keys()

    union_minus_config = fe_union - fe_config
    config_minus_union = fe_config - fe_union

    msgs: list[str] = []
    if union_minus_config:
        msgs.append(
            f"`FindingSource` values missing from `FINDING_SOURCE_CONFIG` "
            f"({len(union_minus_config)}): {sorted(union_minus_config)} — "
            f"add an entry per CLAUDE.md Rule #9 to avoid a `Record<…>` "
            f"`undefined` crash"
        )
    if config_minus_union:
        msgs.append(
            f"`FINDING_SOURCE_CONFIG` keys missing from `FindingSource` "
            f"union ({len(config_minus_union)}): {sorted(config_minus_union)} "
            f"— either remove the dead config entries or add the values "
            f"to the union"
        )

    if msgs:
        pytest.fail(
            "Frontend FindingSource ↔ FINDING_SOURCE_CONFIG mismatch:\n  - "
            + "\n  - ".join(msgs)
        )


def test_finding_source_no_new_db_only_drift():
    """Forward-drift gate: a new DB CHECK value added without being
    reflected in the frontend `FindingSource` union will fail this
    test.  Pre-existing drift is captured in `_KNOWN_DB_ONLY_DRIFT`
    and tolerated."""
    db_values = _load_db_source_values()
    fe_union = _parse_finding_source_union()
    actual_db_only = db_values - fe_union

    new_drift = actual_db_only - _KNOWN_DB_ONLY_DRIFT
    if new_drift:
        pytest.fail(
            f"New DB-only source values appeared since the baseline "
            f"({len(new_drift)}): {sorted(new_drift)}.\n\n"
            f"Resolution: add each to `FindingSource` union in "
            f"`frontend/src/types/index.ts` AND to "
            f"`FINDING_SOURCE_CONFIG` in "
            f"`frontend/src/constants/statusConfig.ts`.  If the value "
            f"is genuinely defunct, drop it from the most recent "
            f"`ck_findings_source` migration instead."
        )

    closed = _KNOWN_DB_ONLY_DRIFT - actual_db_only
    if closed:
        pytest.fail(
            f"Baseline `_KNOWN_DB_ONLY_DRIFT` is stale — these values "
            f"are no longer DB-only ({len(closed)}): {sorted(closed)}.  "
            f"Remove them from the baseline so future regressions on the "
            f"same values are caught.  Likely caused by a recent close "
            f"of pre-existing drift."
        )


def test_finding_source_no_new_fe_only_drift():
    """Forward-drift gate (the other direction): a new frontend
    `FindingSource` member added without a corresponding migration
    will fail this test.  Pre-existing drift in
    `_KNOWN_FE_ONLY_DRIFT` is tolerated."""
    db_values = _load_db_source_values()
    fe_union = _parse_finding_source_union()
    actual_fe_only = fe_union - db_values

    new_drift = actual_fe_only - _KNOWN_FE_ONLY_DRIFT
    if new_drift:
        pytest.fail(
            f"New frontend-only source values appeared since the "
            f"baseline ({len(new_drift)}): {sorted(new_drift)}.\n\n"
            f"Resolution: add a migration recreating "
            f"`ck_findings_source` with the new value (see "
            f"`a9f4e9cdabe2_add_unpack_audit_source.py` for the shape "
            f"— mirror its tuple, add the new value, drop+create the "
            f"constraint).  If the value is never written, drop it "
            f"from the frontend union instead."
        )

    closed = _KNOWN_FE_ONLY_DRIFT - actual_fe_only
    if closed:
        pytest.fail(
            f"Baseline `_KNOWN_FE_ONLY_DRIFT` is stale — these values "
            f"are no longer FE-only ({len(closed)}): {sorted(closed)}.  "
            f"Remove them from the baseline so future regressions on "
            f"the same values are caught."
        )
