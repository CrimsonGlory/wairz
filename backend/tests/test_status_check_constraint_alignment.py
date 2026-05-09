"""DB CHECK constraints (Rule #33c) ↔ Pydantic Literals ↔ code writes.

Background: audit-2026-05-04 Stream C F-C-05 measured 12 production
status / mode / enum-like columns lacking DB CHECK constraints.  Migration
``89007f64cfb0_audit_2026_05_04_add_status_check_.py`` adds CHECK on each.
This test prevents the next drift from being silent — every literal a
service or router writes for one of these columns MUST be in the migration's
allowlist tuple, or the next ``await db.flush()`` raises
``CheckViolationError``.

Mirrors the shape of ``test_fuzzing_status_check_alignment.py``:
alembic-chain walk → extract tuple → set comparison vs source-grep.
Adds Pydantic-Literal alignment for columns whose user-facing schema
narrows the value set (EmulationStartRequest, EmulationPresetCreate,
CraStatus / RequirementStatus enums).
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

_BACKEND_DIR = Path(__file__).parent.parent
_ALEMBIC_VERSIONS = _BACKEND_DIR / "alembic" / "versions"
_APP_DIR = _BACKEND_DIR / "app"


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


def _load_migration(constraint_name: str) -> object:
    """Walk the alembic chain from head and return the migration module
    that creates ``constraint_name``.  Mirrors the resolver shape used in
    test_fuzzing_status_check_alignment so future migrations that re-create
    a constraint (drop+create widening) are picked up automatically.
    """
    chain = _alembic_chain()
    heads = _alembic_heads(chain)
    assert heads, "no alembic head found"

    candidates: set[Path] = set()
    for head in heads:
        rev: str | None = head
        seen: set[str] = set()
        while rev and rev in chain and rev not in seen:
            seen.add(rev)
            path, down = chain[rev]
            text = path.read_text()
            if (
                f'"{constraint_name}"' in text
                and "create_check_constraint" in text
            ):
                candidates.add(path)
                break
            rev = down

    assert candidates, (
        f"no migration found that creates {constraint_name} — did the "
        "constraint get renamed?"
    )
    assert len(candidates) == 1, (
        f"alembic chain has multiple heads with diverging definitions of "
        f"{constraint_name}: {sorted(p.name for p in candidates)}"
    )
    path = next(iter(candidates))
    spec = importlib.util.spec_from_file_location(
        f"_status_check_mig_{constraint_name}", path,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _allowlist(constraint_name: str, tuple_attr: str) -> set[str]:
    mod = _load_migration(constraint_name)
    val = getattr(mod, tuple_attr, None)
    assert isinstance(val, tuple) and val, (
        f"{tuple_attr} on the migration that creates {constraint_name} "
        f"is not a non-empty tuple"
    )
    return set(val)


# ── Migration constants smoke test ─────────────────────────────────────


_CONSTRAINT_TUPLE_MAP: tuple[tuple[str, str], ...] = (
    ("ck_projects_status", "PROJECT_STATUS_VALUES"),
    ("ck_security_reviews_status", "SECURITY_REVIEW_STATUS_VALUES"),
    ("ck_review_agents_status", "REVIEW_AGENT_STATUS_VALUES"),
    ("ck_uart_sessions_status", "UART_SESSION_STATUS_VALUES"),
    (
        "ck_cra_assessments_overall_status",
        "CRA_ASSESSMENT_OVERALL_STATUS_VALUES",
    ),
    (
        "ck_cra_requirement_results_status",
        "CRA_REQUIREMENT_STATUS_VALUES",
    ),
    ("ck_emulation_sessions_mode", "EMULATION_MODE_VALUES"),
    ("ck_emulation_presets_mode", "EMULATION_MODE_VALUES"),
    (
        "ck_emulation_presets_stub_profile",
        "EMULATION_PRESET_STUB_PROFILE_VALUES",
    ),
    ("ck_sbom_vulns_match_confidence", "SBOM_VULN_MATCH_CONFIDENCE_VALUES"),
    ("ck_sbom_vulns_match_tier", "SBOM_VULN_MATCH_TIER_VALUES"),
    ("ck_sbom_vulns_resolved_by", "SBOM_VULN_RESOLVED_BY_VALUES"),
    (
        "ck_sbom_vulns_adjusted_severity",
        "SBOM_VULN_ADJUSTED_SEVERITY_VALUES",
    ),
)


def test_every_new_constraint_resolves_to_an_allowlist_tuple():
    """Sanity: each constraint in the migration map must expose a tuple
    constant the test can import.  If the names drift, this fails first
    so every other assertion below gets an actionable error.
    """
    missing: list[tuple[str, str]] = []
    for cname, tname in _CONSTRAINT_TUPLE_MAP:
        try:
            allow = _allowlist(cname, tname)
        except AssertionError:
            missing.append((cname, tname))
            continue
        assert allow, f"{cname} resolved to an empty tuple {tname}"
    assert not missing, (
        f"constraint→tuple resolution failed for: {missing}.  Every new "
        "CHECK should expose a module-scope ALLOWLIST tuple so this "
        "alignment test can pull it without per-migration edits."
    )


# ── Project status writes vs CHECK ─────────────────────────────────────


def _grep_literal_assignments(
    path: Path, attribute: str,
) -> set[str]:
    """Return the set of literal strings assigned to ``<X>.<attribute> = "lit"``
    in the given file (any leading identifier on the LHS).  Matches both
    ``project.status = "ready"`` and ``self.status = "ready"`` shapes.
    """
    pattern = re.compile(
        rf"""\b\w+\.{re.escape(attribute)}\s*=\s*['"]([^'"]+)['"]"""
    )
    return set(pattern.findall(path.read_text()))


def _grep_kw_assignments(path: Path, attribute: str) -> set[str]:
    """Return literal values from ``<attribute>="lit"`` keyword args in
    constructor / dataclass-style call sites within the file.
    """
    pattern = re.compile(
        rf"""\b{re.escape(attribute)}\s*=\s*['"]([^'"]+)['"]"""
    )
    return set(pattern.findall(path.read_text()))


def test_project_status_writes_in_allowlist():
    """Project.status literal writes (firmware router, arq worker,
    device service) must satisfy ck_projects_status."""
    allow = _allowlist("ck_projects_status", "PROJECT_STATUS_VALUES")
    writes: set[str] = set()
    for rel in (
        "routers/firmware.py",
        "workers/arq_worker.py",
        "services/device_service.py",
    ):
        writes |= _grep_literal_assignments(_APP_DIR / rel, "status")
    # Filter — these files write to other .status attributes too.
    # Anchor by comparing to allowlist + known unrelated values.
    illegal = writes - allow - {
        # Unrelated writes in same files (not project.status):
        "unpacking", "ready", "error", "created",  # already in allowlist
        # Other models the same files touch:
        "running", "stopped", "completed", "failed", "queued", "pending",
        "starting", "booting", "stopping", "connected", "closed",
        "complete", "partial", "cancelled", "in_progress", "exported",
        # `cancelled` is in DEVICE_DUMP_STATUS_VALUES (migration
        # b0c1a2d3e4f5_add_device_dump_sessions.py) — written at
        # device_service.py:233 against DeviceDumpSession.status,
        # never against Project.status.
    }
    assert not illegal, (
        f"unexpected status literals in project-touching files: {illegal}. "
        f"Either add to PROJECT_STATUS_VALUES or rule out as belonging to "
        f"another model's status write."
    )


# ── UART status writes ─────────────────────────────────────────────────


def test_uart_session_status_writes_in_allowlist():
    allow = _allowlist("ck_uart_sessions_status", "UART_SESSION_STATUS_VALUES")
    text = (_APP_DIR / "services" / "uart_service.py").read_text()
    writes = set(
        re.findall(
            r"""(?:session|row)\.status\s*=\s*['"]([^'"]+)['"]""",
            text,
        )
    )
    # Constructor-style: status="connected"
    for m in re.finditer(
        r"""\bstatus\s*=\s*['"]([^'"]+)['"]""", text,
    ):
        writes.add(m.group(1))
    illegal = writes - allow - {
        # Generic words used in the file but not bound to UARTSession.status:
        "running", "stopped", "completed", "failed", "queued", "pending",
        "starting", "booting",
    }
    assert not illegal, (
        f"uart_service.py writes statuses outside ck_uart_sessions_status: "
        f"{illegal}.  Allowed: {sorted(allow)}"
    )


# ── Emulation mode writes ──────────────────────────────────────────────


def test_emulation_session_mode_writes_in_allowlist():
    """Scan attribute-style writes (`<x>.mode = "lit"`) AND keyword
    writes inside ``EmulationSession(...)`` constructor calls only.
    The bare ``mode="lit"`` regex is too broad (matches
    ``tarfile.open(mode="r")`` etc.); we anchor to the constructor
    block via a multi-line lookahead.
    """
    allow = _allowlist("ck_emulation_sessions_mode", "EMULATION_MODE_VALUES")
    files = [
        _APP_DIR / "services" / "system_emulation_service.py",
        _APP_DIR / "services" / "emulation" / "service.py",
    ]
    writes: set[str] = set()
    for path in files:
        if not path.exists():
            continue
        text = path.read_text()
        # Attribute-style: session.mode = "X" / row.mode = "X" / row.mode = "X"
        writes |= set(
            re.findall(
                r"""\b\w+\.mode\s*=\s*['"]([^'"]+)['"]""",
                text,
            )
        )
        # Constructor-style: EmulationSession( ... mode="X" ... )
        # Anchor on the class name — any mode="..." within the same
        # parenthesised call site.
        for ctor_match in re.finditer(
            r"""EmulationSession\s*\(([^)]*)\)""",
            text,
            re.DOTALL,
        ):
            for v in re.findall(
                r"""\bmode\s*=\s*['"]([^'"]+)['"]""",
                ctor_match.group(1),
            ):
                writes.add(v)
    illegal = writes - allow
    assert not illegal, (
        f"emulation services write mode literals outside "
        f"ck_emulation_sessions_mode: {illegal}.  Allowed: {sorted(allow)}"
    )


# ── Pydantic Literal alignment ─────────────────────────────────────────


def test_emulation_pydantic_literal_subset_of_check():
    """The Pydantic-narrowed input set MUST be a subset of the DB CHECK
    allowlist.  If the schema accepts a value the DB rejects, every POST
    that uses that value flushes a CheckViolationError.

    Note: the inverse subset relationship does NOT hold — the DB
    allowlist may include values the schema does NOT accept, because
    other code paths (e.g. system_emulation_service writing
    ``"system-full"``) bypass the schema.  That is by design and
    documented in the migration.
    """
    db_allow = _allowlist(
        "ck_emulation_sessions_mode", "EMULATION_MODE_VALUES",
    )
    schema_path = _APP_DIR / "schemas" / "emulation.py"
    text = schema_path.read_text()
    # Pull every mode: Literal[...] occurrence.
    schema_modes: set[str] = set()
    for m in re.finditer(
        r"""mode\s*:\s*Literal\[([^\]]+)\]""", text,
    ):
        for v in re.findall(r"""['"]([^'"]+)['"]""", m.group(1)):
            schema_modes.add(v)
    assert schema_modes, "no `mode: Literal[...]` found in schemas/emulation.py"
    illegal = schema_modes - db_allow
    assert not illegal, (
        f"EmulationStartRequest / EmulationPresetCreate accepts mode values "
        f"the DB CHECK rejects: {illegal}.  Either widen the CHECK or "
        f"narrow the Literal."
    )


def test_emulation_stub_profile_pydantic_literal_subset_of_check():
    db_allow = _allowlist(
        "ck_emulation_presets_stub_profile",
        "EMULATION_PRESET_STUB_PROFILE_VALUES",
    )
    schema_path = _APP_DIR / "schemas" / "emulation.py"
    text = schema_path.read_text()
    schema_values: set[str] = set()
    for m in re.finditer(
        r"""stub_profile\s*:\s*Literal\[([^\]]+)\]""", text,
    ):
        for v in re.findall(r"""['"]([^'"]+)['"]""", m.group(1)):
            schema_values.add(v)
    assert schema_values, (
        "no `stub_profile: Literal[...]` in schemas/emulation.py"
    )
    illegal = schema_values - db_allow
    assert not illegal, (
        f"EmulationPresetCreate accepts stub_profile values the DB CHECK "
        f"rejects: {illegal}.  Allowed by DB: {sorted(db_allow)}"
    )


def test_cra_status_enum_subset_of_overall_status_check():
    """schemas/cra_compliance.py CraStatus enum must agree with
    ck_cra_assessments_overall_status."""
    db_allow = _allowlist(
        "ck_cra_assessments_overall_status",
        "CRA_ASSESSMENT_OVERALL_STATUS_VALUES",
    )
    text = (_APP_DIR / "schemas" / "cra_compliance.py").read_text()
    # class CraStatus(str, Enum): in_progress = "in_progress"; ...
    section = re.search(
        r"""class\s+CraStatus\s*\([^)]*\)\s*:(.*?)(?=^class\s|\Z)""",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert section, "CraStatus class not found in schemas/cra_compliance.py"
    enum_values = set(
        re.findall(
            r"""=\s*['"]([^'"]+)['"]""",
            section.group(1),
        )
    )
    assert enum_values, "CraStatus enum body parsed empty"
    illegal = enum_values - db_allow
    assert not illegal, (
        f"CraStatus enum values not in ck_cra_assessments_overall_status: "
        f"{illegal}.  Allowed: {sorted(db_allow)}"
    )


def test_cra_requirement_status_enum_subset_of_check():
    db_allow = _allowlist(
        "ck_cra_requirement_results_status",
        "CRA_REQUIREMENT_STATUS_VALUES",
    )
    text = (_APP_DIR / "schemas" / "cra_compliance.py").read_text()
    section = re.search(
        r"""class\s+RequirementStatus\s*\([^)]*\)\s*:(.*?)(?=^class\s|\Z)""",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert section, "RequirementStatus class not found"
    enum_values = set(
        re.findall(
            r"""=\s*['"]([^'"]+)['"]""",
            section.group(1),
        )
    )
    assert enum_values, "RequirementStatus enum body parsed empty"
    illegal = enum_values - db_allow
    assert not illegal, (
        f"RequirementStatus enum values not in "
        f"ck_cra_requirement_results_status: {illegal}.  "
        f"Allowed: {sorted(db_allow)}"
    )


# ── SBOM vuln writes ───────────────────────────────────────────────────


def test_sbom_resolved_by_writes_in_allowlist():
    allow = _allowlist(
        "ck_sbom_vulns_resolved_by", "SBOM_VULN_RESOLVED_BY_VALUES",
    )
    files = [
        _APP_DIR / "routers" / "sbom.py",
        _APP_DIR / "ai" / "tools" / "sbom.py",
    ]
    writes: set[str] = set()
    for path in files:
        text = path.read_text()
        for m in re.finditer(
            r"""\b\w+\.resolved_by\s*=\s*['"]([^'"]+)['"]""",
            text,
        ):
            writes.add(m.group(1))
    illegal = writes - allow
    assert not illegal, (
        f"resolved_by writes outside ck_sbom_vulns_resolved_by: {illegal}.  "
        f"Allowed: {sorted(allow)}"
    )


def test_sbom_match_tier_writes_in_allowlist():
    allow = _allowlist(
        "ck_sbom_vulns_match_tier", "SBOM_VULN_MATCH_TIER_VALUES",
    )
    text = (
        _APP_DIR / "services" / "hardware_firmware" / "cve_matcher.py"
    ).read_text()
    writes = set(re.findall(r"""\btier\s*=\s*['"]([^'"]+)['"]""", text))
    illegal = writes - allow
    assert not illegal, (
        f"cve_matcher.py writes match_tier values outside "
        f"ck_sbom_vulns_match_tier: {illegal}.  Allowed: {sorted(allow)}"
    )


def test_sbom_match_confidence_writes_in_allowlist():
    allow = _allowlist(
        "ck_sbom_vulns_match_confidence",
        "SBOM_VULN_MATCH_CONFIDENCE_VALUES",
    )
    text = (
        _APP_DIR / "services" / "hardware_firmware" / "cve_matcher.py"
    ).read_text()
    writes = set(
        re.findall(r"""\bconfidence\s*=\s*['"]([^'"]+)['"]""", text)
    )
    # Filter the variable-derived assignments that look like confidence=X
    # but where X is not a literal (already excluded by regex requiring
    # quoted string).  No further filtering needed.
    illegal = writes - allow
    assert not illegal, (
        f"cve_matcher.py writes match_confidence values outside "
        f"ck_sbom_vulns_match_confidence: {illegal}.  "
        f"Allowed: {sorted(allow)}"
    )
