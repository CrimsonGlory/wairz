---
name: real-firmware-skip-tier-canary
description: Author a 3-tier real-firmware end-to-end canary for a new forensic-format pipeline (Authenticode / registry / .NET / EVTX / Prefetch / etc.). Tier-1 always runs against synthetic data with mocks; tier-2/3 skip-unless an env-var fixture is provided. Promotes Rule #35b live-canary discipline to a pipeline-level shape.
triggers:
  - "real firmware canary"
  - "skip tier"
  - "live canary pipeline"
  - "end-to-end test"
  - "fixture provisioning"
  - "rule 35b"
edges:
  - target: context/conventions.md
    condition: for the Verify Checklist that lists Rule #35b live canaries
  - target: patterns/add-router-test.md
    condition: when the pipeline is fronted by a router — the router-level test handles HTTP-layer assertions; this recipe handles end-to-end flow
  - target: patterns/add-jsonb-column.md
    condition: when the pipeline persists JSONB results — chain into the normaliser recipe
last_updated: 2026-05-08
---

# Real-Firmware Skip-Tier Canary

## Context

CLAUDE.md Rule #35b (mock vs live canaries) requires that whenever persistence or service behavior matters, you run the new code once against a real production row (or a freshly-created fixture row through the real ORM/service path) and SELECT the persisted row to inspect every field the service explicitly sets. Mocks verify dispatch shape; live canaries verify value flow.

The **3-tier real-firmware canary** is the pipeline-level shape of Rule #35b. It applies when:
- A new service walks a real-world firmware artefact (PE / registry hive / driver INF/CAT / .NET single-file bundle / KB-diff pair / EVTX log / Prefetch / hibernate.sys / etc.) AND
- The service has multiple stages that compose (parser → classifier → emit hook → DB persistence) AND
- Real artefacts are too heavy / licensed / vendor-specific to commit to the repo as a fixture.

Three applications across the windows-coverage-godmode campaign make this Rule-of-Three durable:

| # | Phase | Commit | Pipeline | Tier-1 / Tier-2 / Tier-3 |
|---|-------|--------|----------|--------------------------|
| 1 | β.14a | `77b257d` | Authenticode chain validation | synthetic PE (mocked signify) / real signed PE / real revoked PE |
| 2 | γ.9 | `8437ae3` | Registry hive walk + driver INF/CAT classifier | synthetic hive (mocked regipy) / real Win11 NTUSER.DAT / real driver pkg |
| 3 | δ.9 | `1f09179` | .NET decompile + KB-diff + R2R-stomping | synthetic .NET PE + synthetic KB pair / real .NET 8 bundle / real KB-vs-KB pair |

All three followed the same shape: 5 pass + 2 skip on a typical Linux dev host; canary "graduates" from partial → full via operator fixture commits, with no test code edits needed (the env-var probe + skipif decoration handles the cutover).

## Decide: tier count

- **3 tiers** is the durable shape. Tier-1 covers the FULL pipeline against synthetic data; tier-2 covers a single real artefact (no compose); tier-3 covers a paired real artefact (compose, e.g. older_kb + newer_kb).
- **2 tiers** suffices when the pipeline doesn't compose paired artefacts (e.g. a registry hive walk doesn't have a "two hives compared" stage). Drop tier-3.
- **>3 tiers** is over-engineering — if you find yourself authoring tier-4, you're probably testing service implementation details rather than pipeline behavior. Push details into unit tests.

## Steps

### 1. Identify the pipeline stages

List every stage the canary must drive:

```
parser → classifier → service runner → persistence (DB row) → emit hook (Finding) → MCP registration
```

Each stage gets at least one tier-1 assertion. Tier-2/3 typically assert at the END of the pipeline ("≥1 Finding row with source=X"), not at every stage — the contract is "real artefact survives the full pipeline without exceptions and produces well-shaped output", not "every stage is exercised against the real artefact" (that's tier-1's job).

### 2. Identify the inner-vs-outer runner split

If your pipeline has a background runner that uses `async_session_factory()` (the canonical 202+poll pattern from Rule #33), tier-1 cannot call it directly — `async_session_factory` resolves `DATABASE_URL` with hostname `postgres` (Docker service name), and host pytest can't resolve Docker DNS. Symptom: `socket.gaierror: [Errno -2] Name or service not known`.

The fix shape (δ.5 + γ.4 precedent):

```python
# Service module
async def _do_<op>_run(db: AsyncSession, firmware_id: uuid.UUID) -> ...:
    """Inner runner — accepts a db; pure logic; reusable."""
    ...

async def run_<op>_background(firmware_id: uuid.UUID) -> None:
    """Outer wrapper — owns the Rule #33 .a state machine; uses async_session_factory."""
    async with async_session_factory() as db:
        # ... transition status, call inner, handle errors ...
        await _do_<op>_run(db, firmware_id)
```

Tier-1 calls `_do_<op>_run(test_db, firmware.id)` directly. The outer wrapper is exercised in the running container (where DNS resolves), not the host pytest sweep.

**Mechanical heuristic**: if the runner takes only `firmware_id` (no `db` param), look for an inner function that takes `db`. If none exists, the service was structured for production dispatch only — refactor to expose one (single-line addition; no caller changes). δ.5 antipattern #3 / pattern #2 establishes the discipline.

### 3. Write the test file header

```python
"""Phase <X>.<Y> — Rule #35b real-firmware end-to-end canary set.

Drives the FULL <pipeline> against on-disk fixtures. Mirrors β.14a +
γ.9 + δ.9 precedent (Rule-of-Three skip-tier canary discipline).

3 tiers:
  - Tier 1 (always runs): synthetic ... drives ... asserts ...
  - Tier 2 (skip-unless WAIRZ_TEST_REAL_<X>): real ... asserts ...
  - Tier 3 (skip-unless WAIRZ_TEST_<X>_<PAIRED>): real paired ...

Fixture provisioning:
    export WAIRZ_TEST_REAL_<X>=/path/to/artefact
    export WAIRZ_TEST_<X>_<PAIRED>=/path/to/paired/
    pytest tests/test_<...>_real_firmware.py -v

The canary set graduates from N pass + M skip → (N+M) pass via fixture
commits — no test edits needed.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from app.models import Firmware, Finding, Project, ...
from app.services.<service> import _do_<op>_run, ...
from tests._live_db import make_live_db


# ── Fixture env-var probes ──────────────────────────────────────────────────

_HOST_REAL_<X> = os.environ.get("WAIRZ_TEST_REAL_<X>")
_HOST_<X>_PAIRED = os.environ.get("WAIRZ_TEST_<X>_PAIRED")
```

Naming convention: `WAIRZ_TEST_REAL_<UPPER>` for single-artefact env vars; add a suffix for paired artefacts. Match β.14a / γ.9 / δ.9 names where the artefact type already has precedent.

### 4. Author tier-1 (always runs)

```python
# ── Tier 1 (always runs) ────────────────────────────────────────────────────


def test_tier1_<stage>_<assertion>():
    """Drive <stage> against synthetic data; assert <output shape>."""
    # Build synthetic fixture.
    synthetic = ...

    # Mock third-party libs at SOURCE module per Rule #30.
    with patch("<source-module>.<symbol>") as mock_symbol:
        mock_symbol.return_value = ...
        result = some_service_fn(synthetic)

    assert result.<field> == <expected>


def test_tier1_<inner_runner>_persists_<table>_rows():
    """Drive _do_<op>_run end-to-end against synthetic DB fixture."""
    db = make_live_db()  # tests/_live_db.py — real ORM, isolated test DB

    project = Project(id=uuid.uuid4(), name="canary")
    firmware = Firmware(id=uuid.uuid4(), project_id=project.id, ...)
    db.add_all([project, firmware])
    db.commit()

    # ... seed any prerequisite rows synthetically ...

    asyncio.run(_do_<op>_run(db, firmware.id))  # inner runner — direct call

    # Rule #35b live canary: SELECT the persisted rows.
    rows = db.execute(select(<Table>).where(<Table>.firmware_id == firmware.id)).all()
    assert len(rows) >= 1
    assert all(r.<field> is not None for r in rows)  # value flow, not just call shape
```

Tier-1 should drive every stage of the pipeline. δ.9's tier-1 had 5 tests covering: argv gate, MCP registry shape, classifier, runner end-to-end, emit hook persistence. β.14a's tier-1 had 3 tests covering parsing + chain validation + emit. Match the count to the number of compose stages.

### 5. Author tier-2 (single real artefact)

```python
# ── Tier 2 (real single artefact) ───────────────────────────────────────────


@pytest.mark.skipif(
    not _HOST_REAL_<X>,
    reason="Provide WAIRZ_TEST_REAL_<X> to run tier-2.",
)
def test_tier2_<stage>_handles_real_<X>():
    """Drive <stage> against a real <X> artefact with NO mocks."""
    real_path = _HOST_REAL_<X>
    assert os.path.isfile(real_path) or os.path.isdir(real_path)

    result = some_service_fn(real_path)  # NO mocks; real third-party libs

    # Assert WELL-SHAPED, not specific values (real artefacts vary).
    assert result.<field> is not None
    assert isinstance(result.<list_field>, list)
    assert len(result.<list_field>) >= 1
```

The skipif reason field MUST tell the operator how to provision the fixture (one line). Tier-2 assertions are looser than tier-1 — real artefacts produce variable output, so test "well-shaped" not "exactly N rows with field=Y". δ.9 tier-2 asserted ≥1 draft for an R2R-eligible bundle without specifying which bundle.

### 6. Author tier-3 (paired real artefact)

```python
# ── Tier 3 (real paired artefact) ───────────────────────────────────────────


@pytest.mark.skipif(
    not _HOST_<X>_PAIRED,
    reason="Provide WAIRZ_TEST_<X>_PAIRED to run tier-3.",
)
def test_tier3_<paired_op>_against_real_<X>():
    """Drive paired <X> through <op> with NO mocks."""
    base = _HOST_<X>_PAIRED
    older = os.path.join(base, "older")
    newer = os.path.join(base, "newer")
    assert os.path.isdir(older) and os.path.isdir(newer)

    db = make_live_db()
    # ... seed firmware row, paired-artefact rows ...

    asyncio.run(_do_<op>_run(db, firmware.id))

    rows = db.execute(select(<Table>).where(...)).all()
    assert len(rows) >= 1, "real paired artefacts reliably produce ≥1 result"
```

Skip if the pipeline has no compose stage. δ.9 had tier-3 because KB-vs-KB diff is genuinely paired; γ.9 didn't have tier-3 because registry walk operates on a single hive.

### 7. Run + commit

```sh
docker compose exec -T backend /app/.venv/bin/pytest \
  backend/tests/test_<...>_real_firmware.py -v
```

Expected output (host dev box, no fixtures provisioned): `N passed, M skipped`. The skips list the env vars in the reason field — operator reads + provisions to graduate.

If tier-1 fails with `socket.gaierror`, you missed the inner-vs-outer split (Step 2). Refactor: import `_do_<op>_run` instead of `run_<op>_background`.

If the test passes but the assertion is "trivially true" (e.g. `assert result is not None` only), strengthen — Rule #35b is about value flow, not call shape. Inspect specific fields the service explicitly sets (sources, confidence, status transitions).

## Gotchas

- **`make_live_db()` vs `mock_db`** — tier-1 MUST use `make_live_db()` from `tests/_live_db.py` (real ORM round-trip). A `MagicMock()` for db means you're back to mock-shape testing and lose the Rule #35b backstop.
- **Fixture env-var values that point at directories vs files** — be explicit in the docstring + the skipif reason. δ.9's tier-3 expects a directory containing `older/` + `newer/` subdirs; tier-2 expects a single file path. Don't conflate.
- **Calling `run_<op>_background()` from tier-1** triggers `socket.gaierror` from `async_session_factory`. Always call the inner `_do_<op>_run(db, ...)` instead.
- **Mock target for lazy-imported third-party symbols** — per Rule #30, patch the SOURCE module (`signify.authenticode.AuthenticodeFile`, `regipy.RegistryHive`, `dnfile.dnPE`), not the wairz service module. If the wairz service does `from signify.authenticode import AuthenticodeFile` inside a function body, `patch("app.services.windows_pe_service.AuthenticodeFile")` is a silent no-op.
- **Tier-1 tests asserting timing or perf** — bad. Tier-1 is for shape/value verification; perf goes elsewhere (or never, in pytest).
- **Tier-2 fixture provisioning into the repo** — DON'T. Real artefacts are vendor-licensed (Microsoft signed binaries, OEM firmware blobs) or huge (multi-GB Win11 install). Fixtures live on the operator's disk, referenced via env var. Repo only carries synthetic tier-1 data.
- **Skipif decorator order** — `@pytest.mark.skipif(...)` must be the OUTER decorator if you also use `@pytest.mark.parametrize` etc. Skip evaluation happens first.
- **Multiple env vars on one tier** — when tier-2 needs both `WAIRZ_TEST_REAL_<X>` and `WAIRZ_TEST_<X>_AUX`, decorate with a combined skipif: `@pytest.mark.skipif(not (_HOST_REAL_X and _HOST_X_AUX), reason=...)`.

## Verify

- [ ] Test file is under `backend/tests/` named `test_<area>_real_firmware.py` (matches β.14a / γ.9 / δ.9 convention).
- [ ] Module docstring describes all 3 (or 2) tiers with synthetic-vs-real split + fixture-provisioning bash commands.
- [ ] Tier-1 tests use `make_live_db()` from `tests/_live_db.py`.
- [ ] Tier-1 covers every pipeline stage (count ≈ number of compose stages).
- [ ] Tier-1 mocks third-party libs at SOURCE module per Rule #30, not the wairz service module.
- [ ] Inner-vs-outer runner split applied: tier-1 calls `_do_<op>_run(db, ...)`, NOT `run_<op>_background(...)`.
- [ ] Tier-2 + Tier-3 use `@pytest.mark.skipif(not _HOST_<...>, reason=...)` with the env-var name in the reason field.
- [ ] Tier-2/3 assertions are "well-shaped" (real artefacts vary), not "exactly N rows".
- [ ] Pipeline persistence rows are SELECTed back and inspected (Rule #35b value flow).
- [ ] Test runs clean with no fixtures: `N passed, M skipped` with skip reasons mentioning the env vars.
- [ ] Test runs clean WITH fixtures (when operator provisions): `(N+M) passed`, no test edits needed.

## Debug

- **`socket.gaierror: [Errno -2] Name or service not known`** in tier-1 → calling outer wrapper `run_<op>_background()` instead of inner `_do_<op>_run(db, ...)`. Refactor per Step 2.
- **Tier-1 test passes but real-artefact tier-2 raises an exception** → the synthetic fixture didn't exercise the same code path as the real artefact. Look at what differs (encoding, header version, optional fields). Add a synthetic case that mirrors the real-artefact divergence.
- **`AssertionError: ≥1 row, got 0`** in tier-1 persistence test → inner runner didn't actually persist (transaction rollback, db.flush instead of db.commit, fixture rows missing FK targets). Inspect with `print(db.execute(select(Table)).all())` before the assertion.
- **`fixtures/...` test-data file too big to commit** → that's a tier-2/3, not tier-1. Move to operator-provisioned env-var path.
- **`pytest --collect-only` shows tier-2/3 as deselected even when env var is set** → typo in env var name OR `_HOST_<X>` was evaluated at import time but env var was set after pytest started. Check via `python -c "import os; print(os.environ.get('WAIRZ_TEST_REAL_X'))"` before pytest invocation.
- **Tier-1 mock doesn't fire** → patch target is wrong; per Rule #30, grep `^\s+from <lib>` in the wairz service to detect lazy imports. Patch the SOURCE module if the import is indented.

## Update Scaffold

- [ ] If a fourth pipeline applies the 3-tier shape (Rule-of-Four), update the table at the top of this recipe with the new commit + tier descriptions.
- [ ] If a new env-var naming convention emerges (e.g. `WAIRZ_TEST_FIXTURE_<DIR>` instead of `WAIRZ_TEST_REAL_<X>`), update Step 3.
- [ ] If a fifth pipeline shape requires >3 tiers, reconsider whether it should be split into separate canary files instead.

## References

- CLAUDE.md Rule #30 (mock patch target for lazy-imported third-party symbols)
- CLAUDE.md Rule #33 (202+polling endpoint design — establishes the inner-vs-outer split)
- CLAUDE.md Rule #35b (live canaries verify value flow, not just call shape)
- δ Pattern #1 (`.planning/knowledge/windows-coverage-godmode-delta-2026-05-09-patterns.md`) — Rule-of-Three confirmed for skip-tier canary discipline
- δ Pattern #2 (same file) — inner-vs-outer runner split for live canary testing
- δ.9 implementation: `backend/tests/test_dotnet_update_diff_real_firmware.py` (commit `1f09179`)
- γ.9 implementation: `backend/tests/test_registry_driver_real_firmware.py` (commit `8437ae3`)
- β.14a implementation: `backend/tests/test_authenticode_real_firmware.py` (commit `77b257d`)
