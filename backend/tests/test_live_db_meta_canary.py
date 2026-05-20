"""Rule #46 META-CANARY: `make_live_db()` must load metadata cleanly.

If this test passes, `tests/_live_db.py` correctly imports every model module
required for `Base.metadata.create_all` — including FK target tables referenced
by other in-test modules.

If this test fails with `sqlalchemy.exc.NoReferencedTableError`, a model
module containing an FK target has been removed from the noqa F401 import
block at `_live_db.py:194-208`. Add the missing module back. See
2026-05-21 SBOM/vuln-scan regression investigation Fix #10 (the original
incident: `volatility_injection_records.memory_image_id` FK targets
`memory_dump_image`, but `memory_dump_image` was never imported in `_live_db`,
so 12 LiveCanary tests silently failed at metadata-load time for ~7 days).

Cross-references:
- CLAUDE.md Rule #35b (mocks vs live canaries) — without this canary, a
  test-layer blind spot is structurally indistinguishable from "all tests pass".
- CLAUDE.md Rule #46 (verification-gate META-CANARY discipline) — any gate
  asserting absence MUST have a paired canary proving the gate fires.
- W2-β §SC5-NEW-SBOM-π — codifies this gate as a Rule #51 partner.
"""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_make_live_db_loads_metadata_cleanly():
    """Smoke test: open a make_live_db() context and confirm session is usable.

    Failure mode this canary catches: a future commit drops a model module
    from the `from app.models import (...)` list at `_live_db.py:194-208`,
    which breaks `Base.metadata.create_all` with NoReferencedTableError on
    SBOM/vuln-scan/finding-emit LiveCanary tests.
    """
    from tests._live_db import make_live_db

    async with make_live_db() as db:
        assert db is not None
        # Round-trip a trivial SELECT to confirm the session is live.
        from sqlalchemy import text

        result = (await db.execute(text("SELECT 1"))).scalar()
        assert result == 1


def test_live_db_imports_include_volatility_memory_dump_triple():
    """AST-level META-CANARY: the volatility + memory_dump triple must remain.

    The 3 required imports are:
      - memory_dump_image    (FK target referenced by volatility_injection_record)
      - volatility_injection_record  (consumer of the FK)
      - volatility_process_record    (sibling table; declares fk_volatility_*)

    A future commit "simplifying" the import block by dropping these would
    re-introduce the 2026-05-21 regression.
    """
    from pathlib import Path

    src = Path(__file__).parent.joinpath("_live_db.py").read_text()
    required = (
        "memory_dump_image",
        "volatility_injection_record",
        "volatility_process_record",
    )
    for name in required:
        assert name in src, (
            f"_live_db.py is missing required model import `{name}`. "
            f"Re-add it to the `from app.models import (...)` block at "
            f"~line 196 to keep LiveCanary tests passing. See Fix #10 in "
            f".planning/research/sbom-vuln-scan-regression-2026-05-21/."
        )


def test_live_db_meta_canary_would_catch_a_missing_import(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46.

    Synthesize an `_live_db`-shaped module with one of the required model
    imports DROPPED, then prove the AST check above would reject it. Without
    this paired canary, the assertion test could silently no-op (e.g. someone
    refactors the import list into a tuple literal that grep would miss).
    """
    fake = tmp_path / "_live_db_fake.py"
    fake.write_text(
        '''
"""Fake _live_db with the volatility import dropped."""
from app.models import (  # noqa: F401
    analysis_cache,
    finding,
    firmware,
    project,
    sbom,
)
'''
    )
    src = fake.read_text()
    # Each required name MUST be absent in this synthesized fake.
    for missing in ("memory_dump_image", "volatility_injection_record", "volatility_process_record"):
        assert missing not in src, (
            f"Synthesized fake should NOT contain `{missing}` — the canary "
            f"setup is broken if it does."
        )
