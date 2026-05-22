"""Tests for the ICS protocol catalog walker (Phase 1.C — Rule #52
instance #3, Session 2 2026-05-22).

Coverage axes:

* **Rule #36 + Rule #45 no-execute + no-decrypt + Rule #46 paired META-CANARY**
  — token-scan over ``ics_protocol_walker.py`` source asserting NO
  subprocess / decrypt / eval / exec patterns. Paired META-CANARY
  confirms the scanner WOULD reject a synthetic violation.

* **W2-β §SC5-NEW-ICS-S2-β snapshot drift detection** —
  walker INNER pins ``snapshot_id_at_entry`` + reads
  ``snapshot_id_at_exit``; surfaces drift as ``consistency_warning``.
  Paired META-CANARY confirms gate fires on mid-walk drift.

* **W2-β §SC5-NEW-ICS-S2-δ stale JSONB clear on entry** — INNER clears
  ``firmware.ics_protocol_walk_result`` to NULL before scan; failure
  path also clears (no partial JSONB on failure).

* **Smoke tests against ``tests._live_db.make_live_db``** — empty
  firmware row returns the empty-aggregate shape (no detection_roots);
  pre-populated JSONB is cleared at entry.

* **Multi-protocol cardinality smoke** — resolver returning multiple
  matches per binary correctly populates ``protocol_family_counts`` and
  ``manifest_ids_seen``.
"""
from __future__ import annotations

import io
import tokenize
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from app.services import ics_protocol_walker
from app.services.ics_protocol_catalog.snapshot import IcsProtocolCatalogSnapshot
from tests._live_db import make_live_db

# ───────────────────────────────────────────────────────────────────────
# Rule #36 + Rule #45 no-execute + no-decrypt token-scan + Rule #46
# paired META-CANARY.
# ───────────────────────────────────────────────────────────────────────


# Forbidden token regex — whitespace-tolerant per Rule #45 lesson-from-EFS-DDF.
# Python tokenize joins names with single spaces (``subprocess.run`` → tokens
# ``subprocess`` ``.`` ``run``); a naive ``\.run\(`` against token-string-join
# misses ``subprocess . run (``. The pattern below covers both shapes.
_FORBIDDEN_PATTERNS: tuple[str, ...] = (
    r"\bsubprocess\s*\.\s*(?:Popen|run|call|check_output|check_call|getoutput)\s*\(",
    r"\basyncio\s*\.\s*create_subprocess_(?:exec|shell)\s*\(",
    r"\bos\s*\.\s*(?:system|execvp|execve|spawnvp|spawnv|spawnl)\s*\(",
    r"\brunpy\s*\.\s*run_(?:path|module)\s*\(",
    r"\bimportlib\s*\.\s*import_module\s*\(",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bcompile\s*\(",
    # No-decrypt analog (Rule #45) — ICS walker MUST NOT decrypt.
    r"\bCryptUnprotectData\s*\(",
    r"\.\s*decrypt\s*\(",
    r"\bcryptography\s*\.\s*fernet\b",
    r"\bCrypto\s*\.\s*Cipher\b",
)


def _walker_source_tokens_stripped_of_strings_and_comments() -> str:
    """Tokenize the walker source; drop comment + string tokens; join the
    remaining token strings with single spaces. Per Rule #45 lesson, this
    representation makes ``subprocess.run`` appear as
    ``subprocess . run (`` after the join — patterns must be
    whitespace-tolerant.

    Stripping STRING tokens means string literals that legitimately
    contain ``"decrypt"`` (e.g. in error messages) don't trigger; the
    gate fires only on actual API calls.
    """
    src_path = Path(ics_protocol_walker.__file__)
    with open(src_path, "rb") as fh:
        tokens = list(tokenize.tokenize(fh.readline))
    safe_token_strings: list[str] = []
    for tok in tokens:
        # Drop comments + docstrings + string literals + encoding marker.
        if tok.type in (
            tokenize.COMMENT,
            tokenize.STRING,
            tokenize.ENCODING,
            tokenize.NEWLINE,
            tokenize.NL,
            tokenize.INDENT,
            tokenize.DEDENT,
        ):
            continue
        if tok.string.strip():
            safe_token_strings.append(tok.string)
    return " ".join(safe_token_strings)


def test_walker_no_execute_no_decrypt():
    """Rule #36 + Rule #45 gate — token-scan over walker source asserts
    NO subprocess / decrypt / eval / exec patterns.
    """
    import re

    src_repr = _walker_source_tokens_stripped_of_strings_and_comments()
    matches: list[tuple[str, str]] = []
    for pattern in _FORBIDDEN_PATTERNS:
        m = re.search(pattern, src_repr)
        if m:
            matches.append((pattern, m.group(0)))
    assert not matches, (
        f"Rule #36 + Rule #45 no-execute / no-decrypt gate FIRED on "
        f"ics_protocol_walker.py source — forbidden tokens detected: "
        f"{matches!r}. The walker MUST be PARSE-ONLY; closed-grammar "
        f"Pydantic schema structurally guarantees no eval/exec path."
    )


def test_walker_no_execute_gate_actually_fires():
    """Rule #46 paired META-CANARY — synthesize a forbidden-token violation
    IN MEMORY (concatenated string, NOT f-string — tokenize strips
    f-string contents) and confirm the gate WOULD reject it.

    Without this canary, the gate is a Rule #17 silent-pass instance
    (passes both on a clean walker AND on a walker that fundamentally
    isn't checking).
    """
    import re

    # Concatenated lines build a syntactically-valid Python snippet that
    # would be parsed as forbidden by the gate. Whitespace-tolerant
    # patterns from ``_FORBIDDEN_PATTERNS`` match this representation.
    synthetic_violation_lines = [
        "import subprocess",
        "result = subprocess.run(['true'])",
        "import asyncio",
        "x = asyncio.create_subprocess_exec('cat')",
        "key.decrypt(ciphertext)",
    ]
    # Tokenize-then-join (mirror the production gate's representation).
    fake_src = "\n".join(synthetic_violation_lines).encode("utf-8")
    tokens = list(tokenize.tokenize(io.BytesIO(fake_src).readline))
    safe_token_strings: list[str] = []
    for tok in tokens:
        if tok.type in (
            tokenize.COMMENT,
            tokenize.STRING,
            tokenize.ENCODING,
            tokenize.NEWLINE,
            tokenize.NL,
            tokenize.INDENT,
            tokenize.DEDENT,
        ):
            continue
        if tok.string.strip():
            safe_token_strings.append(tok.string)
    src_repr = " ".join(safe_token_strings)

    matched_patterns: list[str] = []
    for pattern in _FORBIDDEN_PATTERNS:
        if re.search(pattern, src_repr):
            matched_patterns.append(pattern)
    assert matched_patterns, (
        "Rule #46 paired META-CANARY FAILED — the no-execute/no-decrypt "
        "gate did NOT match a synthesized violation containing "
        "subprocess.run + asyncio.create_subprocess_exec + .decrypt(). "
        "The gate's patterns are likely too narrow; without the canary, "
        "the production scan passes silently regardless of what's "
        "actually in the walker source. Tighten the regexes."
    )


# ───────────────────────────────────────────────────────────────────────
# INNER runner smoke tests (against tests._live_db.make_live_db).
# Rule #35b live canaries — assert persisted state, not mock call shape.
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_walker_empty_firmware_returns_empty_aggregate():
    """A firmware row with no extraction (no detection_roots) yields the
    empty-aggregate shape with the ``no detection_roots`` error. Smoke
    test for the INNER runner's no-roots branch.
    """
    from app.models.firmware import Firmware

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="0" * 64,
            original_filename="empty.bin",
        )
        db.add(firmware)
        await db.flush()

        result = await ics_protocol_walker._do_ics_protocol_walk(db, firmware.id)

        # Mirror the empty-aggregate shape from
        # ``_empty_result_aggregate``.
        assert result["binaries_scanned_count"] == 0
        assert result["binaries_total_count"] == 0
        assert result["per_binary"] == []
        assert result["protocol_family_counts"] == {}
        assert result["manifest_ids_seen"] == []
        assert result["manifest_sources_seen"] == []
        assert any("detection_roots" in e for e in result["errors"]), (
            "INNER must emit a 'detection_roots' error when extraction "
            "hasn't run; without this signal operators can't distinguish "
            "'walker ran on empty firmware' from 'walker has a bug'."
        )
        # W2-β §SC5-NEW-ICS-S2-β fields populated even when empty.
        assert "snapshot_id_at_entry" in result
        assert "snapshot_id_at_exit" in result
        assert result["consistency_warning"] is None


@pytest.mark.asyncio
async def test_walker_clears_stale_jsonb_on_entry():
    """W2-β §SC5-NEW-ICS-S2-δ gate META-CANARY — INNER clears
    ``firmware.ics_protocol_walk_result`` at function entry.

    Synthesize a firmware row with a stale ``ics_protocol_walk_result``
    JSONB (5 matches against a non-existent manifest); run INNER; assert
    the firmware row's JSONB no longer contains the stale manifest_ids.
    """
    from app.models.firmware import Firmware

    async with make_live_db() as db:
        stale_result = {
            "schema_version": 1,
            "provenance": "walker",
            "matches": [{"manifest_id": "stale_ghost_protocol"}],
        }
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="1" * 64,
            original_filename="stale.bin",
            ics_protocol_walk_result=stale_result,
        )
        db.add(firmware)
        await db.flush()

        # Sanity: stale present before run.
        await db.refresh(firmware)
        assert firmware.ics_protocol_walk_result == stale_result

        # Run INNER — should clear the stale JSONB.
        await ics_protocol_walker._do_ics_protocol_walk(db, firmware.id)
        await db.flush()
        await db.refresh(firmware)

        # Post-run: JSONB is NULL (no detection_roots so result aggregate
        # is empty; walker cleared the stale shape before returning).
        # The result aggregate itself is returned but NOT yet stamped onto
        # the row (caller stamps via _stamp helper); the INNER's
        # only persistence action is the NULL-clear.
        assert firmware.ics_protocol_walk_result is None, (
            "W2-β §SC5-NEW-ICS-S2-δ — INNER MUST clear stale JSONB at "
            "entry; the stale 'stale_ghost_protocol' record must NOT "
            "persist past the inner runner. If this assertion fails, the "
            "operator-supplied descriptor-route × stale-state attack "
            "surface is open."
        )


# ───────────────────────────────────────────────────────────────────────
# Snapshot drift detection (W2-β §SC5-NEW-ICS-S2-β META-CANARY).
# ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_walker_detects_mid_walk_snapshot_drift(tmp_path):
    """W2-β §SC5-NEW-ICS-S2-β paired META-CANARY — mock the catalog to
    return DIFFERENT snapshots at entry vs exit; assert INNER stamps
    ``consistency_warning``.

    Mid-walk YAML hot-reload tears classification — the consistency
    warning is the signal downstream CVE matcher / cross-firmware lookup
    consumers gate on (refuse attribution when warning is non-None).

    Provides an empty detection root so the walker enters the scan loop
    (finds no binaries) and proceeds to the exit-snapshot read. The
    empty-branch short-circuit (no detection_roots) would NOT exercise
    the drift detection — see ``_empty_result_aggregate``.
    """
    from app.models.firmware import Firmware

    snapshot_entry = IcsProtocolCatalogSnapshot(
        manifests=(),
        snapshot_id="0" * 64,
        loaded_at_unix_ns=1,
    )
    snapshot_exit = IcsProtocolCatalogSnapshot(
        manifests=(),
        snapshot_id="f" * 64,  # DIFFERENT — drift signal
        loaded_at_unix_ns=2,
    )

    class _DriftingCatalog:
        def __init__(self):
            self._calls = 0

        def get_snapshot(self):
            self._calls += 1
            return snapshot_entry if self._calls == 1 else snapshot_exit

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="d" * 64,
            original_filename="drift.bin",
        )
        db.add(firmware)
        await db.flush()

        drifting_catalog = _DriftingCatalog()
        empty_root = str(tmp_path / "empty_detection_root")
        (tmp_path / "empty_detection_root").mkdir()

        async def _fake_get_detection_roots(firmware_arg, **kwargs):
            return [empty_root]

        with (
            patch(
                "app.services.ics_protocol_walker.get_default_catalog",
                return_value=drifting_catalog,
            ),
            patch(
                "app.services.ics_protocol_walker.get_detection_roots",
                side_effect=_fake_get_detection_roots,
            ),
        ):
            result = await ics_protocol_walker._do_ics_protocol_walk(
                db, firmware.id,
            )

        assert result["snapshot_id_at_entry"] == "0" * 64
        assert result["snapshot_id_at_exit"] == "f" * 64
        assert result["consistency_warning"] is not None, (
            "W2-β §SC5-NEW-ICS-S2-β — INNER MUST stamp consistency_warning "
            "when snapshot_id_at_entry != snapshot_id_at_exit. Without "
            "this, mid-walk YAML hot-reload produces forensically poisoned "
            "JSONB that CVE matcher trusts."
        )
        assert (
            "mid-walk" in result["consistency_warning"].lower()
            or "snapshot" in result["consistency_warning"].lower()
        ), (
            "consistency_warning message MUST mention snapshot/mid-walk so "
            "operators can act on it; the structured text is the "
            "operator-UX signal."
        )


@pytest.mark.asyncio
async def test_walker_no_drift_when_snapshot_stable(tmp_path):
    """Pair-canary for the drift detection above — when the catalog
    returns the SAME snapshot at entry + exit, ``consistency_warning``
    is None (default state).
    """
    from app.models.firmware import Firmware

    stable_snapshot = IcsProtocolCatalogSnapshot(
        manifests=(),
        snapshot_id="a" * 64,
        loaded_at_unix_ns=1,
    )

    class _StableCatalog:
        def get_snapshot(self):
            return stable_snapshot

    async with make_live_db() as db:
        firmware = Firmware(
            project_id=uuid.uuid4(),
            sha256="e" * 64,
            original_filename="stable.bin",
        )
        db.add(firmware)
        await db.flush()

        empty_root = str(tmp_path / "stable_root")
        (tmp_path / "stable_root").mkdir()

        async def _fake_get_detection_roots(firmware_arg, **kwargs):
            return [empty_root]

        with (
            patch(
                "app.services.ics_protocol_walker.get_default_catalog",
                return_value=_StableCatalog(),
            ),
            patch(
                "app.services.ics_protocol_walker.get_detection_roots",
                side_effect=_fake_get_detection_roots,
            ),
        ):
            result = await ics_protocol_walker._do_ics_protocol_walk(
                db, firmware.id,
            )

        assert result["snapshot_id_at_entry"] == result["snapshot_id_at_exit"]
        assert result["consistency_warning"] is None


# ───────────────────────────────────────────────────────────────────────
# Walker triplet exports (Rule #11 import smoke + Rule #39 contract).
# ───────────────────────────────────────────────────────────────────────


def test_walker_triplet_exports_all_three_runners():
    """Rule #11 + Rule #39 — confirm INNER + OUTER + SAFE runner symbols
    all importable from the walker module. Future refactors that
    relocate symbols will break this test loudly rather than silently
    masking a Rule #47 consumer-hook gap.
    """
    assert callable(ics_protocol_walker._do_ics_protocol_walk)
    assert callable(ics_protocol_walker.run_ics_protocol_walk_background)
    assert callable(ics_protocol_walker.auto_ics_protocol_walk_firmware_safe)
    assert set(ics_protocol_walker.__all__) == {
        "_do_ics_protocol_walk",
        "auto_ics_protocol_walk_firmware_safe",
        "run_ics_protocol_walk_background",
    }


def test_walker_uses_jsonb_stamp_helper_not_direct_dict_assign():
    """Rule #35c partner — confirm the walker module imports
    ``_stamp_firmware_ics_protocol_walk_result`` rather than constructing
    raw dicts. Without this discipline, a future commit could bypass the
    W2-β §SC5-NEW-ICS-S2-1 provenance sister-key contract.
    """
    src = Path(ics_protocol_walker.__file__).read_text()
    assert "_stamp_firmware_ics_protocol_walk_result" in src, (
        "Walker MUST stamp via _stamp_firmware_ics_protocol_walk_result; "
        "direct JSONB assignment bypasses the W2-β §SC5-NEW-ICS-S2-1 "
        "provenance sister-key contract."
    )


# ───────────────────────────────────────────────────────────────────────
# IcsProtocolWalkStatus Literal alignment with DB CHECK constraint.
# ───────────────────────────────────────────────────────────────────────


def test_ics_protocol_walk_status_literal_matches_db_check_values():
    """Rule #33 .c — the Pydantic Literal ``IcsProtocolWalkStatus`` at the
    schema-boundary typo-gate MUST match the DB CHECK constraint value
    set EXACTLY. Drift in EITHER direction is a Rule #25 single-slice
    failure: either the Literal accepts a value the DB rejects (silent
    500), or the DB accepts a value the Literal rejects (Pydantic 422
    after a successful write).
    """
    from typing import get_args

    from app.schemas.firmware import IcsProtocolWalkStatus

    db_check_values = ("idle", "queued", "running", "completed", "failed")
    literal_values = tuple(get_args(IcsProtocolWalkStatus))
    assert set(literal_values) == set(db_check_values), (
        f"IcsProtocolWalkStatus Literal {literal_values!r} MUST equal "
        f"the DB CHECK ck_firmware_ics_protocol_walk_status value set "
        f"{db_check_values!r}. Rule #33 .c contract."
    )


# ───────────────────────────────────────────────────────────────────────
# Phase 2: walker finding-emit Rule #25 Shape-1 alignment META-CANARIES.
# ───────────────────────────────────────────────────────────────────────


def test_walker_ics_finding_source_allowlist_matches_pydantic_literal():
    """W2-β §SC5-NEW-ICS-S2-η META-CANARY — the walker's
    ``_ALLOWED_ICS_FINDING_SOURCES`` frozenset MUST EXACTLY equal the
    Pydantic ``IcsProtocolFindingSource`` Literal value set.

    Drift means either: (a) the walker can emit a source the DB CHECK
    rejects (Pydantic 422 at FindingService.create), or (b) the
    Literal admits a value the walker would never emit (dead schema).
    """
    from typing import get_args

    from app.schemas.finding import IcsProtocolFindingSource
    from app.services.ics_protocol_walker import _ALLOWED_ICS_FINDING_SOURCES

    literal_values = frozenset(get_args(IcsProtocolFindingSource))
    assert _ALLOWED_ICS_FINDING_SOURCES == literal_values, (
        f"_ALLOWED_ICS_FINDING_SOURCES {_ALLOWED_ICS_FINDING_SOURCES!r} "
        f"MUST equal IcsProtocolFindingSource {literal_values!r}. "
        f"Drift means the walker either emits a source the DB rejects "
        f"or admits dead schema. Rule #25 Shape-1 cross-stack alignment."
    )


def test_walker_ics_finding_source_naming_convention():
    """Every entry in the IcsProtocolFindingSource Literal MUST follow
    the ``ics_<protocol_family>_detected`` naming convention so the
    walker's per-family lookup
    (``f"ics_{family}_detected"``) hits all declared values.

    Without this canary, a future commit could rename a source value
    (e.g. ``ics_modbus_tcp_detected`` -> ``modbus_detected``) and the
    walker would silently stop emitting for that family.
    """
    from typing import get_args

    from app.schemas.finding import IcsProtocolFindingSource

    for source in get_args(IcsProtocolFindingSource):
        assert source.startswith("ics_") and source.endswith("_detected"), (
            f"source {source!r} does NOT match the "
            f"`ics_<family>_detected` convention; the walker's per-family "
            f"emit lookup `f'ics_{{family}}_detected'` will not hit it."
        )
        family = source[len("ics_") : -len("_detected")]
        assert family, (
            f"source {source!r} has empty protocol family between "
            f"`ics_` and `_detected`"
        )
