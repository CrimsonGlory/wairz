"""Phase β.8 contract tests: authenticode-chain background runner.

Tests three layers:

1. **Unit tests** for the pure helpers (:func:`_is_pe_file`,
   :func:`_verdict_to_signature_kwargs`, :data:`DIRECT_MAPPED`).
2. **Live canary** (Rule #35b) for :func:`verify_firmware_pe_chain` —
   real ORM round-trip via ``tests._live_db.make_live_db``: seed
   Project + Firmware + N HardwareFirmwareBlob fixtures (mixed PE +
   non-PE), patch ``verify_pe_file`` to return controlled verdicts,
   run the iteration, SELECT the persisted ``WindowsPESignature`` rows,
   inspect every field the runner explicitly sets. Mocks alone would
   verify call-shape only; the live canary verifies value-flow
   (CLAUDE.md Rule #35b).
3. **Outer-runner status-transition tests** for
   :func:`run_authenticode_chain_background` with
   ``async_session_factory`` patched to point at the live SQLite
   session. Asserts queued → running → completed/failed transitions
   per Rule #33.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from app.models import (
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsPESignature,
)
from app.services.authenticode_chain_runner import (
    DIRECT_MAPPED,
    _is_pe_file,
    _verdict_to_signature_kwargs,
    run_authenticode_chain_background,
    verify_firmware_pe_chain,
)
from app.services.authenticode_service import AuthenticodeVerdict
from tests._live_db import make_live_db


# ── _is_pe_file unit tests ────────────────────────────────────────────────────


def test_is_pe_file_true_on_mz_magic(tmp_path: Path):
    f = tmp_path / "real.exe"
    f.write_bytes(b"MZ" + b"\x00" * 100)
    assert _is_pe_file(str(f)) is True


def test_is_pe_file_false_on_non_mz_magic(tmp_path: Path):
    f = tmp_path / "elf.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert _is_pe_file(str(f)) is False


def test_is_pe_file_false_on_short_file(tmp_path: Path):
    """A file shorter than 2 bytes can't have MZ magic; pre-filter
    safely reports False rather than raising."""
    f = tmp_path / "tiny"
    f.write_bytes(b"M")  # one byte
    assert _is_pe_file(str(f)) is False


def test_is_pe_file_false_on_missing_path(tmp_path: Path):
    """The runner walks blob.blob_path; some legacy rows may have
    paths that no longer exist on disk. Pre-filter must not raise."""
    assert _is_pe_file(str(tmp_path / "does-not-exist")) is False


def test_is_pe_file_false_on_directory(tmp_path: Path):
    """A directory is not a regular file — pre-filter must not raise on
    one (and must not try to read 2 bytes from it)."""
    d = tmp_path / "subdir"
    d.mkdir()
    assert _is_pe_file(str(d)) is False


# ── _verdict_to_signature_kwargs + DIRECT_MAPPED ──────────────────────────────


def test_verdict_to_signature_kwargs_drops_indirect_fields():
    """The verdict-spread helper must drop fields not in DIRECT_MAPPED
    (signatures_count, error) so the WindowsPESignature constructor
    doesn't get unknown-keyword TypeErrors."""
    verdict = AuthenticodeVerdict(
        signed=True,
        chain_status="valid_now",
        signatures_count=2,
        error="not actually an error",
    )

    kwargs = _verdict_to_signature_kwargs(verdict)

    # signatures_count + error are intentionally NOT spread.
    assert "signatures_count" not in kwargs
    assert "error" not in kwargs
    # All DIRECT_MAPPED fields appear (with their default values).
    assert set(kwargs.keys()) == DIRECT_MAPPED
    assert kwargs["signed"] is True
    assert kwargs["chain_status"] == "valid_now"


def test_direct_mapped_is_frozen():
    """DIRECT_MAPPED is the single source of truth shared with the
    drift-detector test — it MUST be immutable so a stray .add() in
    one consumer doesn't silently change the contract elsewhere."""
    assert isinstance(DIRECT_MAPPED, frozenset)
    # Mutation attempts raise AttributeError on frozenset.
    with pytest.raises(AttributeError):
        DIRECT_MAPPED.add("malicious_field")  # type: ignore[attr-defined]


# ── live-canary fixture helpers ───────────────────────────────────────────────


async def _seed_firmware(db) -> Firmware:
    """Seed a Project + Firmware fixture chain.

    The Firmware row defaults to authenticode_chain_status='idle' per
    the column server_default; the runner flips it through the state
    machine.
    """
    project = Project(
        name="auth-chain-test",
        description="Phase β.8 runner test fixture",
    )
    db.add(project)
    await db.flush()

    fw = Firmware(
        project_id=project.id,
        original_filename="windows.cab",
        file_size=4096,
        sha256="d" * 64,
    )
    db.add(fw)
    await db.flush()
    return fw


async def _add_blob(
    db,
    fw: Firmware,
    blob_path: str,
    blob_sha256: str,
    *,
    fmt: str = "raw_bin",
) -> HardwareFirmwareBlob:
    """Append a HardwareFirmwareBlob row pointing at a real on-disk path."""
    blob = HardwareFirmwareBlob(
        firmware_id=fw.id,
        blob_path=blob_path,
        blob_sha256=blob_sha256,
        file_size=Path(blob_path).stat().st_size if Path(blob_path).exists() else 0,
        category="other",
        format=fmt,
        detection_source="test",
    )
    db.add(blob)
    await db.flush()
    return blob


# ── verify_firmware_pe_chain — Rule #35b live canary ──────────────────────────


@pytest.mark.asyncio
async def test_verify_firmware_pe_chain_persists_one_row_per_pe(tmp_path: Path):
    """Mixed firmware: 2 PE blobs + 1 non-PE blob. Runner must produce
    exactly 2 WindowsPESignature rows (one per PE), not 3.

    Rule #35b live canary: the assertion isn't ``mock_db.add.call_count
    == 2`` — it's a SELECT against the persisted rows, exercising the
    full ORM round-trip including JSONB column round-trips.
    """
    pe_signed = tmp_path / "trusted.exe"
    pe_signed.write_bytes(b"MZ" + b"\x00" * 200)
    pe_unsigned = tmp_path / "vendor.dll"
    pe_unsigned.write_bytes(b"MZ" + b"\x00" * 200)
    notpe = tmp_path / "kernel.elf"
    notpe.write_bytes(b"\x7fELF" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe_signed), "1" * 64)
        await _add_blob(db, fw, str(pe_unsigned), "2" * 64)
        await _add_blob(db, fw, str(notpe), "3" * 64, fmt="elf")
        await db.commit()

        # Patch verify_pe_file at the runner module's import boundary.
        # Branch on the basename suffix so the ``trusted.exe`` /
        # ``vendor.dll`` choice cleanly separates the two verdicts —
        # naive substring matches on ``"signed"`` would catch both
        # ``trusted.exe`` AND ``unsigned.dll`` because the latter
        # contains ``signed`` literally.
        def fake_verify(path: str) -> AuthenticodeVerdict:
            if path.endswith("trusted.exe"):
                return AuthenticodeVerdict(
                    signed=True,
                    chain_status="valid_now",
                    signer_subject="CN=Microsoft",
                    leaf_serial="DEADBEEF",
                    sig_hash_algo="sha256",
                    signed_at=datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC),
                    chain_json={"verification_result": "OK"},
                    arch_view={"primary": "amd64"},
                    rich_header_json={"hash_md5": "abc"},
                )
            return AuthenticodeVerdict(
                signed=False,
                chain_status="unknown",
                arch_view=None,
                rich_header_json=None,
            )

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            side_effect=fake_verify,
        ):
            aggregate = await verify_firmware_pe_chain(fw.id, db)

        await db.commit()

        # SELECT-back: exactly 2 signature rows persisted.
        rows = (
            await db.execute(
                select(WindowsPESignature)
                .join(
                    HardwareFirmwareBlob,
                    HardwareFirmwareBlob.id == WindowsPESignature.blob_id,
                )
                .where(HardwareFirmwareBlob.firmware_id == fw.id)
            )
        ).scalars().all()
        assert len(rows) == 2

        # The signed PE produced a row with signed=True, the unsigned
        # PE produced a row with signed=False. The non-PE produced no
        # row at all.
        signed_rows = [r for r in rows if r.signed is True]
        unsigned_rows = [r for r in rows if r.signed is False]
        assert len(signed_rows) == 1
        assert len(unsigned_rows) == 1
        assert signed_rows[0].leaf_serial == "DEADBEEF"
        assert signed_rows[0].signer_subject == "CN=Microsoft"
        assert signed_rows[0].sig_hash_algo == "sha256"
        assert signed_rows[0].chain_status == "valid_now"
        assert signed_rows[0].chain_json == {"verification_result": "OK"}
        assert signed_rows[0].arch_view == {"primary": "amd64"}
        assert signed_rows[0].rich_header_json == {"hash_md5": "abc"}

        # Aggregate matches the persisted rows.
        assert aggregate["total_pe_count"] == 2
        assert aggregate["signed_count"] == 1
        assert aggregate["unsigned_count"] == 1
        assert aggregate["dbx_revoked_count"] == 0
        assert aggregate["by_chain_status"]["valid_now"] == 1
        assert aggregate["by_chain_status"]["unknown"] == 1
        assert aggregate["signed_pct"] == 0.5
        assert aggregate["errors"] == []
        assert isinstance(aggregate["run_seconds"], float)


@pytest.mark.asyncio
async def test_verify_firmware_pe_chain_per_pe_error_containment(tmp_path: Path):
    """Per design constraint #5: a single PE's verify_pe_file exception
    does NOT abort the run. The bad PE lands in the errors list with
    chain_status='unknown'; the run still completes successfully.
    """
    good = tmp_path / "ok.exe"
    good.write_bytes(b"MZ" + b"\x00" * 200)
    bad = tmp_path / "raises.exe"
    bad.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(good), "a" * 64)
        await _add_blob(db, fw, str(bad), "b" * 64)
        await db.commit()

        def fake_verify(path: str) -> AuthenticodeVerdict:
            if path.endswith("raises.exe"):
                raise RuntimeError("simulated parser explosion")
            return AuthenticodeVerdict(signed=True, chain_status="valid_now")

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            side_effect=fake_verify,
        ):
            aggregate = await verify_firmware_pe_chain(fw.id, db)

        await db.commit()

        # Both PEs counted; the failed one in the unknown bucket.
        assert aggregate["total_pe_count"] == 2
        assert aggregate["by_chain_status"]["valid_now"] == 1
        assert aggregate["by_chain_status"]["unknown"] == 1
        # Error captured per design constraint #5.
        assert len(aggregate["errors"]) == 1
        assert aggregate["errors"][0]["blob_path"].endswith("raises.exe")
        assert "RuntimeError" in aggregate["errors"][0]["error"]
        assert "simulated parser explosion" in aggregate["errors"][0]["error"]


@pytest.mark.asyncio
async def test_verify_firmware_pe_chain_idempotent_on_rerun(tmp_path: Path):
    """Re-run idempotency: a second run DELETEs the prior signature rows
    and re-inserts. We end with exactly N rows, not 2N."""
    pe = tmp_path / "drv.sys"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "c" * 64)
        await db.commit()

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=AuthenticodeVerdict(signed=True, chain_status="valid_now"),
        ):
            await verify_firmware_pe_chain(fw.id, db)
            await db.commit()
            await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        # SELECT-back: exactly one row, not two.
        rows = (
            await db.execute(
                select(WindowsPESignature)
                .join(
                    HardwareFirmwareBlob,
                    HardwareFirmwareBlob.id == WindowsPESignature.blob_id,
                )
                .where(HardwareFirmwareBlob.firmware_id == fw.id)
            )
        ).scalars().all()
        assert len(rows) == 1


@pytest.mark.asyncio
async def test_verify_firmware_pe_chain_dbx_revoked_count(tmp_path: Path):
    """dbx_revoked verdicts increment dbx_revoked_count + persist
    dbx_revoked=True / dbx_revocation_kb on the row."""
    pe = tmp_path / "revoked.dll"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "e" * 64)
        await db.commit()

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=AuthenticodeVerdict(
                signed=True,
                chain_status="revoked",
                dbx_revoked=True,
                dbx_revocation_kb="KB5012170",
            ),
        ):
            aggregate = await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        assert aggregate["dbx_revoked_count"] == 1
        assert aggregate["by_chain_status"]["revoked"] == 1

        row = (
            await db.execute(
                select(WindowsPESignature)
                .join(
                    HardwareFirmwareBlob,
                    HardwareFirmwareBlob.id == WindowsPESignature.blob_id,
                )
                .where(HardwareFirmwareBlob.firmware_id == fw.id)
            )
        ).scalar_one()
        assert row.dbx_revoked is True
        assert row.dbx_revocation_kb == "KB5012170"


@pytest.mark.asyncio
async def test_verify_firmware_pe_chain_empty_firmware(tmp_path: Path):
    """A firmware with zero hardware-firmware blobs returns an
    empty-but-shaped aggregate — no rows; histogram pre-seeded to all
    zeros; signed_pct=0.0 (no division-by-zero)."""
    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await db.commit()

        aggregate = await verify_firmware_pe_chain(fw.id, db)
        await db.commit()

        assert aggregate["total_pe_count"] == 0
        assert aggregate["signed_count"] == 0
        assert aggregate["unsigned_count"] == 0
        assert aggregate["dbx_revoked_count"] == 0
        assert aggregate["signed_pct"] == 0.0
        assert aggregate["by_chain_status"] == {
            "valid_at_signing": 0,
            "valid_now": 0,
            "revoked": 0,
            "never_valid": 0,
            "unknown": 0,
        }
        assert aggregate["errors"] == []


@pytest.mark.asyncio
async def test_verify_firmware_pe_chain_verdict_error_lands_in_errors(
    tmp_path: Path,
):
    """When verify_pe_file returns a verdict with .error set (e.g. PE
    parse failed but didn't raise), the run still completes — the
    error string lands in aggregate.errors for operator visibility."""
    pe = tmp_path / "weird.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "f" * 64)
        await db.commit()

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=AuthenticodeVerdict(
                signed=False,
                chain_status="unknown",
                error="PE parse failed: ParseError: malformed signature blob",
            ),
        ):
            aggregate = await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        assert aggregate["total_pe_count"] == 1
        assert aggregate["unsigned_count"] == 1
        assert len(aggregate["errors"]) == 1
        assert "PE parse failed" in aggregate["errors"][0]["error"]


# ── run_authenticode_chain_background — outer status-transition tests ─────────


def _patch_async_session_factory_to(db):
    """Build an ``async_session_factory()``-compatible context manager
    that yields the given session WITHOUT closing it (the test owns the
    session lifetime).

    The runner uses ``async with async_session_factory() as db:`` —
    we stub the factory call to return our @asynccontextmanager.
    """

    @asynccontextmanager
    async def _factory():
        # The SQLite session is shared across runner invocations within
        # one test; do not close it here so the test can still SELECT
        # post-runner.
        yield db

    return _factory


@pytest.mark.asyncio
async def test_run_authenticode_chain_background_completes(tmp_path: Path):
    """Happy-path status-transition: queued → running → completed.
    The firmware row carries the schema-stamped aggregate after the
    runner returns."""
    pe = tmp_path / "good.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "1" * 64)
        # Pretend the POST handler set status=queued before the runner.
        fw.authenticode_chain_status = "queued"
        await db.commit()

        factory = _patch_async_session_factory_to(db)

        with patch(
            "app.services.authenticode_chain_runner.async_session_factory",
            factory,
        ), patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=AuthenticodeVerdict(signed=True, chain_status="valid_now"),
        ):
            await run_authenticode_chain_background(fw.id)

        # SELECT-back: status is 'completed' with a stamped result.
        await db.refresh(fw)
        assert fw.authenticode_chain_status == "completed"
        assert fw.authenticode_chain_started_at is not None
        assert fw.authenticode_chain_finished_at is not None
        assert fw.authenticode_chain_error is None
        result = fw.authenticode_chain_result
        assert isinstance(result, dict)
        # Rule #35c stamp lands.
        assert result["schema_version"] == 1
        # Aggregate keys present.
        assert result["total_pe_count"] == 1
        assert result["signed_count"] == 1
        assert "by_chain_status" in result


@pytest.mark.asyncio
async def test_run_authenticode_chain_background_records_failure(tmp_path: Path):
    """A session-level exception (verify_firmware_pe_chain raises)
    flips status to 'failed' and records a truncated traceback summary
    on authenticode_chain_error so the UI poller surfaces it.
    """
    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        fw.authenticode_chain_status = "queued"
        await db.commit()

        factory = _patch_async_session_factory_to(db)

        # Patch verify_firmware_pe_chain (the heavy worker) to blow up
        # — this simulates a session-level error path (DB unavailable,
        # OOM, etc.) per design constraint #4.
        async def boom(*args, **kwargs):
            raise RuntimeError("simulated DB outage")

        with patch(
            "app.services.authenticode_chain_runner.async_session_factory",
            factory,
        ), patch(
            "app.services.authenticode_chain_runner.verify_firmware_pe_chain",
            side_effect=boom,
        ):
            await run_authenticode_chain_background(fw.id)

        await db.refresh(fw)
        assert fw.authenticode_chain_status == "failed"
        assert fw.authenticode_chain_finished_at is not None
        assert fw.authenticode_chain_error is not None
        assert "simulated DB outage" in fw.authenticode_chain_error
        # Truncation cap is 2000 chars — anything we wrote stays well
        # under it; just confirm length is sane.
        assert len(fw.authenticode_chain_error) <= 2000


@pytest.mark.asyncio
async def test_run_authenticode_chain_background_missing_firmware_is_noop():
    """If the firmware row vanished between POST and runner pickup, the
    runner logs a warning and returns cleanly without touching the DB."""
    async with make_live_db() as db:
        factory = _patch_async_session_factory_to(db)
        bogus_id = uuid.uuid4()

        # No fixture seed — firmware doesn't exist.
        with patch(
            "app.services.authenticode_chain_runner.async_session_factory",
            factory,
        ):
            await run_authenticode_chain_background(bogus_id)

        # No row was created; no exception escaped.
        rows = (
            await db.execute(select(Firmware).where(Firmware.id == bogus_id))
        ).scalars().all()
        assert rows == []


# ── Phase β.12c — verdict-bearing Finding emission live canaries ─────────────
#
# These tests exercise the runner's atomic emission of WindowsPESignature
# rows AND Finding rows in the same session. The Rule #35b live canary
# discipline for β.12c is "after the runner commits, BOTH row sets must
# be present and consistent — counts, source, severity, file_path,
# firmware_id, project_id all round-trip cleanly".


@pytest.mark.asyncio
async def test_runner_emits_authenticode_finding_for_revoked_chain(
    tmp_path: Path,
):
    """A chain_status=revoked verdict produces ONE windows_authenticode
    Finding row alongside the WindowsPESignature row."""
    pe = tmp_path / "legacy.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "1" * 64)
        await db.commit()

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=AuthenticodeVerdict(
                signed=True,
                chain_status="revoked",
                signer_subject="CN=Old Vendor",
                leaf_serial="abc123",
            ),
        ):
            aggregate = await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        assert aggregate["findings_emitted"] == 1

        from app.models import Finding  # noqa: PLC0415 — late import per Rule #30
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == fw.id)
            )
        ).scalars().all()
        assert len(rows) == 1
        f = rows[0]
        assert f.source == "windows_authenticode"
        assert f.severity == "high"
        assert f.confidence == "high"
        assert f.file_path == str(pe)
        assert f.firmware_id == fw.id
        assert f.project_id == fw.project_id
        assert "leaf_serial=abc123" in f.evidence
        assert "signer_subject=CN=Old Vendor" in f.evidence


@pytest.mark.asyncio
async def test_runner_emits_dbx_finding_for_revoked_pe(tmp_path: Path):
    """A dbx_revoked=True verdict produces ONE windows_dbx_revoked
    Finding row at critical severity, independent of chain_status."""
    pe = tmp_path / "boot.efi"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "2" * 64)
        await db.commit()

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=AuthenticodeVerdict(
                signed=True,
                chain_status="valid_now",
                dbx_revoked=True,
                dbx_revocation_kb="KB5012170",
                leaf_serial="cafef00d",
            ),
        ):
            aggregate = await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        # chain_status=valid_now → no authenticode finding; only the
        # dbx finding fires.
        assert aggregate["findings_emitted"] == 1
        assert aggregate["dbx_revoked_count"] == 1

        from app.models import Finding  # noqa: PLC0415
        f = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == fw.id)
            )
        ).scalar_one()
        assert f.source == "windows_dbx_revoked"
        assert f.severity == "critical"
        assert "leaf_serial=cafef00d" in f.evidence
        assert "dbx_revocation_kb=KB5012170" in f.evidence


@pytest.mark.asyncio
async def test_runner_emits_two_findings_for_chain_and_dbx_revoked(
    tmp_path: Path,
):
    """A PE that's BOTH chain-revoked AND DBX-revoked produces TWO
    Finding rows — different sources, different severities. Confirms the
    helper's per-draft create() loop emits both atomically with the
    single WindowsPESignature row."""
    pe = tmp_path / "doublebad.dll"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "3" * 64)
        await db.commit()

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=AuthenticodeVerdict(
                signed=True,
                chain_status="revoked",
                dbx_revoked=True,
                dbx_revocation_kb="KB5025885",
                leaf_serial="deadbeef",
                signer_subject="CN=Compromised Cert",
            ),
        ):
            aggregate = await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        assert aggregate["findings_emitted"] == 2

        from app.models import Finding  # noqa: PLC0415
        rows = (
            await db.execute(
                select(Finding)
                .where(Finding.firmware_id == fw.id)
                .order_by(Finding.source)
            )
        ).scalars().all()
        assert len(rows) == 2
        sources = {r.source for r in rows}
        assert sources == {"windows_authenticode", "windows_dbx_revoked"}

        # Both rows reference the SAME blob path and firmware (atomic
        # emission guarantee — no partial-row state).
        assert all(r.file_path == str(pe) for r in rows)
        assert all(r.firmware_id == fw.id for r in rows)
        assert all(r.project_id == fw.project_id for r in rows)


@pytest.mark.asyncio
async def test_runner_emits_zero_findings_for_clean_pes(tmp_path: Path):
    """Clean PE (signed + valid_now + not dbx-revoked) produces NO
    Finding rows. Asserts the runner doesn't accidentally emit a finding
    for the good case — the good-case verdicts surface only via the
    aggregate's signed_count / by_chain_status histogram."""
    pe = tmp_path / "trusted.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "4" * 64)
        await db.commit()

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=AuthenticodeVerdict(
                signed=True,
                chain_status="valid_now",
                dbx_revoked=False,
            ),
        ):
            aggregate = await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        assert aggregate["findings_emitted"] == 0

        from app.models import Finding  # noqa: PLC0415
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == fw.id)
            )
        ).scalars().all()
        assert rows == []


@pytest.mark.asyncio
async def test_runner_findings_idempotent_on_rerun(tmp_path: Path):
    """Re-run idempotency for Finding rows: a second run DELETEs prior
    windows_* findings for the firmware and re-emits. End state: exactly
    N Finding rows (one per emission), not 2N. Mirrors the existing
    WindowsPESignature re-run idempotency contract."""
    pe = tmp_path / "stale.dll"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "5" * 64)
        await db.commit()

        verdict = AuthenticodeVerdict(
            signed=True,
            chain_status="never_valid",
            dbx_revoked=True,
            dbx_revocation_kb="KB5025885",
        )
        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=verdict,
        ):
            await verify_firmware_pe_chain(fw.id, db)
            await db.commit()
            await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        from app.models import Finding  # noqa: PLC0415
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == fw.id)
            )
        ).scalars().all()
        # Two runs × 2 emissions per run = 4 emissions. With re-run
        # idempotency, the DELETE-then-emit pair leaves exactly 2 rows
        # (1 windows_authenticode + 1 windows_dbx_revoked) — NOT 4.
        assert len(rows) == 2
        sources = {r.source for r in rows}
        assert sources == {"windows_authenticode", "windows_dbx_revoked"}


@pytest.mark.asyncio
async def test_runner_does_not_delete_unrelated_findings_on_rerun(
    tmp_path: Path,
):
    """Re-run idempotency is SCOPED to (firmware_id, source IN
    windows_*). Findings for the same firmware emitted by OTHER sources
    (manual, security_audit, sbom_scan, etc.) MUST NOT be deleted on
    runner re-run. Without this scoping, an operator's manually-tagged
    Finding would silently disappear when the authenticode chain runs."""
    pe = tmp_path / "fw.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "6" * 64)
        await db.commit()

        # Pre-seed a manual finding on the same firmware.
        from app.models import Finding  # noqa: PLC0415
        manual = Finding(
            project_id=fw.project_id,
            firmware_id=fw.id,
            title="Operator-tagged risk",
            severity="medium",
            source="manual",
        )
        db.add(manual)
        await db.commit()

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=AuthenticodeVerdict(
                signed=True,
                chain_status="never_valid",
                dbx_revoked=False,
            ),
        ):
            await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        # Manual finding survives; new windows_authenticode finding lands.
        rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == fw.id)
            )
        ).scalars().all()
        sources = {r.source for r in rows}
        assert "manual" in sources
        assert "windows_authenticode" in sources
        # Sanity: manual row is the SAME row (id stable).
        manual_after = (
            await db.execute(
                select(Finding).where(Finding.title == "Operator-tagged risk")
            )
        ).scalar_one()
        assert manual_after.id == manual.id


@pytest.mark.asyncio
async def test_runner_emits_findings_atomically_with_signatures(tmp_path: Path):
    """Live canary: after one runner cycle + commit, Finding rows AND
    WindowsPESignature rows are BOTH present in the DB. Asserts the
    atomic-emission contract — a partial-failure mode where sigs
    persist but findings don't (or vice versa) would surface here."""
    pe = tmp_path / "atomic.exe"
    pe.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe), "7" * 64)
        await db.commit()

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            return_value=AuthenticodeVerdict(
                signed=True,
                chain_status="revoked",
            ),
        ):
            await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        from app.models import Finding  # noqa: PLC0415
        sigs = (
            await db.execute(
                select(WindowsPESignature)
                .join(
                    HardwareFirmwareBlob,
                    HardwareFirmwareBlob.id == WindowsPESignature.blob_id,
                )
                .where(HardwareFirmwareBlob.firmware_id == fw.id)
            )
        ).scalars().all()
        findings = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == fw.id)
            )
        ).scalars().all()
        # Both row sets present, both round-tripped to/from disk.
        assert len(sigs) == 1
        assert len(findings) == 1
        assert sigs[0].chain_status == "revoked"
        assert findings[0].source == "windows_authenticode"


@pytest.mark.asyncio
async def test_runner_aggregate_includes_findings_emitted_count(
    tmp_path: Path,
):
    """The aggregate's findings_emitted matches the count of persisted
    Finding rows. Adding the field is purely additive (schema_version=1
    unchanged) — readers should use ``payload.get("findings_emitted", 0)``
    so legacy pre-β.12 rows render as 0."""
    pe1 = tmp_path / "a.exe"
    pe1.write_bytes(b"MZ" + b"\x00" * 200)
    pe2 = tmp_path / "b.dll"
    pe2.write_bytes(b"MZ" + b"\x00" * 200)

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(pe1), "8" * 64)
        await _add_blob(db, fw, str(pe2), "9" * 64)
        await db.commit()

        def fake_verify(path: str) -> AuthenticodeVerdict:
            if path.endswith("a.exe"):
                # 1 finding (high authenticode)
                return AuthenticodeVerdict(
                    signed=True, chain_status="never_valid",
                )
            # 2 findings (high authenticode + critical dbx)
            return AuthenticodeVerdict(
                signed=True, chain_status="revoked", dbx_revoked=True,
                dbx_revocation_kb="KB5025885",
            )

        with patch(
            "app.services.authenticode_chain_runner.verify_pe_file",
            side_effect=fake_verify,
        ):
            aggregate = await verify_firmware_pe_chain(fw.id, db)
            await db.commit()

        assert aggregate["findings_emitted"] == 3

        from app.models import Finding  # noqa: PLC0415
        finding_rows = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == fw.id)
            )
        ).scalars().all()
        assert len(finding_rows) == 3
