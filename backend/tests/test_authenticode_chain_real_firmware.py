"""Phase β.14a — Rule #35b real-firmware end-to-end canary.

Activates the deferred Rule #35b real-firmware canary set identified
in the β.10 / β.11 / β.12 postmortem recommendation chain. Drives
REAL on-disk PE binaries through the FULL ``verify_firmware_pe_chain``
+ ``run_authenticode_chain_background`` pipeline (no patched
``verify_pe_file``) and asserts the cumulative β.4–β.12 surface
integration:

  - β.4 chain runner — real signify call per PE.
  - β.5 arch_view — real :func:`format_detection.detect_pe_arch_view`.
  - β.6 rich_header_json — real :func:`rich_header_service.decode_rich_header`.
  - β.7 DBX probe — real :func:`dbx_service.match_dbx_revocation`.
  - β.10 bundled DBX trust anchor — read from ``DBX_BUNDLE_PATH``.
  - β.12 Findings emission — real :meth:`FindingService.emit_pe_signature_findings`.

Acceptance criteria (β.14a kickoff prompt):

  (a) ``WindowsPESignature`` row count > 0
  (b) ``Finding`` row count for source IN ('windows_authenticode',
      'windows_dbx_revoked') > 0
  (c) chain_status histogram non-empty in the aggregate JSONB
  (d) at least one PE chains cleanly to the Microsoft Authenticode
      roots bundled by signify
  (e) DBX-bundle probe + chain runner cooperate to flip
      ``dbx_revoked=True`` on at least one row when the fixture
      covers a known-revoked serial

Test tiers:

  Tier 1 (always runs given mingw-w64 host PEs)

  - ``test_real_pe_runner_direct_smoke`` — runs
    ``verify_firmware_pe_chain`` against host-available unsigned
    PEs (mingw-w64 DLLs / systemd-bootx64.efi). Asserts (a) + (c)
    and the cumulative β.4-β.12 invocation chain. Verdicts are
    typically ``signed=False, chain_status=unknown`` for
    open-source distributions; that exercises the FULL pipeline
    (signify call, DBX probe, persistence) but does not produce
    any Finding.

  - ``test_http_layer_post_authenticode_chain_round_trip`` —
    POST /authenticode-chain → 202 → await background task →
    GET /authenticode-chain/status → 200 completed. Asserts the
    Rule #33 idempotent-202 + 409-on-conflict + status-snapshot
    contract end-to-end through the actual FastAPI ASGI app.

  Tier 2 (skip-unless-fixture; ``backend/tests/fixtures/windows/ms_signed.dll``)

  - ``test_real_ms_signed_pe_chains_to_microsoft_roots`` — asserts
    (d) and (b) when chain_status==revoked. Provisioning
    instructions in the test docstring.

  Tier 3 (skip-unless-fixture; ``backend/tests/fixtures/windows/dbx_revoked.exe``)

  - ``test_real_dbx_revoked_pe_emits_finding`` — asserts (b) and
    (e). Provisioning instructions in the test docstring.

Tier-1 coverage runs immediately on any host with the mingw-w64
runtime DLLs or systemd-boot's EFI binary present (typical Ubuntu
/ Debian dev hosts after ``apt install gcc-mingw-w64 systemd-boot``).
Tier-2 and Tier-3 graduate from skip → pass without code changes
once the operator commits the fixtures to ``backend/tests/fixtures/windows/``;
each tier has a docstring describing the smallest-viable provisioning
path.
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import select

# Imports trigger SQLAlchemy mapper registration on Base.metadata so
# tests._live_db.make_live_db()'s create_all picks up every table the
# canaries SELECT against.
from app.models import (  # noqa: F401
    Finding,
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsPESignature,
)
from app.services.authenticode_chain_runner import (
    run_authenticode_chain_background,
    verify_firmware_pe_chain,
)
from tests._live_db import make_live_db


_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "windows"

# Real PEs commonly available on Linux dev / CI hosts. Used by the
# tier-1 always-runs canaries. mingw-w64 (``gcc-mingw-w64`` apt
# package) and systemd-bootx64.efi (``systemd-boot`` package) are
# present on most Ubuntu / Debian hosts. Any subset is sufficient —
# the tier-1 tests use whichever ones happen to be present.
_HOST_UNSIGNED_PE_CANDIDATES: tuple[str, ...] = (
    "/usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll",
    "/usr/i686-w64-mingw32/lib/libwinpthread-1.dll",
    "/usr/lib/gcc/x86_64-w64-mingw32/10-win32/libgomp-1.dll",
    "/usr/lib/gcc/x86_64-w64-mingw32/10-posix/libgomp-1.dll",
    "/usr/lib/systemd/boot/efi/systemd-bootx64.efi",
)

# Tier-2 / Tier-3 operator-provisioned fixtures. Each test
# skip-unless-presents and documents the provisioning path; the canary
# graduates from skip → pass without code changes once the fixture is
# committed.
_MS_SIGNED_PE_FIXTURE = _FIXTURES_DIR / "ms_signed.dll"
_DBX_REVOKED_PE_FIXTURE = _FIXTURES_DIR / "dbx_revoked.exe"


def _locate_host_unsigned_pes() -> list[str]:
    """Return all ``_HOST_UNSIGNED_PE_CANDIDATES`` that exist on this host."""
    return [p for p in _HOST_UNSIGNED_PE_CANDIDATES if Path(p).is_file()]


async def _seed_firmware(db) -> Firmware:
    """Seed a Project + Firmware row chain for the canary."""
    project = Project(
        name="real-firmware-canary",
        description="Phase β.14a Rule #35b real-firmware end-to-end canary",
    )
    db.add(project)
    await db.flush()
    fw = Firmware(
        project_id=project.id,
        original_filename="real_pe_corpus",
        file_size=0,
        sha256="d" * 64,
        # The HTTP-layer test goes through ``app.routers.deps.resolve_firmware``
        # which 400s if ``extracted_path`` is null. Set a placeholder; the
        # chain runner reads HardwareFirmwareBlob.blob_path, not this field.
        extracted_path="/tmp/test-fw-extracted",
    )
    db.add(fw)
    await db.flush()
    return fw


async def _add_blob(
    db,
    fw: Firmware,
    blob_path: str,
    blob_sha256: str,
) -> HardwareFirmwareBlob:
    """Append a ``HardwareFirmwareBlob`` pointing at a real on-disk PE.

    Per the runner's contract, ``blob_path`` is an absolute on-disk
    path the PE pre-filter can stat + read 2 magic bytes from.
    """
    blob = HardwareFirmwareBlob(
        firmware_id=fw.id,
        blob_path=blob_path,
        blob_sha256=blob_sha256,
        file_size=Path(blob_path).stat().st_size,
        category="other",
        format="raw_bin",
        detection_source="test",
    )
    db.add(blob)
    await db.flush()
    return blob


# ── Tier 1 — host PE smoke (always runs given mingw-w64) ────────────────────


@pytest.mark.asyncio
async def test_real_pe_runner_direct_smoke():
    """Run ``verify_firmware_pe_chain`` against real on-disk host PEs.

    Acceptance: (a) ``WindowsPESignature`` row count > 0,
    (c) chain_status histogram has ≥1 non-zero bucket.

    Real-firmware coverage: every β.4-β.12 surface fires against real
    bytes — signify, ``format_detection.detect_pe_arch_view``,
    ``rich_header_service.decode_rich_header``, ``dbx_service.match_dbx_revocation``,
    ``finding_service.emit_pe_signature_findings`` — all invoked
    unmocked. Verdict will typically be ``signed=False,
    chain_status=unknown`` for open-source distributions; that
    exercises the FULL pipeline but produces no Finding.
    """
    real_pes = _locate_host_unsigned_pes()
    if not real_pes:
        pytest.skip(
            "β.14a tier-1 smoke needs ≥1 real PE on disk; install "
            "gcc-mingw-w64 (`apt install gcc-mingw-w64 systemd-boot`) "
            "or copy any real PE into backend/tests/fixtures/windows/."
        )

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        for i, pe_path in enumerate(real_pes[:3]):
            await _add_blob(db, fw, pe_path, f"{i}" * 64)
        await db.commit()

        # Real verify_pe_file invocation — no patching.
        aggregate = await verify_firmware_pe_chain(fw.id, db)
        await db.commit()

        # (a) — WindowsPESignature row count > 0
        sig_rows = (
            await db.execute(
                select(WindowsPESignature)
                .join(
                    HardwareFirmwareBlob,
                    HardwareFirmwareBlob.id == WindowsPESignature.blob_id,
                )
                .where(HardwareFirmwareBlob.firmware_id == fw.id)
            )
        ).scalars().all()
        assert len(sig_rows) >= 1, (
            "expected the runner to persist ≥1 WindowsPESignature row "
            f"for {len(real_pes[:3])} real input PEs"
        )
        assert aggregate["total_pe_count"] == len(real_pes[:3])

        # (c) — chain_status histogram non-empty (≥1 non-zero bucket).
        non_zero_buckets = [
            (k, v) for k, v in aggregate["by_chain_status"].items() if v > 0
        ]
        assert len(non_zero_buckets) >= 1, (
            f"expected ≥1 non-zero chain_status bucket; got "
            f"{aggregate['by_chain_status']}"
        )

        # Real-firmware sanity: every persisted row carries a real
        # verdict — the runner never inserts NULL into the chain_status
        # CHECK column, ``signed`` is a real bool, etc.
        for row in sig_rows:
            assert row.chain_status in (
                "valid_at_signing",
                "valid_now",
                "revoked",
                "never_valid",
                "unknown",
            )
            assert isinstance(row.signed, bool)


@pytest.mark.asyncio
async def test_http_layer_post_authenticode_chain_round_trip():
    """Full POST /authenticode-chain → poll → GET status round-trip.

    Drives the FastAPI ASGI app via httpx ``ASGITransport`` against
    a real host PE through the production router. Asserts the Rule #33
    idempotent-202 + 409-on-conflict + completed-status state machine.

    The router fires ``asyncio.create_task(run_authenticode_chain_background(...))``
    which would normally race the test's GET-status call; we capture
    the spawned task via a ``create_task`` shim so the test can
    ``await`` it deterministically before asserting the GET response
    reflects ``status='completed'``.
    """
    real_pes = _locate_host_unsigned_pes()
    if not real_pes:
        pytest.skip(
            "β.14a tier-1 HTTP round-trip needs ≥1 real PE on disk; "
            "see test_real_pe_runner_direct_smoke for fixture instructions."
        )

    from httpx import ASGITransport, AsyncClient  # noqa: PLC0415 — late import

    from app.database import get_db  # noqa: PLC0415
    from app.main import app  # noqa: PLC0415

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, real_pes[0], "1" * 64)
        await db.commit()

        async def _override_get_db():
            yield db

        @asynccontextmanager
        async def _factory():
            yield db

        # The router's ``asyncio.create_task(...)`` would normally race
        # the GET-status request. Capture the spawned coroutine so the
        # test can await it deterministically.
        captured: list[asyncio.Task] = []
        original_create_task = asyncio.create_task

        def _capturing_create_task(coro, *args, **kwargs):
            t = original_create_task(coro, *args, **kwargs)
            captured.append(t)
            return t

        app.dependency_overrides[get_db] = _override_get_db
        try:
            with patch(
                "app.routers.hardware_firmware.asyncio.create_task",
                _capturing_create_task,
            ), patch(
                "app.services.authenticode_chain_runner.async_session_factory",
                _factory,
            ):
                transport = ASGITransport(app=app)
                async with AsyncClient(
                    transport=transport,
                    base_url="http://test",
                ) as client:
                    # The router lives under /hardware-firmware (Phase β
                    # placed authenticode-chain on the hardware-firmware
                    # router); firmware_id is a query parameter resolved
                    # by ``app.routers.deps.resolve_firmware``.
                    base = (
                        f"/api/v1/projects/{fw.project_id}"
                        f"/hardware-firmware/authenticode-chain"
                    )
                    qs = f"?firmware_id={fw.id}"

                    # POST → 202 with status='queued'.
                    resp = await client.post(base + qs)
                    assert resp.status_code == 202, resp.text
                    body = resp.json()
                    assert body["status"] == "queued"

                    # Idempotency contract (Rule #33 .a): a second POST
                    # while status is queued returns 409.
                    resp_dup = await client.post(base + qs)
                    assert resp_dup.status_code == 409
                    assert "queued" in resp_dup.text or "running" in resp_dup.text

                    # Drain the captured background task before polling
                    # /status — production polls every 2s; we want
                    # deterministic completion ordering.
                    assert len(captured) == 1
                    await captured[0]

                    # GET status → 200 with status='completed'.
                    resp = await client.get(base + "/status" + qs)
                    assert resp.status_code == 200
                    body = resp.json()
                    assert body["status"] == "completed", body
                    assert body["error"] is None
                    # (a) + (c) at the API surface — the result aggregate
                    # the operator sees on the frontend's last-known render.
                    result = body["result"]
                    assert result is not None
                    assert result["total_pe_count"] >= 1
                    non_zero_buckets = [
                        v for v in result["by_chain_status"].values() if v > 0
                    ]
                    assert len(non_zero_buckets) >= 1
        finally:
            app.dependency_overrides.clear()


# ── Tier 2 — Microsoft-signed PE (skip-unless-fixture) ──────────────────────


@pytest.mark.asyncio
async def test_real_ms_signed_pe_chains_to_microsoft_roots():
    """Microsoft-signed PE fixture chains to Authenticode roots.

    Acceptance: (d) at least one PE chains cleanly to MS roots,
    plus (b) Finding row count > 0 IF the chain_status is anything
    other than ``valid_at_signing`` / ``valid_now`` (e.g. an
    expired-but-signed PE produces a windows_authenticode finding
    at high severity per β.12c's classify_pe_verdict_findings).

    Provisioning ``backend/tests/fixtures/windows/ms_signed.dll``:

    1. Download a Microsoft cumulative KB MSU (e.g. ``Win11-23H2-Cumulative.msu``)
       OR the Microsoft VC++ Redistributable installer.
    2. ``cabextract`` (or ``msiextract``) the inner archive.
    3. Pick any vendor-signed .dll from the inner extraction —
       VC++ runtime DLLs (``msvcp140.dll``, ``vcruntime140.dll``)
       chain to Microsoft Code Signing PCA which signify trusts via
       ``TRUSTED_CERTIFICATE_STORE``.
    4. Copy to ``backend/tests/fixtures/windows/ms_signed.dll``.

    The fixture file is gitignored by .gitignore policy (Win11 license
    terms); commit only when the operator confirms the source PE is
    redistributable.
    """
    if not _MS_SIGNED_PE_FIXTURE.is_file():
        pytest.skip(
            f"β.14a tier-2 needs {_MS_SIGNED_PE_FIXTURE.name}; "
            "see test docstring for provisioning instructions."
        )

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(_MS_SIGNED_PE_FIXTURE), "1" * 64)
        await db.commit()

        aggregate = await verify_firmware_pe_chain(fw.id, db)
        await db.commit()

        sig_rows = (
            await db.execute(
                select(WindowsPESignature)
                .join(
                    HardwareFirmwareBlob,
                    HardwareFirmwareBlob.id == WindowsPESignature.blob_id,
                )
                .where(HardwareFirmwareBlob.firmware_id == fw.id)
            )
        ).scalars().all()
        # Bonus (a): row persisted.
        assert len(sig_rows) == 1
        sig = sig_rows[0]

        # (d) — MS-signed PE produces signed=True with chain to a trusted
        # MS root. signify populates signer_subject + leaf_serial when
        # the verification finds at least one chain.
        assert sig.signed is True, (
            f"expected MS-signed fixture to be signed=True; got "
            f"signed={sig.signed} signer={sig.signer_subject!r} "
            f"chain_status={sig.chain_status}"
        )
        assert sig.signer_subject is not None
        assert sig.leaf_serial is not None
        # Acceptable chain_status values for a fresh-from-MS fixture:
        #   valid_now: chain valid AND counter-sig still current
        #   valid_at_signing: chain was valid at counter-sig timestamp
        #     but the leaf has since expired (older fixtures)
        #   revoked: cert valid AND counter-sig timestamps it BUT the
        #     issuer chain has since been revoked. Hits (b).
        # never_valid would mean "no chain to a trusted root" — fixture
        # provisioning would be wrong (not actually MS-signed).
        assert sig.chain_status in (
            "valid_at_signing",
            "valid_now",
            "revoked",
        ), (
            "MS-signed fixture should chain to a signify-trusted root; "
            f"got chain_status={sig.chain_status}"
        )

        # (b) — Finding emission rule per β.12b's classify_pe_verdict_findings:
        #   chain_status in (valid_at_signing, valid_now) → no finding
        #   chain_status == revoked → 1 windows_authenticode high finding
        #   chain_status in (never_valid,) → 1 windows_authenticode high
        #   chain_status in (unknown,) AND signed=True → 1 windows_authenticode medium
        windows_findings = (
            await db.execute(
                select(Finding).where(
                    Finding.firmware_id == fw.id,
                    Finding.source.in_(
                        ("windows_authenticode", "windows_dbx_revoked")
                    ),
                )
            )
        ).scalars().all()
        if sig.chain_status in ("revoked", "never_valid"):
            assert len(windows_findings) >= 1
            assert aggregate["findings_emitted"] >= 1
        elif sig.chain_status in ("valid_at_signing", "valid_now"):
            assert len(windows_findings) == 0
            assert aggregate["findings_emitted"] == 0


# ── Tier 3 — DBX-revoked PE (skip-unless-fixture) ───────────────────────────


@pytest.mark.asyncio
async def test_real_dbx_revoked_pe_emits_finding():
    """DBX-revoked PE fixture flips ``dbx_revoked=True`` + emits Finding.

    Acceptance: (b) Finding row for source='windows_dbx_revoked' > 0,
    (e) at least one persisted row has ``dbx_revoked=True``.

    Provisioning ``backend/tests/fixtures/windows/dbx_revoked.exe``:

    1. The bundled β.10 DBX (``/opt/wairz/dbxupdate.bin``, 24,053 bytes
       at the production layer) carries Microsoft-revoked serial
       numbers — see ``backend/ms-anchors/README.md``.
    2. Find a PE whose leaf-cert serial number matches one of those
       entries — sources include
       https://uefi.org/revocationlistfile (the UEFI Forum's revocation
       list shipped to OEM partners) or any known-compromised
       pre-2023 driver / bootloader sample.
    3. Copy to ``backend/tests/fixtures/windows/dbx_revoked.exe``.

    The chain runner's β.7 → β.10 cooperation: signify produces the
    leaf_serial; ``dbx_service.match_dbx_revocation`` looks it up in
    the bundled DBX; the runner persists ``dbx_revoked=True``; β.12c
    emits a ``windows_dbx_revoked`` Finding at critical severity.
    """
    if not _DBX_REVOKED_PE_FIXTURE.is_file():
        pytest.skip(
            f"β.14a tier-3 needs {_DBX_REVOKED_PE_FIXTURE.name}; "
            "see test docstring for provisioning instructions."
        )

    # Production deploys the DBX bundle via DBX_BUNDLE_PATH env var
    # (β.10). The host-running test typically lacks /opt/wairz/dbxupdate.bin
    # (it's COPYed inside the worker image); for the canary we accept
    # either DBX_BUNDLE_PATH or the production default.
    bundle_path = os.environ.get(
        "DBX_BUNDLE_PATH",
        "/opt/wairz/dbxupdate.bin",
    )
    if not Path(bundle_path).is_file():
        pytest.skip(
            f"β.14a tier-3 needs the DBX bundle at {bundle_path}; "
            "set DBX_BUNDLE_PATH or copy backend/ms-anchors/dbxupdate.bin "
            "(the Dockerfile COPY source) into a host-readable path."
        )

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, str(_DBX_REVOKED_PE_FIXTURE), "1" * 64)
        await db.commit()

        aggregate = await verify_firmware_pe_chain(fw.id, db)
        await db.commit()

        # (e) — dbx_revoked=True flipped by the chain runner via the
        # β.7 DBX probe + β.10 bundled DBX cooperation.
        sig_row = (
            await db.execute(
                select(WindowsPESignature)
                .join(
                    HardwareFirmwareBlob,
                    HardwareFirmwareBlob.id == WindowsPESignature.blob_id,
                )
                .where(HardwareFirmwareBlob.firmware_id == fw.id)
            )
        ).scalar_one()
        assert sig_row.dbx_revoked is True, (
            "expected DBX-revoked fixture to flip dbx_revoked=True; got "
            f"signed={sig_row.signed} chain_status={sig_row.chain_status} "
            f"dbx_revoked={sig_row.dbx_revoked} "
            f"leaf_serial={sig_row.leaf_serial!r}"
        )
        # Aggregate counter incremented in lockstep.
        assert aggregate["dbx_revoked_count"] >= 1

        # (b) — windows_dbx_revoked Finding row at critical severity.
        dbx_findings = (
            await db.execute(
                select(Finding).where(
                    Finding.firmware_id == fw.id,
                    Finding.source == "windows_dbx_revoked",
                )
            )
        ).scalars().all()
        assert len(dbx_findings) >= 1
        assert dbx_findings[0].severity == "critical"
        assert aggregate["findings_emitted"] >= 1


# ── Outer-runner state machine — always runs given mingw-w64 host PEs ──────


@pytest.mark.asyncio
async def test_real_pe_outer_runner_status_machine():
    """``run_authenticode_chain_background`` end-to-end against real PEs.

    Outer-runner equivalent of ``test_real_pe_runner_direct_smoke``:
    exercises the Rule #33 status state machine + the Rule #35c JSONB
    schema-stamp on real bytes. The outer runner owns its own session
    via ``async_session_factory``; we patch the factory to redirect to
    the live SQLite session so the test owns the row state across the
    runner invocation.
    """
    real_pes = _locate_host_unsigned_pes()
    if not real_pes:
        pytest.skip(
            "β.14a outer-runner state machine needs ≥1 real PE on disk; "
            "see test_real_pe_runner_direct_smoke for fixture instructions."
        )

    async with make_live_db() as db:
        fw = await _seed_firmware(db)
        await _add_blob(db, fw, real_pes[0], "1" * 64)
        # POST handler precedent: status='queued' before runner pickup.
        fw.authenticode_chain_status = "queued"
        await db.commit()

        @asynccontextmanager
        async def _factory():
            yield db

        with patch(
            "app.services.authenticode_chain_runner.async_session_factory",
            _factory,
        ):
            await run_authenticode_chain_background(fw.id)

        # SELECT-back: state machine flipped to 'completed' with
        # schema-stamped aggregate JSONB.
        await db.refresh(fw)
        assert fw.authenticode_chain_status == "completed"
        assert fw.authenticode_chain_started_at is not None
        assert fw.authenticode_chain_finished_at is not None
        assert fw.authenticode_chain_error is None

        result = fw.authenticode_chain_result
        assert isinstance(result, dict)
        # Rule #35c schema_version stamp landed.
        assert result["schema_version"] == 1
        # β.12c canonical-shape keys all present (regression guard).
        for key in (
            "total_pe_count",
            "signed_count",
            "unsigned_count",
            "dbx_revoked_count",
            "findings_emitted",
            "by_chain_status",
            "errors",
            "run_seconds",
            "signed_pct",
        ):
            assert key in result, f"missing aggregate key: {key}"
        assert result["total_pe_count"] >= 1
