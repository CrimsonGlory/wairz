"""Tests for the Linux kernel hardening (KSPP) walker.

Covers the pure-logic ``evaluate_kernel_config`` function + Rule #35c
JSONB normaliser + Rule #45 + Rule #46 META-CANARIES (no-execute /
no-decrypt + paired canary proving the gate's regex catches synthetic
violations).
"""

from __future__ import annotations

import io
import re
import tokenize
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models import Finding, Firmware, HardwareFirmwareBlob, Project
from app.schemas.finding import KernelConfigFindingSource
from app.services.linux_kernel_hardening_walker import (
    _KSPP_EXTENDED_FINDING,
    _KSPP_RULES,
    _LSM_FINDING,
    _LSM_MAJOR_ALTERNATIVES,
    KERNEL_CONFIG_AUDIT_SCHEMA_VERSION,
    _do_kernel_config_audit_run,
    _normalize_kernel_config_audit_result,
    _stamp_kernel_config_audit_result,
    evaluate_kernel_config,
)
from tests._live_db import make_live_db

# -----------------------------------------------------------------------------
# Pure-logic evaluator.
# -----------------------------------------------------------------------------


def test_evaluate_kernel_config_all_hardened_no_failures() -> None:
    """A fully-hardened config — KSPP recommended values everywhere —
    must produce ZERO failures."""
    config = {
        # Required-on rules
        "CONFIG_RANDOMIZE_BASE": "y",
        "CONFIG_MODULE_SIG": "y",
        "CONFIG_STACKPROTECTOR_STRONG": "y",
        "CONFIG_HARDENED_USERCOPY": "y",
        "CONFIG_FORTIFY_SOURCE": "y",
        "CONFIG_DM_VERITY": "y",
        # Required-off rules (risk surfaces)
        "CONFIG_DEVMEM": "n",
        "CONFIG_DEVKMEM": "n",
        "CONFIG_IO_URING": "n",
        # At least one major LSM
        "CONFIG_SECURITY_SELINUX": "y",
    }
    fails = evaluate_kernel_config(config)
    assert fails == [], f"hardened config should produce 0 failures, got {[r.finding_source for r in fails]}"


def test_evaluate_kernel_config_unhardened_all_failures() -> None:
    """A fully-unhardened config — every config disabled, no LSM, risk
    surfaces on — must produce ALL 10 failures."""
    config = {
        # Required-on: all explicitly disabled
        "CONFIG_RANDOMIZE_BASE": "n",
        "CONFIG_MODULE_SIG": "n",
        "CONFIG_STACKPROTECTOR_STRONG": "n",
        "CONFIG_HARDENED_USERCOPY": "n",
        "CONFIG_FORTIFY_SOURCE": "n",
        "CONFIG_DM_VERITY": "n",
        # Required-off: all enabled
        "CONFIG_DEVMEM": "y",
        "CONFIG_DEVKMEM": "y",
        "CONFIG_IO_URING": "y",
        # No LSM
    }
    fails = evaluate_kernel_config(config)
    sources = {r.finding_source for r in fails}
    expected = {
        "kernel_config_no_kaslr",
        "kernel_config_devmem_enabled",
        "kernel_config_devkmem_enabled",
        "kernel_config_no_module_sig",
        "kernel_config_no_lsm",
        "kernel_config_no_stackprotector",
        "kernel_config_no_hardened_usercopy",
        "kernel_config_no_fortify_source",
        "kernel_config_io_uring_enabled",
        "kernel_config_no_dm_verity",
    }
    assert sources == expected, f"missing: {expected - sources}; extra: {sources - expected}"


def test_evaluate_kernel_config_missing_keys_fail_required_on() -> None:
    """Absent (not even `# CONFIG_FOO is not set`) keys count as a
    failure for "missing" rules — the equivalent of "operator didn't
    enable KSPP guidance"."""
    # Only LSM populated; every "missing"-kind rule should fire because
    # the configs are absent.
    config = {"CONFIG_SECURITY_SELINUX": "y"}
    fails = evaluate_kernel_config(config)
    sources = {r.finding_source for r in fails}
    # All "missing" rules fire; LSM does NOT fire (selinux=y satisfies it).
    assert "kernel_config_no_kaslr" in sources
    assert "kernel_config_no_module_sig" in sources
    assert "kernel_config_no_stackprotector" in sources
    assert "kernel_config_no_lsm" not in sources, \
        "LSM check should pass when SELinux=y"


def test_evaluate_kernel_config_tegra_l4t_real_case() -> None:
    """The DS1 Tegra L4T R32.3.1 reference case — the firmware that
    drove this campaign.  Real .config snapshot extracted from the
    firmware/Image binary via parsers/kernel_image.py."""
    config = {
        "CONFIG_RANDOMIZE_BASE": "y",         # KASLR on (pass)
        "CONFIG_DEVMEM": "y",                 # FAIL — risk surface present
        "CONFIG_DEVKMEM": "y",                # FAIL — risk surface present
        "CONFIG_MODULE_SIG": "n",             # FAIL — modules unsigned
        "CONFIG_HARDENED_USERCOPY": "y",      # pass
        # CONFIG_STACKPROTECTOR_STRONG absent → FAIL
        # CONFIG_FORTIFY_SOURCE absent → FAIL
        # CONFIG_IO_URING absent (kernel 4.9 predates io_uring) → no FAIL ("enabled"-kind)
        # CONFIG_DM_VERITY absent → FAIL
        # No major LSM → FAIL
    }
    fails = evaluate_kernel_config(config)
    sources = {r.finding_source for r in fails}
    # Expected DS1-specific finding set.
    expected = {
        "kernel_config_devmem_enabled",
        "kernel_config_devkmem_enabled",
        "kernel_config_no_module_sig",
        "kernel_config_no_stackprotector",
        "kernel_config_no_fortify_source",
        "kernel_config_no_dm_verity",
        "kernel_config_no_lsm",
    }
    assert sources == expected, f"DS1 reference case drift: missing {expected - sources}, extra {sources - expected}"


# -----------------------------------------------------------------------------
# Rule #25 single-slice cross-stack alignment — every rule's finding_source
# MUST be in the KernelConfigFindingSource Literal.
# -----------------------------------------------------------------------------


def test_kspp_rule_sources_align_with_pydantic_literal() -> None:
    """Every rule in _KSPP_RULES + the composite LSM rule + the extended
    placeholder must use a finding_source declared in the Pydantic
    KernelConfigFindingSource Literal (which itself aligns with the DB
    CHECK + frontend mirror per Rule #48).
    """
    import typing
    literal_values = set(typing.get_args(KernelConfigFindingSource))
    rule_sources = {rule.finding_source for rule in _KSPP_RULES}
    rule_sources.add(_LSM_FINDING.finding_source)
    # Phase kernel-image-followup-T3 Phase 2 — extended placeholder
    # documents the source vocabulary the Phase 3 walker swap will emit
    # dynamically (upstream kernel-hardening-checker catalogue).
    rule_sources.add(_KSPP_EXTENDED_FINDING.finding_source)

    # The KernelConfigFindingSource Literal is SHARED across two walkers:
    # the KSPP hardening AUDIT walker (this module — rule_sources above) AND
    # the C1 generic kernel-config EXTRACTION walker
    # (kernel_config_walker.py), which emits the ONE structural source
    # ``kernel_config_extraction_blocked`` for the BLOCKED ff12d941 path.
    # That source is NOT a KSPP rule, so exclude it from this KSPP-walker
    # alignment check (it has its own emit + DB CHECK + frontend mirror
    # via the f4a5b6c7d8e9 cross-stack-alignment commit).
    c1_extraction_sources = {"kernel_config_extraction_blocked"}

    assert rule_sources <= literal_values, (
        f"walker emits sources NOT in KernelConfigFindingSource Literal: "
        f"{rule_sources - literal_values}"
    )
    # Conversely — confirm we don't have orphan Literal values that no
    # rule emits.  This catches stale finding_source declarations that
    # got the DB CHECK extension but no walker rule was wired. The C1
    # extraction sources are emitted by kernel_config_walker, not this
    # KSPP audit walker, so they're expected on the Literal but absent
    # from rule_sources.
    orphans = literal_values - rule_sources - c1_extraction_sources
    assert not orphans, (
        f"Literal values with NO walker rule emitting them (and not a "
        f"known C1 extraction source): {orphans}"
    )


def test_kspp_rule_count_size_lock() -> None:
    """Rule #48 size-lock: pin the rule catalogue at its current
    documented size so drift forces a deliberate edit + postmortem."""
    assert len(_KSPP_RULES) == 9, (
        "9 single-config rules expected (LSM is a composite +1 = 10 sources). "
        f"got {len(_KSPP_RULES)}"
    )
    assert len(_LSM_MAJOR_ALTERNATIVES) == 4, (
        "4 major LSMs expected (SELinux/AppArmor/SMACK/TOMOYO). "
        f"got {len(_LSM_MAJOR_ALTERNATIVES)}"
    )


# -----------------------------------------------------------------------------
# Rule #35c JSONB normaliser + stamp helper.
# -----------------------------------------------------------------------------


def test_normalize_kernel_config_audit_result_idempotent() -> None:
    """Canonical pass-through case: dict in, dict out."""
    payload = {"audited_at": "2026-05-22T21:00:00Z", "blobs_audited": 2}
    assert _normalize_kernel_config_audit_result(payload) == payload


def test_normalize_kernel_config_audit_result_defensive_coercion() -> None:
    """Defensive: None / wrong-type returns None (not an empty dict)."""
    assert _normalize_kernel_config_audit_result(None) is None
    assert _normalize_kernel_config_audit_result([]) is None
    assert _normalize_kernel_config_audit_result("nope") is None
    assert _normalize_kernel_config_audit_result(42) is None


def test_stamp_adds_schema_version_and_provenance() -> None:
    """Stamp helper writes schema_version + provenance sister-keys."""
    payload = {"audited_at": "2026-05-22T21:00:00Z", "findings_emitted_count": 7}
    stamped = _stamp_kernel_config_audit_result(payload)
    assert stamped["schema_version"] == KERNEL_CONFIG_AUDIT_SCHEMA_VERSION == 1
    assert stamped["provenance"] == "linux_kernel_hardening_walker"
    assert stamped["audited_at"] == "2026-05-22T21:00:00Z"
    assert stamped["findings_emitted_count"] == 7
    # Original payload not mutated.
    assert "schema_version" not in payload


# -----------------------------------------------------------------------------
# Rule #45 + Rule #46 META-CANARY: walker source contains no decrypt /
# subprocess / eval / exec / os.system tokens.
# -----------------------------------------------------------------------------


def _walker_source_tokens() -> str:
    """Tokenize the walker source + strip comment + string tokens."""
    walker_path = (
        Path(__file__).parent.parent
        / "app/services/linux_kernel_hardening_walker.py"
    )
    assert walker_path.is_file(), f"walker source missing: {walker_path}"
    with walker_path.open("rb") as f:
        tokens = []
        try:
            for tok in tokenize.tokenize(f.readline):
                if tok.type in (tokenize.COMMENT, tokenize.STRING):
                    continue
                tokens.append(tok.string)
        except tokenize.TokenizeError:
            pass
    return " ".join(tokens)


_FORBIDDEN_TOKEN_RE = re.compile(
    r"\.\s*(decrypt|encrypt)\s*\(|"
    r"subprocess\s*\.\s*(run|Popen|call|check_output|check_call)\s*\(|"
    r"os\s*\.\s*(system|execvp|execve|spawnvp)\s*\(|"
    r"asyncio\s*\.\s*create_subprocess_(exec|shell)\s*\(|"
    r"(?<![A-Za-z_0-9])eval\s*\(|"
    r"(?<![A-Za-z_0-9])exec\s*\(",
    re.IGNORECASE,
)


def test_walker_no_decrypt_no_exec_no_subprocess() -> None:
    """Rule #45 parse-only: walker MUST NOT decrypt, exec, or spawn
    subprocesses.  Walker reads metadata + emits Findings — pure DB
    work."""
    joined = _walker_source_tokens()
    matches = _FORBIDDEN_TOKEN_RE.findall(joined)
    assert not matches, (
        f"Rule #45 violation in linux_kernel_hardening_walker.py: "
        f"forbidden tokens found: {matches}"
    )


def test_walker_no_decrypt_gate_actually_fires() -> None:
    """Rule #46 META-CANARY: prove the gate above would catch a
    synthesised violation.  Without this canary the gate is a Rule #17
    silent-pass risk (passing test only meaningful if we know the gate
    would have caught a bug).

    Whitespace-tolerant regex per κ.D lesson — tokenize joins tokens
    with single spaces (``obj.decrypt(`` becomes ``obj . decrypt (``).
    """
    synthetic = b"def x(): subprocess.run(['echo', 'hi'])\n"
    tokens = []
    try:
        for tok in tokenize.tokenize(io.BytesIO(synthetic).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            tokens.append(tok.string)
    except tokenize.TokenizeError:
        pass
    joined = " ".join(tokens)
    assert _FORBIDDEN_TOKEN_RE.search(joined), (
        f"Rule #46 META-CANARY: the no-decrypt gate's regex FAILED to "
        f"catch a synthesised violation. Tokenized source: {joined!r}"
    )

    # Also confirm an eval() synthetic gets caught.
    synthetic2 = b"def y(): eval('1+1')\n"
    tokens2 = []
    try:
        for tok in tokenize.tokenize(io.BytesIO(synthetic2).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            tokens2.append(tok.string)
    except tokenize.TokenizeError:
        pass
    joined2 = " ".join(tokens2)
    assert _FORBIDDEN_TOKEN_RE.search(joined2), (
        f"Rule #46 META-CANARY: gate FAILED to catch eval() synthetic: {joined2!r}"
    )


# -----------------------------------------------------------------------------
# Rule #35b live canary — _do_kernel_config_audit_run ORM dispatch
# -----------------------------------------------------------------------------
#
# Backfills postmortem recommendation #1 (kernel-image-ikcfg-walker-2026-05-22).
# The pure-logic ``evaluate_kernel_config`` tests above cover rule logic but
# have no view into how the walker reads ``blob.blob_path``, ``blob.metadata_``,
# or persists Findings via ``FindingService``.  The original campaign's
# ``blob.file_path`` typo (fixed in commit c5e7f75) survived 11 mock-passing
# tests precisely because no test exercised the ORM dispatch shape; the bug
# only surfaced when a live canary call to ``run_kernel_config_audit_background``
# raised ``AttributeError`` mid-iteration.
#
# These tests use ``make_live_db()`` (in-memory SQLite with the production
# schema) so the value-flow contract (constructor args → persisted columns)
# is verified end-to-end.  Mock-only coverage cannot catch the F-A-06-shape
# class of bug per CLAUDE.md Rule #35b.
# -----------------------------------------------------------------------------


_UNHARDENED_REFERENCE_CONFIG: dict[str, str] = {
    # All required-on rules explicitly disabled.
    "CONFIG_RANDOMIZE_BASE": "n",
    "CONFIG_MODULE_SIG": "n",
    "CONFIG_STACKPROTECTOR_STRONG": "n",
    "CONFIG_HARDENED_USERCOPY": "n",
    "CONFIG_FORTIFY_SOURCE": "n",
    "CONFIG_DM_VERITY": "n",
    # Required-off rules enabled (risk surfaces present).
    "CONFIG_DEVMEM": "y",
    "CONFIG_DEVKMEM": "y",
    "CONFIG_IO_URING": "y",
    # No LSM keys → composite _LSM_FINDING fires.
}


async def _seed_kernel_blob(
    db,
    *,
    project_name: str,
    sha256: str,
    extracted_path: str,
    blob_path: str,
    blob_sha256_suffix: str,
    kernel_config: dict[str, str] | None,
    kernel_semver: str = "4.9.140",
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Seed Project + Firmware + HardwareFirmwareBlob.

    When ``kernel_config`` is None the blob is shaped as a non-kernel
    artefact (no ``metadata.kernel_config``) so the walker should skip it.
    Returns ``(project_id, firmware_id, blob_id)``.
    """
    project = Project(name=project_name)
    db.add(project)
    await db.flush()
    firmware = Firmware(
        project_id=project.id,
        sha256=sha256,
        extracted_path=extracted_path,
    )
    db.add(firmware)
    await db.flush()
    meta: dict = {"kernel_semver": kernel_semver}
    if kernel_config is not None:
        meta["kernel_config"] = kernel_config
        meta["kernel_banner"] = f"Linux version {kernel_semver} (live-canary test)"
    blob = HardwareFirmwareBlob(
        firmware_id=firmware.id,
        blob_path=blob_path,
        # blob_sha256 must be unique per (firmware_id, blob_sha256) — pad to
        # 64 hex chars with the caller's suffix to keep collisions impossible
        # across the 3 tests below.
        blob_sha256=("0" * (64 - len(blob_sha256_suffix))) + blob_sha256_suffix,
        file_size=1024,
        category="kernel_image" if kernel_config is not None else "other",
        format="raw_bin",
        detection_source="kernel_image_parser" if kernel_config is not None else "test",
        metadata_=meta,
    )
    db.add(blob)
    await db.flush()
    return project.id, firmware.id, blob.id


async def test_do_kernel_config_audit_run_persists_findings_referencing_blob_path() -> None:
    """Live canary per Rule #35b — exercises _do_kernel_config_audit_run's
    ORM dispatch shape end-to-end.

    Would have caught the ``blob.file_path`` → ``blob.blob_path`` typo from
    the original campaign (postmortem failure #1, commit c5e7f75) because
    each persisted Finding's ``evidence`` string MUST contain the actual
    ``blob.blob_path`` value — and a mocked HardwareFirmwareBlob cannot
    reproduce the ORM column-name resolution.
    """
    async with make_live_db() as db:
        blob_path = "/tmp/fake-firmware/kernel/Image"
        _project_id, firmware_id, blob_id = await _seed_kernel_blob(
            db,
            project_name="kernel-config-audit-live-canary",
            sha256="a" * 64,
            extracted_path="/tmp/fake-firmware",
            blob_path=blob_path,
            blob_sha256_suffix="aa",
            kernel_config=_UNHARDENED_REFERENCE_CONFIG,
        )
        await db.commit()

        result = await _do_kernel_config_audit_run(db, firmware_id)
        await db.commit()

        # ── Aggregate result shape ──
        assert result["blobs_audited"] == 1
        assert result["blobs_with_ikconfig"] == 1
        assert result["findings_emitted_count"] == 10
        assert result["errors"] == []
        assert len(result["per_blob"]) == 1
        per_blob = result["per_blob"][0]
        assert per_blob["blob_id"] == str(blob_id)
        assert per_blob["blob_path"] == blob_path
        assert per_blob["config_entries"] == len(_UNHARDENED_REFERENCE_CONFIG)
        assert len(per_blob["findings"]) == 10

        # ── Live SELECTs — VALUE FLOW VERIFICATION (Rule #35b) ──
        findings = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware_id)
            )
        ).scalars().all()
        assert len(findings) == 10, f"expected 10 Findings, got {len(findings)}"

        # CRITICAL: every Finding's evidence string MUST reference blob_path.
        # This is the assertion that would have caught the c5e7f75 bug
        # (blob.file_path vs blob.blob_path) — pure-mock tests cannot
        # observe this because they never persist a real HardwareFirmwareBlob.
        for f in findings:
            assert blob_path in (f.evidence or ""), (
                f"Rule #35b violation — Finding {f.source} evidence does "
                f"not reference blob.blob_path ({blob_path}): {f.evidence!r}"
            )
            assert f.firmware_id == firmware_id
            assert f.confidence == "high"
            assert f.source.startswith("kernel_config_")
            assert f.severity in ("high", "medium", "low")
            assert f.cwe_ids, f"{f.source} missing cwe_ids"

        # All 10 expected sources fired.
        sources = {f.source for f in findings}
        expected = {
            "kernel_config_no_kaslr",
            "kernel_config_devmem_enabled",
            "kernel_config_devkmem_enabled",
            "kernel_config_no_module_sig",
            "kernel_config_no_lsm",
            "kernel_config_no_stackprotector",
            "kernel_config_no_hardened_usercopy",
            "kernel_config_no_fortify_source",
            "kernel_config_io_uring_enabled",
            "kernel_config_no_dm_verity",
        }
        assert sources == expected, (
            f"finding sources drift: missing={expected - sources}, "
            f"extra={sources - expected}"
        )


async def test_do_kernel_config_audit_run_skips_blobs_without_kernel_config() -> None:
    """Blobs without ``metadata.kernel_config`` (i.e. non-kernel-image
    artefacts — bootloaders, DTBs, RFS partitions) are skipped without
    emitting Findings.  Confirms the guard at walker line 346
    ``if not isinstance(config, dict) or not config: continue``.
    """
    async with make_live_db() as db:
        _project_id, firmware_id, _ = await _seed_kernel_blob(
            db,
            project_name="kernel-config-audit-skip-test",
            sha256="b" * 64,
            extracted_path="/tmp/fake-firmware-2",
            blob_path="/tmp/fake-firmware-2/random.bin",
            blob_sha256_suffix="bb",
            kernel_config=None,
        )
        await db.commit()

        result = await _do_kernel_config_audit_run(db, firmware_id)
        await db.commit()

        assert result["blobs_audited"] == 1
        assert result["blobs_with_ikconfig"] == 0
        assert result["findings_emitted_count"] == 0
        assert result["per_blob"] == []

        findings = (
            await db.execute(
                select(Finding).where(Finding.firmware_id == firmware_id)
            )
        ).scalars().all()
        assert findings == []


async def test_do_kernel_config_audit_run_handles_missing_firmware() -> None:
    """Non-existent firmware id returns an aggregate with errors[] entry
    and zero blobs audited — confirms graceful degradation rather than
    an exception escaping the inner runner (which the Rule #39 outer
    wrapper would catch as ``status=failed`` but is less informative).
    """
    async with make_live_db() as db:
        bogus = uuid.uuid4()
        result = await _do_kernel_config_audit_run(db, bogus)

        assert result["blobs_audited"] == 0
        assert result["findings_emitted_count"] == 0
        assert any(f"firmware {bogus} not found" in e for e in result["errors"])
