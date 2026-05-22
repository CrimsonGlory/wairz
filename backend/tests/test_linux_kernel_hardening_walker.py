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
from pathlib import Path

import pytest

from app.schemas.finding import KernelConfigFindingSource
from app.services.linux_kernel_hardening_walker import (
    _KSPP_RULES,
    _LSM_FINDING,
    _LSM_MAJOR_ALTERNATIVES,
    KERNEL_CONFIG_AUDIT_SCHEMA_VERSION,
    _normalize_kernel_config_audit_result,
    _stamp_kernel_config_audit_result,
    evaluate_kernel_config,
)

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
    """Every rule in _KSPP_RULES + the composite LSM rule must use a
    finding_source declared in the Pydantic KernelConfigFindingSource
    Literal (which itself aligns with the DB CHECK + frontend mirror per
    Rule #48)."""
    import typing
    literal_values = set(typing.get_args(KernelConfigFindingSource))
    rule_sources = {rule.finding_source for rule in _KSPP_RULES}
    rule_sources.add(_LSM_FINDING.finding_source)

    assert rule_sources <= literal_values, (
        f"walker emits sources NOT in KernelConfigFindingSource Literal: "
        f"{rule_sources - literal_values}"
    )
    # Conversely — confirm we don't have orphan Literal values that no
    # rule emits.  This catches stale finding_source declarations that
    # got the DB CHECK extension but no walker rule was wired.
    assert literal_values <= rule_sources, (
        f"Literal values with NO walker rule emitting them: "
        f"{literal_values - rule_sources}"
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
