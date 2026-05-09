"""Phase δ.6: tests for ``app.services.r2r_stomping``.

Covers:

1. ``classify_r2r_stomp_findings`` returns 0 drafts for non-.NET PEs.
2. Tier-1 draft for R2R-eligible PEs (LOW confidence review candidate).
3. Tier-2 draft when IL output is missing for R2R-promoted PE.
4. Source/severity constant alignment with the (forthcoming δ.8)
   WindowsFindingSource Literal extension.
5. Rule #30 patch-at-source-module discipline for dnfile.

The actual FindingService.emit + DB persistence wiring lands in δ.8
(cross-stack alignment slice); this test surface covers the pure-function
classifier.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.services.r2r_stomping import (
    R2R_PROLOGUE_HEAD_BYTES,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SOURCE_IL_CAPA,
    SOURCE_R2R_STOMP,
    _R2RStompDraft,
    classify_r2r_stomp_findings,
)

# ─────────────────────────────────────────────────────────────────────────────
# Constants — align with the (δ.8) WindowsFindingSource Literal extension
# ─────────────────────────────────────────────────────────────────────────────


def test_source_constants():
    """The δ.8 alignment migration extends ck_findings_source with these
    exact strings; this test pins the spelling so a typo in either layer
    fails immediately at code-load time."""
    assert SOURCE_R2R_STOMP == "windows_r2r_stomp"
    assert SOURCE_IL_CAPA == "windows_il_capa"


def test_severity_constants_match_finding_severity_set():
    """Severity strings match the existing Severity Literal in the schema
    layer — low / medium / high. (Critical exists too but δ.6 doesn't
    emit critical until Tier-4 is shipped post-δ.)"""
    assert SEVERITY_LOW == "low"
    assert SEVERITY_MEDIUM == "medium"
    assert SEVERITY_HIGH == "high"


def test_r2r_prologue_head_bytes_constant():
    """16 bytes is the standard PE prologue prefix — enough to detect
    an entry stub change without paying for full-section reads."""
    assert R2R_PROLOGUE_HEAD_BYTES == 16


# ─────────────────────────────────────────────────────────────────────────────
# classify_r2r_stomp_findings — non-.NET / not-R2R cases (0 drafts)
# ─────────────────────────────────────────────────────────────────────────────


def test_classify_returns_empty_when_path_missing(tmp_path):
    """Non-existent PE path returns empty draft list."""
    drafts = classify_r2r_stomp_findings(str(tmp_path / "missing.dll"))
    assert drafts == []


def test_classify_returns_empty_when_dnfile_raises(tmp_path):
    """dnfile parse failure → 0 drafts (defensive boundary)."""
    p = tmp_path / "broken.dll"
    p.write_bytes(b"not a real PE")
    with patch("dnfile.dnPE", side_effect=Exception("malformed")):
        assert classify_r2r_stomp_findings(str(p)) == []


def test_classify_returns_empty_for_native_pe(tmp_path):
    """Native PE (no .NET metadata) is filtered — δ.6 only scopes to
    .NET assemblies."""
    p = tmp_path / "native.dll"
    p.write_bytes(b"native bytes")
    fake_pe = MagicMock()
    fake_pe.net = None
    with patch("dnfile.dnPE", return_value=fake_pe):
        assert classify_r2r_stomp_findings(str(p)) == []


def test_classify_returns_empty_for_dotnet_without_r2r(tmp_path):
    """A .NET assembly without an R2R section → 0 drafts (no stomping
    surface to flag)."""
    p = tmp_path / "managed.dll"
    p.write_bytes(b"managed bytes")
    fake_pe = MagicMock()
    fake_pe.net = MagicMock()
    fake_pe.net.struct.ManagedNativeHeader.Size = 0  # no R2R native code
    with patch("dnfile.dnPE", return_value=fake_pe):
        assert classify_r2r_stomp_findings(str(p)) == []


# ─────────────────────────────────────────────────────────────────────────────
# Tier-1 — R2R-eligible review candidate (LOW confidence)
# ─────────────────────────────────────────────────────────────────────────────


def test_classify_emits_tier1_draft_for_r2r_eligible_pe(tmp_path):
    """An R2R-eligible PE (managed + non-zero ManagedNativeHeader.Size)
    yields exactly one Tier-1 LOW draft when no decompile_root provided."""
    p = tmp_path / "r2r.dll"
    p.write_bytes(b"r2r assembly bytes")
    fake_pe = MagicMock()
    fake_pe.net = MagicMock()
    fake_pe.net.struct.ManagedNativeHeader.Size = 4096
    fake_pe.net.mdtables.MethodDef.rows = [object()] * 50
    fake_pefile = MagicMock()
    fake_pefile.FILE_HEADER.Machine = 0x8664  # amd64
    with (
        patch("dnfile.dnPE", return_value=fake_pe),
        patch("pefile.PE", return_value=fake_pefile),
    ):
        drafts = classify_r2r_stomp_findings(str(p))
    assert len(drafts) == 1
    d = drafts[0]
    assert isinstance(d, _R2RStompDraft)
    assert d.source == SOURCE_R2R_STOMP
    assert d.severity == SEVERITY_LOW
    assert d.confidence_tier == 1
    assert "review" in d.title.lower() or "r2r-eligible" in d.title.lower()
    assert "amd64" in d.evidence
    assert "r2r_section_size=4096" in d.evidence
    assert "il_method_count=50" in d.evidence
    assert d.pe_path == str(p)


def test_classify_tier1_evidence_carries_arch(tmp_path):
    """Tier-1 evidence string includes the PE arch — operators sorting
    by 'amd64 vs arm64 vs msil' want this surfaced."""
    p = tmp_path / "r2r_arm.dll"
    p.write_bytes(b"r2r arm assembly")
    fake_pe = MagicMock()
    fake_pe.net = MagicMock()
    fake_pe.net.struct.ManagedNativeHeader.Size = 2048
    fake_pe.net.mdtables.MethodDef.rows = [object()] * 10
    fake_pefile = MagicMock()
    fake_pefile.FILE_HEADER.Machine = 0xAA64  # arm64
    with (
        patch("dnfile.dnPE", return_value=fake_pe),
        patch("pefile.PE", return_value=fake_pefile),
    ):
        drafts = classify_r2r_stomp_findings(str(p))
    assert len(drafts) == 1
    assert "arm64" in drafts[0].evidence


# ─────────────────────────────────────────────────────────────────────────────
# Tier-2 — capa/IL divergence (MEDIUM confidence)
# ─────────────────────────────────────────────────────────────────────────────


def test_classify_emits_tier2_draft_when_il_missing(tmp_path):
    """When decompile_root is provided AND no IL file exists for the PE,
    Tier-2 fires (missing IL for R2R-promoted PE = divergence signal)."""
    pe_path = tmp_path / "stomped.dll"
    pe_path.write_bytes(b"r2r bytes")
    decompile_root = tmp_path / "decomp"
    decompile_root.mkdir()
    # Note: NO matching stomped.il under decompile_root.

    fake_pe = MagicMock()
    fake_pe.net = MagicMock()
    fake_pe.net.struct.ManagedNativeHeader.Size = 4096
    fake_pe.net.mdtables.MethodDef.rows = [object()] * 100
    fake_pefile = MagicMock()
    fake_pefile.FILE_HEADER.Machine = 0x8664
    with (
        patch("dnfile.dnPE", return_value=fake_pe),
        patch("pefile.PE", return_value=fake_pefile),
    ):
        drafts = classify_r2r_stomp_findings(
            str(pe_path), str(decompile_root),
        )
    assert len(drafts) == 2
    tier1 = next(d for d in drafts if d.confidence_tier == 1)
    tier2 = next(d for d in drafts if d.confidence_tier == 2)
    assert tier1.severity == SEVERITY_LOW
    assert tier2.severity == SEVERITY_MEDIUM
    assert tier2.source == SOURCE_R2R_STOMP
    assert "missing-il-for-r2r-promoted-pe" in tier2.evidence
    assert "stomp" in tier2.title.lower()


def test_classify_no_tier2_when_il_present(tmp_path):
    """When matching .il file exists in decompile_root, Tier-2 doesn't
    fire (only Tier-1 is emitted) — this is the "no signal" case for
    Tier-2 in our δ.6 first cut."""
    pe_path = tmp_path / "ok.dll"
    pe_path.write_bytes(b"r2r bytes")
    decompile_root = tmp_path / "decomp"
    decompile_root.mkdir()
    # Matching IL output present — δ.6 Tier-2 doesn't fire.
    (decompile_root / "ok.il").write_text("// IL bytecode here")

    fake_pe = MagicMock()
    fake_pe.net = MagicMock()
    fake_pe.net.struct.ManagedNativeHeader.Size = 4096
    fake_pe.net.mdtables.MethodDef.rows = [object()] * 100
    fake_pefile = MagicMock()
    fake_pefile.FILE_HEADER.Machine = 0x8664
    with (
        patch("dnfile.dnPE", return_value=fake_pe),
        patch("pefile.PE", return_value=fake_pefile),
    ):
        drafts = classify_r2r_stomp_findings(
            str(pe_path), str(decompile_root),
        )
    assert len(drafts) == 1
    assert drafts[0].confidence_tier == 1


def test_classify_skips_tier2_when_decompile_root_missing(tmp_path):
    """A non-existent decompile_root path doesn't crash; it just skips
    Tier-2 and returns Tier-1 only."""
    p = tmp_path / "r2r.dll"
    p.write_bytes(b"r2r bytes")
    fake_pe = MagicMock()
    fake_pe.net = MagicMock()
    fake_pe.net.struct.ManagedNativeHeader.Size = 4096
    fake_pe.net.mdtables.MethodDef.rows = []
    fake_pefile = MagicMock()
    fake_pefile.FILE_HEADER.Machine = 0x8664
    with (
        patch("dnfile.dnPE", return_value=fake_pe),
        patch("pefile.PE", return_value=fake_pefile),
    ):
        drafts = classify_r2r_stomp_findings(
            str(p), "/nonexistent/decompile/root",
        )
    assert len(drafts) == 1
    assert drafts[0].confidence_tier == 1
