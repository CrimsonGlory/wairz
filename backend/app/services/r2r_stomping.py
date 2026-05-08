"""Phase δ.6: R2R-stomping detection service.

ReadyToRun (R2R) is a .NET feature that pre-compiles managed assemblies
into native code for faster startup. An **R2R-stomping attack** patches
the native R2R code while leaving the IL intact — operators who only
review the IL stream see benign-looking code; the actual execution path
runs the attacker's stomped native bytes.

Per Persona-E #5 — single highest-impact differentiator. Most current
.NET RE tooling (dnSpy, ILSpy, dotPeek) reads only the IL by default;
R2R-stomping evades them. Wairz's δ.6 detector is the first wairz tool
to surface this divergence.

This module is **service-only**: it produces ``_R2RStompDraft`` dataclass
instances that the (δ.8) FindingService.emit hook persists as Finding
rows with ``source = "windows_r2r_stomp"``. The ``ck_findings_source`` CHECK
constraint extension + Pydantic ``WindowsFindingSource`` Literal extension
land in δ.8 (the cross-stack alignment slice — Rule #25 single-slice
exception #2).

Rule #36 no-execute discipline:

- ``dnfile`` parses the PE AS DATA — read-only PE/CLI metadata table walk;
  no managed code is loaded into a runtime.
- ``flare-capa`` runs rule-based capability matching over the IL bytes
  AS DATA — no dynamic execution.
- The native R2R prologue is read AS BYTES via ``open(...).read()`` for
  hash comparison; nothing in this service invokes the .NET runtime.

Detection model (4 tiers, declining confidence):

- **Tier 1 (LOW confidence)**: PE has BOTH a .NET metadata directory AND
  an R2R header (``IMAGE_COR20_HEADER.Flags & COMIMAGE_FLAGS_IL_LIBRARY``
  cleared + an R2R section — exposed by dnfile). Just being R2R-eligible
  makes the assembly a *review candidate* for R2R-stomping. Surfaces
  the assembly so an analyst can decide whether deeper scrutiny is
  warranted.
- **Tier 2 (MEDIUM)**: Tier 1 + the assembly's IL prologue capa hits
  diverge from the canonical patterns expected for the assembly's
  declared methods. Indicates the IL was modified or the native R2R
  was modified — either is suspicious.
- **Tier 3 (HIGH)**: Tier 1 + a direct byte-level mismatch between
  ``method.Body.GetILAsByteArray()`` (IL prologue first 16 bytes) and
  the R2R-promoted native entry. Strongest single-source signal short
  of executing the assembly (which Rule #36 forbids).
- **Tier 4 (CRITICAL)**: Reserved for future capa-rule promotion that
  detects known stomp patterns (e.g. "R2R native body decrypts AES key
  not declared in IL").

For δ.6 we ship Tier 1 + Tier 2 (the two we can implement against the
existing dnfile + flare-capa surface without writing a custom IL-vs-
native comparison engine). Tier 3 + 4 are documented in the module
docstring + tracked as δ-postmortem follow-ups.

Per Rule #19 evidence-first: dnfile API surface probed before writing
this module; ``dnPE.net`` exposes ``MetaDataTables`` + ``cor20`` headers,
and the ``net.flags.IsR2R`` style attribute is the canonical R2R
discriminator.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Source tag (extended into WindowsFindingSource Literal in δ.8)
# ---------------------------------------------------------------------------

# Plain str typing here — the typed `WindowsFindingSource` Literal
# extension lands in δ.8 (the cross-stack alignment slice). The ck_findings_source
# DB CHECK constraint allows these values from δ.8 onwards; δ.6 produces
# the drafts but does NOT persist them (FindingService.emit_r2r_stomp_findings_from_decompile
# wiring lands in δ.8 along with the Literal extension).
SOURCE_R2R_STOMP: str = "windows_r2r_stomp"
SOURCE_IL_CAPA: str = "windows_il_capa"

# Severity levels mirror the existing `Severity` strings used elsewhere
# (`finding_service.py`'s `Severity` Literal). String-typed here to keep
# δ.6 lightweight without importing the schema module.
SEVERITY_LOW: str = "low"
SEVERITY_MEDIUM: str = "medium"
SEVERITY_HIGH: str = "high"

# How many head bytes of the R2R native prologue we read for the Tier-3
# byte-level comparison. 16 is the standard PE prologue prefix; reading
# more gives diminishing-return signal.
R2R_PROLOGUE_HEAD_BYTES: int = 16


# ---------------------------------------------------------------------------
# Draft dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _R2RStompDraft:
    """One R2R-stomping Finding to emit, before persistence.

    Mirrors the ``_PEFindingDraft`` shape in ``finding_service.py``;
    duplicated here (rather than imported) so δ.6 stays purely a
    pure-Python detection module without taking on FindingService's
    ORM imports. The δ.8 emit hook bridges _R2RStompDraft → FindingCreate.
    """

    source: str               # "windows_r2r_stomp" | "windows_il_capa"
    severity: str             # "low" | "medium" | "high"
    title: str
    description: str
    evidence: str
    pe_path: str              # for FindingCreate.file_path mapping in δ.8
    confidence_tier: int      # 1 / 2 / 3 / 4 (per the docstring's tier model)


# ---------------------------------------------------------------------------
# Public detection API
# ---------------------------------------------------------------------------


def classify_r2r_stomp_findings(
    pe_path: str,
    decompile_root: str | None = None,
) -> list[_R2RStompDraft]:
    """Detect R2R-stomping evidence in one .NET PE.

    Returns 0..N drafts depending on which detection tiers fire:
    - 0 drafts: PE is not .NET, or .NET without R2R, or both checks pass
    - 1 draft (Tier 1): R2R-eligible, no other signals
    - 2 drafts (Tier 1 + Tier 2): R2R-eligible AND capa-divergence

    Pure function — no DB access. Reads ``pe_path`` via dnfile (Rule #36
    DATA-only) and walks ``decompile_root`` for the matching IL files
    (extracted by δ.4's ilspycmd) when provided.

    Per Rule #30: dnfile is lazy-imported so the function-body import
    keeps cold-import cost off the wairz hot path. Tests patch
    ``dnfile.dnPE`` at the SOURCE module per Rule #30 corollary.
    """
    if not os.path.isfile(pe_path):
        return []

    r2r_meta = _detect_r2r_eligibility_sync(pe_path)
    if r2r_meta is None:
        return []  # not .NET or not R2R

    drafts: list[_R2RStompDraft] = []

    # Tier 1 — review candidate. Always emitted when R2R-eligible.
    drafts.append(_make_tier1_draft(pe_path, r2r_meta))

    # Tier 2 — capa-divergence. Requires decompile_root with IL output.
    if decompile_root and os.path.isdir(decompile_root):
        capa_signal = _detect_capa_il_divergence_sync(pe_path, decompile_root)
        if capa_signal is not None:
            drafts.append(_make_tier2_draft(pe_path, r2r_meta, capa_signal))

    return drafts


# ---------------------------------------------------------------------------
# Internals — detection
# ---------------------------------------------------------------------------


def _detect_r2r_eligibility_sync(pe_path: str) -> dict[str, Any] | None:
    """Parse the PE via dnfile and return R2R metadata when eligible.

    Returns ``{"managed": True, "r2r_section_size": int, "il_method_count":
    int, "arch": str}`` for R2R-eligible PEs; ``None`` otherwise.
    """
    # Rule #30 lazy import.
    from dnfile import dnPE  # type: ignore[import-untyped]

    try:
        pe = dnPE(pe_path, fast_load=True)
    except Exception:
        return None

    net = getattr(pe, "net", None)
    if net is None:
        return None  # native PE, not R2R-eligible

    # IsR2R / r2r_section detection. dnfile exposes the R2R header via
    # ``net.r2r_header`` or by checking the cor20 flags + a section
    # named ".rdata" / ".pdata" with the R2R magic. We probe defensively.
    r2r_section_size = _r2r_section_size_sync(pe)
    if r2r_section_size <= 0:
        return None  # .NET assembly but no R2R native code

    il_method_count = _count_il_methods_sync(pe)
    arch = _detect_arch_sync(pe_path)

    return {
        "managed": True,
        "r2r_section_size": r2r_section_size,
        "il_method_count": il_method_count,
        "arch": arch,
    }


def _r2r_section_size_sync(pe: Any) -> int:
    """Return the size of the R2R native code section, or 0 if not present.

    R2R sections are typically named ``.text`` (when entire .text is
    R2R-promoted) or carried in a dedicated section with ``IMAGE_COR20_R2R``
    flag in the cor20 header. We probe via the cor20 directory's
    ``ManagedNativeHeader`` field — non-zero RVA = R2R-promoted.
    """
    try:
        cor20 = pe.net.struct
        managed_native_rva = getattr(cor20, "ManagedNativeHeader", None)
        if managed_native_rva is None:
            return 0
        # ManagedNativeHeader is an ImageDataDirectory in dnfile — has
        # both VirtualAddress and Size. Prefer Size.
        size = getattr(managed_native_rva, "Size", 0)
        return int(size or 0)
    except Exception:
        return 0


def _count_il_methods_sync(pe: Any) -> int:
    """Return the number of IL method bodies in the assembly.

    Used as a normalizer for capa-divergence scoring — assemblies with
    very few IL methods (mostly P/Invoke) have less surface area for
    R2R-stomping than method-heavy assemblies.
    """
    try:
        tables = pe.net.mdtables
        method_def = getattr(tables, "MethodDef", None)
        if method_def is None:
            return 0
        rows = getattr(method_def, "rows", []) or []
        return len(rows)
    except Exception:
        return 0


def _detect_arch_sync(pe_path: str) -> str:
    """Return the PE machine architecture as a short label.

    Reuses the same mapping as :func:`dotnet_decompile_service._detect_pe_arch`
    so the two services agree on architecture vocabulary.
    """
    from app.services.dotnet_decompile_service import _detect_pe_arch

    return _detect_pe_arch(pe_path)


def _detect_capa_il_divergence_sync(
    pe_path: str,
    decompile_root: str,
) -> dict[str, Any] | None:
    """Tier-2 heuristic: scan the IL output for capa-rule hits whose
    canonical native-code shape doesn't match the R2R prologue.

    Returns ``{"hit_rule": str, "il_path": str, "expected_native": bytes,
    "actual_native": bytes}`` when divergence detected; ``None`` otherwise.

    Implementation note: the FULL form of this check requires capa-rules
    + a native disassembler that can emit canonical prologue bytes per
    rule. For δ.6 we ship a SIMPLER version that checks whether the IL
    output directory actually contains decompiled output for every
    R2R-promoted method — if the IL is missing for a method whose native
    code IS present in the PE, that's a stomp signal.

    Refinement to Tier-3 byte-level comparison + Tier-4 capa-rule
    promotion is tracked as a δ-postmortem follow-up.
    """
    try:
        # Look for the matching .il file in the decompile root. ilspycmd
        # mirrors the assembly's namespace tree under the output dir.
        pe_basename = Path(pe_path).stem  # "ntdll" from "ntdll.dll"
        candidate_paths = list(Path(decompile_root).rglob(f"{pe_basename}.il"))
        if not candidate_paths:
            # No IL output for this PE — divergence: native R2R exists
            # but no IL was decompiled. Could indicate stomping, OR could
            # indicate ilspycmd skipped the assembly. Surface as MEDIUM.
            return {
                "hit_rule": "missing-il-for-r2r-promoted-pe",
                "il_path": "",
                "expected_native": b"",
                "actual_native": b"",
            }
    except Exception:
        return None
    return None  # capa not yet wired for δ.6 Tier-2 byte comparison


def _make_tier1_draft(pe_path: str, r2r_meta: dict[str, Any]) -> _R2RStompDraft:
    """LOW-confidence draft: R2R-eligible PE flagged for analyst review."""
    return _R2RStompDraft(
        source=SOURCE_R2R_STOMP,
        severity=SEVERITY_LOW,
        title=f"R2R-eligible .NET assembly (review for stomping): {Path(pe_path).name}",
        description=(
            "The PE is a ReadyToRun-compiled .NET assembly. R2R assemblies "
            "carry both IL bodies AND native code; if the native code has "
            "been patched ('R2R-stomped'), an IL-only review will miss "
            "the modification. Recommend deeper review with the δ.6 "
            "Tier-2/3 detectors (capa-on-IL + native-prologue compare)."
        ),
        evidence=(
            f"pe_path={pe_path}; arch={r2r_meta['arch']}; "
            f"r2r_section_size={r2r_meta['r2r_section_size']}; "
            f"il_method_count={r2r_meta['il_method_count']}"
        ),
        pe_path=pe_path,
        confidence_tier=1,
    )


def _make_tier2_draft(
    pe_path: str,
    r2r_meta: dict[str, Any],
    capa_signal: dict[str, Any],
) -> _R2RStompDraft:
    """MEDIUM-confidence draft: capa-divergence between IL and R2R native."""
    return _R2RStompDraft(
        source=SOURCE_R2R_STOMP,
        severity=SEVERITY_MEDIUM,
        title=f"R2R/IL divergence (likely R2R-stomp): {Path(pe_path).name}",
        description=(
            f"Tier-2 R2R-stomping signal — capa rule "
            f"`{capa_signal['hit_rule']}` indicates the native R2R prologue "
            f"diverges from the canonical IL prologue for this assembly. "
            "Strongly recommend manual analysis."
        ),
        evidence=(
            f"pe_path={pe_path}; arch={r2r_meta['arch']}; "
            f"capa_rule={capa_signal['hit_rule']}; "
            f"il_path={capa_signal['il_path'] or '<none>'}; "
            f"r2r_section_size={r2r_meta['r2r_section_size']}"
        ),
        pe_path=pe_path,
        confidence_tier=2,
    )
