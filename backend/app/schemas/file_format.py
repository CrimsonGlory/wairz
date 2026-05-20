"""File-format manifest schema — closed-grammar Pydantic Literals.

Operator-extensible YAML at
``backend/app/services/file_format_catalog/data/file_formats/<vendor>/<format>.yaml``
loaded via :class:`app.services.file_format_catalog.FormatCatalog` (which
internally uses :class:`app.utils.yaml_cache.MtimeCachedYamlLoader`) and
validated against the models in this file. Hot-reload on mtime change
(no docker restart for YAML edits).

**Hard rule (CLAUDE.md Rule #52 — schema-driven discipline; promoted
from bare-metal-MCU-specific to wairz-wide architectural principle):**
the YAML is DATA. NO ``regex`` / ``script`` / ``template`` / ``vql`` /
``lua`` / ``expression`` / ``predicate`` / ``eval`` keys EVER. Every
extensible field is either a FREE STRING (taxonomy: vendor, category,
format_id, product) or a CLOSED LITERAL (executable semantics).
Plugin references are REGISTRY NAMES looked up at snapshot construction,
never Python import paths.

Extending the grammar requires:

1. Rule #25 single-slice cross-stack alignment commit (DB CHECK ↔
   Pydantic ``Literal`` ↔ frontend ``Record`` mirror + alignment test).
2. Rule #46 META-CANARY confirming the new value lands through the gate.
3. Code review of the new ``ref`` in the resolver's registry constant.

This bound is the durable defense against the YAML becoming a programming
language (Wave-1 S2 binwalk/yara/Velociraptor CVE class). See
:file:`.planning/research/file-format-yaml-registry-wave1-synthesis-2026-05-19.md`.

Three-level hierarchy:

    FileFormatManifest         # one YAML file per format
      ├─ Detection             # how to recognise this format
      │   └─ DetectionSignal   # cost-sorted by resolver, NOT YAML order
      ├─ Dispatch              # container fan-out by partition/inner-file/magic
      ├─ Refinement            # path-context refinement (file location-based)
      ├─ Plugin                # closed-grammar pointers to in-tree plugins
      ├─ Output                # what the classifier emits when this matches
      ├─ PreUploadHint         # surface C (format_detection.detect_format)
      ├─ ExternalManifestsPolicy  # per-format-id policy for external pushes
      ├─ Deprecation           # lifecycle field
      └─ ProvenanceStub        # contributor org + attestation pointer (P3.1 unsigned)

**Adaptability surface** (user direction 2026-05-19 — repeated 3×):
operators drop a new YAML at ``data/file_formats/<vendor>/<format>.yaml``
(in-tree, ``manifest_source: core``) or ``data/file_formats.local/<format>.yaml``
(operator overlay, ``manifest_source: operator``) and the next walker
invocation picks it up. No docker restart. No code change. Taxonomy
fields (vendor, category, format_id, product) are FREE STRINGS so partners
can contribute medical / ICS / automotive formats without core merges.
Plugin pointers are registry-name strings (validated at snapshot construction),
never Python import paths.

Wave-1 contradiction resolutions are reflected here verbatim (W2-α 2026-05-19):

* Overlay semantics — explicit ``mode: new|override|extend``; default
  ``new`` rejects duplicate ``format_id`` at load (silent shadowing closed).
* ``manifest_source`` — closed 5-value Literal; tier rank ALWAYS outranks
  numeric ``precedence`` (Scout GG §SC5 dual).
* Signal evaluation — resolver cost-sorts; YAML order is docs only.
* Match semantics — single value ``evaluation_mode: "best_match"``
  (forced default) — first-match was the bug shape.
* Plugin role — explicit ``primary | refine | none`` + on_disagreement;
  ``side_effects: "none"`` (only permitted value) closes the side-channel
  ordering attack.

Cross-feature loader validators (Wave-2 β; NOT in this schema — they live
in app/services/file_format_catalog/catalog.py because they require
catalog state):

* A1: when mode=override, override-source's manifest_source rank MUST be
  >= override-target's manifest_source rank (prevents external override of
  operator's local override).
* A2: vendor_authority is DERIVED from THIS manifest's manifest_source;
  alias_of does NOT propagate vendor_authority.
* A3: REJECT catalog load if any dispatch.cases.* target has
  deprecation.status == "removed".
* A4: REJECT cross-vendor same-precedence same-magic collision unless
  manifest_source differs.
* A5: REJECT catalog load if dispatch.depth_max >= 2 AND any chained
  manifest has plugin.matcher.bind=eager AND that plugin's cost_class
  >= magic_bytes.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    model_validator,
)

# ---------------------------------------------------------------------------
# Closed-grammar Literal enumerations.
# Adding values requires Rule #25 + Rule #46 discipline — see module docstring.
# ---------------------------------------------------------------------------

#: Manifest provenance source. Drives precedence arbitration when N manifests
#: declare the same format_id or overlapping detection signatures (Wave-1 S5 H
#: — direct dual of Scout GG §SC5). Loader cross-checks declared value against
#: on-disk path; mismatch → REJECT at load.
#:
#: Rank semantics (resolver source ``_SOURCE_PRECEDENCE``):
#:    _system:                 100   # data/file_formats/_system/ ONLY
#:    core:                     80   # data/file_formats/<vendor>/
#:    operator:                 60   # data/file_formats.local/
#:    attested_external:        40   # P4 — verified signature required
#:    unauthenticated_external: 20   # P4 — HTTP-pushed, never trusted
#:
#: Manifest_source rank ALWAYS outranks numeric ``precedence`` (operator at
#: precedence=200 STILL beats unauthenticated_external at precedence=50).
ManifestSource = Literal[
    "_system",
    "core",
    "operator",
    "attested_external",
    "unauthenticated_external",
]

#: Derived view of manifest_source for CVE-narrowing decisions. NOT authored
#: directly in YAML — the loader computes it from manifest_source. CVE
#: narrowing on output.classifier_vendor only fires when vendor_authority
#: == "curated".
VendorAuthority = Literal["curated", "operator_supplied", "external_attested"]

#: How a manifest interacts with prior manifests under the same format_id.
#: Default "new" → REJECT duplicate format_id at load (silent-shadow closed —
#: Wave-1 S5 C HIGH stop-the-line).
OverlayMode = Literal["new", "override", "extend"]

#: Match semantics when multiple manifests match. Single value today (default
#: forced); Literal kept for future extension. First-match was the bug shape
#: (Wave-1 S5 B HIGH). Resolver always collects ALL matches, sorts by total-
#: order tuple, returns lowest rank.
EvaluationMode = Literal["best_match"]

#: Closed signal-combine semantics within ONE manifest's detection block.
#: Wave-1 S5 F.
Combine = Literal["all_required", "any", "weighted"]

#: Cost-sorted detection-signal kinds. Resolver evaluates signals in cost-class
#: order, NOT YAML declaration order (Wave-1 S5 attack O — I/O cost
#: amplification DoS). Each value maps to a Python evaluator in
#: :data:`app.services.file_format_catalog.SIGNAL_EVALUATORS`. Exhaustive
#: dispatch is Rule #46 META-CANARY enforced.
#:
#: Cost-class groupings (resolver constant ``_SIGNAL_COST_CLASS``):
#:    zero:      filename, path_context, size_range
#:    cheap:     elf_check, intel_hex_check, pe_check, text_format
#:    mid:       magic_bytes, substring_in_head (≤512 bytes head read)
#:    expensive: zip_markers, tar_markers, rtos_check
#:
#: P3.x (2026-05-20): ``substring_in_head`` ships closed-grammar literal
#: substring search over head bytes. Closes the windows_installer_iso +
#: iso_9660 bridge case (legacy ``_legacy_bridge_detect`` bootmgr upgrade)
#: by giving the catalog a "head contains needle X" signal — operator-
#: extensible via :class:`SubstringInHeadConstraint`, NO regex.
DetectionSignalKind = Literal[
    "filename",
    "path_context",
    "size_range",
    "elf_check",
    "intel_hex_check",
    "pe_check",
    "text_format",
    "magic_bytes",
    "substring_in_head",
    "zip_markers",
    "tar_markers",
    "rtos_check",
    "always_matches",
]

#: Container fan-out semantics. Each value maps to a dispatch evaluator in
#: :data:`app.services.file_format_catalog.DISPATCH_EVALUATORS` (Rule #46
#: META-CANARY exhaustive). ``by_rtos_family`` (P3.2.c) routes via the
#: free-string rtos_family value emitted by an rtos_check signal's plugin.
DispatchKind = Literal[
    "by_partition_name",
    "by_zip_inner_file",
    "by_inner_magic",
    "by_rtos_family",
    "alias",
    "none",
]


#: Sort-tier policy. Controls where this manifest sorts among matched
#: candidates BEFORE source_rank / precedence / specificity. The resolver
#: maps each tier to an integer rank via
#: :data:`app.services.file_format_catalog.resolver._TIER_RANK` (Rule #46
#: META-CANARY exhaustive). Ascending sort, so ceiling wins; floor loses.
#:
#: ``ceiling``  → invariants: ALWAYS wins among matched candidates.
#:                RESERVED to ``manifest_source="_system"`` (schema validator
#:                + loader path cross-check). No current author — slot
#:                ships now so future "THIS magic is ALWAYS this format
#:                regardless of operator override" invariants extend
#:                mechanically (Rule #25 Shape-1 commit).
#: ``general``  → default tier — sort by source_rank / precedence /
#:                specificity per ``_SOURCE_PRECEDENCE``. All ``core`` /
#:                ``operator`` / ``attested_external`` /
#:                ``unauthenticated_external`` manifests are general-tier.
#:                ``_system`` manifests MAY be general (e.g. linux_squashfs).
#: ``floor``    → sentinel catch-alls: ALWAYS LOSE among matched candidates.
#:                Today: ``linux_blob_fallback`` only. RESERVED to
#:                ``manifest_source="_system"``. Per-tier cardinality (today
#:                1) enforced at catalog load — loosen via Rule #25 Shape-1
#:                when concrete second-floor use case appears.
#:
#: Rule #52 + #46: closed Literal. Adding a tier value requires Rule #25
#: cross-stack alignment + Rule #46 paired META-CANARY.
SortTier = Literal["floor", "general", "ceiling"]


#: Character class accepted in the record body after the start byte.
#: P3.2.b: closed-grammar text-format evaluator (Wave-1 S4 + W2-α
#: convergence — `hex_space_separated` added for TI-TXT data lines).
#: Each value maps to a frozen byte set in
#: :data:`app.services.file_format_catalog.resolver._TEXT_FORMAT_CHARSET_BYTES`
#: (Rule #46 META-CANARY exhaustive).
TextFormatCharset = Literal[
    "hex_upper",
    "hex_lower",
    "hex_mixed",
    "hex_space_separated",  # W2-α: TI-TXT data lines (space-delimited hex)
    "ascii_printable",
    "base64_url",
]


#: Line terminator accepted in the record stream. ``any`` is permissive
#: (LF / CRLF / CR); strict values enforce a specific terminator. P3.2.b.
TextFormatLineTerminator = Literal["lf", "crlf", "cr", "any"]


#: First-line tolerance. ``record_start`` requires the first non-empty
#: line to begin with the record_start_byte; ``any`` allows operator
#: comments / shebangs / vendor headers before the first record. P3.2.b.
TextFormatFirstLine = Literal["record_start", "any"]

#: Plugin binding strategy. Eager → load-time resolution; ImportError fatal at
#: catalog refresh. Lazy → match-time resolution per ``fallback`` policy.
#: Default eager (Wave-1 S5 E).
PluginBind = Literal["eager", "lazy"]

#: Plugin fallback when ``bind: lazy`` and the plugin isn't registered at
#: match time. Wave-1 S5 E.
PluginFallback = Literal["skip", "reject", "raw_bin"]

#: Plugin role in the matcher chain. Wave-1 S5 G.
PluginRole = Literal["primary", "refine", "none"]

#: How to resolve disagreement between static manifest output and plugin
#: output. Wave-1 S5 G.
PluginDisagreement = Literal[
    "log_warn",
    "reject",
    "plugin_wins",
    "static_wins",
]

#: Plugin side-effect declaration. Only "none" is accepted (Wave-1 S5 attack
#: P — plugin call-order side-channel). Plugins MUST be pure.
PluginSideEffects = Literal["none"]

#: Policy for external-pushed manifests overriding THIS format_id. Operator can
#: pin core YAML's primacy (Wave-1 S5 L).
ExternalManifestsPolicy = Literal["deny", "allow", "require_attestation"]

#: Confidence band emitted on Classification.
Confidence = Literal["high", "medium", "low"]

#: Vendor-name precedence in the refinement block (Wave-1 S1 §2). Closes the
#: filename-wins-vs-path-wins implicit-precedence ambiguity.
VendorPrecedence = Literal["filename_wins", "path_wins"]

#: Final-tier tie-breaker tokens when all upstream rank fields tied. Closed
#: Literal (NO operator regex/predicate). Wave-1 S5 A.
TieBreaker = Literal[
    "rule_specificity",
    "vendor_lex_asc",
    "filename_lex_asc",
]

#: Surface C — DetectedFormat from format_detection.detect_format (today's
#: hardcoded enum, ported to Literal so the registry can derive it at startup).
#: Wave-1 W2-α Q6 resolution. Adding a value REQUIRES Rule #25 cross-stack
#: alignment (DB CHECK ↔ Pydantic Literal ↔ frontend Record mirror).
DetectedFormat = Literal[
    "linux_firmware_blob",
    "android_apk",
    "android_ota",
    "windows_installer_iso",
    "acronis_backup",
    "qnx_ifs",
    "pe_executable",
    "wim_archive",
    "iso_9660",
    "tar_archive",
    "zip_archive",
    "windows_cab",
    "windows_msi",
    "windows_msix",
    "windows_msu",
    "windows_psf",
    "windows_vhdx",
    "windows_driver_package",
    "unknown",
]

#: Surface C — ExtractionCapability. Mirrors format_detection module.
ExtractionCapability = Literal["full", "partial", "none"]

#: Lifecycle state for the format itself. Wave-1 S5 Q.
DeprecationStatus = Literal["active", "deprecated", "removed"]


# ---------------------------------------------------------------------------
# Detection sub-models.
# ---------------------------------------------------------------------------


class TextFormatConstraint(BaseModel):
    """Closed-grammar text-format detection constraint set (P3.2.b).

    Operators add new textual firmware/data formats (Intel HEX, SREC,
    TI-TXT, Tektronix Hex, HP Universal Hex, future ECU log dumps) by
    authoring a YAML manifest with a ``text_format`` signal carrying a
    ``text_format_constraint`` block — NO Python code change.

    The evaluator at
    :func:`app.services.file_format_catalog.resolver._eval_text_format`
    is the single consumer; it walks the constraint fields and validates
    the first N records of the blob_head. Rule #46 META-CANARY
    ``test_meta_canary_text_format_evaluator_uses_declared_constraints_not_hardcoded``
    AST-walks the evaluator body and forbids hardcoded byte literals —
    every byte the evaluator compares against MUST come from a field on
    this model.

    Hard rule (Rule #52): NO regex / script / template / eval / lua /
    vql / predicate / expression. Every extensibility surface is a
    closed Literal or a bounded numeric range or a single-byte sentinel.
    """

    record_start_byte_hex: str = Field(
        min_length=2, max_length=2, pattern=r"^[0-9a-f]{2}$",
        description="Lowercase hex of the single byte that opens every "
                    "record. Examples: '3a' for Intel HEX ':', '53' for "
                    "SREC 'S', '40' for TI-TXT '@'. Single-byte by "
                    "construction — multi-byte start markers use "
                    "magic_bytes instead.",
    )
    charset: TextFormatCharset = Field(
        description="Character class accepted in the record body after "
                    "the start byte. ``hex_mixed`` is the common default "
                    "for MCU-firmware text formats; ``hex_space_separated`` "
                    "for TI-TXT data lines (space-delimited hex bytes); "
                    "stricter values only when the spec mandates them.",
    )
    line_terminator: TextFormatLineTerminator = Field(
        default="any",
        description="Line terminator. ``any`` accepts LF / CRLF / CR; "
                    "tighten to a specific value when the spec mandates.",
    )
    min_line_length: int = Field(
        ge=4, le=4096,
        description="Minimum record length INCLUDING the start byte. "
                    "Intel HEX min=11 (`:LLAAAATT[CC]`); SREC min=10; "
                    "TI-TXT min=5 (`@FFE0`).",
    )
    max_line_length: int = Field(
        ge=4, le=4096,
        description="Maximum record length. Intel HEX max=521; SREC "
                    "max=515; TI-TXT max=80. Cap at 4096 to bound "
                    "evaluator memory.",
    )
    first_line_must_match: TextFormatFirstLine = Field(
        default="record_start",
        description="``record_start`` requires the first non-empty line "
                    "to begin with the record_start_byte. ``any`` allows "
                    "operator comments / shebangs / vendor headers "
                    "before the first record. Strict by default.",
    )
    min_first_block_records: int = Field(
        default=4, ge=1, le=64,
        description="How many records to validate before declaring a "
                    "positive match. Intel HEX / SREC = 4; TI-TXT = 2 "
                    "(`@<addr>` + 1 data line). Cap at 64 for evaluator "
                    "cost bound.",
    )
    header_pattern_hex: str | None = Field(
        default=None, max_length=64, pattern=r"^[0-9a-f]{0,64}$",
        description="Optional hex-encoded byte sequence the evaluator "
                    "checks IMMEDIATELY after the record_start_byte on "
                    "the FIRST record only. None disables the check.",
    )
    terminator_record_hex: str | None = Field(
        default=None, max_length=128, pattern=r"^[0-9a-f]{0,128}$",
        description="Optional hex-encoded byte sequence that MUST appear "
                    "as the last record (excluding trailing whitespace). "
                    "Intel HEX = `:00000001FF` minus terminator. The "
                    "evaluator looks for this in the LAST 256 bytes of "
                    "blob_head as a best-effort tail check. None disables.",
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_length_bounds(self) -> "TextFormatConstraint":
        if self.min_line_length > self.max_line_length:
            raise ValueError(
                f"text_format_constraint: min_line_length="
                f"{self.min_line_length} > max_line_length="
                f"{self.max_line_length}"
            )
        # Constraint-strength floor — prevent operator manifests with
        # near-empty constraints that match all text files. W2-β A8
        # high-collision floor: low min_first_block_records + permissive
        # charset + short min_line_length collectively risk over-matching.
        if self.min_first_block_records < 2 and self.min_line_length < 8:
            raise ValueError(
                "text_format_constraint: min_first_block_records<2 "
                "AND min_line_length<8 — constraint too weak; "
                "either bump record count or line length (Wave-2 W2-β A8)"
            )
        return self


#: Combine policy for substring_in_head needles.
#: ``any`` — match when any single needle is present (legacy bootmgr OR
#: sources/boot.wim semantic).
#: ``all`` — match only when EVERY needle is present (stricter co-presence
#: invariants — e.g. "both vendor-string AND product-string appear").
SubstringInHeadCombine = Literal["any", "all"]


class SubstringInHeadConstraint(BaseModel):
    """Closed-grammar substring-in-head detection constraint set (P3.x 2026-05-20).

    Operators add new "head contains literal byte sequence X" detection
    paths (Windows installer ISO bootmgr substring; UEFI capsule GUID
    string in PE rsrc; vendor-specific banners in compressed-then-zeroed
    head regions) by authoring a YAML manifest with a ``substring_in_head``
    signal carrying a ``substring_in_head_constraint`` block — NO Python
    code change.

    The evaluator at
    :func:`app.services.file_format_catalog.resolver._eval_substring_in_head`
    is the single consumer; it scans the configured head window for the
    declared needles using literal ``bytes.__contains__`` lookups. Rule
    #46 META-CANARY ``test_meta_canary_substring_in_head_evaluator_uses_declared_needles_not_hardcoded``
    AST-walks the evaluator body and forbids hardcoded byte literals —
    every byte the evaluator searches for MUST come from a needle on this
    model.

    Hard rule (Rule #52): NO regex / script / template / eval / lua / vql
    / predicate / expression. Every needle is a literal hex-encoded byte
    sequence. The case_sensitive flag toggles a ``bytes.lower()`` pre-
    normalization; it does NOT enable any matching DSL.
    """

    needles_hex: list[str] = Field(
        min_length=1, max_length=16,
        description="Lowercase hex-encoded byte needles. Each entry: even "
                    "length, min 2 bytes (4 hex chars), max 64 bytes (128 "
                    "hex chars). 16-needle max bounds evaluator cost class "
                    "(Wave-1 S5 attack O — I/O cost amplification floor). "
                    "Literal verbatim substring search; NO regex.",
    )
    case_sensitive: bool = Field(
        default=False,
        description="When False (default), evaluator lower-cases the head "
                    "window AND the needles before comparison — ASCII bytes "
                    "only; non-ASCII bytes pass through unchanged. When True, "
                    "exact byte match. False matches the legacy bootmgr "
                    "substring upgrade semantic.",
    )
    combine: SubstringInHeadCombine = Field(
        default="any",
        description="``any`` — match when at least ``min_count`` needles "
                    "are present (default 1 of N). ``all`` — match only "
                    "when EVERY needle is present (overrides min_count). "
                    "``any`` is the common case; ``all`` is for "
                    "co-presence invariants.",
    )
    min_count: int = Field(
        default=1, ge=1, le=16,
        description="Minimum needle hits required when combine='any'. "
                    "Ignored when combine='all' (all needles required). "
                    "Operator can require ``2 of 5`` shape evidence for "
                    "weaker individual signals. min_count<=len(needles_hex) "
                    "enforced by validator.",
    )
    search_offset: int = Field(
        default=0, ge=0, le=2**16,
        description="Byte offset where the head-window search starts. "
                    "Default 0 (start of head). Bounded at 64KB so the "
                    "search window stays within the resolver's HEAD_BYTES "
                    "buffer for any reasonable read size.",
    )
    search_length: int | None = Field(
        default=None, ge=64, le=2**20,
        description="Length of the head window to scan. None (default) "
                    "scans from ``search_offset`` to end of available head "
                    "bytes. Capped at 1 MB so a hostile operator can't "
                    "request unbounded scans. The resolver passes a "
                    "blob_head buffer of bounded size — declaring more "
                    "doesn't actually read more.",
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_needles(self) -> "SubstringInHeadConstraint":
        for i, needle in enumerate(self.needles_hex):
            if len(needle) % 2 != 0:
                raise ValueError(
                    f"substring_in_head_constraint.needles_hex[{i}]: "
                    f"odd hex length {len(needle)} (not byte-aligned)"
                )
            if len(needle) < 4:
                raise ValueError(
                    f"substring_in_head_constraint.needles_hex[{i}]: "
                    f"min 2 bytes (4 hex chars); got {len(needle)} chars. "
                    "Single-byte needles match too much; use magic_bytes "
                    "for offset-pinned 1-byte sentinels (Wave-1 S5 attack O)."
                )
            if len(needle) > 128:
                raise ValueError(
                    f"substring_in_head_constraint.needles_hex[{i}]: "
                    f"max 64 bytes (128 hex chars); got {len(needle)} chars"
                )
            try:
                bytes.fromhex(needle)
            except ValueError as exc:
                raise ValueError(
                    f"substring_in_head_constraint.needles_hex[{i}]: "
                    f"invalid hex: {exc}"
                ) from exc
        if self.min_count > len(self.needles_hex):
            raise ValueError(
                f"substring_in_head_constraint: min_count="
                f"{self.min_count} > len(needles_hex)="
                f"{len(self.needles_hex)} — impossible to satisfy"
            )
        return self


class DetectionSignal(BaseModel):
    """One detection signal — closed kinds, cost-sorted at evaluation.

    NO regex anywhere. ``patterns`` and ``substrings`` are literal byte/string
    sequences searched verbatim. Wave-1 size caps + element-length floors
    (S3 §2) enforced by Field constraints below.
    """

    kind: DetectionSignalKind
    weight: float = Field(default=1.0, ge=0.0, le=1.0,
                          description="Contribution under combine=weighted; ignored otherwise")

    # filename
    stems_lower: list[str] | None = Field(
        default=None, max_length=64,
        description="Exact basename matches (lowercased). Min 4 chars per entry.",
    )
    extensions_lower: list[str] | None = Field(
        default=None, max_length=32,
        description="Extension tokens including the dot (e.g. '.bin'). Min 2 chars.",
    )

    # path_context
    path_substrings_any_of: list[str] | None = Field(
        default=None, max_length=32,
        description="Path substring match (any of). MUST start with '/' and be >=6 chars (Wave-1 S3 §2).",
    )

    # size_range
    size_min: int | None = Field(default=None, ge=0, le=2**40)
    size_max: int | None = Field(default=None, ge=0, le=2**40)

    # magic_bytes
    offset: int | None = Field(default=None, ge=0, le=2**32 - 1,
                               description="Byte offset for magic_bytes; <=4GB.")
    bytes_hex: str | None = Field(default=None, max_length=1024,
                                  description="Lowercase hex; <=512 bytes (1024 hex chars). Wave-1 S3 §2.")
    mask_hex: str | None = Field(default=None, max_length=1024,
                                 description="Optional bitmask; same length as bytes_hex.")

    # zip_markers / tar_markers
    inner_file_names: list[str] | None = Field(default=None, max_length=32)
    inner_basenames: list[str] | None = Field(default=None, max_length=32)
    inner_min_count: int | None = Field(default=None, ge=1, le=64)

    # rtos_check
    rtos_plugin_ref: str | None = Field(
        default=None, max_length=64,
        description="Registry name for the RTOS plugin. Resolved at snapshot time.",
    )

    # text_format (P3.2.b)
    text_format_constraint: TextFormatConstraint | None = Field(
        default=None,
        description="Closed-grammar text-format constraint set. REQUIRED "
                    "when kind == 'text_format'; rejected otherwise. "
                    "Wave-1 S4 closure of the P3.1 _eval_text_format stub.",
    )

    # substring_in_head (P3.x 2026-05-20)
    substring_in_head_constraint: SubstringInHeadConstraint | None = Field(
        default=None,
        description="Closed-grammar substring-in-head constraint set. "
                    "REQUIRED when kind == 'substring_in_head'; rejected "
                    "otherwise. Closes the legacy ``_legacy_bridge_detect`` "
                    "bootmgr substring upgrade for windows_installer_iso.",
    )

    description: str | None = Field(default=None, max_length=256)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_kind_fields(self) -> "DetectionSignal":
        if self.kind == "magic_bytes":
            if self.bytes_hex is None or self.offset is None:
                raise ValueError(
                    "magic_bytes signal: bytes_hex and offset are REQUIRED"
                )
            if len(self.bytes_hex) % 2 != 0:
                raise ValueError("magic_bytes: bytes_hex must have even length")
            if len(self.bytes_hex) < 4:
                raise ValueError(
                    "magic_bytes: minimum 2 bytes (4 hex chars). "
                    "Negative-evidence formats (PE/MZ at 2 bytes) MUST set "
                    "precedence >= 5000 — see manifest validator."
                )
            if self.mask_hex is not None:
                if len(self.mask_hex) != len(self.bytes_hex):
                    raise ValueError("magic_bytes: mask_hex length mismatch")
                if all(c == "0" for c in self.mask_hex):
                    raise ValueError(
                        "magic_bytes: mask_hex all-zero matches everything; "
                        "use detection.always_matches=True for catch-all formats"
                    )
        if self.kind == "filename":
            if not self.stems_lower and not self.extensions_lower:
                raise ValueError(
                    "filename signal: at least one of stems_lower / extensions_lower"
                )
            if self.stems_lower:
                for s in self.stems_lower:
                    if len(s) < 4:
                        raise ValueError(
                            f"filename.stems_lower[{s!r}]: min 4 chars "
                            "(Wave-1 S3 §2 floor)"
                        )
        if self.kind == "path_context":
            if not self.path_substrings_any_of:
                raise ValueError("path_context signal: path_substrings_any_of required")
            for p in self.path_substrings_any_of:
                if not p.startswith("/"):
                    raise ValueError(
                        f"path_context: {p!r} must start with '/' "
                        "(Wave-1 S3 §2)"
                    )
                if len(p) < 6:
                    raise ValueError(
                        f"path_context: {p!r} min 6 chars (Wave-1 S3 §2)"
                    )
        if self.kind == "size_range":
            if self.size_min is None and self.size_max is None:
                raise ValueError("size_range: declare at least size_min or size_max")
            if (self.size_min is not None and self.size_max is not None
                    and self.size_min > self.size_max):
                raise ValueError("size_range: size_min > size_max")
        if self.kind == "rtos_check" and not self.rtos_plugin_ref:
            raise ValueError("rtos_check: rtos_plugin_ref required")
        if self.kind in ("zip_markers", "tar_markers"):
            if not (self.inner_file_names or self.inner_basenames):
                raise ValueError(
                    f"{self.kind}: declare inner_file_names or inner_basenames"
                )
        # P3.2.b: text_format ⇔ text_format_constraint
        if self.kind == "text_format" and self.text_format_constraint is None:
            raise ValueError(
                "text_format signal: text_format_constraint is REQUIRED "
                "(Wave-1 S4 closed-grammar evaluator)"
            )
        if (self.text_format_constraint is not None
                and self.kind != "text_format"):
            raise ValueError(
                f"text_format_constraint set but kind={self.kind!r} "
                "— constraint only meaningful for kind='text_format'"
            )
        # P3.x 2026-05-20: substring_in_head ⇔ substring_in_head_constraint
        if (self.kind == "substring_in_head"
                and self.substring_in_head_constraint is None):
            raise ValueError(
                "substring_in_head signal: substring_in_head_constraint "
                "is REQUIRED (closed-grammar evaluator)"
            )
        if (self.substring_in_head_constraint is not None
                and self.kind != "substring_in_head"):
            raise ValueError(
                f"substring_in_head_constraint set but kind={self.kind!r} "
                "— constraint only meaningful for kind='substring_in_head'"
            )
        return self


class Detection(BaseModel):
    """Detection block — how to recognise this format.

    ``signals`` is preserved in declaration order for serialization /
    documentation purposes only. The resolver SORTS by cost class at evaluation
    time (Wave-1 S5 attack O — I/O cost amplification DoS closed).
    """

    combine: Combine = Field(
        default="all_required",
        description="all_required -> AND; any -> OR; weighted -> score must clear min_confidence_score",
    )
    signals: list[DetectionSignal] = Field(
        min_length=1, max_length=32,
        description="Cost-sorted at evaluation by resolver — declaration order is documentation",
    )
    min_confidence_score: float | None = Field(
        default=None, ge=0.0, le=100.0,
        description="REQUIRED when combine=weighted; sum-of-(weight*match) floor",
    )
    always_matches: bool = Field(
        default=False,
        description="ONLY the single _system fallback (linux_blob) sets True. "
                    "Loader rejects True if manifest_source != '_system'.",
    )
    sort_tier: SortTier = Field(
        default="general",
        description=(
            "Sort-tier policy. ``floor`` (RESERVED to _system) sentinels lose "
            "to all general matches; ``ceiling`` (RESERVED to _system) "
            "invariants win over all general matches. ``general`` (default) "
            "sorts by source_rank/precedence/specificity. Schema permits N "
            "floor manifests (per-tier cardinality enforced at catalog load) "
            "so per-failure-class sentinels can be added without schema reform."
        ),
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_combine_constraints(self) -> "Detection":
        if self.combine == "weighted" and self.min_confidence_score is None:
            raise ValueError(
                "detection.combine=weighted requires min_confidence_score"
            )
        if self.always_matches and any(
            s.kind != "always_matches" for s in self.signals
        ):
            raise ValueError(
                "detection.always_matches=True permits only signals of kind "
                "'always_matches'"
            )
        return self

    @model_validator(mode="after")
    def _check_sort_tier_invariants(self) -> "Detection":
        # always_matches and sort_tier are SEPARATE concepts but correlate:
        # every always_matches=True manifest is a catch-all sentinel and
        # MUST sort to the floor. Mis-authored manifests are rejected here.
        if self.always_matches and self.sort_tier != "floor":
            raise ValueError(
                "detection.always_matches=True requires sort_tier='floor' "
                "(the sentinel catch-all tier reserved for _system); author "
                "the sentinel with both fields explicit"
            )
        return self


# ---------------------------------------------------------------------------
# Dispatch / refinement / plugin sub-models.
# ---------------------------------------------------------------------------


class Dispatch(BaseModel):
    """Container fan-out — when a format wraps N inner formats.

    Wave-1 S1 §1: cross-manifest format_id refs in ``cases`` with cycle
    detection at catalog load. ``depth_max`` caps recursion (Wave-1 S3 §10).
    """

    kind: DispatchKind = "none"
    cases: dict[str, str] = Field(
        default_factory=dict, max_length=128,
        description="Discriminator value -> target format_id. Resolved at snapshot construction.",
    )
    default: str | None = Field(
        default=None, max_length=64, pattern=r"^[a-z][a-z0-9_]*$",
        description="Fallback format_id when no case matches",
    )
    depth_max: int = Field(default=2, ge=1, le=4)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_cases(self) -> "Dispatch":
        if self.kind == "none":
            if self.cases or self.default:
                raise ValueError("dispatch.kind=none rejects cases/default")
        else:
            if not self.cases and not self.default:
                raise ValueError(
                    f"dispatch.kind={self.kind}: declare at least cases or default"
                )
        for case_value, target_id in self.cases.items():
            if len(case_value) > 128:
                raise ValueError(f"dispatch.cases[{case_value!r}] discriminator too long")
            if not target_id or not target_id[0].isalpha():
                raise ValueError(
                    f"dispatch.cases[{case_value!r}]: target {target_id!r} "
                    "must match ^[a-z][a-z0-9_]*$"
                )
        return self


class Refinement(BaseModel):
    """Path-context refinement block — SEPARATE from detection (Wave-1 S1 §2).

    Triggers when ``applies_when`` matches; replaces category/vendor/product
    from the detection result. ``vendor_precedence`` closes the implicit
    filename-vs-path ambiguity in the existing classifier.
    """

    applies_when: Literal["category_is_other", "any"] = "category_is_other"
    path_substrings_any_of: list[str] = Field(
        default_factory=list, max_length=32,
        description="At least one substring MUST match the lowercased extraction-tree path",
    )
    partition_prefixes: list[str] = Field(default_factory=list, max_length=32)
    output_category: str = Field(min_length=1, max_length=64)
    output_vendor: str = Field(min_length=1, max_length=64)
    output_confidence: Confidence
    output_product: str | None = Field(default=None, max_length=64)
    vendor_precedence: VendorPrecedence = "filename_wins"

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_path_floor(self) -> "Refinement":
        for p in self.path_substrings_any_of:
            if not p.startswith("/") or len(p) < 6:
                raise ValueError(
                    f"refinement.path_substrings_any_of[{p!r}]: must start "
                    "with '/' and be >=6 chars (Wave-1 S3 §2)"
                )
        return self


class PluginRef(BaseModel):
    """One closed-grammar reference into the in-tree plugin registry.

    ``ref`` is a REGISTRY NAME (validated at snapshot construction against
    :data:`app.services.file_format_catalog.PLUGIN_REGISTRY`). Never a Python
    import path. ``side_effects`` is locked to ``"none"`` — plugins MUST be
    pure (Wave-1 S5 attack P).
    """

    ref: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    bind: PluginBind = "eager"
    fallback: PluginFallback = "skip"
    role: PluginRole = "refine"
    on_disagreement: PluginDisagreement = "log_warn"
    side_effects: PluginSideEffects = "none"
    applicable_format_ids: list[str] = Field(
        default_factory=list, max_length=64,
        description="Plugin applicability allowlist (Wave-1 S3 §3). "
                    "Plugin's own protocol declares ``applicable_format_ids``; "
                    "mismatch rejected at catalog refresh.",
    )

    model_config = ConfigDict(extra="forbid")


class Plugin(BaseModel):
    """Plugin pointers — matcher / parser / unpack pipeline.

    All three are REGISTRY NAMES, runtime-resolved at snapshot construction.
    The schema VALIDATES STRUCTURE; the catalog VALIDATES THAT THE REGISTRY
    NAME RESOLVES.
    """

    matcher: PluginRef | None = None
    parser: PluginRef | None = None
    unpack_pipeline: PluginRef | None = None

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Output / pre-upload / external policy / deprecation / provenance.
# ---------------------------------------------------------------------------


class Output(BaseModel):
    """What the classifier emits when this format matches.

    Free-string taxonomy fields (Wave-1 user direction repeated 3×). Operators
    extend without core merges. Cross-stack alignment (Rule #25 Shape-1)
    propagates new vendor/category values to DB CHECK + frontend mirror.
    """

    classifier_format: str = Field(min_length=1, max_length=64,
                                   pattern=r"^[a-z][a-z0-9_]*$")
    classifier_category: str = Field(min_length=1, max_length=64)
    classifier_vendor: str = Field(min_length=1, max_length=64)
    classifier_product: str | None = Field(default=None, max_length=64)
    confidence: Confidence = "high"

    model_config = ConfigDict(extra="forbid")


class PreUploadHint(BaseModel):
    """Surface C bridge — what format_detection.detect_format() emits.

    Wave-1 W2-α Q6: surface C reads this sub-block to derive its
    ``DetectedFormat`` enum + ``EXTRACTION_CAPABILITY`` dict at startup
    (snapshot-pinned). One registry, two consumers.
    """

    detected_format: DetectedFormat
    extraction_capability: ExtractionCapability
    banner_note: str | None = Field(
        default=None, max_length=2048,
        description="Human-readable note rendered in the frontend banner when "
                    "extraction_capability is 'partial' or 'none'",
    )

    model_config = ConfigDict(extra="forbid")


class ExternalManifestsPolicyBlock(BaseModel):
    """Per-format-id policy for external-pushed manifests (P4 surface).

    Wave-1 S5 L: operator can pin core YAML's primacy via ``policy: deny``.
    Default deny on core/system manifests; operator can ``allow`` per format_id.
    """

    policy: ExternalManifestsPolicy = "deny"
    scope: list[str] = Field(
        default_factory=list, max_length=64,
        description="format_ids this policy applies to (empty = self only)",
    )

    model_config = ConfigDict(extra="forbid")


class Deprecation(BaseModel):
    """Lifecycle field — Wave-1 S5 Q.

    Catalog refresh emits WARN for every deprecated YAML loaded. Cross-stack
    alignment (Rule #25 Shape-1) keeps deprecated values valid through DB
    CHECK + frontend mirror until ``status: removed``.
    """

    status: DeprecationStatus = "active"
    replaced_by: str | None = Field(
        default=None, max_length=64, pattern=r"^[a-z][a-z0-9_]*$",
        description="Required when status != active",
    )
    removal_phase: str | None = Field(default=None, max_length=32)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_lifecycle(self) -> "Deprecation":
        if self.status in ("deprecated", "removed") and not self.replaced_by:
            raise ValueError(
                f"deprecation.status={self.status}: replaced_by is REQUIRED"
            )
        if self.status == "deprecated" and not self.removal_phase:
            raise ValueError(
                "deprecation.status=deprecated: removal_phase is REQUIRED"
            )
        return self


class ProvenanceStub(BaseModel):
    """Contributor attribution. P3.1 ships unsigned stub; P4 adds verification.

    Wave-1 W2-α Q1: ``signature`` accepted as opaque field but NOT validated
    in P3.1. P4 adds detached-signature verification gated on
    ``manifest_source: attested_external``.
    """

    contributor_org: str = Field(min_length=1, max_length=128)
    attestation_url: HttpUrl | None = None
    signature: str | None = Field(
        default=None, max_length=4096,
        description="OPAQUE in P3.1 — not crypto-validated. P4 adds ed25519 "
                    "detached-signature verification.",
    )
    received_at: datetime | None = Field(
        default=None,
        description="Loader-stamped; do NOT author manually",
    )
    supersedes: str | None = Field(
        default=None, max_length=64,
        description="Prior manifest_descriptor_id this supersedes (P4 surface)",
    )

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Top-level manifest.
# ---------------------------------------------------------------------------


class FileFormatManifest(BaseModel):
    """One file-format YAML manifest.

    See module docstring for the hard rule and adaptability contract.

    Taxonomy fields (``vendor``, ``category``, ``format_id``, ``product``) are
    FREE STRINGS so partners contribute medical / ICS / automotive formats
    without core merges. Closed Literals appear ONLY where YAML maps to
    executable Python semantics (Rule #52 hard cap).
    """

    schema_version: Literal[1] = 1

    # identity
    format_id: str = Field(
        min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$",
        description="Globally unique format identifier across the catalog. "
                    "FREE STRING within pattern constraint.",
    )
    alias_of: str | None = Field(
        default=None, max_length=64, pattern=r"^[a-z][a-z0-9_]*$",
        description="If set, declares this manifest is the same format as the "
                    "referenced format_id (legitimate magic-byte overlap; "
                    "Wave-1 S4). Resolved at snapshot; no alias chains > 1.",
    )

    # overlay semantics
    mode: OverlayMode = Field(
        default="new",
        description="Default 'new' REJECTS duplicate format_id at load. "
                    "'override' / 'extend' require explicit ``overrides`` path. "
                    "Silent shadowing closed (Wave-1 S5 C).",
    )
    overrides: str | None = Field(
        default=None, max_length=256,
        description="Required when mode=override; relative path to the prior "
                    "manifest (e.g. 'qualcomm/qcom_mbn.yaml')",
    )

    # provenance / authority
    manifest_source: ManifestSource = Field(
        description="MUST match the on-disk path tier (loader cross-checks). "
                    "Wave-1 S5 H — Scout GG §SC5 dual.",
    )
    precedence: int = Field(
        default=100, ge=0, le=10_000,
        description="Numeric precedence within manifest_source tier. "
                    "Operator/external default 100; reserved [0,9] for _system, "
                    "[>=5000] for negative-evidence magic bytes (PE/MZ etc.).",
    )
    tie_breakers: list[TieBreaker] = Field(
        default_factory=lambda: [
            "rule_specificity", "vendor_lex_asc", "filename_lex_asc",
        ],
        max_length=8,
        description="Final-tier tie-breakers when manifest_source rank + "
                    "precedence + rule_specificity all tied (Wave-1 S5 A).",
    )
    evaluation_mode: EvaluationMode = Field(
        default="best_match",
        description="Single value today — first-match was the bug shape. "
                    "Collect-then-sort always. Wave-1 S5 B.",
    )

    # taxonomy (FREE STRINGS)
    category: str = Field(
        min_length=1, max_length=64,
        description="FREE STRING. Examples: bootloader, modem, tee, mcu, "
                    "windows_pe, linux_blob, medical_device, ics_plc, "
                    "automotive_ecu. Cross-stack alignment via Rule #25 "
                    "Shape-1 when adding values that need DB/frontend mirror.",
    )
    vendor: str = Field(
        min_length=1, max_length=64,
        description="FREE STRING. Examples: qualcomm, mediatek, medtronic, "
                    "siemens, bosch, unknown.",
    )
    product: str | None = Field(default=None, max_length=64,
                                description="FREE STRING. Optional product code.")

    confidence: Confidence = "high"
    notes: str | None = Field(
        default=None, max_length=8192,
        description="Operator free-text. NDA references, compliance pointers, "
                    "spec citations live here (Wave-1 W2-α Q8).",
    )

    # core blocks
    detection: Detection
    dispatch: Dispatch = Field(default_factory=Dispatch)
    refinement: Refinement | None = None
    plugin: Plugin = Field(default_factory=Plugin)
    output: Output
    pre_upload: PreUploadHint | None = None
    external_manifests: ExternalManifestsPolicyBlock = Field(
        default_factory=ExternalManifestsPolicyBlock,
    )
    deprecation: Deprecation = Field(default_factory=Deprecation)
    provenance: ProvenanceStub | None = None

    references: list[str] = Field(default_factory=list, max_length=16)
    source_path: str | None = Field(
        default=None,
        description="Loader-stamped; do NOT author manually",
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_cross_field_invariants(self) -> "FileFormatManifest":
        if self.mode == "override" and not self.overrides:
            raise ValueError(
                "mode=override requires overrides: <path> (Wave-1 S5 C)"
            )
        if self.mode != "override" and self.overrides:
            raise ValueError(
                f"mode={self.mode}: overrides field is permitted only when "
                "mode=override"
            )

        if self.alias_of and self.dispatch.kind != "none":
            raise ValueError(
                f"format {self.format_id!r}: alias_of and dispatch.kind="
                f"{self.dispatch.kind!r} are mutually exclusive — alias is "
                "identity reuse; dispatch is container fan-out (Wave-1 W2-α Q3)"
            )

        if self.precedence < 10 and self.manifest_source != "_system":
            raise ValueError(
                f"precedence={self.precedence}: range [0,9] is RESERVED for "
                "_system manifests (Wave-1 S3 §1)"
            )

        if self.detection.always_matches and self.manifest_source != "_system":
            raise ValueError(
                "detection.always_matches=True is reserved for the _system "
                "linux_blob sentinel (Wave-1 S1 §3)"
            )

        if (self.detection.sort_tier in ("floor", "ceiling")
                and self.manifest_source != "_system"):
            raise ValueError(
                f"detection.sort_tier={self.detection.sort_tier!r} is RESERVED "
                f"to manifest_source='_system' (P3.2 Wave-2 §SC5 dual): loader "
                f"path cross-check enforces _system disk tier; this validator "
                f"catches authoring drift at parse time"
            )

        for sig in self.detection.signals:
            if (sig.kind == "magic_bytes"
                    and sig.bytes_hex
                    and len(sig.bytes_hex) <= 4
                    and self.precedence < 5000):
                raise ValueError(
                    f"format {self.format_id!r}: magic_bytes <=2 bytes "
                    f"(e.g. PE/MZ) requires precedence >= 5000 to avoid "
                    "false-positive cascade (Wave-1 S1 §3)"
                )
            # P3.2.b A8 (Wave-2 W2-β) — high-collision text_format floor.
            # An operator-supplied text_format signal with permissive
            # charset (ascii_printable) matches arbitrary text files;
            # require precedence>=5000 OR _system source to prevent the
            # "always_matches without the flag" attack surface.
            if (sig.kind == "text_format"
                    and sig.text_format_constraint is not None
                    and sig.text_format_constraint.charset == "ascii_printable"
                    and self.manifest_source != "_system"
                    and self.precedence < 5000):
                raise ValueError(
                    f"format {self.format_id!r}: text_format with charset="
                    f"'ascii_printable' from non-_system source requires "
                    f"precedence >= 5000 to avoid false-positive cascade "
                    f"on arbitrary text files (Wave-2 W2-β §SC5-NEW-2 A8)"
                )

        return self


# ---------------------------------------------------------------------------
# Runtime / snapshot models.
# ---------------------------------------------------------------------------


class FormatMatch(BaseModel):
    """A single match candidate returned by the resolver.

    Serializable for both DB persistence (Rule #35c JSONB normaliser) and
    MCP tool output. ``evidence`` carries per-signal breakdown so operators
    can audit confidence.
    """

    format_id: str
    confidence_score: float = Field(ge=0.0, le=100.0)
    evidence: list[dict] = Field(default_factory=list)
    manifest_source: ManifestSource
    source_path: str

    model_config = ConfigDict(extra="forbid")


__all__ = [
    "Combine",
    "Confidence",
    "DeprecationStatus",
    "Deprecation",
    "DetectedFormat",
    "Detection",
    "DetectionSignal",
    "DetectionSignalKind",
    "Dispatch",
    "DispatchKind",
    "EvaluationMode",
    "ExternalManifestsPolicy",
    "ExternalManifestsPolicyBlock",
    "ExtractionCapability",
    "FileFormatManifest",
    "FormatMatch",
    "ManifestSource",
    "OverlayMode",
    "Output",
    "Plugin",
    "PluginBind",
    "PluginDisagreement",
    "PluginFallback",
    "PluginRef",
    "PluginRole",
    "PluginSideEffects",
    "PreUploadHint",
    "ProvenanceStub",
    "Refinement",
    "SortTier",
    "SubstringInHeadCombine",
    "SubstringInHeadConstraint",
    "TextFormatCharset",
    "TextFormatConstraint",
    "TextFormatFirstLine",
    "TextFormatLineTerminator",
    "TieBreaker",
    "VendorAuthority",
    "VendorPrecedence",
]
