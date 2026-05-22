"""ICS protocol decoder manifest schema — closed-grammar Pydantic Literals.

Third application of CLAUDE.md Rule #52 (closed-grammar schema-driven
discipline) after bare-metal MCU/DSP (instance #1) and file-format YAML
registry (instance #2). When Session 2 ships the walker + MCP tools +
plugins, this surface promotes Rule #52 from Rule-of-Two to Rule-of-Three
DURABLE BEYOND DEBATE.

Operator-extensible YAML at
``backend/app/services/ics_protocol_catalog/data/ics_protocols/<vendor>/<protocol>.yaml``
(in-tree, ``manifest_source: core``) or
``backend/app/services/ics_protocol_catalog/data/ics_protocols.local/<protocol>.yaml``
(operator overlay, ``manifest_source: operator``). Hot-reload on mtime
change via :class:`app.utils.yaml_cache.MtimeCachedYamlLoader` — no docker
restart for YAML edits.

**Hard rule (CLAUDE.md Rule #52):** the YAML is DATA. NO ``regex`` /
``script`` / ``template`` / ``vql`` / ``lua`` / ``expression`` /
``predicate`` / ``eval`` keys EVER. Every extensible field is either a
FREE STRING (taxonomy: vendor, protocol_version, vendor_product) or a
CLOSED LITERAL (executable semantics). Plugin references are REGISTRY
NAMES looked up at snapshot construction, never Python import paths
(deferred to Session 2 plugin escape hatch).

Extending the grammar requires:

1. Rule #25 single-slice cross-stack alignment commit (DB CHECK ↔
   Pydantic ``Literal`` ↔ frontend ``Record`` mirror + alignment test).
2. Rule #46 paired META-CANARY confirming the new value lands through
   the gate (exhaustive + paired gate-canary).
3. Code review of the new ``ref`` in the resolver's registry constant.

Three-level hierarchy (Session 1 scope):

    IcsProtocolManifest        # one YAML file per protocol detection
      ├─ IcsDetection          # how to recognise this protocol stack
      │   └─ IcsDetectionSignal  # cost-sorted by resolver, NOT YAML order
      ├─ IcsOutput             # what the classifier emits when matched
      └─ Deprecation           # lifecycle field (reused from file_format)

Session 2 scope (deferred): Plugin sub-model + PluginRef registry +
Refinement block + Dispatch block + ProvenanceStub + ExternalManifestsPolicy.

**Adaptability surface** (user direction repeated 4+ sessions):
operators drop a new YAML at the partner/operator tier; the next catalog
load picks it up; no docker restart; no Python edit. Taxonomy fields
(vendor, vendor_product, protocol_version) are FREE STRINGS so partners
contribute medical / ICS / OT formats without core merges.

Cross-feature loader validators (Wave-2 β; live in
``app/services/ics_protocol_catalog/catalog.py`` because they require
catalog state):

* I1: when mode=override, override-source's manifest_source rank MUST be
  >= override-target's manifest_source rank (mirror file_format A1).
* I2: vendor_authority is DERIVED from THIS manifest's manifest_source
  (mirror file_format A2).
* I3: REJECT catalog load if any dispatch.cases.* target has
  ``deprecation.status == "removed"`` (mirror file_format A3; for ICS
  catalog WARN downgrade per Wave-2 W2-β §SC5-NEW-ICS-3 risk).
* I4: REJECT cross-vendor same-precedence same-magic collision unless
  manifest_source differs (mirror file_format A4).
* I5: depth_max + eager-expensive plugin (defer to Session 2 when
  plugins ship; placeholder gate).
* I6: dispatch-rank-monotonicity (defer to Session 2 with dispatch).
* I7: plugin-namespace-disjointness (defer to Session 2 with plugins).
* I8-I13: high-collision floor + transport-port × protocol-family
  agreement + F-FORENSIC-10 narrowing + refinement guards + cycle
  detection (defer to Session 2 with full surface).

Wave-1 + Wave-2 research summarised at
``.planning/research/ics-protocol-2026-05-20/``.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------
# Closed-grammar Literal enumerations.
# Adding values requires Rule #25 + Rule #46 discipline — see module docstring.
# ---------------------------------------------------------------------------


#: Manifest provenance source. Drives precedence arbitration when N manifests
#: declare the same protocol or overlapping detection signatures. Mirror of
#: ``file_format.ManifestSource``. Loader cross-checks declared value against
#: on-disk path; mismatch → REJECT at load.
#:
#: Rank semantics (resolver ``_SOURCE_PRECEDENCE``):
#:    _system:                 100   # data/ics_protocols/_system/ ONLY
#:    core:                     80   # data/ics_protocols/<vendor>/
#:    operator:                 60   # data/ics_protocols.local/
#:    attested_external:        40   # external partner manifest, signed
#:    unauthenticated_external: 20   # external partner manifest, unsigned
IcsManifestSource = Literal[
    "_system",
    "core",
    "operator",
    "attested_external",
    "unauthenticated_external",
]


#: ICS protocol family. Closed Literal — adding a value requires Rule #25
#: single-slice cross-stack alignment commit (DB CHECK + Pydantic Literal +
#: frontend Config mirror). v0 ships with 3 protocols; subsequent Rule #25
#: Shape-1 commits add OPC-UA Binary + BACnet/IP + IEC-104 + EtherNet/IP +
#: Profinet + IEC-61850 MMS + EtherCAT + DLMS-COSEM + FINS + MELSEC.
#:
#: ``unknown_ics`` is the catch-all when a plugin (Session 2) detects an ICS
#: stack but cannot identify the family — reserved for plugin escape hatch.
IcsProtocolFamily = Literal[
    "modbus_tcp",        # Modbus/TCP (RFC-style, IANA port 502)
    "modbus_rtu",        # Modbus RTU over serial (RS-485)
    "dnp3",              # DNP3 / IEEE 1815, IANA port 20000
    "s7comm",            # Siemens S7Comm / S7Comm-Plus over TPKT/COTP, port 102
    "unknown_ics",       # plugin-detected; family TBD (Session 2)
]


#: Protocol-stack layer where the detection signal fires. Operator may declare
#: a single manifest detecting either the application layer (function codes /
#: object types) or transport (port + magic bytes). Mirror of OSI layer model.
IcsLayer = Literal[
    "application",       # function codes, object types, message types
    "transport",         # TCP/UDP port + TPKT/COTP transport magic
    "data_link",         # EtherType (0x88A4 EtherCAT; 0x8892 Profinet RT) (Session 2)
    "session",           # OPC-UA SecureChannel session (Session 2)
]


#: Transport binding declared by the manifest. ``serial_rs485`` covers Modbus
#: RTU + BACnet MS/TP. ``any`` lets a manifest match irrespective of binding
#: (intended for application-layer-only signals like function-code tables).
IcsTransport = Literal[
    "tcp",
    "udp",
    "ethernet_raw",
    "serial_rs485",
    "any",
]


#: Cost-sorted detection-signal kinds. Resolver evaluates signals in cost-class
#: order, NOT YAML declaration order (Wave-1 S5 attack O — I/O cost
#: amplification DoS). Each value maps to a Python evaluator in
#: :data:`app.services.ics_protocol_catalog.SIGNAL_EVALUATORS`. Exhaustive
#: dispatch is Rule #46 META-CANARY enforced.
#:
#: Cost-class groupings (resolver constant ``_SIGNAL_COST_CLASS``):
#:    zero:      port_signature, path_context (bounded; pre-flight only)
#:    cheap:     magic_bytes (≤512 bytes head read)
#:    mid:       function_code_set, library_symbol
#:    expensive: string_in_binary (literal substring scan over head window)
#:
#: Session 2 will add: oid_or_object_type (OPC-UA NodeId), config_file_path,
#: always_matches (plugin escape hatch).
IcsSignalKind = Literal[
    "magic_bytes",          # bytes at fixed offset (e.g. S7Comm 0x32 at offset 0)
    "port_signature",       # IANA-assigned default port present in .rodata
    "function_code_set",    # protocol-specific function-code lookup table
    "string_in_binary",     # literal byte-substring scan over head window
    "library_symbol",       # ELF dynsym / PE import substring (Session 2 plugin)
]


#: Artefact source the signal applies to. Useful when a manifest's signals
#: target different artefact families (e.g. magic_bytes for embedded blobs,
#: string_in_binary for shared-library .rodata). ``any`` = match irrespective.
IcsArtifactSource = Literal[
    "binary",          # ELF / PE / static blob (string + library_symbol)
    "config_file",     # /etc/*.conf, *.xml capture (Session 2 — adds path_context)
    "embedded_blob",   # raw firmware blob (magic in payload)
    "any",
]


#: Detection certainty band emitted on IcsOutput. Caps the operator-facing
#: confidence label per the strength of the underlying evidence:
#:    ``stack_present``  — binary symbols / function-code table — DEFINITELY ships ICS stack
#:    ``config_present`` — config file mentions protocol but binary unproven
#:    ``string_only``    — substring mention only; not load-bearing evidence
#:
#: Maps to Confidence at IcsOutput rendering — string_only → low; stack_present
#: → high; config_present → medium.
IcsCertainty = Literal[
    "stack_present",
    "config_present",
    "string_only",
]


#: Signal-combination semantics within ONE manifest's detection block. Mirror
#: of ``file_format.Combine``.
IcsCombine = Literal[
    "all_required",
    "any",
    "weighted",
]


#: Confidence band emitted on IcsOutput. Mirror of ``file_format.Confidence``.
IcsConfidence = Literal["high", "medium", "low"]


#: Lifecycle state for the protocol entry itself. Mirror of
#: ``file_format.DeprecationStatus``.
IcsDeprecationStatus = Literal["active", "deprecated", "removed"]


#: Vendor authority derived from manifest_source (Wave-1 S5 H + Wave-2 W2-β
#: §SC5-NEW-ICS-1 mitigation). Mirror of ``file_format.VendorAuthority``.
#: ``curated`` is reserved to ``_system`` + ``core``; ``operator_supplied``
#: covers operator + attested_external; ``community`` covers unauthenticated_
#: external. CVE matcher reads `curated` only — operator-supplied is
#: informational only.
IcsVendorAuthority = Literal["curated", "operator_supplied", "community"]


# ---------------------------------------------------------------------------
# Detection sub-models — closed-grammar evaluators.
# ---------------------------------------------------------------------------


class IcsStringInBinaryConstraint(BaseModel):
    """Closed-grammar literal-substring scan over the binary head window.

    Mirrors the file_format ``SubstringInHeadConstraint`` shape from the P3.x
    ``substring_in_head`` signal kind shipped 2026-05-20. Every needle is a
    literal hex-encoded byte sequence; NO regex anywhere. The case_sensitive
    flag toggles a ``bytes.lower()`` pre-normalisation; it does NOT enable
    any matching DSL.

    Rule #52 hard rule: NO regex / script / template / eval / lua / vql /
    predicate / expression. Every needle is verbatim bytes.
    """

    needles_hex: list[str] = Field(
        min_length=1, max_length=16,
        description="Lowercase hex-encoded byte needles. Each entry: even "
                    "length, min 2 bytes (4 hex chars), max 64 bytes (128 "
                    "hex chars). 16-needle max bounds evaluator cost class "
                    "(Wave-1 S5 attack O floor). Literal verbatim substring "
                    "search; NO regex.",
    )
    case_sensitive: bool = Field(
        default=False,
        description="When False (default), evaluator lower-cases the head "
                    "window AND the needles before comparison — ASCII bytes "
                    "only; non-ASCII bytes pass through unchanged. When True, "
                    "exact byte match.",
    )
    combine: Literal["any", "all"] = Field(
        default="any",
        description="``any`` — match when at least ``min_count`` needles are "
                    "present. ``all`` — match only when EVERY needle is "
                    "present (overrides min_count).",
    )
    min_count: int = Field(
        default=1, ge=1, le=16,
        description="Minimum needle hits required when combine='any'. "
                    "Ignored when combine='all'. min_count<=len(needles_hex) "
                    "enforced by validator.",
    )
    search_offset: int = Field(
        default=0, ge=0, le=2**16,
        description="Byte offset where the head-window search starts.",
    )
    search_length: int | None = Field(
        default=None, ge=64, le=2**20,
        description="Length of the head window to scan. None scans from "
                    "``search_offset`` to end of available head bytes.",
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_needles(self) -> IcsStringInBinaryConstraint:
        for i, needle in enumerate(self.needles_hex):
            if len(needle) % 2 != 0:
                raise ValueError(
                    f"string_in_binary.needles_hex[{i}]: odd hex length "
                    f"{len(needle)} (not byte-aligned)"
                )
            if len(needle) < 4:
                raise ValueError(
                    f"string_in_binary.needles_hex[{i}]: min 2 bytes "
                    f"(4 hex chars); got {len(needle)} chars."
                )
            if len(needle) > 128:
                raise ValueError(
                    f"string_in_binary.needles_hex[{i}]: max 64 bytes "
                    f"(128 hex chars); got {len(needle)} chars"
                )
            try:
                bytes.fromhex(needle)
            except ValueError as exc:
                raise ValueError(
                    f"string_in_binary.needles_hex[{i}]: invalid hex: {exc}"
                ) from exc
        if self.min_count > len(self.needles_hex):
            raise ValueError(
                f"string_in_binary: min_count={self.min_count} > "
                f"len(needles_hex)={len(self.needles_hex)} — impossible"
            )
        return self


class IcsFunctionCodeSetConstraint(BaseModel):
    """Closed-grammar function-code lookup-table fingerprint.

    Detects protocol stacks by the presence of a function-code dispatch
    table in the binary's ``.rodata`` or ``.text``. Each protocol declares
    its standard function codes (Modbus 0x01..0x18, DNP3 object groups,
    S7Comm job codes 0x04/0x05/0x1A, etc.). The evaluator scans for a
    sorted-ascending byte sequence containing ``min_count`` of the declared
    codes within a bounded window.

    Wave-2 W2-β §SC5-NEW-ICS-2 mitigation: ``min_count`` floor of 2 forces
    co-occurrence; operator cannot declare a single-byte trigger.
    """

    function_codes_hex: list[str] = Field(
        min_length=2, max_length=64,
        description="Lowercase hex-encoded function-code bytes (single byte "
                    "each). Min 2 to prevent single-byte triggers (W2-β A8 "
                    "high-collision floor). Max 64 caps evaluator cost.",
    )
    min_count: int = Field(
        default=2, ge=2, le=64,
        description="Minimum function-code matches required in a bounded "
                    "window. Floor of 2 prevents single-byte triggers.",
    )
    window_bytes: int = Field(
        default=512, ge=64, le=4096,
        description="Byte-window length within which min_count codes must "
                    "appear contiguously / proximally.",
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_codes(self) -> IcsFunctionCodeSetConstraint:
        for i, code in enumerate(self.function_codes_hex):
            if len(code) != 2:
                raise ValueError(
                    f"function_code_set.function_codes_hex[{i}]: must be "
                    f"exactly 2 hex chars (1 byte); got {len(code)} chars"
                )
            try:
                bytes.fromhex(code)
            except ValueError as exc:
                raise ValueError(
                    f"function_code_set.function_codes_hex[{i}]: invalid "
                    f"hex: {exc}"
                ) from exc
        if self.min_count > len(self.function_codes_hex):
            raise ValueError(
                f"function_code_set: min_count={self.min_count} > "
                f"len(function_codes_hex)={len(self.function_codes_hex)}"
            )
        return self


class IcsDetectionSignal(BaseModel):
    """One detection signal — closed kinds, cost-sorted at evaluation.

    NO regex anywhere. ``needles_hex``, ``bytes_hex``, and ``function_codes_hex``
    are literal byte sequences searched verbatim. Wave-1 size caps + element-
    length floors (S3 §2) enforced by Field constraints below.
    """

    kind: IcsSignalKind
    weight: float = Field(
        default=1.0, ge=0.0, le=1.0,
        description="Contribution under combine=weighted; ignored otherwise",
    )
    artifact_source: IcsArtifactSource = Field(
        default="any",
        description="Restrict the signal to a specific artefact family. "
                    "Default 'any' means the signal evaluates regardless.",
    )

    # magic_bytes
    offset: int | None = Field(
        default=None, ge=0, le=2**32 - 1,
        description="Byte offset for magic_bytes; <=4GB.",
    )
    bytes_hex: str | None = Field(
        default=None, max_length=1024,
        description="Lowercase hex; <=512 bytes (1024 hex chars).",
    )
    mask_hex: str | None = Field(
        default=None, max_length=1024,
        description="Optional bitmask; same length as bytes_hex.",
    )

    # port_signature
    ports: list[int] | None = Field(
        default=None, max_length=8,
        description="IANA-assigned default ports the protocol listens on.",
    )
    transport_required: IcsTransport | None = Field(
        default=None,
        description="When set, port_signature ALSO requires the manifest to "
                    "declare matching transport (mitigation for W2-β port-"
                    "aliasing attack #2).",
    )

    # function_code_set
    function_code_constraint: IcsFunctionCodeSetConstraint | None = Field(
        default=None,
        description="Closed-grammar function-code lookup-table fingerprint. "
                    "REQUIRED when kind == 'function_code_set'; rejected "
                    "otherwise.",
    )

    # string_in_binary
    string_in_binary_constraint: IcsStringInBinaryConstraint | None = Field(
        default=None,
        description="Closed-grammar substring-in-binary constraint set. "
                    "REQUIRED when kind == 'string_in_binary'; rejected "
                    "otherwise.",
    )

    # library_symbol (Session 2 ELF/PE symbol scanner)
    symbol_patterns_lower: list[str] | None = Field(
        default=None, max_length=32,
        description="ELF dynsym / PE import substring patterns (lowercased; "
                    "literal substring match). Min 5 chars per entry to "
                    "prevent generic matches. Session 2 ELF/PE plugin "
                    "consumes these.",
    )

    description: str | None = Field(default=None, max_length=256)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_kind_fields(self) -> IcsDetectionSignal:
        if self.kind == "magic_bytes":
            if self.bytes_hex is None or self.offset is None:
                raise ValueError(
                    "magic_bytes signal: bytes_hex AND offset are REQUIRED"
                )
            if len(self.bytes_hex) % 2 != 0:
                raise ValueError(
                    "magic_bytes: bytes_hex must have even length"
                )
            if len(self.bytes_hex) < 4:
                raise ValueError(
                    "magic_bytes: minimum 2 bytes (4 hex chars). Negative-"
                    "evidence formats MUST set precedence >= 5000."
                )
            try:
                bytes.fromhex(self.bytes_hex)
            except ValueError as exc:
                raise ValueError(
                    f"magic_bytes: invalid bytes_hex: {exc}"
                ) from exc
            if self.mask_hex is not None:
                if len(self.mask_hex) != len(self.bytes_hex):
                    raise ValueError(
                        "magic_bytes: mask_hex length mismatch with bytes_hex"
                    )
                if all(c == "0" for c in self.mask_hex):
                    raise ValueError(
                        "magic_bytes: mask_hex all-zero matches everything"
                    )

        if self.kind == "port_signature":
            if not self.ports:
                raise ValueError(
                    "port_signature signal: ports list is REQUIRED"
                )
            for p in self.ports:
                if not (0 < p <= 65535):
                    raise ValueError(
                        f"port_signature.ports: {p} is not a valid TCP/UDP port"
                    )

        if (self.kind == "function_code_set"
                and self.function_code_constraint is None):
            raise ValueError(
                "function_code_set signal: function_code_constraint is REQUIRED"
            )
        if (self.function_code_constraint is not None
                and self.kind != "function_code_set"):
            raise ValueError(
                f"function_code_constraint set but kind={self.kind!r} — "
                "constraint only meaningful for kind='function_code_set'"
            )

        if (self.kind == "string_in_binary"
                and self.string_in_binary_constraint is None):
            raise ValueError(
                "string_in_binary signal: string_in_binary_constraint is REQUIRED"
            )
        if (self.string_in_binary_constraint is not None
                and self.kind != "string_in_binary"):
            raise ValueError(
                f"string_in_binary_constraint set but kind={self.kind!r} — "
                "constraint only meaningful for kind='string_in_binary'"
            )

        if self.kind == "library_symbol":
            if not self.symbol_patterns_lower:
                raise ValueError(
                    "library_symbol signal: symbol_patterns_lower is REQUIRED"
                )
            for i, sym in enumerate(self.symbol_patterns_lower):
                if len(sym) < 5:
                    raise ValueError(
                        f"library_symbol.symbol_patterns_lower[{i}]: min 5 "
                        f"chars; got {len(sym)}"
                    )
                if sym != sym.lower():
                    raise ValueError(
                        f"library_symbol.symbol_patterns_lower[{i}]: must be "
                        "lowercased"
                    )

        return self


class IcsDetection(BaseModel):
    """Detection block — how to recognise this ICS protocol stack.

    ``signals`` is preserved in declaration order for serialization /
    documentation purposes only. The resolver SORTS by cost class at
    evaluation time (Wave-1 S5 attack O — I/O cost amplification DoS closed).
    """

    combine: IcsCombine = Field(
        default="all_required",
        description="all_required -> AND; any -> OR; weighted -> score floor",
    )
    signals: list[IcsDetectionSignal] = Field(
        min_length=1, max_length=16,
        description="Cost-sorted at evaluation by resolver — declaration "
                    "order is documentation only.",
    )
    min_confidence_score: float | None = Field(
        default=None, ge=0.0, le=100.0,
        description="REQUIRED when combine=weighted; sum-of-(weight*match) "
                    "floor.",
    )
    certainty: IcsCertainty = Field(
        default="stack_present",
        description="Caps the IcsOutput.confidence at evaluation. "
                    "string_only → low; config_present → medium; "
                    "stack_present → high.",
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_combine(self) -> IcsDetection:
        if self.combine == "weighted" and self.min_confidence_score is None:
            raise ValueError(
                "detection.combine=weighted requires min_confidence_score"
            )
        return self


class IcsOutput(BaseModel):
    """What the catalog emits when this protocol matches a binary.

    Free-string taxonomy fields (vendor + vendor_product + protocol_version)
    per Rule #52 free-string-taxonomy discipline. Operator can ship a YAML
    declaring ``vendor: codesys`` without a core merge.
    """

    protocol_family: IcsProtocolFamily
    layer: IcsLayer
    transport: IcsTransport
    vendor: str = Field(
        min_length=1, max_length=64,
        description="Free-string vendor identifier (e.g. 'schneider', "
                    "'siemens', 'rockwell'). Operator extensible; CVE matcher "
                    "consumes vendor_authority derived from manifest_source, "
                    "NOT from this free string (Wave-2 §SC5-NEW-ICS-1 fix).",
    )
    vendor_product: str | None = Field(
        default=None, max_length=64,
        description="Vendor product identifier (e.g. 'modicon_m340', "
                    "'simatic_s7_1500', 'compactlogix_5380').",
    )
    protocol_version: str | None = Field(
        default=None, max_length=32,
        description="Detected protocol version (e.g. 'v3.6', 'MBAP-1', "
                    "'S7Comm-Plus-v0.6'). Optional — version is often "
                    "extracted by deeper plugin in Session 2.",
    )
    confidence: IcsConfidence = Field(
        default="medium",
        description="Capped by IcsDetection.certainty at evaluation. The "
                    "operator-supplied value is the CEILING; resolver "
                    "downgrades per certainty.",
    )

    model_config = ConfigDict(extra="forbid")


class IcsDeprecation(BaseModel):
    """Lifecycle state for the protocol entry.

    Mirror of file_format.Deprecation. Status ``removed`` triggers I3 gate
    rejection (REJECT at catalog load — WARN downgrade per W2-β
    §SC5-NEW-ICS-3 mitigation when ICS catalog matures).
    """

    status: IcsDeprecationStatus = "active"
    replaced_by: str | None = Field(default=None, max_length=64)
    sunset_at: str | None = Field(
        default=None, max_length=64,
        description="ISO date string when this entry will be removed.",
    )
    notes: str | None = Field(default=None, max_length=512)

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Top-level manifest.
# ---------------------------------------------------------------------------


class IcsProtocolManifest(BaseModel):
    """Top-level ICS protocol manifest — one YAML file per detection entry.

    Loaded from ``data/ics_protocols/<vendor>/<protocol>.yaml`` or the
    ``data/ics_protocols.local/`` overlay. Validated by this Pydantic model
    at catalog construction; cross-feature gates (I1-I13 in catalog.py)
    apply additional invariants requiring catalog state.

    **Rule #52 closed-grammar invariants:**
    * ``manifest_id`` must match ``^[a-z][a-z0-9_]*$`` (no path traversal).
    * ``manifest_source`` is a closed Literal; loader path cross-check
      rejects mismatches (Wave-2 W2-β §SC5-NEW-ICS-4 mitigation).
    * ``precedence`` floor: [0, 9] is RESERVED to ``_system``; loader
      rejects core/operator/external manifests with ``precedence < 10``.
    * No regex / script / template / eval / lua / vql / predicate /
      expression keys ANYWHERE in the model tree (`extra='forbid'`).
    """

    schema_version: Literal[1] = 1
    manifest_id: str = Field(
        ..., pattern=r"^[a-z][a-z0-9_]*$", max_length=64,
        description="Globally-unique identifier; mirrors filename stem.",
    )
    manifest_source: IcsManifestSource
    precedence: int = Field(
        default=100, ge=0, le=10_000,
        description="Numeric precedence within the same manifest_source "
                    "tier. Lower precedence wins (Wave-1 S2 precedence-flip "
                    "P3.2.a). [0, 9] RESERVED to _system.",
    )

    detection: IcsDetection
    output: IcsOutput
    deprecation: IcsDeprecation = Field(default_factory=IcsDeprecation)

    notes: str | None = Field(default=None, max_length=8192)
    references: list[str] = Field(
        default_factory=list, max_length=16,
        description="External documentation references (RFC, NIST, spec).",
    )

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _check_precedence_floor(self) -> IcsProtocolManifest:
        if self.precedence < 10 and self.manifest_source != "_system":
            raise ValueError(
                f"precedence={self.precedence} reserved to manifest_source="
                "'_system' (Wave-1 S3 §1; precedence floor [0,9] is for "
                "wairz invariants only). Use precedence >= 10."
            )
        return self


# ---------------------------------------------------------------------------
# Catalog snapshot + match result types.
# ---------------------------------------------------------------------------


class IcsProtocolMatch(BaseModel):
    """Result type emitted by the resolver when a manifest matches.

    Resolver returns ``list[IcsProtocolMatch]`` (vs file_format's single
    ``FormatMatch``) because a binary can speak N protocols simultaneously
    (Modbus + OPC-UA + DNP3 in one HMI is real-world; Wave-1 Scout A
    cardinality observation).
    """

    manifest_id: str
    manifest_source: IcsManifestSource
    protocol_family: IcsProtocolFamily
    layer: IcsLayer
    transport: IcsTransport
    vendor: str
    vendor_product: str | None
    protocol_version: str | None
    confidence: IcsConfidence
    certainty: IcsCertainty
    matched_signals: list[str] = Field(
        default_factory=list,
        description="The kind() values of signals that fired, in evaluation "
                    "order. Used for operator-facing evidence rendering.",
    )

    model_config = ConfigDict(extra="forbid")


__all__ = [
    "IcsCertainty",
    "IcsCombine",
    "IcsConfidence",
    "IcsDeprecation",
    "IcsDeprecationStatus",
    "IcsDetection",
    "IcsDetectionSignal",
    "IcsFunctionCodeSetConstraint",
    "IcsLayer",
    "IcsManifestSource",
    "IcsOutput",
    "IcsProtocolFamily",
    "IcsProtocolManifest",
    "IcsProtocolMatch",
    "IcsSignalKind",
    "IcsArtifactSource",
    "IcsStringInBinaryConstraint",
    "IcsTransport",
    "IcsVendorAuthority",
]
