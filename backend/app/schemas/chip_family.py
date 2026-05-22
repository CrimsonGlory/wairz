"""Chip-family manifest schema — closed-grammar Pydantic Literals.

Operator-extensible YAML at
``backend/app/services/hardware_firmware/data/chip_families/<vendor>/<family>.yaml``
loaded via :class:`app.utils.yaml_cache.MtimeCachedYamlLoader` and validated
against the models in this file. Hot-reload on mtime change (no docker
restart for YAML edits).

**Hard rule (CLAUDE.md Rule #52 — schema-driven discipline):** the YAML is
DATA. NO ``regex`` / ``script`` / ``template`` / ``vql`` / ``lua`` /
``expression`` / ``predicate`` keys EVER. Every extensible field is a CLOSED
LITERAL. Extending the grammar requires:

1. Rule #25 single-slice cross-stack alignment commit (DB CHECK ↔ Pydantic
   ``Literal`` ↔ frontend ``Record`` mirror + alignment test).
2. Rule #46 META-CANARY confirming the new value lands through the gate.
3. Code review of the new ``semantic`` in the walker's ``SEMANTIC_REGISTRY``.

This bound is the durable defense against the YAML becoming a programming
language (Scout CC §SC7 attack-surface review 2026-05-19; see
:file:`.planning/knowledge/baremetal-mcu-converged-design-2026-05-19-*`).

Three-level hierarchy (Scout CC §SC1 — composite SoCs):

    ChipFamilyManifest          # one YAML file per chip family
      └─ Domain                 # one execution domain (ISA + address space)
          └─ AddressRegion      # one memory region with semantic + policy

Composite SoCs (NXP S32G, TI Sitara AM62x, NVIDIA Tegra) declare N domains
under one family file; ``hardware_firmware_blobs.chip_target`` references a
``"<vendor>/<family>/<domain>"`` triple, not just the family.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Closed-grammar Literal enumerations.
# Adding values requires Rule #25 + Rule #46 discipline — see module docstring.
# ---------------------------------------------------------------------------

#: Address-region semantic taxonomy. Each value maps to a ``SemanticHandler``
#: in :data:`app.services.bare_metal_walker.SEMANTIC_REGISTRY`. Adding a value
#: REQUIRES wiring a handler in the walker + Rule #25 cross-stack alignment.
RegionSemantic = Literal[
    "flash_code",
    "flash_data",
    "boot_rom",
    "boot_assist_module",
    "sram",
    "otp",
    "security_password",          # generic password-protected debug-unlock
    "security_password_csm",      # TI C28x dummy-read CSM (0xFFFF = unlocked)
    "security_password_rdp",      # STM32 RDP-style
    "vector_table",
    "peripheral_register",
    "encrypted_region",           # walker SKIPS policy audit (Rule #45)
    "signed_code_region",
    "mpu_protected",
    "hsm_sram",
    "reserved",
]

#: Policy-rule operators. Each maps to a Python evaluator in
#: :data:`app.services.bare_metal_walker.POLICY_EVALUATORS`. NO operator-supplied
#: expression strings (Scout CC §SC7 — hard cap).
PolicyOperator = Literal[
    "unsecure_when_all_words_equal",
    "unsecure_when_any_word_equal",
    "perma_lock_when_all_words_equal",
    "required_value_at_offset",
    "forbidden_value_at_offset",
    "entropy_floor",
    "entropy_ceiling",
    "informational",
]

#: Endianness — closed enum. Per-region overrides allowed (Scout CC §SC16
#: mid-firmware endian flip).
Endianness = Literal["little", "big", "mixed_be8", "bi_endian"]

#: Access mode. Informational + future Ghidra hint passthrough.
RegionAccess = Literal[
    "read-execute",
    "read-only",
    "read-write",
    "write-once",
    "secret",                     # read-once via dummy-read (CSM-style)
]

#: Architecture identifier. Decoupled from the Ghidra processor string so a
#: chip family can declare its conceptual arch even when Ghidra lacks a SLEIGH
#: spec (e.g. TI C28x today). Adding values requires Rule #25 cross-stack
#: alignment.
Arch = Literal[
    "arm-cortex-m",
    "arm-cortex-m-pcrop",         # boot-time decrypt variant
    "arm-cortex-a",
    "arm-cortex-r",
    "thumb",
    "thumb2",
    "aarch64",
    "mips",
    "mipsel",
    "powerpc",
    "powerpc-vle",                # NXP SPC58 / e200 cores
    "powerpc-spe",
    "tms320c28x",                 # TI Piccolo / Delfino — 16-bit word-addressed
    "tms320c54x",
    "tms320c55x",
    "tms320c6000",
    "msp430",
    "msp430x",
    "avr",
    "pic16",
    "pic18",
    "pic24",
    "pic32",
    "riscv32",
    "riscv64",
    "tensilica-xtensa",           # ESP32 family
    "tricore",                    # Infineon
    "blackfin",                   # ADI
    "adsp-21xxx",                 # ADI SHARC — 24/40-bit hybrid
    "unknown",
]

#: Ghidra ``-processor`` allowlist. NOT a free string — operator-supplied YAML
#: cannot trigger an arbitrary Ghidra plugin load (Scout CC §SC8). The walker
#: passes this verbatim to ``analyzeHeadless`` via ``ghidra_service``.
GhidraProcessor = Literal[
    "ARM:LE:32:Cortex",
    "ARM:LE:32:default",
    "ARM:BE:32:default",
    "ARM:LE:32:v7",
    "AARCH64:LE:64:v8A",
    "MIPS:LE:32:default",
    "MIPS:BE:32:default",
    "PowerPC:BE:32:default",
    "PowerPC:BE:32:VLE",
    "TMS320C28x:LE:32:default",   # pending community SLEIGH; declared for forward use
    "MSP430:LE:16:default",
    "MSP430X:LE:32:default",
    "AVR8:LE:16:default",
    "PIC-16:LE:16:default",
    "PIC-18:LE:24:default",
    "RISCV:LE:32:default",
    "RISCV:LE:64:default",
    "Xtensa:LE:32:default",
    "TriCore:LE:32:default",
]

#: Detection-signal kinds. Closed set — each maps to a Python signal
#: evaluator in :mod:`app.services.hardware_firmware.matchers.yaml_driven`.
DetectionSignalKind = Literal[
    "silicon_id_byte_match",      # exact bytes at offset
    "reset_vector_at",            # plausible reset vector address in range
    "vector_table_shape",         # SP + ResetHandler + ISR ladder
    "string_present",             # literal byte sequences (NOT regex)
    "bam_signature",              # NXP SPC58 BAM RCHW
    "boot_header_magic",          # vendor-format boot headers
    "elf_magic",                  # rejects elf-shaped inputs upfront
    "entropy_band",               # min/max entropy for a region
]

#: Discovery mode for relocatable regions (Scout CC §SC4 — VTOR-relocated
#: Cortex-M vector tables, ``__data_load$`` runtime copies). When set, the
#: walker treats ``start`` as a fallback hint, not a contract.
RegionDiscovery = Literal[
    "scan_first_64kb_aligned_256",  # ARM Cortex-M VTOR-style scan
    "vtor_register_observed",       # explicit VTOR value carried in descriptor
    "ti_pie_vector_layout",         # TI C28x PIE table at 0x000D00
]

#: Descriptor provenance source. Drives arbitration when N descriptors compete
#: (Scout CC §SC11): operator > attested_external > unauthenticated_external >
#: auto_detection. Maps 1:1 to ``findings.source`` after walker emit.
DescriptorSource = Literal[
    "operator",
    "attested_external",
    "unauthenticated_external",
    "auto_detection",
]

#: File-to-memory packing — distinguishes on-disk byte layouts that look
#: identical at the file level but represent different memory contents (Scout
#: AA §1 attack-surface #2). A TI C28x flash dumped as ``ti_txt_native_word``
#: (one byte per address) vs ``two_bytes_per_word_le`` (canonical 16-bit-word
#: .bin) have entirely different byte sequences — detection scoring MUST
#: consume this.
Packing = Literal[
    "one_byte_per_address",
    "two_bytes_per_word_le",
    "two_bytes_per_word_be",
    "ti_txt_native_word",
    "intel_hex_packed",
]


# ---------------------------------------------------------------------------
# Policy + region models.
# ---------------------------------------------------------------------------


class PolicyRule(BaseModel):
    """One policy enforcement on an address region.

    Closed-vocabulary by :attr:`operator`. The :attr:`value_hex` field is
    parsed into bytes/words by the walker, not the validator — schema
    validates STRUCTURE; walker validates SEMANTICS against the actual blob.
    """

    operator: PolicyOperator
    value_hex: str | None = None
    word_size_bits: int | None = Field(default=None, ge=1, le=64)
    offset: int | None = Field(default=None, ge=0)
    cwe_ids: list[int] = Field(default_factory=list, max_length=8)
    confidence: Literal["low", "medium", "high"] = "high"
    severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    finding_source: str | None = None      # e.g. ``c28x_unsecure_csm`` — validated by walker against findings.source allowlist
    description: str | None = Field(default=None, max_length=4096)

    model_config = {"extra": "forbid"}


class AddressRegion(BaseModel):
    """One memory region inside a chip's address space.

    Either :attr:`size` OR :attr:`end` MUST be declared (validator enforces).
    The ``packing`` (file-to-memory byte layout) is on the parent
    :class:`Domain`, not per-region — within one domain, packing is uniform.

    :attr:`alias_of` declares an alias relationship for dual-mapped flash /
    boot-region aliasing (Scout CC §SC6). The walker normalises aliased
    regions to canonical before policy evaluation.

    :attr:`discover` enables runtime-relocation discovery (Scout CC §SC4):
    e.g. ``scan_first_64kb_aligned_256`` tells the walker to scan for a
    plausible vector table rather than trusting :attr:`start` literally.
    """

    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    start: int = Field(ge=0, le=2**48 - 1)
    size: int | None = Field(default=None, ge=1, le=2**32)
    end: int | None = Field(default=None, ge=0, le=2**48 - 1)
    access: RegionAccess = "read-only"
    semantic: list[RegionSemantic] = Field(default_factory=list, max_length=8)
    policy: list[PolicyRule] = Field(default_factory=list, max_length=16)
    endianness_override: Endianness | None = None
    alias_of: str | None = None
    discover: RegionDiscovery | None = None
    active_when: dict[str, str] | None = None
    description: str | None = Field(default=None, max_length=4096)

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def _normalise_size_and_end(self) -> AddressRegion:
        if self.size is None and self.end is None:
            raise ValueError(f"region {self.name!r}: must declare size: or end:")
        if self.size is not None and self.end is not None:
            implied_end = self.start + self.size - 1
            if implied_end != self.end:
                raise ValueError(
                    f"region {self.name!r}: size and end disagree "
                    f"(start=0x{self.start:X}, size={self.size}, "
                    f"implied end=0x{implied_end:X}, declared end=0x{self.end:X})"
                )
        if self.end is None and self.size is not None:
            object.__setattr__(self, "end", self.start + self.size - 1)
        if self.size is None and self.end is not None:
            object.__setattr__(self, "size", self.end - self.start + 1)
        if self.active_when:
            for k, v in self.active_when.items():
                if k != "boot_mode":
                    raise ValueError(
                        f"region {self.name!r}: active_when key {k!r} not in "
                        f"closed set {{'boot_mode'}} (operator DSL not permitted)"
                    )
                if not isinstance(v, str) or not v:
                    raise ValueError(
                        f"region {self.name!r}: active_when[{k!r}] must be a "
                        f"non-empty string"
                    )
        return self


class GhidraImportParams(BaseModel):
    """Hints fed through to ``analyzeHeadless`` via ``ghidra_service``.

    :attr:`processor` is whitelist-bound (see :data:`GhidraProcessor`) so
    operator-supplied YAML cannot trigger arbitrary Ghidra plugin loads
    (Scout CC §SC8).
    """

    processor: GhidraProcessor
    loader: Literal["BinaryLoader", "ElfLoader", "PeLoader"] = "BinaryLoader"
    base_addr: int = Field(ge=0)
    entry_point: int | None = Field(default=None, ge=0)
    load_offset_in_file: int = Field(default=0, ge=0)
    load_length: int | None = Field(default=None, ge=1)
    cspec: str | None = Field(default=None, max_length=64)

    model_config = {"extra": "forbid"}


class DetectionSignal(BaseModel):
    """One detection signal — closed kinds, weighted contribution to confidence.

    No regex anywhere — :attr:`patterns` is a list of literal byte sequences
    searched verbatim (Scout CC §SC7 + §SC8).
    """

    kind: DetectionSignalKind
    weight: float = Field(ge=0.0, le=1.0)
    address: int | None = Field(default=None, ge=0)
    mask_hex: str | None = None
    bytes_hex: str | None = None
    patterns: list[str] | None = Field(default=None, max_length=32)
    entropy_min: float | None = Field(default=None, ge=0.0, le=8.0)
    entropy_max: float | None = Field(default=None, ge=0.0, le=8.0)
    region_name: str | None = None
    description: str | None = Field(default=None, max_length=256)

    model_config = {"extra": "forbid"}


class Domain(BaseModel):
    """One execution domain inside a chip complex — one ISA + address space.

    Composite SoCs (Scout CC §SC1: NXP S32G, TI Sitara AM62x, NVIDIA Tegra)
    carry N domains under one :class:`ChipFamilyManifest`. The
    ``hardware_firmware_blobs.chip_target`` FK references a
    ``"<vendor>/<family>/<domain>"`` triple, not just the family.

    Word-size geometry is per-domain rather than per-chip because Harvard
    architectures (PIC18, AVR) and DSPs with split buses (ADSP-21xxx, classic
    C5x) declare separate instruction/data widths (Scout CC §SC5).
    """

    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    arch: Arch
    endianness: Endianness
    instruction_word_bits: int = Field(ge=8, le=64)
    data_word_bits: int = Field(ge=8, le=64)
    address_bus_bits: int = Field(ge=8, le=64)
    packing: Packing = "one_byte_per_address"
    address_regions: list[AddressRegion] = Field(min_length=1, max_length=64)
    detection_signals: list[DetectionSignal] = Field(default_factory=list, max_length=16)
    ghidra_import_params: GhidraImportParams | None = None
    description: str | None = Field(default=None, max_length=4096)

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def _check_region_constraints(self) -> Domain:
        region_names = {r.name for r in self.address_regions}
        if len(region_names) != len(self.address_regions):
            seen: dict[str, int] = {}
            for r in self.address_regions:
                seen[r.name] = seen.get(r.name, 0) + 1
            dupes = sorted(n for n, c in seen.items() if c > 1)
            raise ValueError(
                f"domain {self.name!r}: duplicate region names {dupes!r}"
            )
        max_addr = (1 << self.address_bus_bits) - 1
        for r in self.address_regions:
            if r.alias_of and r.alias_of not in region_names:
                raise ValueError(
                    f"region {r.name!r}: alias_of={r.alias_of!r} does not match "
                    f"any region in domain {self.name!r}"
                )
            if r.end is None or r.end > max_addr:
                raise ValueError(
                    f"region {r.name!r}: end=0x{(r.end or 0):X} exceeds domain "
                    f"address_bus_bits={self.address_bus_bits} (max 0x{max_addr:X})"
                )
        non_alias = sorted(
            (r for r in self.address_regions if not r.alias_of),
            key=lambda r: r.start,
        )
        for prev, curr in zip(non_alias, non_alias[1:]):
            if prev.end is None or curr.start <= prev.end:
                raise ValueError(
                    f"domain {self.name!r}: regions {prev.name!r} "
                    f"(0x{prev.start:X}-0x{prev.end:X}) and {curr.name!r} "
                    f"(0x{curr.start:X}-0x{curr.end:X}) overlap; declare "
                    f"alias_of: if intentional, otherwise fix region bounds"
                )
        for sig in self.detection_signals:
            if sig.region_name and sig.region_name not in region_names:
                raise ValueError(
                    f"domain {self.name!r}: detection_signal references "
                    f"unknown region_name={sig.region_name!r}"
                )
        return self


class ChipFamilyManifest(BaseModel):
    """Top-level chip-family YAML manifest.

    One file per chip family (e.g. ``ti/tms320f28066.yaml``). Composite SoCs
    declare multiple :attr:`domains` under the same family.

    :attr:`schema_version` per Rule #35c: bump on breaking changes; older
    consumers WARN+skip via the loader rather than raising (graceful-degrade
    per Rule #34).
    """

    schema_version: int = 1
    vendor: str = Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_]*$")
    family: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    display_name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=8192)
    domains: list[Domain] = Field(min_length=1, max_length=8)
    references: list[str] = Field(default_factory=list, max_length=16)
    source_path: str | None = None     # set by loader, not authored manually

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def _check_unique_domain_names(self) -> ChipFamilyManifest:
        names = [d.name for d in self.domains]
        if len(set(names)) != len(names):
            raise ValueError(
                f"chip family {self.vendor}/{self.family}: duplicate domain "
                f"names {names!r}"
            )
        return self

    @property
    def family_id(self) -> str:
        """Globally-unique identifier across the catalog."""
        return f"{self.vendor}/{self.family}"

    def domain_id(self, domain_name: str) -> str:
        """Return the ``vendor/family/domain`` triple for FK use."""
        return f"{self.family_id}/{domain_name}"


# ---------------------------------------------------------------------------
# Runtime / persistence models.
# ---------------------------------------------------------------------------


class ChipMatch(BaseModel):
    """A single match candidate returned by ``ChipMatcher.detect()``.

    Serialisable for both DB persistence (Rule #35c JSONB normaliser) and
    MCP tool output. :attr:`evidence` carries per-signal breakdown so
    operators can audit confidence.
    """

    family_id: str                         # "<vendor>/<family>"
    domain_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[dict] = Field(default_factory=list)
    descriptor_source: DescriptorSource = "auto_detection"

    @property
    def domain_id(self) -> str:
        return f"{self.family_id}/{self.domain_name}"


class ChipDescriptor(BaseModel):
    """External-ingestor or operator-supplied chip descriptor.

    Idempotent on :attr:`descriptor_hash` per Rule #33 .a. The
    :attr:`inline_chip_family` field carries a full
    :class:`ChipFamilyManifest` for the operator's one-off chip when the
    catalog doesn't yet cover it (Scout CC §SC14) — scope-limited to a
    single firmware, NEVER promoted to the catalog automatically.
    """

    schema_version: int = 1
    firmware_id: str                       # UUID string
    descriptor_source: DescriptorSource
    ingestor_id: str | None = Field(default=None, max_length=128)
    descriptor_hash: str | None = Field(default=None, max_length=128)
    chip_family_hint: str | None = None    # "<vendor>/<family>"
    domain_hint: str | None = None
    inline_chip_family: ChipFamilyManifest | None = None
    address_regions_override: list[AddressRegion] = Field(default_factory=list, max_length=64)
    evidence: dict = Field(default_factory=dict)
    received_at: str | None = None         # ISO-8601 — set by service
    supersedes: str | None = None          # descriptor_id of prior

    model_config = {"extra": "forbid"}


__all__ = [
    "Arch",
    "AddressRegion",
    "ChipDescriptor",
    "ChipFamilyManifest",
    "ChipMatch",
    "DescriptorSource",
    "DetectionSignal",
    "DetectionSignalKind",
    "Domain",
    "Endianness",
    "GhidraImportParams",
    "GhidraProcessor",
    "Packing",
    "PolicyOperator",
    "PolicyRule",
    "RegionAccess",
    "RegionDiscovery",
    "RegionSemantic",
]
