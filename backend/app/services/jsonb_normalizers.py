"""Boundary normalisers for every JSONB column on the wairz schema (CLAUDE.md Rule #35c).

Each helper here is the SOLE blessed read-boundary for one JSONB column. Every
consumer reading the column should route through the matching ``_normalize_*``
function rather than touching the raw value, because:

- Legacy rows pre-date current writer discipline and may have a different
  shape (e.g. ``device_metadata['vendor_decryption']`` exists as both
  ``list[dict]`` (canonical) and ``dict`` with ``blobs: list[str]``
  (legacy)). The unpack-audit incident (2026-05-04) is the inciting case;
  see ``unpack_audit_service._normalize_vendor_decryption``.
- ``None`` flows through every nullable JSONB column. Each consumer would
  otherwise have to repeat the ``or {}`` / ``or []`` defensive default.
- Future shape changes can be discriminated via the ``schema_version`` field
  stamped by the writer; the normaliser owns the dispatch.

Conventions:
- Naming: ``_normalize_<table>_<column>``. (Trailing underscore on a Python
  attribute name like ``metadata_`` is dropped — column name is what matters.)
- Signature: accept any of the historically-seen shapes plus ``None``;
  return the canonical empty default for unparseable inputs rather than
  raising. The boundary is defensive; inner logic can rely on the canonical
  shape.
- Idempotent: passing a canonical value back through returns the same
  canonical value. Tests must include this property.
- Schema version constants: ``<TABLE>_<COLUMN>_SCHEMA_VERSION = 1`` for
  columns whose writers stamp the version. Bump only on backwards-incompatible
  shape change AND extend the matching normaliser's dispatch.

The forward-looking discipline applies even to columns whose production
data is currently uniform — shape divergence accumulates over time, and the
helpers exist now so no future consumer has to remember to defend at the
boundary.
"""
from __future__ import annotations

from typing import Any

# ── firmware.device_metadata ──────────────────────────────────────────────────
#
# Canonical shape: ``dict`` containing arbitrary sub-keys written by
# different stages (firmware upload, unblob worker, vendor-AES decrypt,
# detection_audit, device acquisition, etc.). Sub-keys themselves may have
# their own normalisers (e.g. ``_normalize_vendor_decryption`` lives in
# ``unpack_audit_service``). This top-level normaliser only validates the
# column's outer container shape.
FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION = 1


def _normalize_firmware_device_metadata(value: Any) -> dict:
    """Return the canonical ``dict`` shape for ``Firmware.device_metadata``.

    ``None``, missing, or wrong-typed values yield an empty dict — this is
    a metadata-bag column, so absence is semantically equivalent to
    ``no extra metadata``. Callers that need to distinguish ``set-but-empty``
    from ``never-written`` should consult the row directly.
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_firmware_device_metadata(payload: dict | None) -> dict | None:
    """Stamp the schema_version onto a writer payload, preserving null contract.

    Returns ``None`` when ``payload`` is ``None`` or an empty dict so the
    column's nullable semantic survives (some writers clear the dict by
    assigning ``None``). For non-empty dicts, mutates-in-place and returns
    the same dict with the current ``FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION``
    stamped at ``payload["schema_version"]``. Idempotent — re-stamping a
    payload that already has the current version is a no-op.
    """
    if not payload:
        return None
    payload["schema_version"] = FIRMWARE_DEVICE_METADATA_SCHEMA_VERSION
    return payload


# ── firmware.device_metadata['windows_artifacts'] (sub-key) ───────────────────
#
# Aggregate Windows-ecosystem artifact summary nested under
# ``firmware.device_metadata['windows_artifacts']``. Distinct from the
# top-level ``device_metadata`` normaliser because the sub-key has its
# own canonical shape and ≥3 consumers (windows_archive MCP tools,
# WindowsHubPage frontend, Phase β/γ/δ analysis services).
#
# Canonical shape (Phase α — counts of detected/extracted artifacts):
#
#   {
#     "schema_version": 1,
#     "cab_count": int,                       # CABs detected/extracted
#     "msi_count": int,                       # MSI installers
#     "msix_count": int,                      # MSIX/AppX/MSIXBundle
#     "msu_count": int,                       # Microsoft Update packages
#     "psf_count": int,                       # Patch Storage File deltas
#     "vhdx_count": int,                      # VHD/VHDX virtual disks
#     "driver_package_count": int,            # CAB+INF+SYS+CAT bundles
#     "driver_package_subtype": str | None,   # cab_inf_sys_cat | driver_store_dir | dch | msi_installer_driver
#     ... (Phase β fills pe_count / signed_pe_count;
#          Phase γ fills inf_count / cat_count / hive_count;
#          Phase δ fills dotnet_count / r2r_count / dual_signed_count)
#   }
#
# Reads via ``_normalize_firmware_windows_artifacts`` at every consumer
# boundary (Rule #35c). Writes via ``_stamp_firmware_windows_artifacts``
# from the unpack workers' UnpackResult-to-row plumbing.
FIRMWARE_WINDOWS_ARTIFACTS_SCHEMA_VERSION = 1


def _normalize_firmware_windows_artifacts(value: Any) -> dict:
    """Return the canonical ``dict`` shape for the ``windows_artifacts``
    sub-key under ``firmware.device_metadata``.

    ``None`` / missing / wrong-typed values yield ``{}`` — the sub-key is
    absent for non-Windows firmware uploads, so the empty dict is the
    natural floor (consumers ``.get('cab_count', 0)`` into it).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_firmware_windows_artifacts(payload: dict | None) -> dict | None:
    """Stamp the schema_version onto a writer payload, preserving null contract.

    Returns ``None`` when ``payload`` is ``None`` or empty (writer's
    "clear" semantic for the sub-key). For non-empty dicts, mutates-
    in-place and returns the same dict with the current schema version
    stamped. Idempotent — re-stamping is a no-op.
    """
    if not payload:
        return None
    payload["schema_version"] = FIRMWARE_WINDOWS_ARTIFACTS_SCHEMA_VERSION
    return payload


# ── conversations.messages ────────────────────────────────────────────────────
#
# Canonical shape: ``list[dict]`` — a chat-style sequence of role/content
# message dicts. Server default is ``[]``. The column is currently unused
# at the consumer level (the AI conversation table is dormant) but the
# normaliser defends future LLM consumers from shape drift on the day
# they're wired up.
CONVERSATIONS_MESSAGES_SCHEMA_VERSION = 1


def _normalize_conversations_messages(value: Any) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for ``Conversation.messages``.

    Accepts the canonical list-of-dicts, ``None``, or non-list inputs
    (returned as the empty list). Drops non-dict elements from a list to
    survive a future regression where a stray scalar lands in the array.
    """
    if not isinstance(value, list):
        return []
    return [m for m in value if isinstance(m, dict)]


# ── analysis_cache.result ─────────────────────────────────────────────────────
#
# Canonical shape: ``dict`` of analysis-tool-specific output. Same column
# stores Ghidra decompilations, radare2 protections, mobsfscan reports,
# CWE-checker findings — keyed by ``(firmware_id, binary_sha256, operation)``
# so the per-row shape is governed by ``operation``. The normaliser only
# guards the column-level dict shape; the per-operation interpretation is
# the caller's responsibility (and they read keys of their own choosing).
ANALYSIS_CACHE_RESULT_SCHEMA_VERSION = 1


def _normalize_analysis_cache_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``AnalysisCache.result``.

    Distinct from ``device_metadata``: a missing cache row legitimately
    means "not yet computed" — so ``None`` is preserved rather than
    coerced to ``{}``. Wrong-typed values (a list / string accidentally
    written) collapse to ``None`` too, signalling "no usable cache".
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_analysis_cache_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Stamp the schema_version onto an analysis_cache.result writer payload.

    Mutates-in-place and returns the same dict. Idempotent. Always
    receives a non-None dict (the column is nullable but writers always
    pass a populated result), so this helper is unconditionally
    additive.
    """
    payload["schema_version"] = ANALYSIS_CACHE_RESULT_SCHEMA_VERSION
    return payload


# ── firmware.binary_info ──────────────────────────────────────────────────────
#
# Canonical shape: ``dict`` of binary-analysis output (architecture,
# endianness, format, extracted_filename, optional rtos / companion
# components, optional cpu_rec arch_candidates). Written once during
# unpack; ``None`` for firmwares whose primary file isn't a single
# analysable binary (Linux rootfs, Android, multi-partition).
FIRMWARE_BINARY_INFO_SCHEMA_VERSION = 1


def _normalize_firmware_binary_info(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.binary_info``.

    ``None`` is preserved — it carries semantic load (the firmware was
    not analysed as a single binary). Wrong-typed inputs collapse to
    ``None`` rather than ``{}`` so callers checking
    ``if firmware.binary_info is not None`` to detect "single binary"
    aren't fooled by an accidental empty dict.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_binary_info(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.binary_info``. ``None`` is preserved (column is nullable).
    """
    if payload is None:
        return None
    payload["schema_version"] = FIRMWARE_BINARY_INFO_SCHEMA_VERSION
    return payload


# ── firmware.cve_match_result ─────────────────────────────────────────────────
#
# Canonical shape: ``CveMatchRunResult.model_dump()`` — a dict of CVE
# match aggregate per the Pydantic schema in
# ``schemas/hardware_firmware.py``. Written by the 202+polling
# cve-match background runner (Rule #33), read by ``_firmware_to_status``.
# Two consumers — normaliser-only strategy (no schema_version stamp; the
# Pydantic model itself is the schema).


def _normalize_firmware_cve_match_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.cve_match_result``.

    ``None`` is preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None`` (treat as "unusable
    persisted result"; the next run will overwrite).
    """
    if isinstance(value, dict):
        return value
    return None


# ── firmware.authenticode_chain_result ───────────────────────────────────────
#
# Canonical shape: dict aggregate for the Phase β Authenticode batch
# validation run. Written by ``_run_authenticode_chain_background``
# (Phase β.4) and read by ``_firmware_to_status`` (Phase β.7) +
# WindowsHubPage / PeHardeningPage frontend renders. Schema-version
# stamped per Rule #35c since 3+ consumers.
#
# Canonical shape:
#   {
#     "schema_version": 1,
#     "signed_count": int,
#     "signed_pct": float,                # signed_count / total_pe_count
#     "unsigned_count": int,
#     "dbx_revoked_count": int,
#     "findings_emitted": int,            # Phase β.12c — Finding rows the
#                                         # runner produced this run (sum of
#                                         # windows_authenticode +
#                                         # windows_dbx_revoked emissions).
#                                         # Optional for legacy pre-β.12 rows;
#                                         # readers should use
#                                         # ``payload.get("findings_emitted", 0)``.
#     "by_chain_status": {                # bucket histogram
#        "valid_at_signing": int,
#        "valid_now": int,
#        "revoked": int,
#        "never_valid": int,
#        "unknown": int,
#     },
#     "run_seconds": float,
#     "total_pe_count": int,
#   }
FIRMWARE_AUTHENTICODE_CHAIN_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_authenticode_chain_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.authenticode_chain_result``.

    ``None`` is preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None`` (treat as "unusable
    persisted result"; the next run will overwrite).
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_authenticode_chain_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload. Always non-None
    (the column is nullable but writers always pass a populated dict)."""
    payload["schema_version"] = FIRMWARE_AUTHENTICODE_CHAIN_RESULT_SCHEMA_VERSION
    return payload


# ── windows_pe_signatures.arch_view (Phase β.5) ──────────────────────────────
#
# Canonical shape: dict carrying the ARM64EC / ARM64X bimorphic
# discriminator for one PE binary. ``None`` for single-arch PEs (the
# durable signal that no bimorphic split exists). Written by
# :func:`format_detection.detect_pe_arch_view` via the Phase β.4 +
# β.5 ``AuthenticodeVerdict.arch_view`` field, persisted by the Phase
# β.7 background runner that maps the verdict onto a
# ``WindowsPESignature`` row.
#
# Canonical shape (Phase β.5):
#
#   {
#     "schema_version": 1,
#     "primary":   "arm64x" | "arm64ec",
#     "secondary": "amd64"  | "x64_abi",
#     "divergence_score": int,
#   }
#
# Three consumers — schema_version stamping per Rule #35c:
# 1. ``authenticode_service`` (writer; Phase β.4 / β.5 verdict path).
# 2. ``windows_pe_signature.py`` MCP category (Phase β.7
#    ``detect_pe_arch_view`` MCP tool returns the column verbatim).
# 3. ``PeHardeningPage.tsx`` frontend renders bimorphic chips off this
#    column (Phase β.6).
WINDOWS_PE_SIGNATURES_ARCH_VIEW_SCHEMA_VERSION = 1


def _normalize_windows_pe_signatures_arch_view(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``WindowsPESignature.arch_view``.

    ``None`` is preserved — semantic load is "single-arch PE; no
    bimorphic discriminator". Wrong-typed values (a stray list or a
    string) collapse to ``None`` (treat as "no usable arch_view"; the
    next verdict run will overwrite). Distinct from
    ``device_metadata`` because the column carries semantic ``None``
    meaning, not "no metadata yet".
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_windows_pe_signatures_arch_view(payload: dict | None) -> dict | None:
    """Stamp the schema_version onto a writer payload, preserving the
    null-meaning contract.

    Returns ``None`` when ``payload`` is ``None`` or empty (writer's
    "single-arch / clear" semantic). For non-empty dicts, mutates-in-
    place and returns the same dict with the current schema version
    stamped at ``payload["schema_version"]``. Idempotent — re-stamping
    a payload that already has the current version is a no-op.
    """
    if not payload:
        return None
    payload["schema_version"] = WINDOWS_PE_SIGNATURES_ARCH_VIEW_SCHEMA_VERSION
    return payload


# ── windows_pe_signatures.rich_header_json (Phase β.6) ───────────────────────
#
# Canonical shape: dict carrying the decoded Microsoft RICH header
# (toolchain fingerprint) for one PE binary. Written by
# :func:`rich_header_service.decode_rich_header` via the Phase β.4 + β.6
# ``AuthenticodeVerdict.rich_header_json`` field, persisted by the Phase
# β.7 background runner.
#
# Canonical shape (Phase β.6):
#
#   {
#     "schema_version": 1,
#     "xor_key":      str,    # "0x12345678"
#     "entry_count":  int,
#     "entries": [            # one dict per RICH entry
#         {"comp_id": int, "build_number": int,
#          "product_id": int, "instances": int},
#         ...
#     ],
#     "hash_md5":     str,    # cluster fingerprint
#   }
#
# Three consumers — schema_version stamping per Rule #35c:
# 1. ``rich_header_service`` / ``authenticode_service`` (writer; Phase β.4 /
#    β.6 verdict path).
# 2. ``windows_pe_signature.py`` MCP category (Phase β.8 / β.9
#    ``decode_rich_header`` MCP tool returns the column verbatim).
# 3. ``PeHardeningPage.tsx`` frontend renders toolchain chips off this
#    column (Phase β.10).
WINDOWS_PE_SIGNATURES_RICH_HEADER_JSON_SCHEMA_VERSION = 1


def _normalize_windows_pe_signatures_rich_header_json(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``WindowsPESignature.rich_header_json``.

    ``None`` is preserved — semantic load is "PE has no RICH header
    (non-Microsoft toolchain, stripped, or pre-VS2002)". Wrong-typed
    values collapse to ``None`` (treat as "no usable RICH fingerprint";
    the next verdict run will overwrite). Distinct from
    ``device_metadata`` in the same way ``arch_view`` is — null carries
    semantic load, not "data missing".
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_windows_pe_signatures_rich_header_json(
    payload: dict | None,
) -> dict | None:
    """Stamp the schema_version onto a writer payload, preserving the
    null-meaning contract.

    Returns ``None`` when ``payload`` is ``None`` or empty (writer's
    "no RICH header / clear" semantic). For non-empty dicts, mutates-
    in-place and returns the same dict with the current schema version
    stamped. Idempotent.
    """
    if not payload:
        return None
    payload["schema_version"] = WINDOWS_PE_SIGNATURES_RICH_HEADER_JSON_SCHEMA_VERSION
    return payload


# ── fuzzing_campaigns.config ──────────────────────────────────────────────────
#
# Canonical shape: ``dict`` of AFL++ campaign configuration (timeout,
# memory_limit, dictionary, seed_corpus). Server default is ``{}``.
FUZZING_CAMPAIGNS_CONFIG_SCHEMA_VERSION = 1


def _normalize_fuzzing_campaigns_config(value: Any) -> dict:
    """Return the canonical ``dict`` shape for ``FuzzingCampaign.config``.

    ``None`` and wrong-typed values coerce to ``{}`` so consumers can
    ``.get()`` safely. Server default is ``{}``, so the empty dict is
    the natural floor.
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_fuzzing_campaigns_config(payload: dict[str, Any]) -> dict[str, Any]:
    """Stamp the schema_version onto a writer payload."""
    payload["schema_version"] = FUZZING_CAMPAIGNS_CONFIG_SCHEMA_VERSION
    return payload


# ── fuzzing_campaigns.stats ───────────────────────────────────────────────────
#
# Canonical shape: ``dict`` of AFL++ runtime stats (execs_per_sec,
# total_execs, corpus_count, saved_crashes, saved_hangs, stability,
# bitmap_cvg, last_find, run_time). Server default is ``{}``; populated
# every poll interval by the campaign runner.
FUZZING_CAMPAIGNS_STATS_SCHEMA_VERSION = 1


def _normalize_fuzzing_campaigns_stats(value: Any) -> dict:
    """Return the canonical ``dict`` shape for ``FuzzingCampaign.stats``."""
    if isinstance(value, dict):
        return value
    return {}


def _stamp_fuzzing_campaigns_stats(payload: dict[str, Any]) -> dict[str, Any]:
    """Stamp the schema_version onto a writer payload."""
    payload["schema_version"] = FUZZING_CAMPAIGNS_STATS_SCHEMA_VERSION
    return payload


# ── emulation_sessions.port_forwards ──────────────────────────────────────────
#
# Canonical shape: ``list[dict]`` with each dict carrying ``host`` and
# ``guest`` integer keys (TCP/UDP forwards from the QEMU container to
# the host network). Server default ``[]``. Same shape used by
# ``emulation_presets.port_forwards`` (separate normaliser kept per
# column for consistency).
EMULATION_SESSIONS_PORT_FORWARDS_SCHEMA_VERSION = 1


def _normalize_emulation_sessions_port_forwards(value: Any) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``EmulationSession.port_forwards``.

    Accepts None, non-list, or list-with-stray-elements; returns the
    canonical list-of-dicts. Drops stray non-dict entries so consumers
    can ``pf['host']`` safely. The schema_version marker (when stamped)
    lives at the EmulationSession-level metadata, not embedded in the
    list — see Rule #35c on list-shaped columns.
    """
    if not isinstance(value, list):
        return []
    return [pf for pf in value if isinstance(pf, dict)]


# ── emulation_sessions.discovered_services ────────────────────────────────────
#
# Canonical shape: ``list[dict]`` with each dict carrying ``port``,
# ``protocol``, ``service``, ``host_port``, ``url`` keys (FirmAE shim's
# /ports response, mapped to host ports via Docker container.attrs).
# Nullable column (None until the FirmAE startup probe runs).
EMULATION_SESSIONS_DISCOVERED_SERVICES_SCHEMA_VERSION = 1


def _normalize_emulation_sessions_discovered_services(value: Any) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``EmulationSession.discovered_services``.

    Distinct from port_forwards: the column is nullable (None until the
    FirmAE shim probe completes), but consumers always want a list to
    iterate. Drops non-dict entries.
    """
    if not isinstance(value, list):
        return []
    return [s for s in value if isinstance(s, dict)]


# ── emulation_sessions.nvram_state ────────────────────────────────────────────
#
# Canonical shape: ``dict[str, str]`` of NVRAM key → value pairs read
# from FirmAE's libnvram storage. One writer
# (``system_emulation_service.get_nvram_state``); column is nullable.
# 2 consumers — normaliser-only strategy per the per-column threshold.


def _normalize_emulation_sessions_nvram_state(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``EmulationSession.nvram_state``.

    ``None`` is preserved — semantic load is "NVRAM not yet read".
    Wrong-typed values collapse to ``None`` to surface as "not yet
    read" to consumers.
    """
    if isinstance(value, dict):
        return value
    return None


# ── emulation_presets.port_forwards ───────────────────────────────────────────
#
# Same shape as ``emulation_sessions.port_forwards`` (list[dict] with
# host/guest keys), but a separate column on the EmulationPreset model
# storing the preset-level port-forward template. Per the per-column
# discipline, kept as its own normaliser for boundary clarity.
EMULATION_PRESETS_PORT_FORWARDS_SCHEMA_VERSION = 1


def _normalize_emulation_presets_port_forwards(value: Any) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``EmulationPreset.port_forwards``. Mirror of the EmulationSession
    helper; same coercion semantics.
    """
    if not isinstance(value, list):
        return []
    return [pf for pf in value if isinstance(pf, dict)]


# ── attack_surface_entries.score_breakdown ────────────────────────────────────
#
# Canonical shape: ``dict`` of scoring component → integer points
# (network_score, cgi_score, dangerous_score, setuid_score, etc.).
# Server default ``{}``. NOT NULL.
ATTACK_SURFACE_ENTRIES_SCORE_BREAKDOWN_SCHEMA_VERSION = 1


def _normalize_attack_surface_entries_score_breakdown(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``AttackSurfaceEntry.score_breakdown``. Coerces None / non-dict to
    ``{}`` (the column's server default).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_attack_surface_entries_score_breakdown(payload: dict[str, Any]) -> dict[str, Any]:
    """Stamp the schema_version onto a writer payload."""
    payload["schema_version"] = ATTACK_SURFACE_ENTRIES_SCORE_BREAKDOWN_SCHEMA_VERSION
    return payload


# ── attack_surface_entries.dangerous_imports ──────────────────────────────────
#
# Canonical shape: ``list[str]`` of dangerous-import symbol names
# (e.g. ``["strcpy", "gets", "sprintf"]``). Server default ``[]``.
ATTACK_SURFACE_ENTRIES_DANGEROUS_IMPORTS_SCHEMA_VERSION = 1


def _normalize_attack_surface_entries_dangerous_imports(value: Any) -> list[str]:
    """Return the canonical ``list[str]`` shape for
    ``AttackSurfaceEntry.dangerous_imports``.

    Drops non-string entries (forward-discipline against accidental
    dict/list nesting). Coerces None / non-list to ``[]``.
    """
    if not isinstance(value, list):
        return []
    return [s for s in value if isinstance(s, str)]


# ── attack_surface_entries.input_categories ───────────────────────────────────
#
# Canonical shape: ``list[str]`` of input-category labels
# (e.g. ``["network", "filesystem", "ipc"]``). Server default ``[]``.
ATTACK_SURFACE_ENTRIES_INPUT_CATEGORIES_SCHEMA_VERSION = 1


def _normalize_attack_surface_entries_input_categories(value: Any) -> list[str]:
    """Return the canonical ``list[str]`` shape for
    ``AttackSurfaceEntry.input_categories``. Same semantics as
    dangerous_imports.
    """
    if not isinstance(value, list):
        return []
    return [s for s in value if isinstance(s, str)]


# ── sbom_components.metadata ──────────────────────────────────────────────────
#
# Canonical shape: ``dict`` of detector-specific metadata
# (e.g. ``{"package": "openssl", "epoch": "1"}`` for dpkg / opkg /
# busybox-shipped components). Server default ``{}``. 1 reader
# (export_service serialisation); normaliser-only.
SBOM_COMPONENTS_METADATA_SCHEMA_VERSION = 1


def _normalize_sbom_components_metadata(value: Any) -> dict:
    """Return the canonical ``dict`` shape for ``SbomComponent.metadata_``.
    Coerces None / non-dict to ``{}`` (the column's server default).
    """
    if isinstance(value, dict):
        return value
    return {}


# ── hardware_firmware_blobs.metadata ──────────────────────────────────────────
#
# Canonical shape: ``dict`` of parser-specific metadata. Heavily
# consumed (kernel_semver, known_vulnerabilities, firmware_deps,
# firmware_names, vendor-specific keys). Server default ``{}``.
# ≥3 readers → schema_version.
HARDWARE_FIRMWARE_BLOBS_METADATA_SCHEMA_VERSION = 1


def _normalize_hardware_firmware_blobs_metadata(value: Any) -> dict:
    """Return the canonical ``dict`` shape for ``HardwareFirmwareBlob.metadata_``.
    Coerces None / non-dict to ``{}`` so consumers can ``meta.get(...)`` safely.
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_hardware_firmware_blobs_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    """Stamp the schema_version onto a writer payload."""
    payload["schema_version"] = HARDWARE_FIRMWARE_BLOBS_METADATA_SCHEMA_VERSION
    return payload


# ── cra_requirement_results: 4 list[str] columns ──────────────────────────────
#
# All four CRA requirement-result columns store homogeneous primitive
# string arrays. Shared coercion shape; per-column public boundary
# preserved (Rule #35c "one normaliser per column" discipline). 2
# consumers each (cra_compliance_service.py reads and writes) →
# normaliser-only strategy.
CRA_REQUIREMENT_RESULTS_FINDING_IDS_SCHEMA_VERSION = 1
CRA_REQUIREMENT_RESULTS_TOOL_SOURCES_SCHEMA_VERSION = 1
CRA_REQUIREMENT_RESULTS_RELATED_CWES_SCHEMA_VERSION = 1
CRA_REQUIREMENT_RESULTS_RELATED_CVES_SCHEMA_VERSION = 1


def _normalize_str_list(value: Any) -> list[str]:
    """Internal helper: coerce Any → list[str] for homogeneous string-array
    JSONB columns. Drops non-string entries; ``None`` / wrong-type → ``[]``.
    """
    if not isinstance(value, list):
        return []
    return [s for s in value if isinstance(s, str)]


def _normalize_cra_requirement_results_finding_ids(value: Any) -> list[str]:
    """Return canonical ``list[str]`` of Finding row IDs linked to this
    CRA requirement result. Server default ``[]``."""
    return _normalize_str_list(value)


def _normalize_cra_requirement_results_tool_sources(value: Any) -> list[str]:
    """Return canonical ``list[str]`` of tool-source labels (``yara``,
    ``ghidra``, ``mobsfscan``, etc.) that contributed evidence."""
    return _normalize_str_list(value)


def _normalize_cra_requirement_results_related_cwes(value: Any) -> list[str]:
    """Return canonical ``list[str]`` of CWE IDs (``CWE-79``) linked to
    this requirement."""
    return _normalize_str_list(value)


def _normalize_cra_requirement_results_related_cves(value: Any) -> list[str]:
    """Return canonical ``list[str]`` of CVE IDs (``CVE-2024-1234``)
    linked to this requirement."""
    return _normalize_str_list(value)


# ── windows_registry_extracts.parsed_tree (Phase γ.1) ────────────────────────
#
# Per-hive registry walk result. The γ.4 worker walks each hive (regipy
# read-only binding) and stamps the result here; γ.6 MCP tools
# (``windows_registry.list_hives`` / ``walk_hive`` / ``get_run_keys`` /
# ``scan_persistence`` / ``dump_subkey`` / ``diff_hives``) read it; the
# γ.7 frontend (``RegistryHivePage``, ``RegistryDiffPage``) renders it;
# the γ.8 finding-emitter classifier reads it to derive
# ``windows_registry_persistence`` Findings. 4+ consumer files at γ
# shipping time → schema_version discriminator strategy per Rule #35c.
#
# Canonical shape (Phase γ — flat list-of-paths walk capped by walker
# depth + max-keys-per-hive defaults; flat list rather than nested-dict
# for cheap query / serialisation):
#
#   {
#     "schema_version": 1,
#     "hive_type": "SOFTWARE",       # mirrors row.hive_type for self-contained docs
#     "walk_complete": bool,         # False if depth/key cap reached
#     "depth_limit": int,            # walker's max_depth at run time
#     "key_count": int,              # total keys walked (mirrors row.key_count)
#     "value_count": int,            # total values walked (mirrors row.value_count)
#     "truncated": bool,             # True if cap stopped the walk early
#     "errors": list[str],           # parse errors collected during walk
#     "subkeys": list[
#       {
#         "path": "Microsoft\\Windows\\CurrentVersion\\Run",
#         "values": [
#           {"name": "OneDrive", "type": "REG_SZ", "data": "C:\\..."},
#           ...
#         ],
#       },
#       ...
#     ],
#   }
#
# Forward-discipline: bump the SCHEMA_VERSION constant + extend dispatch
# in the normaliser if the walker shape changes (e.g. deeper aggregation,
# alternate value encoding, schema-aware filtering).

WINDOWS_REGISTRY_EXTRACTS_PARSED_TREE_SCHEMA_VERSION = 1


def _normalize_windows_registry_extracts_parsed_tree(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``WindowsRegistryExtract.parsed_tree``.

    ``None`` is preserved — semantic load is "walker did not produce a
    parsed_tree for this row" (e.g. row created with walk_status=skipped
    before the walker ran, or the row predates Phase γ). Wrong-typed
    values collapse to ``None`` rather than ``{}`` so callers checking
    ``if extract.parsed_tree is not None`` to detect "walked"
    aren't fooled by an accidental empty dict.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_windows_registry_extracts_parsed_tree(
    payload: dict | None,
) -> dict | None:
    """Stamp the schema_version onto a writer payload for
    ``WindowsRegistryExtract.parsed_tree``. ``None`` is preserved (column
    is nullable). Idempotent — re-stamping a payload at the current
    version is a no-op.
    """
    if payload is None:
        return None
    payload["schema_version"] = WINDOWS_REGISTRY_EXTRACTS_PARSED_TREE_SCHEMA_VERSION
    return payload


# ── windows_drivers.inf_metadata (Phase γ.2) ──────────────────────────────────
#
# Parsed INF block content for one driver-package extract. The γ.5 worker
# parses the INF (no shell-out per Rule #36) and stamps the result here;
# γ.6 MCP tools (``windows_driver.list_drivers`` / ``get_driver_info`` /
# ``list_signed_drivers`` / ``get_signing_tier`` / ``scan_inf_imports`` /
# ``diff_driver_matrix``) read it; the γ.7 frontend (``DriverMatrixPage``,
# ``DriverDetailPage``) renders it; the γ.8 finding-emitter classifier
# reads it to derive ``windows_inf`` + ``windows_driver_imports``
# Findings. 4+ consumer files at γ shipping time → schema_version
# discriminator strategy per Rule #35c.
#
# Canonical shape (Phase γ.5 INF parse — section-block dicts plus the
# expanded models list, mirroring the INF file's logical structure
# without losing the raw [Strings] substitution table needed to dereference
# tokenised values like ``%MfgName%``):
#
#   {
#     "schema_version": 1,
#     "version_block": {
#       "Class": str | None,                       # e.g. "Display"
#       "ClassGuid": str | None,                   # e.g. "{4d36e968-...}"
#       "Provider": str | None,                    # may carry %SubstToken%
#       "DriverVer": str | None,                   # mm/dd/yyyy,version
#       "CatalogFile": str | None,                 # filename, no path
#     },
#     "manufacturer_block": list[                  # multi-mfg INFs supported
#       {
#         "name": str,                             # %SubstToken% allowed
#         "section": str,                          # the [Models] section name
#         "decorations": list[str],                # OS/arch decorations like NTAMD64.10.0
#       },
#       ...
#     ],
#     "models": list[                              # one per device entry
#       {
#         "manufacturer": str,                     # parent mfg name
#         "device_description": str,
#         "install_section": str,
#         "hardware_id": str,                      # primary HW id
#         "compatible_ids": list[str],             # additional fall-throughs
#       },
#       ...
#     ],
#     "strings": dict[str, str],                   # [Strings] block raw map
#     "errors": list[str],                         # parse errors collected
#   }
#
# Forward-discipline: bump SCHEMA_VERSION + extend dispatch in the
# normaliser if the INF parser shape changes (e.g. tokenisation policy
# change, additional sections like [Targets] or [DeviceFunctions]).

WINDOWS_DRIVERS_INF_METADATA_SCHEMA_VERSION = 1


def _normalize_windows_drivers_inf_metadata(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``WindowsDriver.inf_metadata``.

    ``None`` is preserved — semantic load is "INF parser did not run for
    this row" (e.g. driver detected via SYS-only path, or the row
    predates Phase γ). Wrong-typed values collapse to ``None`` rather
    than ``{}`` so callers checking ``if driver.inf_metadata is not None``
    to detect "INF parsed" aren't fooled by an accidental empty dict.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_windows_drivers_inf_metadata(
    payload: dict | None,
) -> dict | None:
    """Stamp the schema_version onto a writer payload for
    ``WindowsDriver.inf_metadata``. ``None`` is preserved (column is
    nullable). Idempotent — re-stamping at the current version is a
    no-op.
    """
    if payload is None:
        return None
    payload["schema_version"] = WINDOWS_DRIVERS_INF_METADATA_SCHEMA_VERSION
    return payload


# ── firmware.registry_hive_walk_result (Phase γ.3) ────────────────────────────
#
# Aggregate result of the batch registry-walk run launched via the
# γ.3 firmware.registry_hive_walk_* status set (Rule #33 contract). The
# γ.4 background runner walks every hive in the firmware's blobs (regipy
# read-only binding per Rule #36 — DATA only) and stamps the aggregate
# here when the run completes; γ.6 MCP tool ``windows_registry.list_hives``
# reads it for the run summary; γ.7 frontend ``RegistryHivePage`` reads
# it for the last-known-result render. 3+ consumer files at γ shipping
# time → schema_version discriminator strategy per Rule #35c.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,                     # wall-clock for the run
#     "hive_count": int,                        # total hives walked
#     "by_hive_type": dict[str, int],           # {"SOFTWARE": 1, "SYSTEM": 1, ...}
#     "by_walk_status": dict[str, int],         # {"completed": 5, "partial": 1, "failed": 0, "skipped": 2}
#     "total_keys": int,                        # sum of key_count across extracts
#     "total_values": int,                      # sum of value_count across extracts
#     "errors": list[str],                      # session-level errors (per-hive errors live on extract rows)
#   }
#
# Forward-discipline: bump SCHEMA_VERSION + extend dispatch in the
# normaliser if the aggregate shape changes (e.g. add per-hive_type
# total_keys breakdown for a future hist-of-hist aggregation).

FIRMWARE_REGISTRY_HIVE_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_registry_hive_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.registry_hive_walk_result``.

    ``None`` is preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None`` (treat as "unusable
    persisted result"; the next run will overwrite).
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_registry_hive_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.registry_hive_walk_result``.

    Always receives a non-None dict (the runner always writes a
    populated aggregate when transitioning to ``completed``), so this
    helper is unconditionally additive. Idempotent.
    """
    payload["schema_version"] = FIRMWARE_REGISTRY_HIVE_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_update_packages.update_metadata (Phase δ.1) ──────────────────────
#
# Per-package parsed manifest payload — bill-of-files, supersedence chain
# (both directions), applicability rules, file SHA256 list. Phase δ.4
# extends ``unpack_msu`` / ``unpack_cab`` workers to write the row + this
# JSONB; δ.5 update-diff service reads it to compute per-DLL changeset
# between two firmwares' KBs; δ.6 R2R-stomping detector reads the file
# list to scope its PE walk; δ.7 MCP ``windows_update.list_packages`` /
# ``get_package_metadata`` / ``get_supersedence_chain`` / ``list_kb_files``
# / ``diff_kb_packages`` tools read it; δ.8 frontend ``UpdateDiffPage``
# renders the delta. 5+ consumer files at δ shipping time → schema_version
# discriminator strategy per Rule #35c.
#
# Canonical shape (Phase δ — flat manifest mirror; supersedence both
# directions; file BOM with sha256+size for δ.5 diff hashing):
#
#   {
#     "schema_version": 1,
#     "manifest": {
#       "title": "2024-04 Cumulative Update for Windows 11 Version 23H2 ...",
#       "description": "Install this update to resolve issues...",
#       "support_url": "https://support.microsoft.com/help/5036893",
#       "msu_handler": "Windows Update Standalone Installer",  # may be null
#     },
#     "supersedence": {
#       "supersedes": list[str],     # KB IDs replaced by this package
#       "superseded_by": list[str],  # KB IDs that replace this package
#     },
#     "applicability": {
#       "products": list[str],        # ["Windows 11", "Windows Server 2022"]
#       "architectures": list[str],   # ["amd64", "arm64"]
#       "release_channels": list[str],# ["GA", "ZDP"]
#     },
#     "files": list[                  # per-file BOM for δ.5 diff
#       {
#         "path": "Windows10.0-KB5036893-x64.cab",  # path within package
#         "size": 1234567,
#         "sha256": "abc123...",
#         "is_pe": bool,              # True for .dll/.exe/.sys (δ.5 hot-path)
#         "kind": "binary" | "manifest" | "catalog" | "config" | "other",
#       },
#       ...
#     ],
#     "errors": list[str],            # parser-level errors collected during scan
#   }
#
# Forward-discipline: bump SCHEMA_VERSION + extend dispatch in the
# normaliser if the manifest-parser shape changes (e.g. add per-file
# Authenticode/CAT cross-reference, add CBS-CSI/MUM expansion blob).

WINDOWS_UPDATE_PACKAGES_UPDATE_METADATA_SCHEMA_VERSION = 1


def _normalize_windows_update_packages_update_metadata(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``WindowsUpdatePackage.update_metadata``.

    ``None`` is preserved — semantic load is "manifest parser did not run
    for this row" (e.g. row created with a known package_path but no
    parsed manifest, or the row predates Phase δ). Wrong-typed values
    collapse to ``None`` rather than ``{}`` so callers checking
    ``if pkg.update_metadata is not None`` to detect "manifest parsed"
    aren't fooled by an accidental empty dict.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_windows_update_packages_update_metadata(
    payload: dict | None,
) -> dict | None:
    """Stamp the schema_version onto a writer payload for
    ``WindowsUpdatePackage.update_metadata``. ``None`` is preserved
    (column is nullable). Idempotent — re-stamping at the current
    version is a no-op.
    """
    if payload is None:
        return None
    payload["schema_version"] = WINDOWS_UPDATE_PACKAGES_UPDATE_METADATA_SCHEMA_VERSION
    return payload


# ── firmware.dotnet_decompile_result (Phase δ.2) ──────────────────────────────
#
# Aggregate result of the batch .NET single-file bundle decompile run
# launched via the δ.2 firmware.dotnet_decompile_* status set (Rule #33
# contract). The δ.4 worker arq job walks every .NET single-file bundle
# in the firmware's blobs (dnfile read-only PE table walking per Rule
# #36 — DATA only) and stamps the aggregate here when the run completes;
# δ.6 R2R-stomping detector reads the per-bundle output paths to scope
# its R2R analysis; δ.7 MCP tool ``windows_dotnet.list_bundles`` reads
# it for the run summary; δ.8 frontend ``DotNetBrowserPage`` reads it
# for the last-known-result render. 4+ consumer files at δ shipping
# time → schema_version discriminator strategy per Rule #35c.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,                     # wall-clock for the run
#     "bundle_count": int,                      # total bundles processed
#     "bundles_decompiled": int,                # bundles that produced IL output
#     "bundles_failed": int,                    # bundles that failed decompile
#     "total_assemblies_extracted": int,        # sum across all bundles
#     "by_arch": dict[str, int],                # {"amd64": 3, "arm64": 1, "msil": 5}
#     "bundles": list[
#       {
#         "bundle_path": "Windows/...",         # path within firmware tree
#         "bundle_sha256": str,
#         "extracted_count": int,               # assemblies pulled out of bundle
#         "decompile_target_dir": str,          # ilspycmd output root
#         "errors": list[str],                  # per-bundle errors
#       },
#       ...
#     ],
#     "errors": list[str],                      # session-level errors
#   }
#
# Forward-discipline: bump SCHEMA_VERSION + extend dispatch in the
# normaliser if the aggregate shape changes (e.g. add per-bundle
# capa-on-IL hits, R2R-stomp counts).

FIRMWARE_DOTNET_DECOMPILE_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_dotnet_decompile_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.dotnet_decompile_result``.

    ``None`` is preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None`` (treat as "unusable
    persisted result"; the next run will overwrite).
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_dotnet_decompile_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.dotnet_decompile_result``.

    Always receives a non-None dict (the runner always writes a populated
    aggregate when transitioning to ``completed``), so this helper is
    unconditionally additive. Idempotent.
    """
    payload["schema_version"] = FIRMWARE_DOTNET_DECOMPILE_RESULT_SCHEMA_VERSION
    return payload


# ── firmware.windows_update_diff_result (Phase δ.3) ───────────────────────────
#
# Aggregate result of the batch KB-vs-KB update-diff run launched via the
# δ.3 firmware.windows_update_diff_* status set (Rule #33 contract). The
# δ.5 background runner walks every (older_kb, newer_kb) pair across the
# firmware's windows_update_packages rows (δ.1), computes per-DLL changeset
# via SHA256 comparison over already-extracted CAB/MSU contents (Rule #36
# DATA-only), persists per-DLL diff rows incrementally to a dedicated
# table (δ.5) for restart recovery, and stamps the aggregate here when
# the run completes; δ.7 MCP tool ``windows_update.get_diff_summary`` reads
# it for the run summary; δ.8 frontend ``UpdateDiffPage`` reads it for the
# last-known-result render. 3+ consumer files at δ shipping time →
# schema_version discriminator strategy per Rule #35c.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,                     # wall-clock for the run
#     "package_count": int,                     # update packages compared
#     "kb_pair_count": int,                     # (older, newer) pairs computed
#     "dlls_compared": int,                     # total DLLs across pairs
#     "dlls_added": int,                        # present in newer KB only
#     "dlls_removed": int,                      # present in older KB only
#     "dlls_modified": int,                     # present in both, sha256 differs
#     "dlls_unchanged": int,                    # present in both, identical sha256
#     "by_kb_pair": list[
#       {
#         "older_kb": "KB5034441",
#         "newer_kb": "KB5036893",
#         "added": int,
#         "removed": int,
#         "modified": int,
#         "unchanged": int,
#       },
#       ...
#     ],
#     "errors": list[str],                      # session-level errors
#   }
#
# Forward-discipline: bump SCHEMA_VERSION + extend dispatch in the
# normaliser if the aggregate shape changes (e.g. add per-DLL category
# breakdown, add by-arch breakdown, surface .NET vs native split).

FIRMWARE_WINDOWS_UPDATE_DIFF_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_windows_update_diff_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.windows_update_diff_result``.

    ``None`` is preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None`` (treat as "unusable
    persisted result"; the next run will overwrite).
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_windows_update_diff_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.windows_update_diff_result``.

    Always receives a non-None dict (the runner always writes a populated
    aggregate when transitioning to ``completed``), so this helper is
    unconditionally additive. Idempotent.
    """
    payload["schema_version"] = FIRMWARE_WINDOWS_UPDATE_DIFF_RESULT_SCHEMA_VERSION
    return payload


# ── firmware.evtx_walk_result (Phase ε.1.b.3) ────────────────────────────────
#
# Per-firmware aggregate written by ``run_evtx_walk_background`` (ε.1.b.3)
# from the inner ``_do_evtx_walk_run`` orchestrator. ε.1.b.4 MCP tools
# read it for the run summary; ε.1.b.4 frontend ``EvtxWalkPage`` reads
# it for the last-known-result render. Per ε.1.b campaign Decision #1,
# per-event row persistence is DEFERRED to a future ζ.X phase — the
# walker's full-record list lives only in this aggregate (sample + counts;
# operators can re-walk to inspect specific records). 3+ consumer files
# at ε shipping time → schema_version discriminator strategy per Rule
# #35c.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,                     # wall-clock for the run
#     "evtx_count": int,                        # total .evtx files walked
#     "by_provider": dict[str, int],            # {"Microsoft-Windows-Sysmon": 142, ...}
#     "by_status": dict[str, int],              # {"ok": 4, "error": 1, "unavailable": 0}
#     "total_records": int,                     # sum of record_count across files
#     "sample_records_per_file": int,           # cap on sample-records persisted per .evtx
#     "errors": list[str],                      # session-level errors (per-file errors live in the per_file list)
#     "per_file": list[dict],                   # [{"path": str, "status": str, "record_count": int, "error": str|None}]
#   }
#
# Forward-discipline: bump SCHEMA_VERSION + extend dispatch in the
# normaliser if the aggregate shape changes (e.g. add by-EID histogram
# for the future ζ.X "search events" feature).

FIRMWARE_EVTX_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_evtx_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.evtx_walk_result``.

    ``None`` is preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None`` (treat as "unusable
    persisted result"; the next run will overwrite).
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_evtx_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.evtx_walk_result``.

    Always receives a non-None dict (the runner always writes a populated
    aggregate when transitioning to ``completed``), so this helper is
    unconditionally additive. Idempotent.
    """
    payload["schema_version"] = FIRMWARE_EVTX_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_event_records.message_xml (Phase ε.2.A) ──────────────────────────
#
# Per-event parsed-EVTX-detail payload. ε.1.b's walker aggregates summaries
# into ``firmware.evtx_walk_result``; ε.2.A introduces the per-event landing
# zone so future search-events MCP tools (ε.2.C, deferred) can paginate
# filtered results without re-walking. Writer is the ε.2.B walker extension
# (deferred to a follow-up session per the windows-coverage-godmode-housekeeping
# campaign decomposition); readers will be the ε.2.C MCP search tools +
# any FE search-page renderer.
#
# 3+ consumer files projected at full ε.2 shipping (writer + 2-3 search MCP
# tools + 1 FE page) → schema_version discriminator strategy per Rule #35c.
# Ship the stamp helper now so ε.2.B doesn't need a follow-up commit when
# the consumer count crosses the threshold.
#
# Canonical shape (provider+EID-dependent; per-EID schemas can be discriminated
# by readers via the ``provider`` + ``event_id`` columns, NOT by inspecting
# message_xml):
#
#   {
#     "schema_version": 1,
#     "EventData": dict | list[dict] | None,    # parsed System.EventData (Win)
#     "UserData": dict | None,                  # parsed System.UserData (rare)
#     "DebugData": dict | None,                 # parsed System.DebugData (rarer)
#     "Binary": str | None,                     # System.Binary (hex string)
#     ... (other parser-emitted top-level keys)
#   }
#
# python-evtx's ``Evtx.Record.lxml`` produces an XML tree; the walker (ε.2.B)
# converts it to a dict per Microsoft's WindowsEventLog schema (RFC-style),
# stamping schema_version onto the resulting dict before persisting.
#
# Forward-discipline: bump SCHEMA_VERSION + extend dispatch in the normaliser
# if the per-event envelope shape changes (e.g. add a flattened ``params``
# convenience map for common EIDs, or move from XML-derived dict to a
# protobuf-style normalised form).

WINDOWS_EVENT_RECORDS_MESSAGE_XML_SCHEMA_VERSION = 1


def _normalize_windows_event_records_message_xml(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``WindowsEventRecord.message_xml``.

    ``None`` is preserved — semantic load is "raw event captured, parsed
    payload not extracted" (e.g. parser-skipped, EVTX corruption, or
    storage-budget walker config). Wrong-typed values collapse to ``None``
    (treat as "unusable persisted payload"; the raw_xml column remains
    available for full-text fallback).
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_windows_event_records_message_xml(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``WindowsEventRecord.message_xml``.

    Idempotent. The walker constructs the dict from python-evtx's parsed
    XML tree, then calls this helper before passing to ``db.add()``.
    """
    payload["schema_version"] = WINDOWS_EVENT_RECORDS_MESSAGE_XML_SCHEMA_VERSION
    return payload


# ── firmware.prefetch_walk_result (Phase ζ.2.B) ──────────────────────────────
#
# Per-firmware aggregate from a single Prefetch walk. Mirrors the
# evtx_walk_result / registry_hive_walk_result shape — a flat dict with
# top-level summary fields. The runner stamps this once at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "prefetch_count": int,                    # total .pf files walked
#     "by_status": {"ok": int, "error": int},   # parse outcomes
#     "executable_count": int,                  # unique executables seen
#     "total_runs_recorded": int,               # sum of run_count across files
#     "errors": list[str],                      # session-level errors
#     "per_file": list[dict],                   # [{"path": str, "status": str,
#                                                  "executable_name": str|None,
#                                                  "run_count": int|None,
#                                                  "error": str|None}]
#   }

FIRMWARE_PREFETCH_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_prefetch_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.prefetch_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_prefetch_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.prefetch_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_PREFETCH_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_prefetch_records JSONB columns (Phase ζ.2.A) ──────────────────────
#
# Three JSONB columns on ``windows_prefetch_records``:
#   - ``all_run_times``: list-shaped (list of ISO-8601 strings)
#   - ``filenames_referenced``: list-shaped (list of UTF-16-decoded paths)
#   - ``volumes``: list-shaped (list of dicts: serial + path + creation_time)
#
# Per Rule #35c, list-shaped JSONB columns get the SCHEMA_VERSION constant
# but NO inline stamp marker (the discriminator can't live INSIDE the list
# cleanly). Wrap the payload in ``{"schema_version": N, "items": [...]}``
# at the writer boundary so the discriminator AND the list can coexist.
#
# Writer (Phase ζ.2.B inner runner):
#   record.all_run_times = _stamp_windows_prefetch_records_all_run_times(
#       [ts.isoformat() for ts in pf.timestamps]
#   )
#
# Reader (any consumer; canary is the search MCP tool ζ.2.E):
#   ts_list = _normalize_windows_prefetch_records_all_run_times(
#       record.all_run_times
#   )  # always returns list[str], never None
#
# 3+ consumer files projected at full ζ.2 shipping (writer + search MCP +
# any FE renderer + Finding-emit classifier) → schema_version discriminator
# strategy per Rule #35c.

WINDOWS_PREFETCH_RECORDS_ALL_RUN_TIMES_SCHEMA_VERSION = 1
WINDOWS_PREFETCH_RECORDS_FILENAMES_REFERENCED_SCHEMA_VERSION = 1
WINDOWS_PREFETCH_RECORDS_VOLUMES_SCHEMA_VERSION = 1


def _normalize_windows_prefetch_records_all_run_times(value: Any) -> list[str]:
    """Return the canonical ``list[str]`` shape for
    ``WindowsPrefetchRecord.all_run_times``.

    Accepts the canonical envelope ``{"schema_version": 1, "items": [...]}``,
    bare list (legacy / pre-stamp), and ``None``. Returns ``list[str]``
    unconditionally — empty list semantically means "no run times recorded"
    (e.g. parser couldn't decode any of the 8 timestamp slots).
    """
    if isinstance(value, dict) and isinstance(value.get("items"), list):
        return [str(x) for x in value["items"] if x is not None]
    if isinstance(value, list):
        return [str(x) for x in value if x is not None]
    return []


def _stamp_windows_prefetch_records_all_run_times(items: list[str]) -> dict:
    """Stamp the schema_version envelope onto an ``all_run_times`` payload.

    Idempotent — calling twice with the result of a prior stamp is safe
    (the envelope's items field is what we're wrapping; double-wrapping
    is detected via the dict shape).
    """
    if isinstance(items, dict) and "items" in items:
        items = items["items"]
    return {
        "schema_version": WINDOWS_PREFETCH_RECORDS_ALL_RUN_TIMES_SCHEMA_VERSION,
        "items": list(items),
    }


def _normalize_windows_prefetch_records_filenames_referenced(value: Any) -> list[str]:
    """Return the canonical ``list[str]`` shape for
    ``WindowsPrefetchRecord.filenames_referenced``.

    Same envelope as ``all_run_times``. Defensive coercion to str via
    ``str(x)`` so non-UTF-8 paths don't trip readers.
    """
    if isinstance(value, dict) and isinstance(value.get("items"), list):
        return [str(x) for x in value["items"] if x is not None]
    if isinstance(value, list):
        return [str(x) for x in value if x is not None]
    return []


def _stamp_windows_prefetch_records_filenames_referenced(items: list[str]) -> dict:
    """Stamp the schema_version envelope onto a ``filenames_referenced``
    payload. Idempotent."""
    if isinstance(items, dict) and "items" in items:
        items = items["items"]
    return {
        "schema_version": WINDOWS_PREFETCH_RECORDS_FILENAMES_REFERENCED_SCHEMA_VERSION,
        "items": list(items),
    }


def _normalize_windows_prefetch_records_volumes(value: Any) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``WindowsPrefetchRecord.volumes``.

    Each entry is a dict with shape:
        {"device_path": str, "serial_number": str | None,
         "creation_time": str | None}

    Defensive: skips non-dict entries silently (treat as "unparseable
    volume row in legacy data").
    """
    if isinstance(value, dict) and isinstance(value.get("items"), list):
        return [v for v in value["items"] if isinstance(v, dict)]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _stamp_windows_prefetch_records_volumes(items: list[dict]) -> dict:
    """Stamp the schema_version envelope onto a ``volumes`` payload.
    Idempotent."""
    if isinstance(items, dict) and "items" in items:
        items = items["items"]
    return {
        "schema_version": WINDOWS_PREFETCH_RECORDS_VOLUMES_SCHEMA_VERSION,
        "items": list(items),
    }


# ── windows_srum_records.extra_metadata (Phase ζ.3.A) ────────────────────────
#
# Type-specific overflow + future-proofing for SRUM records. The five
# canonical record_type values ('network_data_usage', 'network_connectivity',
# 'application_resource_usage', 'push_notification', 'energy_usage') each
# have typed columns for their primary metrics; ``extra_metadata`` carries
# any per-record-type fields that didn't fit a typed column AND any
# walker-time enrichments (e.g. raw ESEDB column-name dump for forensic
# audit, GUID-table-name for traceability).
#
# Canonical envelope per Rule #35c — discriminator key + payload dict.
# Wrong-typed values collapse to None (treat as "no extra metadata"; the
# typed columns remain authoritative for the row's metrics).

WINDOWS_SRUM_RECORDS_EXTRA_METADATA_SCHEMA_VERSION = 1


def _normalize_windows_srum_records_extra_metadata(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``WindowsSrumRecord.extra_metadata``.

    ``None`` preserved — semantic load is "no extra metadata captured".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_windows_srum_records_extra_metadata(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``WindowsSrumRecord.extra_metadata``. Idempotent."""
    payload["schema_version"] = WINDOWS_SRUM_RECORDS_EXTRA_METADATA_SCHEMA_VERSION
    return payload


# ── firmware.srum_walk_result (Phase ζ.3.B) ─────────────────────────────────
#
# Per-firmware aggregate from a single SRUM walk. Mirrors the
# evtx_walk_result / prefetch_walk_result shape — a flat dict with
# top-level summary fields. The runner stamps this once at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "srudb_count": int,                       # SRUDB.dat files walked
#     "by_record_type": {                       # counts per discriminator
#         "network_data_usage": int, ...
#     },
#     "by_status": {"ok": int, "error": int, "unavailable": int},
#     "total_records": int,                     # rows persisted
#     "unique_apps": int,                       # distinct app_identifier
#     "errors": list[str],
#     "per_file": list[dict],                   # [{"path": str, "status":
#                                                  str, "record_count":
#                                                  int, "error": str|None}]
#   }

FIRMWARE_SRUM_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_srum_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.srum_walk_result``."""
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_srum_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.srum_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_SRUM_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_scheduled_tasks JSONB columns (Phase η.B.A) ──────────────────────
#
# Four JSONB columns on ``windows_scheduled_tasks``:
#   - ``triggers``: list-shaped (list of trigger dicts)
#   - ``actions``: list-shaped (list of action dicts)
#   - ``principal``: dict-shaped (single Principal block)
#   - ``settings``: dict-shaped (single Settings block)
#
# Per Rule #35c, list-shaped JSONB columns wrap as
# ``{"schema_version": N, "items": [...]}`` so the discriminator AND the
# list can coexist; dict-shaped columns stamp inline as
# ``{"schema_version": N, ...}``.
#
# 3+ consumer files projected at full η.B shipping (writer η.B.C +
# search MCP tool η.B.E + classifier η.B.D + future windows-hub
# frontend renderer) → schema_version discriminator strategy per
# Rule #35c.

WINDOWS_SCHEDULED_TASKS_TRIGGERS_SCHEMA_VERSION = 1
WINDOWS_SCHEDULED_TASKS_ACTIONS_SCHEMA_VERSION = 1
WINDOWS_SCHEDULED_TASKS_PRINCIPAL_SCHEMA_VERSION = 1
WINDOWS_SCHEDULED_TASKS_SETTINGS_SCHEMA_VERSION = 1


def _normalize_windows_scheduled_tasks_triggers(value: Any) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``WindowsScheduledTask.triggers``.

    Accepts the canonical envelope ``{"schema_version": 1, "items": [...]}``,
    bare list (legacy / pre-stamp), and ``None``. Returns ``list[dict]``
    unconditionally — empty list semantically means "no triggers parsed"
    (e.g. malformed XML or task with only manual-start activation).

    Defensive: skips non-dict entries silently (treat as "unparseable
    trigger row in legacy data").
    """
    if isinstance(value, dict) and isinstance(value.get("items"), list):
        return [v for v in value["items"] if isinstance(v, dict)]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _stamp_windows_scheduled_tasks_triggers(items: list[dict]) -> dict:
    """Stamp the schema_version envelope onto a ``triggers`` payload.

    Idempotent — calling twice with the result of a prior stamp is safe
    (the envelope's items field is what we're wrapping; double-wrapping
    is detected via the dict shape).
    """
    if isinstance(items, dict) and "items" in items:
        items = items["items"]
    return {
        "schema_version": WINDOWS_SCHEDULED_TASKS_TRIGGERS_SCHEMA_VERSION,
        "items": list(items),
    }


def _normalize_windows_scheduled_tasks_actions(value: Any) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``WindowsScheduledTask.actions``.

    Same envelope as ``triggers``. Each entry is a dict with shape:
        {"type": str, "command": str | None, "arguments": str | None,
         "working_directory": str | None, "class_id": str | None,
         "details": dict}
    """
    if isinstance(value, dict) and isinstance(value.get("items"), list):
        return [v for v in value["items"] if isinstance(v, dict)]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _stamp_windows_scheduled_tasks_actions(items: list[dict]) -> dict:
    """Stamp the schema_version envelope onto an ``actions`` payload.
    Idempotent."""
    if isinstance(items, dict) and "items" in items:
        items = items["items"]
    return {
        "schema_version": WINDOWS_SCHEDULED_TASKS_ACTIONS_SCHEMA_VERSION,
        "items": list(items),
    }


def _normalize_windows_scheduled_tasks_principal(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsScheduledTask.principal``.

    Inline-stamped (no envelope wrapper — single-Principal block is
    naturally dict-shaped). Returns empty dict for None / wrong-typed
    inputs (defensive boundary).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_scheduled_tasks_principal(payload: dict) -> dict:
    """Stamp the schema_version inline onto a ``principal`` payload for
    ``WindowsScheduledTask.principal``. Idempotent."""
    payload["schema_version"] = WINDOWS_SCHEDULED_TASKS_PRINCIPAL_SCHEMA_VERSION
    return payload


def _normalize_windows_scheduled_tasks_settings(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsScheduledTask.settings``.

    Inline-stamped (no envelope wrapper — Settings block is naturally
    dict-shaped). Returns empty dict for None / wrong-typed inputs.
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_scheduled_tasks_settings(payload: dict) -> dict:
    """Stamp the schema_version inline onto a ``settings`` payload for
    ``WindowsScheduledTask.settings``. Idempotent."""
    payload["schema_version"] = WINDOWS_SCHEDULED_TASKS_SETTINGS_SCHEMA_VERSION
    return payload


# ── firmware.scheduled_task_walk_result (Phase η.B.B) ───────────────────────
#
# Per-firmware aggregate from a single Scheduled Task XML walk. Mirrors
# the evtx_walk_result / prefetch_walk_result / srum_walk_result shape
# — a flat dict with top-level summary fields. The runner stamps this
# once at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "task_count": int,                        # total .xml task files walked
#     "by_status": {"ok": int, "error": int},   # parse outcomes
#     "unique_authors": int,                    # distinct Author values
#     "highest_available_count": int,           # tasks with RunLevel=HighestAvailable
#     "encoded_powershell_count": int,          # tasks with encoded-PS action shape
#     "errors": list[str],                      # session-level errors
#     "per_file": list[dict],                   # [{"path": str, "status":
#                                                  str, "task_uri": str|None,
#                                                  "author": str|None,
#                                                  "error": str|None}]
#   }

FIRMWARE_SCHEDULED_TASK_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_scheduled_task_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.scheduled_task_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_scheduled_task_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.scheduled_task_walk_result``. Idempotent."""
    payload["schema_version"] = (
        FIRMWARE_SCHEDULED_TASK_WALK_RESULT_SCHEMA_VERSION
    )
    return payload


# ── windows_lnk_records JSONB column (Phase η.C.A) ───────────────────────────
#
# One JSONB column on ``windows_lnk_records``:
#   - ``target_metadata``: dict-shaped (full LnkParse3 .get_json() output)
#
# Per Rule #35c, dict-shaped JSONB columns stamp inline as
# ``{"schema_version": N, ...}``.
#
# 3+ consumer files projected at full η.C shipping (writer η.C.C +
# search MCP tool η.C.E + classifier η.C.D + future windows-hub
# frontend renderer) → schema_version discriminator strategy per
# Rule #35c.
#
# Canonical shape mirrors LnkParse3.lnk_file.LnkFile.get_json() output:
#   {
#     "schema_version": 1,
#     "size": int,                # total LNK file size in bytes
#     "header": {                 # ShellLinkHeader fields
#       "guid": str,              # CLSID (canonical: 00021401-...)
#       "creation_time": str,     # FILETIME → ISO-8601 datetime string
#       "accessed_time": str,
#       "modified_time": str,
#       "file_size": int,
#       "icon_index": int,
#       "windowstyle": str,       # SW_SHOWNORMAL / SW_SHOWMAXIMIZED / etc.
#       "hotkey": str,            # free-form parser string
#       "r_hotkey": int,          # raw 16-bit hotkey value
#       "r_link_flags": int,      # raw LinkFlags
#       "r_file_flags": int,      # raw FileAttributes
#       "link_flags": list[str],  # decoded flag names
#       "file_flags": list[str]
#     },
#     "link_info": {              # LinkInfo block (often empty)
#       "local_base_path": str,   # resolved drive-letter target
#       "common_path_suffix": str,
#       "volume_id": dict,
#       "common_network_relative_link": dict
#     },
#     "data": {                   # StringData section
#       "description": str,       # NAME_STRING
#       "relative_path": str,
#       "working_directory": str,
#       "command_line_arguments": str,
#       "icon_location": str
#     },
#     "extra": {                  # ExtraData blocks (TrackerDataBlock etc.)
#       "TRACKER_DATA_BLOCK": dict,
#       "ENVIRONMENT_VARIABLE_DATA_BLOCK": dict,
#       ...
#     }
#   }

WINDOWS_LNK_RECORDS_TARGET_METADATA_SCHEMA_VERSION = 1


def _normalize_windows_lnk_records_target_metadata(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsLnkRecord.target_metadata``.

    Inline-stamped (no envelope wrapper — single LnkParse3 .get_json()
    output is naturally dict-shaped). Returns empty dict for None /
    wrong-typed inputs (defensive boundary). Empty-dict semantics
    means "no metadata available" (e.g. parse failed but we kept
    the row for the source_path / lnk_filename evidence trail).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_lnk_records_target_metadata(payload: dict) -> dict:
    """Stamp the schema_version inline onto a ``target_metadata``
    payload for ``WindowsLnkRecord.target_metadata``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_LNK_RECORDS_TARGET_METADATA_SCHEMA_VERSION
    )
    return payload


# ── firmware.lnk_walk_result (Phase η.C.B) ──────────────────────────────────
#
# Per-firmware aggregate from a single LNK file walk. Mirrors the
# scheduled_task_walk_result / evtx_walk_result / prefetch_walk_result /
# srum_walk_result shape — a flat dict with top-level summary fields.
# The runner stamps this once at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "lnk_count": int,                      # total .lnk files walked
#     "by_status": {"ok": int, "error": int, "unavailable": int, "skipped": int},
#     "unique_targets": int,                 # distinct target_path values
#     "non_microsoft_target_count": int,     # tier-MEDIUM candidates
#     "encoded_powershell_count": int,       # tier-HIGH candidates
#     "errors": list[str],                   # session-level errors
#     "per_file": list[dict],                # [{"path": str, "status":
#                                               str, "target_path": str|None,
#                                               "lnk_filename": str,
#                                               "error": str|None}]
#   }

FIRMWARE_LNK_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_lnk_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.lnk_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_lnk_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.lnk_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_LNK_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_mft_records JSONB columns (Phase η.A.A) ──────────────────────────
#
# Two JSONB columns on ``windows_mft_records``:
#   - ``ads_streams``: list-shaped per-record named ADS roster.
#   - ``target_metadata``: dict-shaped catchall for per-record extras.
#
# Per Rule #35c:
#   - list-shaped columns get an envelope-style normalizer (list[dict])
#     with a SCHEMA_VERSION constant + stamp helper.
#   - dict-shaped columns stamp inline as ``{"schema_version": N, ...}``.
#
# 3+ consumer files projected at full η.A shipping (writer η.A.C +
# search MCP tool η.A.F + classifier η.A.D + future windows-hub frontend
# renderer) → schema_version discriminator strategy per Rule #35c.
#
# Canonical shape for ads_streams (list[dict]):
#   [
#     {"name": str, "size": int, "data_size": int | None},
#     ...
#   ]
# Empty list when the record has no named ADS streams (the common case).
# data_size carries the on-disk allocated size when distinct from the
# stream's logical size; None when only one size is known.
#
# Canonical shape for target_metadata (dict):
#   {
#     "schema_version": 1,
#     "parent_segment_ref": int | None,
#     "reparse_point": bool,
#     "attribute_flags": int,
#     "hard_link_count": int | None,
#     "sequence_number": int | None,
#   }

WINDOWS_MFT_RECORDS_ADS_STREAMS_SCHEMA_VERSION = 1
WINDOWS_MFT_RECORDS_TARGET_METADATA_SCHEMA_VERSION = 1


def _normalize_windows_mft_records_ads_streams(value: Any) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``WindowsMftRecord.ads_streams``.

    Defensive boundary:
    - canonical list[dict] passes through unchanged
    - bare list with non-dict items: coerce each item to ``{"name": str(item)}``
    - None / wrong-typed inputs collapse to empty list
    - dict input (legacy single-stream shape) coerces to a single-element list

    Idempotent. Empty list means "no named ADS streams on this record"
    (the common case for the median file).
    """
    if value is None:
        return []
    if isinstance(value, dict):
        # Legacy single-stream shape — coerce to a single-element list.
        return [{
            "name": str(value.get("name", "")),
            "size": int(value.get("size") or 0),
            "data_size": value.get("data_size"),
        }]
    if isinstance(value, list):
        out: list[dict] = []
        for item in value:
            if isinstance(item, dict):
                out.append(item)
            elif item is not None:
                out.append({"name": str(item), "size": 0, "data_size": None})
        return out
    return []


def _stamp_windows_mft_records_ads_streams(payload: list[dict]) -> list[dict]:
    """Stamp each list entry with the schema_version onto a writer
    payload for ``WindowsMftRecord.ads_streams``. Idempotent.

    List-shaped column: each dict carries its own schema_version key,
    not a single top-level envelope (so a downstream consumer reading
    one entry doesn't need the parent list context to discriminate).
    """
    for entry in payload:
        entry["schema_version"] = WINDOWS_MFT_RECORDS_ADS_STREAMS_SCHEMA_VERSION
    return payload


def _normalize_windows_mft_records_target_metadata(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsMftRecord.target_metadata``.

    Inline-stamped (no envelope wrapper — single per-record dict).
    Returns empty dict for None / wrong-typed inputs (defensive
    boundary). Empty-dict semantics means "no extras surfaced" (e.g.
    record with no reparse point and no parent segment).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_mft_records_target_metadata(payload: dict) -> dict:
    """Stamp the schema_version inline onto a ``target_metadata``
    payload for ``WindowsMftRecord.target_metadata``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_MFT_RECORDS_TARGET_METADATA_SCHEMA_VERSION
    )
    return payload


# ── firmware.mft_walk_result (Phase η.A.B) ───────────────────────────────────
#
# Per-firmware aggregate from a single MFT walk. Mirrors the
# lnk_walk_result / scheduled_task_walk_result / evtx_walk_result /
# prefetch_walk_result / srum_walk_result shape — a flat dict with
# top-level summary fields. The runner stamps this once at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "images_scanned": int,                    # NTFS images opened
#     "records_walked": int,                    # MFT segments iterated
#     "records_persisted": int,                 # rows written
#     "ads_streams_seen": int,                  # named ADS streams across all records
#     "timestomp_candidates": int,              # $SI mtime < $FN mtime hits
#     "ads_hidden_candidates": int,             # named ADS with non-trivial size
#     "errors": list[str],                      # session-level errors
#     "per_image": list[dict],                  # [{"path": str, "records": int,
#                                                  "status": str, "error": str|None}]
#   }

FIRMWARE_MFT_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_mft_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.mft_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_mft_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.mft_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_MFT_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_bcd_entries.custom_elements (Phase θ.A.A) ────────────────────────
#
# Per-entry roster of BCD elements not promoted to flat columns
# (DisplayOrder 0x14000006, DefaultObject 0x23000003, vendor- or
# attacker-planted elements). Canonical shape:
#
#   [
#     {
#       "schema_version": 1,
#       "element_type": str,   # hex string like "0x14000006"
#       "element_value": str | int | bool | list[str] | None,
#     },
#     ...
#   ]
#
# Empty list means "no extra elements surfaced beyond the flat
# columns" (the common case). List-shaped so each entry carries its
# own schema_version stamp — a downstream consumer reading one entry
# doesn't need the parent list context to discriminate.

WINDOWS_BCD_ENTRIES_CUSTOM_ELEMENTS_SCHEMA_VERSION = 1


def _normalize_windows_bcd_entries_custom_elements(value: Any) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``WindowsBcdEntry.custom_elements``.

    Defensive boundary:
    - canonical list[dict] passes through unchanged
    - bare list with non-dict items: coerce each to ``{"element_type": str(item)}``
    - None / wrong-typed inputs collapse to empty list
    - dict input (legacy single-element shape) coerces to a single-element list

    Idempotent. Empty list means "no extra elements" (the common case
    for entries whose elements are fully captured by flat columns).
    """
    if value is None:
        return []
    if isinstance(value, dict):
        return [{
            "element_type": str(value.get("element_type", "")),
            "element_value": value.get("element_value"),
        }]
    if isinstance(value, list):
        out: list[dict] = []
        for item in value:
            if isinstance(item, dict):
                out.append(item)
            elif item is not None:
                out.append({"element_type": str(item), "element_value": None})
        return out
    return []


def _stamp_windows_bcd_entries_custom_elements(
    payload: list[dict],
) -> list[dict]:
    """Stamp each list entry with the schema_version onto a writer
    payload for ``WindowsBcdEntry.custom_elements``. Idempotent.

    List-shaped column: each dict carries its own schema_version key,
    not a single top-level envelope (so a downstream consumer reading
    one entry doesn't need the parent list context to discriminate).
    """
    for entry in payload:
        entry["schema_version"] = (
            WINDOWS_BCD_ENTRIES_CUSTOM_ELEMENTS_SCHEMA_VERSION
        )
    return payload


# ── windows_bcd_entries.anomaly_flags (Phase θ.A.A) ──────────────────────────
#
# Per-entry heuristic detection aggregate for the θ.A.D classifier.
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "suspicious_path": bool,
#     "non_microsoft_description": bool,
#     "testsigning_enabled": bool,
#     "no_integrity_checks": bool,
#     "nx_disabled": bool,
#     "is_default_boot": bool,
#   }
#
# NULL when no anomaly evaluation was performed (rare — defensive
# shape; the walker stamps this on every emit).

WINDOWS_BCD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_windows_bcd_entries_anomaly_flags(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsBcdEntry.anomaly_flags``.

    Inline-stamped (no envelope wrapper — single per-entry dict).
    Returns empty dict for None / wrong-typed inputs (defensive
    boundary). Empty-dict semantics means "no anomaly evaluation"
    (e.g. parser-failure path).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_bcd_entries_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags``
    payload for ``WindowsBcdEntry.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_BCD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.bcd_walk_result (Phase θ.A.B) ───────────────────────────────────
#
# Per-firmware aggregate from a single BCD store walk. Mirrors the
# lnk_walk_result / scheduled_task_walk_result / evtx_walk_result /
# prefetch_walk_result / srum_walk_result / mft_walk_result shape — a
# flat dict with top-level summary fields. The runner stamps this once
# at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "stores_scanned": int,                # BCD files opened
#     "entries_walked": int,                # \Objects\{guid} subkeys iterated
#     "entries_persisted": int,             # rows written
#     "testsigning_count": int,             # entries with TestSigning=True
#     "suspicious_path_count": int,         # path-heuristic hits
#     "non_microsoft_description_count": int,
#     "anomaly_total": int,                 # entries flagged by ≥1 anomaly
#     "errors": list[str],                  # session-level errors
#     "per_store": list[dict],              # [{"path": str, "entries": int,
#                                              "status": str, "error": str|None}]
#   }

FIRMWARE_BCD_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_bcd_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.bcd_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_bcd_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.bcd_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_BCD_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_wmi_events.consumer_payload (Phase θ.B.B) ────────────────────────
#
# Per-binding roster of EventConsumer payload details surfaced by the
# vendored PyWMIPersistenceFinder. List-shape because the vendor
# parser may emit multiple distinct payloads from the same consumer
# name across allocated + unallocated repository regions (each
# detail-record is preserved verbatim for forensic visibility).
#
# Canonical shape:
#
#   [
#     {
#       "schema_version": 1,
#       "consumer_type": str,    # e.g. "CommandLineEventConsumer"
#       "arguments": str,        # printable-filtered command line / payload
#       "other": str,            # secondary field per upstream regex
#     },
#     ...
#   ]
#
# Empty list when no payload details extracted (the binding pass
# fired but the consumer details pass didn't match — partial corrupt
# repository, etc.). NULL only on defensive parser failure.
#
# Per Rule #36: this is DATA, never passed as argv to any
# process-spawn primitive.

WINDOWS_WMI_EVENTS_CONSUMER_PAYLOAD_SCHEMA_VERSION = 1


def _normalize_windows_wmi_events_consumer_payload(value: Any) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``WindowsWmiEvent.consumer_payload``.

    Defensive boundary:
    - canonical list[dict] passes through unchanged
    - bare list with non-dict items: coerce each to a minimal dict
      with consumer_type=str(item)
    - None / wrong-typed inputs collapse to empty list
    - dict input (legacy single-record shape) coerces to a
      single-element list

    Idempotent. Empty list means "no payload details extracted"
    (binding pass fired but consumer-details regex didn't match).
    """
    if value is None:
        return []
    if isinstance(value, dict):
        return [{
            "consumer_type": str(value.get("consumer_type", "")),
            "arguments": str(value.get("arguments", "")),
            "other": str(value.get("other", "")),
        }]
    if isinstance(value, list):
        out: list[dict] = []
        for item in value:
            if isinstance(item, dict):
                out.append(item)
            elif item is not None:
                out.append({
                    "consumer_type": str(item),
                    "arguments": "",
                    "other": "",
                })
        return out
    return []


def _stamp_windows_wmi_events_consumer_payload(
    payload: list[dict],
) -> list[dict]:
    """Stamp each list entry with the schema_version onto a writer
    payload for ``WindowsWmiEvent.consumer_payload``. Idempotent.

    List-shaped column: each dict carries its own schema_version key,
    not a single top-level envelope.
    """
    for entry in payload:
        entry["schema_version"] = (
            WINDOWS_WMI_EVENTS_CONSUMER_PAYLOAD_SCHEMA_VERSION
        )
    return payload


# ── windows_wmi_events.anomaly_flags (Phase θ.B.B) ──────────────────────────
#
# Per-binding heuristic detection aggregate for the θ.B.E classifier.
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "encoded_powershell": bool,
#     "script_host_invocation": bool,
#     "active_script_consumer": bool,
#     "non_benign_binding": bool,
#     "high_severity": bool,
#   }
#
# NULL when no anomaly evaluation was performed (rare — defensive
# shape; the walker stamps this on every emit).

WINDOWS_WMI_EVENTS_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_windows_wmi_events_anomaly_flags(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsWmiEvent.anomaly_flags``.

    Inline-stamped (no envelope wrapper — single per-binding dict).
    Returns empty dict for None / wrong-typed inputs (defensive
    boundary). Empty-dict semantics means "no anomaly evaluation"
    (e.g. parser-failure path).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_wmi_events_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags``
    payload for ``WindowsWmiEvent.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_WMI_EVENTS_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.wmi_walk_result (Phase θ.B.C) ──────────────────────────────────
#
# Per-firmware aggregate from a single WMI persistence walk. Mirrors
# the bcd_walk_result / mft_walk_result / lnk_walk_result shape — a
# flat dict with top-level summary fields. The runner stamps this once
# at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "objects_data_scanned": int,    # OBJECTS.DATA files opened
#     "bindings_walked": int,         # FilterToConsumerBindings found
#     "bindings_persisted": int,      # rows written
#     "active_script_count": int,     # ActiveScriptEventConsumer bindings
#     "command_line_count": int,      # CommandLineEventConsumer bindings
#     "encoded_powershell_count": int,
#     "non_benign_count": int,        # bindings with probably_benign=False
#     "errors": list[str],            # session-level errors
#     "per_repository": list[dict],   # per-OBJECTS.DATA summaries
#   }

FIRMWARE_WMI_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_wmi_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.wmi_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_wmi_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.wmi_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_WMI_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_esp_entries.authenticode_chain (Phase θ.C.A) ───────────────────
#
# Per-`.efi` Authenticode chain summary, sourced verbatim from the β.4
# verify_pe_file pipeline (signify). Canonical shape:
#
#   {
#     "schema_version": 1,
#     "signed": bool,
#     "chain_status": str,         # signify ChainStatus literal
#     "signer_subject": str | None,
#     "signer_issuer": str | None,
#     "leaf_serial": str | None,
#     "sig_hash_algo": str | None,
#     "signed_at": str | None,     # ISO-8601 from countersigner
#     "signatures_count": int,
#     "error": str | None,
#   }

WINDOWS_ESP_ENTRIES_AUTHENTICODE_CHAIN_SCHEMA_VERSION = 1


def _normalize_windows_esp_entries_authenticode_chain(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsEspEntry.authenticode_chain``.

    Inline-stamped (no envelope wrapper — single per-entry dict).
    Returns empty dict for None / wrong-typed inputs (defensive
    boundary). Empty-dict semantics means "no chain extracted"
    (parse_failed path).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_esp_entries_authenticode_chain(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``authenticode_chain``
    payload for ``WindowsEspEntry.authenticode_chain``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_ESP_ENTRIES_AUTHENTICODE_CHAIN_SCHEMA_VERSION
    )
    return payload


# ── windows_esp_entries.dbx_revocation_match (Phase θ.C.A) ─────────────────
#
# Per-`.efi` DBX revocation match, sourced verbatim from the β.10
# match_dbx_revocation pipeline. NULL when no match was made (either
# bundle wasn't provisioned OR leaf-serial wasn't revoked).
# Canonical shape on a hit:
#
#   {
#     "schema_version": 1,
#     "revoked": bool,
#     "revocation_kb": str | None,
#     "leaf_serial_normalized": str,
#     "match_kind": str,           # "x509_serial" | "sha256"
#     "bundle_entries": int,
#     "bundle_path": str,
#   }

WINDOWS_ESP_ENTRIES_DBX_REVOCATION_MATCH_SCHEMA_VERSION = 1


def _normalize_windows_esp_entries_dbx_revocation_match(
    value: Any,
) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``WindowsEspEntry.dbx_revocation_match``.

    ``None`` preserved — semantic load is "no DBX match".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_windows_esp_entries_dbx_revocation_match(
    payload: dict,
) -> dict:
    """Stamp the schema_version inline onto a
    ``dbx_revocation_match`` payload. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_ESP_ENTRIES_DBX_REVOCATION_MATCH_SCHEMA_VERSION
    )
    return payload


# ── windows_esp_entries.anomaly_flags (Phase θ.C.A) ────────────────────────
#
# Per-`.efi` heuristic detection aggregate for the θ.C.D classifier.
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "is_unsigned": bool,
#     "is_expired": bool,
#     "is_revoked": bool,
#     "is_non_microsoft_signer": bool,
#     "is_known_bootloader_path": bool,
#     "is_vendor_path": bool,
#     "is_suspiciously_small": bool,
#   }

WINDOWS_ESP_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_windows_esp_entries_anomaly_flags(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsEspEntry.anomaly_flags``.

    Inline-stamped. Returns empty dict for None / wrong-typed inputs
    (defensive boundary)."""
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_esp_entries_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags``
    payload for ``WindowsEspEntry.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_ESP_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.esp_walk_result (Phase θ.C.B) ─────────────────────────────────
#
# Per-firmware aggregate from a single ESP `.efi` chain walk. Mirrors
# the wmi_walk_result / bcd_walk_result shape.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "efi_files_scanned": int,
#     "efi_files_persisted": int,
#     "signed_valid_count": int,
#     "signed_expired_count": int,
#     "signed_revoked_count": int,
#     "unsigned_count": int,
#     "parse_failed_count": int,
#     "dbx_revoked_count": int,
#     "non_microsoft_signer_count": int,
#     "known_bootloader_anomaly_count": int,
#     "errors": list[str],
#     "per_root": list[dict],
#   }

FIRMWARE_ESP_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_esp_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.esp_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_esp_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.esp_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_ESP_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_mbr_vbr_sectors.anomaly_flags (Phase θ.E.A) ─────────────────────
#
# Per-sector heuristic detection aggregate for the θ.E.D classifier.
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "non_zero_padding": bool,
#     "unexpected_partition_table": bool,
#     "non_standard_jmp": bool,
#     "non_zero_disk_signature": bool,
#     "is_mbr": bool,
#     "is_vbr": bool,
#   }

WINDOWS_MBR_VBR_SECTORS_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_windows_mbr_vbr_sectors_anomaly_flags(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsMbrVbrSector.anomaly_flags``.

    Inline-stamped. Returns empty dict for None / wrong-typed inputs
    (defensive boundary)."""
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_mbr_vbr_sectors_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags``
    payload for ``WindowsMbrVbrSector.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_MBR_VBR_SECTORS_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.mbr_vbr_walk_result (Phase θ.E.B) ──────────────────────────────
#
# Per-firmware aggregate from a single MBR/VBR boot-sector walk.
# Mirrors the esp_walk_result / wmi_walk_result / bcd_walk_result shape.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "images_scanned": int,
#     "sectors_persisted": int,
#     "mbr_count": int,
#     "vbr_count": int,
#     "known_good_match_count": int,
#     "known_bootkit_match_count": int,
#     "anomaly_count": int,
#     "errors": list[str],
#     "per_root": list[dict],
#   }

FIRMWARE_MBR_VBR_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_mbr_vbr_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.mbr_vbr_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_mbr_vbr_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.mbr_vbr_walk_result``. Idempotent."""
    payload["schema_version"] = (
        FIRMWARE_MBR_VBR_WALK_RESULT_SCHEMA_VERSION
    )
    return payload


# ── windows_sdb_entries.shim_payload (Phase θ.D.B) ──────────────────────────
#
# Per-entry payload for the θ.D Application Compatibility Shim
# Database walker. For TAG_SHIM rows the payload carries the shim
# name + module / DLL filename + command-line + description. For
# TAG_PATCH rows the payload carries the PATCH name + raw
# TAG_PATCH_BITS hex blob + patch_bits size. The flat shim_class
# column discriminates which fields are populated.
#
# Canonical shape (TAG_SHIM):
#   {
#     "schema_version": 1,
#     "kind": "shim",
#     "shim_name": str,
#     "module": str,
#     "command_line": str,
#     "description": str,
#   }
#
# Canonical shape (TAG_PATCH):
#   {
#     "schema_version": 1,
#     "kind": "patch",
#     "patch_name": str,
#     "patch_bits_hex": str,
#     "patch_bits_size": int,
#   }

WINDOWS_SDB_ENTRIES_SHIM_PAYLOAD_SCHEMA_VERSION = 1


def _normalize_windows_sdb_entries_shim_payload(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsSdbEntry.shim_payload``.

    Returns empty dict for None / wrong-typed inputs (defensive
    boundary)."""
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_sdb_entries_shim_payload(payload: dict) -> dict:
    """Stamp the schema_version inline onto a ``shim_payload``
    payload for ``WindowsSdbEntry.shim_payload``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_SDB_ENTRIES_SHIM_PAYLOAD_SCHEMA_VERSION
    )
    return payload


# ── windows_sdb_entries.anomaly_flags (Phase θ.D.B) ─────────────────────────
#
# Per-entry heuristic detection aggregate for the θ.D.E classifier.
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "is_custom_path": bool,
#     "has_inject_dll": bool,
#     "has_redirect_exe": bool,
#     "has_get_command_line": bool,
#     "has_redirect_shortcut": bool,
#     "has_dll_outside_appdir": bool,
#     "has_command_line": bool,
#   }

WINDOWS_SDB_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_windows_sdb_entries_anomaly_flags(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsSdbEntry.anomaly_flags``.

    Returns empty dict for None / wrong-typed inputs (defensive
    boundary)."""
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_sdb_entries_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags``
    payload for ``WindowsSdbEntry.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_SDB_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.sdb_walk_result (Phase θ.D.C) ──────────────────────────────────
#
# Per-firmware aggregate from a single SDB shim walk.
# Mirrors the mbr_vbr_walk_result / esp_walk_result / wmi_walk_result /
# bcd_walk_result shape.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "files_scanned": int,
#     "entries_persisted": int,
#     "shim_count": int,
#     "patch_count": int,
#     "custom_path_count": int,
#     "inject_dll_count": int,
#     "redirect_exe_count": int,
#     "get_command_line_count": int,
#     "redirect_shortcut_count": int,
#     "anomaly_count": int,
#     "errors": list[str],
#     "per_file": list[dict],
#   }

FIRMWARE_SDB_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_sdb_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.sdb_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_sdb_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.sdb_walk_result``. Idempotent."""
    payload["schema_version"] = (
        FIRMWARE_SDB_WALK_RESULT_SCHEMA_VERSION
    )
    return payload


# ── linux_journald_entries.anomaly_flags (Phase ι.A.A — FIRST LINUX) ─────────
#
# Per-entry heuristic detection aggregate for the ι.A.D classifier.
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "priority_critical": bool,   # priority <= 2 (emerg/alert/crit)
#     "oom_killer": bool,          # message matches kernel oom-killer
#     "audit_failure": bool,       # transport=audit AND failure marker
#     "selinux_denied": bool,      # message matches SELinux denial
#     "segfault": bool,            # message matches segfault pattern
#     "suspicious_unit": bool,     # unit path under writable directory
#     "log_clear_marker": bool,    # message matches journalctl vacuum
#   }
#
# NULL when no anomaly evaluation was performed (rare — defensive
# shape; the walker stamps this on every emit).
#
# Consumers (≥3 — Rule #35c stamp helper required):
# - app/services/journald_walker.py (writer)
# - app/services/finding_service.py (emit_journald_findings_from_walk)
# - app/ai/tools/linux_journald.py (MCP tools surface flags in JSON)

LINUX_JOURNALD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_linux_journald_entries_anomaly_flags(value: Any) -> dict:
    """Return the canonical ``dict`` shape for
    ``LinuxJournaldEntry.anomaly_flags``.

    Inline-stamped (no envelope wrapper — single per-entry dict).
    Returns empty dict for None / wrong-typed inputs (defensive
    boundary). Empty-dict semantics means "no anomaly evaluation"
    (e.g. parser-failure path).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_linux_journald_entries_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags``
    payload for ``LinuxJournaldEntry.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        LINUX_JOURNALD_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.journald_walk_result (Phase ι.A.B) ──────────────────────────────
#
# Per-firmware aggregate from a single journald walk. Mirrors the
# bcd_walk_result / esp_walk_result / sdb_walk_result shape — a
# flat dict with top-level summary fields. The runner stamps this
# once at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "files_scanned": int,                # .journal files opened
#     "entries_walked": int,               # total entries iterated
#     "entries_persisted": int,            # rows written
#     "priority_critical_count": int,      # priority <= 2 entries
#     "oom_killer_count": int,
#     "audit_failure_count": int,
#     "selinux_denied_count": int,
#     "suspicious_unit_count": int,
#     "log_clear_marker_count": int,
#     "anomaly_total": int,                # entries flagged by ≥1 anomaly
#     "oversize_skipped": int,             # files >500 MB skipped
#     "errors": list[str],                 # session-level errors
#     "per_file": list[dict],              # per-journal-file aggregates
#   }

FIRMWARE_JOURNALD_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_journald_walk_result(value: Any) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.journald_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_journald_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.journald_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_JOURNALD_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── linux_systemd_units.* (Phase ι.B.A — SECOND LINUX WALKER) ────────────────
#
# 8 JSONB columns on the linux_systemd_units table — each gets its own
# normalizer per CLAUDE.md Rule #35c. The list-shape columns (wanted_by /
# required_by / requires / after / before) canonicalize to list[str].
# The dict-shape columns (triggers / socket_listen) canonicalize to
# dict[str, Any]. The anomaly_flags column carries the heuristic
# detection aggregate (canonical shape lives in the docstring of
# ``LinuxSystemdUnit.anomaly_flags``).
#
# Consumers (≥3 — Rule #35c stamp helpers required for any field whose
# read sites span 3+ files):
# - app/services/systemd_walker.py (writer — populates from parsed
#   INI text via stdlib configparser)
# - app/services/finding_service.py (emit_systemd_findings_from_walk —
#   ι.B.D classifier)
# - app/ai/tools/linux_systemd.py (MCP tools — surface fields in
#   tool output JSON)


def _normalize_linux_systemd_units_wanted_by(value: object) -> list:
    """Return the canonical ``list[str]`` shape for
    ``LinuxSystemdUnit.wanted_by``.

    Canonical: list of strings (each a systemd target unit name such
    as ``multi-user.target``). Defensive: None → empty list; wrong-
    typed values collapse to empty list; non-string list elements are
    coerced via ``str()``.
    """
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []


def _normalize_linux_systemd_units_required_by(value: object) -> list:
    """Return the canonical ``list[str]`` shape for
    ``LinuxSystemdUnit.required_by``. Same shape as wanted_by."""
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []


def _normalize_linux_systemd_units_requires(value: object) -> list:
    """Return the canonical ``list[str]`` shape for
    ``LinuxSystemdUnit.requires``. Same shape as wanted_by."""
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []


def _normalize_linux_systemd_units_after(value: object) -> list:
    """Return the canonical ``list[str]`` shape for
    ``LinuxSystemdUnit.after``. Same shape as wanted_by."""
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []


def _normalize_linux_systemd_units_before(value: object) -> list:
    """Return the canonical ``list[str]`` shape for
    ``LinuxSystemdUnit.before``. Same shape as wanted_by."""
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []


def _normalize_linux_systemd_units_triggers(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``LinuxSystemdUnit.triggers``.

    Canonical shape: dict[str, Any] where keys are [Timer]-section
    directive names (OnCalendar / OnBootSec / OnUnitActiveSec /
    OnStartupSec / etc) and values are the raw strings as parsed
    from the INI file. Defensive: None / wrong-typed → empty dict.
    Empty dict means "no [Timer] section parsed for this unit".
    """
    if isinstance(value, dict):
        return value
    return {}


def _normalize_linux_systemd_units_socket_listen(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``LinuxSystemdUnit.socket_listen``.

    Canonical shape: dict[str, Any] where keys are [Socket]-section
    directive names (ListenStream / ListenDatagram / ListenFIFO /
    ListenSequentialPacket / etc) and values are the raw strings as
    parsed. Defensive: None / wrong-typed → empty dict. Empty dict
    means "no [Socket] section parsed for this unit".
    """
    if isinstance(value, dict):
        return value
    return {}


# Schema version for the inline-stamped anomaly_flags column.
LINUX_SYSTEMD_UNITS_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_linux_systemd_units_anomaly_flags(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``LinuxSystemdUnit.anomaly_flags``.

    Canonical shape (all 7 bits inline-stamped with schema_version):

      {
        "schema_version": 1,
        "suspicious_path": bool,          # ExecStart under writable dir
        "suspicious_unit_name": bool,     # unit name matches rand-hex
        "socket_unusual_port": bool,      # socket on non-standard port
        "root_minimal_deps": bool,        # User=root + minimal Requires
        "disabled_but_present": bool,     # no enabled-symlink found
        "enabled_outside_standard": bool, # WantedBy != standard targets
        "obfuscated_exec": bool,          # base64/eval/long-shell pattern
      }

    Defensive: None / wrong-typed → empty dict. Empty dict means
    "no anomaly evaluation was performed" (e.g. parser-failure path).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_linux_systemd_units_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags``
    payload for ``LinuxSystemdUnit.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        LINUX_SYSTEMD_UNITS_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.systemd_walk_result (Phase ι.B.B) ───────────────────────────────
#
# Per-firmware aggregate from a single systemd-units walk. Mirrors the
# journald_walk_result shape — a flat dict with top-level summary
# fields. The runner stamps this once at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "units_scanned": int,                  # unit files parsed
#     "units_persisted": int,                # rows written
#     "service_count": int,
#     "timer_count": int,
#     "socket_count": int,
#     "target_count": int,
#     "other_count": int,                    # path / mount / swap / etc
#     "enabled_count": int,
#     "suspicious_path_count": int,
#     "suspicious_unit_name_count": int,
#     "socket_unusual_port_count": int,
#     "root_minimal_deps_count": int,
#     "disabled_but_present_count": int,
#     "enabled_outside_standard_count": int,
#     "obfuscated_exec_count": int,
#     "anomaly_total": int,                  # units flagged by ≥1 anomaly
#     "errors": list[str],                   # session-level errors
#     "per_root": list[dict],                # per-detection-root aggregates
#   }

FIRMWARE_SYSTEMD_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_systemd_walk_result(value: object) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.systemd_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_systemd_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.systemd_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_SYSTEMD_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_etl_events.payload (Phase ι.C.A) ─────────────────────────────────
#
# Decoded ETW event payload — manifest-resolved field key/value pairs
# when dissect.etl matched the provider GUID to a known manifest; raw-
# bytes preview otherwise. Canonical shape: dict[str, Any] of decoded
# fields keyed by manifest-declared name. Defensive: None → empty dict
# (matches "no manifest match — no decoded payload" semantic).
#
# Consumers (≥3):
# - app/services/etl_walker.py (writer — populates from dissect.etl
#   ``EventRecord.event.event_values()`` or raw bytes preview)
# - app/services/finding_service.py (emit_etl_findings_from_walk —
#   ι.C.D classifier)
# - app/ai/tools/windows_etl.py (MCP tools — surface field in tool
#   output JSON)


WINDOWS_ETL_EVENTS_PAYLOAD_SCHEMA_VERSION = 1


def _normalize_windows_etl_events_payload(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsEtlEvent.payload``.

    Canonical: dict[str, Any] of decoded payload fields (manifest-
    resolved key/value pairs) OR a small raw-bytes preview as
    ``{"raw_b64": "...", "raw_size": N}`` when no manifest match.
    Defensive: None / wrong-typed → empty dict. Empty dict means "no
    payload decoded for this event" — typical for system-control
    records or events whose provider has no shipped manifest.
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_etl_events_payload(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``WindowsEtlEvent.payload``. Idempotent."""
    payload["schema_version"] = WINDOWS_ETL_EVENTS_PAYLOAD_SCHEMA_VERSION
    return payload


# ── windows_etl_events.anomaly_flags (Phase ι.C.A) ───────────────────────────
#
# Anomaly aggregate computed by the ι.C.C classifier per event/file.
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "kernel_proc_after_evtx_clear": bool,
#     "provider_disable_evidence": bool,
#     "unusual_provider": bool,
#     "non_microsoft_in_diagtrack": bool,
#   }
#
# Consumers (≥3):
# - app/services/etl_walker.py (writer — populates from classifier)
# - app/services/finding_service.py (emit_etl_findings_from_walk —
#   ι.C.D classifier)
# - app/ai/tools/windows_etl.py (MCP tools — exposes anomaly_only
#   filter)


WINDOWS_ETL_EVENTS_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_windows_etl_events_anomaly_flags(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsEtlEvent.anomaly_flags``.

    Defensive: None / wrong-typed → empty dict. Empty dict means "no
    anomaly evaluation was performed" (e.g. parser-failure path).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_etl_events_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags`` payload
    for ``WindowsEtlEvent.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_ETL_EVENTS_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.etl_walk_result (Phase ι.C.B) ───────────────────────────────────
#
# Per-firmware aggregate from a single ETL walk. Mirrors the
# systemd_walk_result + journald_walk_result shape — a flat dict with
# top-level summary fields. The runner stamps this once at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "files_scanned": int,
#     "events_walked": int,                    # event records iterated
#     "events_persisted": int,                 # rows written
#     "oversize_skipped": int,                 # .etl files skipped (>500 MB)
#     "events_capped": int,                    # events dropped (per-firmware cap)
#     "kernel_proc_after_evtx_clear_count": int,
#     "provider_disable_evidence_count": int,
#     "unusual_provider_count": int,
#     "non_microsoft_in_diagtrack_count": int,
#     "anomaly_total": int,                    # events flagged by ≥1 anomaly
#     "errors": list[str],
#     "per_file": list[dict],                  # per-.etl-file aggregates
#   }


FIRMWARE_ETL_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_etl_walk_result(value: object) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.etl_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_etl_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.etl_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_ETL_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── firmware.efs_walk_result (Phase ι.D.B) ───────────────────────────────────
#
# Per-firmware aggregate from a single EFS walk. Mirrors the
# etl_walk_result + systemd_walk_result shape — a flat dict with
# top-level summary fields. The runner stamps this once at completion.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "images_scanned": int,             # raw NTFS image candidates parsed
#     "files_walked": int,               # MFT records iterated
#     "encrypted_files_found": int,      # files with FILE_ATTRIBUTE_ENCRYPTED
#     "encrypted_files_persisted": int,  # rows written
#     "files_capped": int,               # rows dropped (per-firmware cap)
#     "parse_errors": int,               # $EFS attribute parse failures
#     "orphaned_drf_count": int,         # files with DRF but no DDF
#     "unusual_recovery_agent_count": int,
#     "multiple_ddf_users_count": int,
#     "large_drf_count": int,            # files with >2 recovery agents
#     "domain_admin_in_ddf_count": int,
#     "anomaly_total": int,              # files flagged by ≥1 anomaly bit
#     "errors": list[str],
#     "per_image": list[dict],
#   }


FIRMWARE_EFS_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_efs_walk_result(value: object) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.efs_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_efs_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.efs_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_EFS_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_efs_encrypted_files.ddf_users (Phase ι.D.A) ──────────────────────
#
# Per-file DDF (Data Decryption Field) user list. Each entry is a dict
# with the SID + cert thumbprint + optional friendly name. Canonical
# shape:
#
#   [
#     {
#       "sid": "S-1-5-21-...-1001",
#       "cert_thumbprint": "0123456789abcdef..." (40-char SHA-1 hex),
#       "friendly_name": str | null,
#     },
#     ...
#   ]
#
# Defensive: None / wrong-type → empty list. Empty list semantics: "no
# DDF entries parsed for this file" — equivalent to a parse error or a
# file with no DDF (malformed $EFS).
#
# Consumers (≥3):
# - app/services/efs_walker.py (writer — populates from $EFS parser)
# - app/services/finding_service.py (emit_efs_findings_from_walk —
#   ι.D.D classifier)
# - app/ai/tools/windows_efs.py (MCP tools — surface field + search-by-sid)


WINDOWS_EFS_ENCRYPTED_FILES_DDF_USERS_SCHEMA_VERSION = 1


def _normalize_windows_efs_encrypted_files_ddf_users(value: object) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``WindowsEfsEncryptedFile.ddf_users``.

    Canonical: list of dicts, each with at minimum ``sid`` (str) +
    ``cert_thumbprint`` (str) + ``friendly_name`` (str | None).
    Defensive: None / wrong-typed / non-list → empty list. Non-dict
    elements are silently dropped.
    """
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _stamp_windows_efs_encrypted_files_ddf_users(payload: list[dict]) -> list[dict]:
    """Stamp the schema_version sentinel onto the writer payload for
    ``WindowsEfsEncryptedFile.ddf_users``.

    Unusually for Rule #35c, this is a list-typed field (not a dict) —
    we add a sentinel dict at the start of the list (``{"schema_version": 1}``)
    rather than mutating a top-level dict. Idempotent — calling twice
    doesn't double-stamp.
    """
    if not payload:
        return [{"schema_version": WINDOWS_EFS_ENCRYPTED_FILES_DDF_USERS_SCHEMA_VERSION}]
    first = payload[0]
    if isinstance(first, dict) and first.get("schema_version") == WINDOWS_EFS_ENCRYPTED_FILES_DDF_USERS_SCHEMA_VERSION:
        return payload
    return [
        {"schema_version": WINDOWS_EFS_ENCRYPTED_FILES_DDF_USERS_SCHEMA_VERSION},
        *payload,
    ]


# ── windows_efs_encrypted_files.drf_recovery_agents (Phase ι.D.A) ────────────
#
# Per-file DRF (Data Recovery Field) recovery-agent list. Same per-entry
# shape as ddf_users (SID + cert thumbprint + optional friendly name).
# Recovery agents are typically the DRA (Designated Recovery Agent)
# certificates pushed via Group Policy from the domain or the local
# EFS Recovery Agent configuration.
#
# Defensive: None / wrong-type → empty list. Empty list semantics: "no
# recovery agents configured for this file" — common on standalone
# Windows installs without corporate policy.
#
# Consumers (≥3):
# - app/services/efs_walker.py (writer — populates from $EFS parser)
# - app/services/finding_service.py (emit_efs_findings_from_walk —
#   ι.D.D classifier)
# - app/ai/tools/windows_efs.py (MCP tools — surface field +
#   cross-firmware aggregation)


WINDOWS_EFS_ENCRYPTED_FILES_DRF_RECOVERY_AGENTS_SCHEMA_VERSION = 1


def _normalize_windows_efs_encrypted_files_drf_recovery_agents(
    value: object,
) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``WindowsEfsEncryptedFile.drf_recovery_agents``.

    Canonical: list of dicts, each with at minimum ``sid`` (str) +
    ``cert_thumbprint`` (str) + ``friendly_name`` (str | None).
    Defensive: None / wrong-typed / non-list → empty list.
    """
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _stamp_windows_efs_encrypted_files_drf_recovery_agents(
    payload: list[dict],
) -> list[dict]:
    """Stamp the schema_version sentinel onto the writer payload for
    ``WindowsEfsEncryptedFile.drf_recovery_agents``. Idempotent."""
    if not payload:
        return [
            {
                "schema_version": (
                    WINDOWS_EFS_ENCRYPTED_FILES_DRF_RECOVERY_AGENTS_SCHEMA_VERSION
                )
            }
        ]
    first = payload[0]
    if (
        isinstance(first, dict)
        and first.get("schema_version")
        == WINDOWS_EFS_ENCRYPTED_FILES_DRF_RECOVERY_AGENTS_SCHEMA_VERSION
    ):
        return payload
    return [
        {
            "schema_version": (
                WINDOWS_EFS_ENCRYPTED_FILES_DRF_RECOVERY_AGENTS_SCHEMA_VERSION
            )
        },
        *payload,
    ]


# ── windows_efs_encrypted_files.anomaly_flags (Phase ι.D.A) ──────────────────
#
# Anomaly aggregate computed by the ι.D.C classifier per file. Canonical
# shape:
#
#   {
#     "schema_version": 1,
#     "orphaned_drf": bool,            # DRF without matching DDF (insider-stealth)
#     "unusual_recovery_agent": bool,  # DRF SID not in standard Windows EFS family
#     "multiple_ddf_users": bool,      # >1 user in DDF
#     "large_drf": bool,               # >2 recovery agents
#     "cert_thumbprint_anomaly": bool, # cert thumbprint flagged (informational)
#     "domain_admin_in_ddf": bool,     # domain admin SID in DDF
#     "parse_error": bool,             # $EFS attribute couldn't be parsed
#   }
#
# Consumers (≥3):
# - app/services/efs_walker.py (writer — populates from classifier)
# - app/services/finding_service.py (emit_efs_findings_from_walk —
#   ι.D.D classifier)
# - app/ai/tools/windows_efs.py (MCP tools — exposes anomaly_only filter)


WINDOWS_EFS_ENCRYPTED_FILES_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_windows_efs_encrypted_files_anomaly_flags(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsEfsEncryptedFile.anomaly_flags``.

    Defensive: None / wrong-typed → empty dict. Empty dict means "no
    anomaly evaluation was performed" (e.g. early-init path).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_efs_encrypted_files_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags`` payload
    for ``WindowsEfsEncryptedFile.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_EFS_ENCRYPTED_FILES_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── linux_container_artifacts.* (Phase ι.E.A — FIFTH ι, THIRD LINUX WALKER) ──
#
# 5 JSONB columns on the linux_container_artifacts table — each gets its
# own normalizer per CLAUDE.md Rule #35c. The list-shape columns
# (mounts / capabilities_add / capabilities_drop / env_vars) canonicalize
# to list[str] (or list[dict] for mounts which has structured per-entry
# shape). The dict-shape anomaly_flags column carries the heuristic
# detection aggregate.
#
# Consumers (≥3 — Rule #35c stamp helpers required for any field whose
# read sites span 3+ files):
# - app/services/container_walker.py (writer — populates from JSON state
#   files parsed via stdlib json)
# - app/services/finding_service.py (emit_container_findings_from_walk —
#   ι.E.D classifier)
# - app/ai/tools/linux_container.py (MCP tools — surface fields in tool
#   output JSON + cross-firmware aggregation)


def _normalize_linux_container_artifacts_mounts(value: object) -> list[dict]:
    """Return the canonical ``list[dict]`` shape for
    ``LinuxContainerArtifact.mounts``.

    Canonical: list of dicts, each with at minimum ``source`` (str) +
    ``destination`` (str) + optional ``mode`` (str) + ``type`` (str).
    Defensive: None / wrong-typed / non-list → empty list; non-dict
    elements dropped.
    """
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _normalize_linux_container_artifacts_capabilities_add(
    value: object,
) -> list[str]:
    """Return the canonical ``list[str]`` shape for
    ``LinuxContainerArtifact.capabilities_add``.

    Canonical: list of strings (each a Linux capability name such as
    ``CAP_SYS_ADMIN``). Defensive: None / wrong-typed → empty list;
    non-string list elements coerced via ``str()``; None elements
    dropped.
    """
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []


def _normalize_linux_container_artifacts_capabilities_drop(
    value: object,
) -> list[str]:
    """Return the canonical ``list[str]`` shape for
    ``LinuxContainerArtifact.capabilities_drop``. Same shape as
    capabilities_add."""
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []


def _normalize_linux_container_artifacts_env_vars(value: object) -> list[str]:
    """Return the canonical ``list[str]`` shape for
    ``LinuxContainerArtifact.env_vars``.

    Canonical: list of strings — environment variable KEYS only
    (values are dropped at the writer boundary for security since
    secrets often live in env vars). Defensive: None / wrong-typed →
    empty list.
    """
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []


# Schema version for the inline-stamped anomaly_flags column.
LINUX_CONTAINER_ARTIFACTS_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_linux_container_artifacts_anomaly_flags(
    value: object,
) -> dict:
    """Return the canonical ``dict`` shape for
    ``LinuxContainerArtifact.anomaly_flags``.

    Canonical shape (all 9 bits inline-stamped with schema_version):

      {
        "schema_version": 1,
        "privileged_mode": bool,            # --privileged flag
        "host_pid_namespace": bool,         # PidMode=host
        "host_network_namespace": bool,     # NetworkMode=host
        "host_ipc_namespace": bool,         # IpcMode=host
        "dangerous_capability": bool,       # CAP_SYS_ADMIN / etc
        "unconfined_seccomp": bool,         # seccomp=unconfined
        "unconfined_apparmor": bool,        # apparmor=unconfined
        "unsafe_mount": bool,               # host-sensitive bind mount
        "unknown_registry": bool,           # image from non-major registry
      }

    Defensive: None / wrong-typed → empty dict. Empty dict means "no
    anomaly evaluation was performed" (e.g. parser-failure path).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_linux_container_artifacts_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags`` payload
    for ``LinuxContainerArtifact.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        LINUX_CONTAINER_ARTIFACTS_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.container_walk_result (Phase ι.E.B) ──────────────────────────────
#
# Per-firmware aggregate from a single container-runtime artefact walk.
# Mirrors etl_walk_result / systemd_walk_result / efs_walk_result.
#
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "artifacts_scanned": int,
#     "artifacts_persisted": int,
#     "containers_count": int,                # docker/containerd/podman states
#     "images_count": int,                    # oci_manifest + repositories
#     "configs_count": int,                   # daemon/runtime configs
#     "privileged_count": int,
#     "host_namespace_count": int,
#     "dangerous_capability_count": int,
#     "unsafe_mount_count": int,
#     "unconfined_security_count": int,
#     "unknown_registry_count": int,
#     "anomaly_total": int,
#     "errors": list[str],
#     "per_root": list[dict],
#   }

FIRMWARE_CONTAINER_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_container_walk_result(value: object) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.container_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_container_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.container_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_CONTAINER_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── windows_appcompat_entries.anomaly_flags (Phase κ.B.A) ────────────────────
#
# Per-entry anomaly aggregate computed by the κ.B.C classifier. Canonical
# shape:
#
#   {
#     "schema_version": 1,
#     "suspicious_path": bool,        # under canonical adversary-staging directories
#     "temp_execution": bool,         # .tmp/.dat extension on exec-shape path
#     "unusual_extension": bool,      # extension outside the standard set
#     "parse_error": bool,            # entry failed structured parse
#   }
#
# Consumers (≥3 — Rule #35c stamp helper required):
# - app/services/appcompat_walker.py (writer — populates from classifier)
# - app/services/finding_service.py (emit_appcompat_findings_from_walk —
#   κ.B.D classifier)
# - app/ai/tools/windows_appcompat.py (MCP tools — exposes anomaly_only filter)

WINDOWS_APPCOMPAT_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_windows_appcompat_entries_anomaly_flags(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsAppCompatEntry.anomaly_flags``.

    Defensive: None / wrong-typed → empty dict. Empty dict means "no
    anomaly evaluation was performed" (e.g. early-init path).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_appcompat_entries_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags`` payload
    for ``WindowsAppCompatEntry.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_APPCOMPAT_ENTRIES_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.appcompat_walk_result (Phase κ.B.B) ──────────────────────────────
#
# Per-firmware aggregate from a single AppCompat walk. Mirrors
# etl_walk_result / efs_walk_result / container_walk_result. Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "hives_scanned": int,
#     "entries_persisted": int,
#     "entries_capped": int,
#     "parse_errors": int,
#     "suspicious_path_count": int,
#     "temp_execution_count": int,
#     "unusual_extension_count": int,
#     "anomaly_total": int,
#     "errors": list[str],
#     "per_hive": list[dict],
#   }

FIRMWARE_APPCOMPAT_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_appcompat_walk_result(value: object) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.appcompat_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_appcompat_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.appcompat_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_APPCOMPAT_WALK_RESULT_SCHEMA_VERSION
    return payload


# ── linux_bash_history_entries.suspicious_flags (Phase κ.C.A) ────────────────
#
# Per-line heuristic aggregate computed by the κ.C.D classifier over a
# Linux bash_history file. Canonical shape:
#
#   {
#     "schema_version": 1,
#     "clear_marker": bool,        # T1070.003 clear-history attempt
#     "download_pattern": bool,    # T1105 ingress-tool-transfer
#     "priv_esc_pattern": bool,    # T1548.003 / T1222.002 priv-esc
#   }
#
# Consumers (≥3 — Rule #35c stamp helper required):
# - app/services/linux_persistence_walker.py (writer — populates from classifier)
# - app/services/finding_service.py (emit_linux_persistence_findings_from_walk —
#   κ.C.D classifier)
# - app/ai/tools/linux_persistence.py (MCP tools — exposes suspicious_only filter)

LINUX_BASH_HISTORY_ENTRIES_SUSPICIOUS_FLAGS_SCHEMA_VERSION = 1


def _normalize_linux_bash_history_suspicious_flags(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``LinuxBashHistoryEntry.suspicious_flags``.

    Defensive: None / wrong-typed → empty dict.
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_linux_bash_history_suspicious_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto a ``suspicious_flags`` payload
    for ``LinuxBashHistoryEntry.suspicious_flags``. Idempotent."""
    payload["schema_version"] = (
        LINUX_BASH_HISTORY_ENTRIES_SUSPICIOUS_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── linux_cron_jobs.suspicious_flags (Phase κ.C.A) ───────────────────────────
#
# Per-line heuristic aggregate for a Linux crontab. Canonical shape:
#
#   {
#     "schema_version": 1,
#     "temp_path_command": bool,
#     "reboot_persistence": bool,
#     "network_egress_pattern": bool,
#   }

LINUX_CRON_JOBS_SUSPICIOUS_FLAGS_SCHEMA_VERSION = 1


def _normalize_linux_cron_suspicious_flags(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``LinuxCronJob.suspicious_flags``.

    Defensive: None / wrong-typed → empty dict.
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_linux_cron_suspicious_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto a ``suspicious_flags`` payload
    for ``LinuxCronJob.suspicious_flags``. Idempotent."""
    payload["schema_version"] = (
        LINUX_CRON_JOBS_SUSPICIOUS_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── linux_ld_preload_entries.suspicious_flags (Phase κ.C.A) ──────────────────
#
# Per-line heuristic aggregate for a Linux ld.so.preload file. Canonical:
#
#   {
#     "schema_version": 1,
#     "temp_path_library": bool,
#     "unusual_extension": bool,
#     "world_writable_dir": bool,
#   }

LINUX_LD_PRELOAD_ENTRIES_SUSPICIOUS_FLAGS_SCHEMA_VERSION = 1


def _normalize_linux_ld_preload_suspicious_flags(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``LinuxLdPreloadEntry.suspicious_flags``.

    Defensive: None / wrong-typed → empty dict.
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_linux_ld_preload_suspicious_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto a ``suspicious_flags`` payload
    for ``LinuxLdPreloadEntry.suspicious_flags``. Idempotent."""
    payload["schema_version"] = (
        LINUX_LD_PRELOAD_ENTRIES_SUSPICIOUS_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.persistence_walk_result (Phase κ.C.B) ────────────────────────────
#
# Per-firmware aggregate from a single Linux persistence-triplet walk.
# Mirrors appcompat_walk_result / efs_walk_result / container_walk_result.
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     # Per-artefact counts
#     "bash_history_files_scanned": int,
#     "bash_history_lines_persisted": int,
#     "cron_files_scanned": int,
#     "cron_lines_persisted": int,
#     "ld_preload_files_scanned": int,
#     "ld_preload_lines_persisted": int,
#     # Per-anomaly-bit aggregates
#     "bash_clear_marker_count": int,
#     "bash_download_pattern_count": int,
#     "bash_priv_esc_pattern_count": int,
#     "cron_temp_path_command_count": int,
#     "cron_reboot_persistence_count": int,
#     "cron_network_egress_pattern_count": int,
#     "ld_preload_temp_path_library_count": int,
#     "ld_preload_unusual_extension_count": int,
#     "ld_preload_world_writable_dir_count": int,
#     "anomaly_total": int,
#     "errors": list[str],
#     "per_artefact": list[dict],
#   }
#
# Consumers (≥3 — Rule #35c stamp helper required):
# - app/services/linux_persistence_walker.py (writer)
# - app/services/finding_service.py (reader for re-emit gating)
# - app/ai/tools/linux_persistence.py (MCP tools — status reader)

FIRMWARE_PERSISTENCE_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_persistence_walk_result(value: object) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.persistence_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_persistence_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.persistence_walk_result``. Idempotent."""
    payload["schema_version"] = (
        FIRMWARE_PERSISTENCE_WALK_RESULT_SCHEMA_VERSION
    )
    return payload


# ── windows_dpapi_master_keys.anomaly_flags (Phase κ.D.A) ─────────────────────
#
# Per-file anomaly aggregate computed by the κ.D.D classifier. Canonical
# shape:
#
#   {
#     "schema_version": 1,
#     "orphaned_masterkey": bool,    # creator_sid no match elsewhere
#     "admin_creator_sid": bool,     # creator_sid matches RID 500/512/519/18
#     "large_masterkey": bool,       # file_size_bytes > 2048
#     "parse_error": bool,           # file header parse failed
#   }
#
# PARSE-ONLY DISCIPLINE (Rule #36 + Rule #45): the κ.D.C walker NEVER
# decrypts any master-key data and NEVER stamps anything cryptographic
# in this JSONB.
#
# Consumers (≥3 — Rule #35c stamp helper required):
# - app/services/dpapi_walker.py (writer — populates from classifier)
# - app/services/finding_service.py (emit_dpapi_findings_from_walk —
#   κ.D.D classifier)
# - app/ai/tools/windows_dpapi.py (MCP tools — exposes anomaly_only filter)

WINDOWS_DPAPI_MASTER_KEYS_ANOMALY_FLAGS_SCHEMA_VERSION = 1


def _normalize_windows_dpapi_anomaly_flags(value: object) -> dict:
    """Return the canonical ``dict`` shape for
    ``WindowsDpapiMasterKey.anomaly_flags``.

    Defensive: None / wrong-typed → empty dict. Empty dict means "no
    anomaly evaluation was performed" (e.g. early-init path).
    """
    if isinstance(value, dict):
        return value
    return {}


def _stamp_windows_dpapi_anomaly_flags(payload: dict) -> dict:
    """Stamp the schema_version inline onto an ``anomaly_flags`` payload
    for ``WindowsDpapiMasterKey.anomaly_flags``. Idempotent."""
    payload["schema_version"] = (
        WINDOWS_DPAPI_MASTER_KEYS_ANOMALY_FLAGS_SCHEMA_VERSION
    )
    return payload


# ── firmware.dpapi_walk_result (Phase κ.D.B) ──────────────────────────────────
#
# Per-firmware aggregate from a single DPAPI master-key METADATA walk.
# Mirrors appcompat_walk_result / efs_walk_result / persistence_walk_result.
# Canonical shape:
#
#   {
#     "schema_version": 1,
#     "run_seconds": float,
#     "files_scanned": int,
#     "files_persisted": int,
#     "files_capped": int,
#     "parse_errors": int,
#     "orphaned_masterkey_count": int,
#     "admin_creator_sid_count": int,
#     "large_masterkey_count": int,
#     "anomaly_total": int,
#     "errors": list[str],
#     "per_file": list[dict],
#   }
#
# PARSE-ONLY DISCIPLINE (Rule #36 + Rule #45): the walker NEVER
# decrypts; this JSONB carries METADATA aggregates only.

FIRMWARE_DPAPI_WALK_RESULT_SCHEMA_VERSION = 1


def _normalize_firmware_dpapi_walk_result(value: object) -> dict | None:
    """Return the canonical ``dict`` (or ``None``) shape for
    ``Firmware.dpapi_walk_result``.

    ``None`` preserved — semantic load is "no completed run yet".
    Wrong-typed values collapse to ``None``.
    """
    if isinstance(value, dict):
        return value
    return None


def _stamp_firmware_dpapi_walk_result(payload: dict) -> dict:
    """Stamp the schema_version onto a writer payload for
    ``Firmware.dpapi_walk_result``. Idempotent."""
    payload["schema_version"] = FIRMWARE_DPAPI_WALK_RESULT_SCHEMA_VERSION
    return payload
