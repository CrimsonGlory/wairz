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
