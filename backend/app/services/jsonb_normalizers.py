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
