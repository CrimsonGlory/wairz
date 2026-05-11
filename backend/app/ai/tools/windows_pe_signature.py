"""Windows PE signature MCP tools — Phase β.9.

Surfaces the Phase β.4-β.8 Authenticode + RICH + DBX + ARM-arch
verdicts to the MCP layer:

- ``verify_authenticode`` — runs signify Authenticode validation on
  one PE in the firmware tree (wraps :func:`authenticode_service.verify_pe_file`).
- ``decode_rich_header`` — decodes the Microsoft RICH header
  toolchain fingerprint (wraps :func:`rich_header_service.decode_rich_header`).
- ``scan_dbx_revocation`` — cross-references a leaf certificate serial
  against the offline ``dbxupdate.bin`` bundle (wraps
  :func:`dbx_service.match_dbx_revocation`).
- ``detect_pe_arch_view`` — surfaces ARM64EC / ARM64X bimorphic
  discriminator (wraps :func:`format_detection.detect_pe_arch_view`).
- ``list_signatures`` — reads persisted ``WindowsPESignature`` rows for
  the active firmware (Phase β.8 background-runner output).
- ``get_signature_chain`` — returns the full per-PE record by blob_path
  basename match against the active firmware's blobs.

Sandbox discipline (Rule #1): every input ``path`` is resolved via
``context.resolve_path()`` before any read; the helper realpath-walks
against the firmware extraction root and raises if the target escapes.

Output truncation (Rule #29): tool outputs ≤ 30 KB; large dumps
emit a tail-truncation marker.

Why these tools wrap services rather than re-implementing: the heavy
lifting (signify init, asn1crypto serial parsing, RICH XOR-walking,
LIEF arch detection) lives in the services. MCP tools provide:
(a) sandboxed path resolution so the AI can hand a relative
firmware-tree path, (b) JSON-shaped output the operator can copy-paste
into a finding, (c) consistency with the α.4 ``windows_archive``
pattern so operators see a uniform tool-category shape across phases.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import asdict
from typing import Any

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.models.windows_pe_signature import WindowsPESignature
from app.services.authenticode_service import verify_pe_file
from app.services.dbx_service import match_dbx_revocation
from app.services.format_detection import detect_pe_arch_view
from app.services.rich_header_service import decode_rich_header

logger = logging.getLogger(__name__)


# ── 30 KB output cap (Rule #29) ────────────────────────────────────────────
_OUTPUT_CAP_BYTES = 30 * 1024


def _truncate(text: str, cap: int = _OUTPUT_CAP_BYTES) -> str:
    """Truncate to MCP byte cap, preserving the head and noting the cut."""
    if len(text) <= cap:
        return text
    keep = cap - 64
    return text[:keep] + f"\n... [truncated; {len(text) - keep} more bytes]\n"


def _json_default(obj: Any) -> Any:
    """JSON serializer for dataclasses, datetimes, and UUIDs.

    The verdict dataclass carries a ``signed_at`` datetime + nested dicts
    with arbitrary value types; the standard ``json.dumps`` chokes on
    those. We accept ``str()`` as the universal fallback so the operator
    always gets a readable representation.
    """
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


def _verdict_to_json(verdict: Any) -> str:
    """Render an ``AuthenticodeVerdict`` dataclass as pretty-printed JSON."""
    return json.dumps(asdict(verdict), indent=2, default=_json_default)


def register_windows_pe_signature_tools(registry: ToolRegistry) -> None:
    """Register all Phase β.9 Windows PE signature MCP tools."""

    registry.register(
        name="verify_authenticode",
        description=(
            "Verify a Windows PE binary's Authenticode signature chain "
            "via signify. Returns the canonical verdict: signed (bool), "
            "chain_status (valid_at_signing | valid_now | revoked | "
            "never_valid | unknown), signer_subject, signer_issuer, "
            "leaf_serial, sig_hash_algo, tsa_authority, signed_at "
            "(RFC 3161 counter-signature timestamp), signatures_count "
            "(dual-sig PEs), arch_view (ARM64EC/X bimorphic), "
            "rich_header_json (toolchain fingerprint), dbx_revoked + "
            "dbx_revocation_kb. Offline-trust per Rule #37: signify "
            "ships Microsoft Authenticode roots — no network fetch at "
            "scan time."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path inside the firmware tree to a PE binary (.exe / .dll / .sys / .efi).",
                },
            },
            "required": ["path"],
        },
        handler=_handle_verify_authenticode,
    )

    registry.register(
        name="decode_rich_header",
        description=(
            "Decode the Microsoft RICH header of a PE binary into its "
            "toolchain fingerprint: xor_key, entry_count, entries (each "
            "with comp_id / build_number / product_id / instances), and "
            "hash_md5 (cluster fingerprint). Returns null when the PE has "
            "no RICH header (non-MS toolchain, stripped, or pre-VS2002). "
            "Capped at 1000 entries per Phase β.6 sanity bound."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path inside the firmware tree to a PE binary.",
                },
            },
            "required": ["path"],
        },
        handler=_handle_decode_rich_header,
    )

    registry.register(
        name="scan_dbx_revocation",
        description=(
            "Cross-reference a leaf certificate serial number against "
            "the offline UEFI Secure Boot revocation bundle "
            "(``dbxupdate.bin``). Accepts either a hex serial directly "
            "or a PE path (the tool extracts the serial via signify). "
            "Returns match_kind (x509_serial | sha256_image | none), "
            "revoked (bool), revocation_kb (KB string from the side-car "
            "metadata when β.10 lands), bundle_entries (parser stats), "
            "bundle_path. Returns null when the bundle isn't provisioned "
            "(β.10 deferral) — the verdict is honestly 'no DBX information'."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "leaf_serial": {
                    "type": "string",
                    "description": (
                        "Hex serial of the PE's leaf certificate "
                        "(e.g. 'DEADBEEF'). Mutually exclusive with `path`."
                    ),
                },
                "path": {
                    "type": "string",
                    "description": (
                        "Path inside the firmware tree to a PE binary; "
                        "the tool runs signify to extract the leaf "
                        "serial then matches it. Mutually exclusive with "
                        "`leaf_serial`."
                    ),
                },
            },
        },
        handler=_handle_scan_dbx_revocation,
    )

    registry.register(
        name="detect_pe_arch_view",
        description=(
            "Detect ARM64EC / ARM64X bimorphic discriminator on a PE "
            "binary via lief. Returns: primary (arm64x | arm64ec), "
            "secondary (amd64 | x64_abi), divergence_score (entry-point "
            "delta — higher = more functions diverge between the two "
            "loader views). Returns null for single-arch PEs (the durable "
            "signal that no bimorphic split exists)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path inside the firmware tree to a PE binary.",
                },
            },
            "required": ["path"],
        },
        handler=_handle_detect_pe_arch_view,
    )

    registry.register(
        name="list_signatures",
        description=(
            "List persisted ``WindowsPESignature`` rows for the active "
            "firmware (Phase β.8 background-runner output). Returns a "
            "compact summary per row: blob_path, signed (bool), "
            "chain_status, signer_subject, leaf_serial, dbx_revoked. "
            "Run POST /authenticode-chain first if no rows exist; the "
            "frontend's PeHardeningPage triggers this automatically. "
            "Output capped at 50 rows; pass ``offset`` to page."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "offset": {
                    "type": "integer",
                    "description": "Row offset for pagination (default 0).",
                    "minimum": 0,
                },
                "chain_status": {
                    "type": "string",
                    "description": (
                        "Optional filter: only rows whose chain_status "
                        "matches (valid_at_signing | valid_now | revoked "
                        "| never_valid | unknown)."
                    ),
                },
            },
        },
        handler=_handle_list_signatures,
    )

    registry.register(
        name="get_signature_chain",
        description=(
            "Return the full per-PE ``WindowsPESignature`` record matched "
            "against the active firmware's blobs by blob_path basename. "
            "The path argument can be the original firmware-tree path "
            "OR just the basename. Surfaces every column including the "
            "raw chain_json (signify's verification_result + "
            "has_countersigner + verify_exception), arch_view JSONB, "
            "rich_header_json JSONB, and dbx_revocation_kb."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Firmware-tree path to a PE binary OR the "
                        "basename (e.g. 'vendor.sys'). The tool matches "
                        "against blob.blob_path basename."
                    ),
                },
            },
            "required": ["path"],
        },
        handler=_handle_get_signature_chain,
    )


# ── Handlers ───────────────────────────────────────────────────────────────


async def _handle_verify_authenticode(input: dict, context: ToolContext) -> str:
    pe_path = context.resolve_path(input.get("path", ""))
    # Rule #5 — verify_pe_file is sync; offload to thread executor.
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, pe_path):
        return f"PE file not found: {pe_path}"

    try:
        verdict = await loop.run_in_executor(None, verify_pe_file, pe_path)
    except Exception as exc:  # noqa: BLE001
        # verify_pe_file is supposed to never raise, but defend against
        # an unexpected bug in the executor pipeline.
        logger.debug("verify_pe_file raised unexpectedly", exc_info=True)
        return f"verify_authenticode failed: {exc.__class__.__name__}: {exc}"

    return _truncate(_verdict_to_json(verdict))


async def _handle_decode_rich_header(input: dict, context: ToolContext) -> str:
    pe_path = context.resolve_path(input.get("path", ""))
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, pe_path):
        return f"PE file not found: {pe_path}"

    try:
        decoded = await loop.run_in_executor(None, decode_rich_header, pe_path)
    except Exception as exc:  # noqa: BLE001
        logger.debug("decode_rich_header raised unexpectedly", exc_info=True)
        return f"decode_rich_header failed: {exc.__class__.__name__}: {exc}"

    if decoded is None:
        return (
            f"No RICH header in {os.path.basename(pe_path)} — non-Microsoft "
            "toolchain, stripped binary, or pre-VS2002 (the durable null signal)."
        )

    return _truncate(json.dumps(decoded, indent=2, default=_json_default))


async def _handle_scan_dbx_revocation(input: dict, context: ToolContext) -> str:
    leaf_serial = input.get("leaf_serial")
    path = input.get("path")

    if leaf_serial and path:
        return (
            "scan_dbx_revocation: pass exactly one of `leaf_serial` or "
            "`path`, not both."
        )
    if not leaf_serial and not path:
        return (
            "scan_dbx_revocation: pass either `leaf_serial` (hex) or "
            "`path` (PE binary). Neither was provided."
        )

    # Path branch: extract the serial via signify first.
    if path:
        pe_path = context.resolve_path(path)
        loop = asyncio.get_running_loop()
        if not await loop.run_in_executor(None, os.path.isfile, pe_path):
            return f"PE file not found: {pe_path}"
        try:
            verdict = await loop.run_in_executor(None, verify_pe_file, pe_path)
        except Exception as exc:  # noqa: BLE001
            return f"verify_pe_file (for serial extraction) failed: {exc}"
        leaf_serial = verdict.leaf_serial
        if leaf_serial is None:
            return (
                f"PE {os.path.basename(pe_path)} has no extractable leaf "
                "certificate serial (unsigned, parse failed, or signature "
                "lacks signer_info). DBX scan is gated on a serial."
            )

    loop = asyncio.get_running_loop()
    try:
        match = await loop.run_in_executor(
            None, match_dbx_revocation, leaf_serial,
        )
    except Exception as exc:  # noqa: BLE001
        return f"match_dbx_revocation failed: {exc}"

    if match is None:
        return (
            f"DBX bundle not provisioned (β.10 deferral) — match call "
            f"returned None. Leaf serial {leaf_serial!r} cannot be "
            "checked offline until the bundle lands at "
            "$DBX_BUNDLE_PATH."
        )

    return _truncate(json.dumps(match, indent=2, default=_json_default))


async def _handle_detect_pe_arch_view(input: dict, context: ToolContext) -> str:
    pe_path = context.resolve_path(input.get("path", ""))
    loop = asyncio.get_running_loop()
    if not await loop.run_in_executor(None, os.path.isfile, pe_path):
        return f"PE file not found: {pe_path}"

    try:
        view = await loop.run_in_executor(None, detect_pe_arch_view, pe_path)
    except Exception as exc:  # noqa: BLE001
        return f"detect_pe_arch_view failed: {exc.__class__.__name__}: {exc}"

    if view is None:
        return (
            f"{os.path.basename(pe_path)} is single-arch (no ARM64EC / "
            "ARM64X bimorphic split). The null signal is durable — "
            "single-arch PEs land in WindowsPESignature.arch_view IS NULL."
        )

    return _truncate(json.dumps(view, indent=2, default=_json_default))


_VALID_CHAIN_STATUSES: frozenset[str] = frozenset({
    "valid_at_signing", "valid_now", "revoked", "never_valid", "unknown",
})


async def _handle_list_signatures(input: dict, context: ToolContext) -> str:
    offset = int(input.get("offset", 0) or 0)
    chain_status_filter = input.get("chain_status")

    if chain_status_filter and chain_status_filter not in _VALID_CHAIN_STATUSES:
        return (
            f"Invalid chain_status filter {chain_status_filter!r}. "
            f"Allowed: {sorted(_VALID_CHAIN_STATUSES)}"
        )

    # JOIN WindowsPESignature → HardwareFirmwareBlob to filter by the
    # ToolContext's firmware_id and pull blob_path for the operator.
    stmt = (
        select(WindowsPESignature, HardwareFirmwareBlob.blob_path)
        .join(
            HardwareFirmwareBlob,
            HardwareFirmwareBlob.id == WindowsPESignature.blob_id,
        )
        .where(HardwareFirmwareBlob.firmware_id == context.firmware_id)
    )
    if chain_status_filter:
        stmt = stmt.where(
            WindowsPESignature.chain_status == chain_status_filter
        )
    stmt = stmt.order_by(WindowsPESignature.created_at).offset(offset).limit(50)

    rows = (await context.db.execute(stmt)).all()

    if not rows:
        return (
            f"No WindowsPESignature rows for firmware {context.firmware_id} "
            f"(filter={chain_status_filter or 'none'}, offset={offset}). "
            "Trigger a run via "
            "`POST /api/v1/projects/{project_id}/hardware-firmware/"
            "authenticode-chain` and poll "
            "`/authenticode-chain/status` until status='completed'."
        )

    summaries: list[dict[str, Any]] = []
    for sig, blob_path in rows:
        summaries.append({
            "blob_path": blob_path,
            "signed": sig.signed,
            "chain_status": sig.chain_status,
            "signer_subject": sig.signer_subject,
            "leaf_serial": sig.leaf_serial,
            "sig_hash_algo": sig.sig_hash_algo,
            "dbx_revoked": sig.dbx_revoked,
            "dbx_revocation_kb": sig.dbx_revocation_kb,
            "arch_view_present": sig.arch_view is not None,
            "rich_header_present": sig.rich_header_json is not None,
        })

    return _truncate(
        f"Found {len(summaries)} signature row(s) "
        f"(offset={offset}, filter={chain_status_filter or 'none'}):\n\n"
        f"{json.dumps(summaries, indent=2, default=_json_default)}"
    )


async def _handle_get_signature_chain(input: dict, context: ToolContext) -> str:
    requested = input.get("path", "")
    if not requested:
        return "get_signature_chain: `path` is required."

    # Accept either a full firmware-tree path or a bare basename. We
    # always match by basename against blob.blob_path because absolute
    # blob_paths in the DB are post-extraction filesystem paths that
    # may not match the operator's virtualised view.
    basename = os.path.basename(requested.rstrip("/"))
    if not basename:
        return f"get_signature_chain: could not derive basename from {requested!r}"

    stmt = (
        select(WindowsPESignature, HardwareFirmwareBlob)
        .join(
            HardwareFirmwareBlob,
            HardwareFirmwareBlob.id == WindowsPESignature.blob_id,
        )
        .where(HardwareFirmwareBlob.firmware_id == context.firmware_id)
    )
    candidates = (await context.db.execute(stmt)).all()
    matches = [
        (sig, blob)
        for sig, blob in candidates
        if os.path.basename(blob.blob_path) == basename
    ]

    if not matches:
        return (
            f"No WindowsPESignature row matches basename {basename!r} "
            f"under firmware {context.firmware_id}. Run "
            "`list_signatures` to see what's persisted, or trigger a "
            "fresh authenticode-chain run."
        )
    if len(matches) > 1:
        # Multiple blobs share a basename (rare but possible — same file
        # at different paths inside the firmware). Surface all.
        out = [
            f"Multiple matches for basename {basename!r} ({len(matches)} rows):\n"
        ]
        for sig, blob in matches:
            out.append(f"\nblob_path: {blob.blob_path}")
            out.append(json.dumps(
                {
                    "signed": sig.signed,
                    "chain_status": sig.chain_status,
                    "signer_subject": sig.signer_subject,
                    "leaf_serial": sig.leaf_serial,
                    "dbx_revoked": sig.dbx_revoked,
                    "dbx_revocation_kb": sig.dbx_revocation_kb,
                    "arch_view": sig.arch_view,
                    "rich_header_json": sig.rich_header_json,
                    "chain_json": sig.chain_json,
                },
                indent=2,
                default=_json_default,
            ))
        return _truncate("\n".join(out))

    sig, blob = matches[0]
    payload = {
        "blob_path": blob.blob_path,
        "blob_id": str(blob.id),
        "signed": sig.signed,
        "chain_status": sig.chain_status,
        "signer_subject": sig.signer_subject,
        "signer_issuer": sig.signer_issuer,
        "leaf_serial": sig.leaf_serial,
        "sig_hash_algo": sig.sig_hash_algo,
        "tsa_authority": sig.tsa_authority,
        "signed_at": sig.signed_at.isoformat() if sig.signed_at else None,
        "chain_json": sig.chain_json,
        "dbx_revoked": sig.dbx_revoked,
        "dbx_revocation_kb": sig.dbx_revocation_kb,
        "rich_header_json": sig.rich_header_json,
        "arch_view": sig.arch_view,
        "created_at": sig.created_at.isoformat() if sig.created_at else None,
        "updated_at": sig.updated_at.isoformat() if sig.updated_at else None,
    }
    return _truncate(json.dumps(payload, indent=2, default=_json_default))
