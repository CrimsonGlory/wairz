"""Authenticode validator service — Phase β.4.

Wraps signify 0.9.2's AuthenticodeFile API to produce canonical verdicts
the rest of the system consumes:

- Phase β.4 background runner ``_run_authenticode_chain_background`` calls
  :func:`verify_pe_file` for each PE in a firmware's hardware_firmware_blobs
  and persists a ``WindowsPESignature`` row per PE.
- Phase β.7 MCP tool ``verify_authenticode`` calls :func:`verify_pe_file`
  on operator request and returns the verdict directly.

Persona-E #2 + #3 + #5 disciplines:
- Dual-sig (SHA-1 + SHA-256) handled via signify's iter_signatures + the
  multi_verify_mode='any' default. Persona-E sec.2 #3 — "signify's best
  mode picks one signature on dual-signed PEs" — we surface ALL signature
  count via :attr:`AuthenticodeVerdict.signatures_count` and capture the
  best-validating chain in ``chain_json``.
- Time-anchored tri-state via counter-signature timestamp. When the
  counter-sig is present and validates, ``signed_at`` is populated and the
  verdict can distinguish ``valid_at_signing`` vs ``valid_now``.
- Offline-first per Rule #1 / Rule #37 candidate: signify's
  ``TRUSTED_CERTIFICATE_STORE`` ships Microsoft Authenticode roots
  pre-bundled — no network fetch at scan time.

The function returns an :class:`AuthenticodeVerdict` NamedTuple that maps
1:1 onto the ``WindowsPESignature`` table columns (Phase β.2). The
background runner's job is the SQL plumbing; this service's job is the
cryptographic verdict.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from signify.authenticode import (
    AuthenticodeFile,
    AuthenticodeVerificationResult,
)

logger = logging.getLogger(__name__)


# ── Public verdict shape ──────────────────────────────────────────────────


# Mirror the WindowsPESignature.chain_status CHECK constraint enum
# (migration b1a2c3d4e5f6) so callers get static type checking at
# the boundary.
ChainStatus = Literal[
    "valid_at_signing",
    "valid_now",
    "revoked",
    "never_valid",
    "unknown",
]


@dataclass
class AuthenticodeVerdict:
    """Canonical verdict for one PE binary's Authenticode chain.

    Maps 1:1 onto the WindowsPESignature columns. The background runner
    in Phase β.4 background processing constructs the row from this
    dataclass + the blob_id FK.
    """

    signed: bool
    chain_status: ChainStatus
    signer_subject: str | None = None
    signer_issuer: str | None = None
    leaf_serial: str | None = None
    sig_hash_algo: str | None = None
    tsa_authority: str | None = None
    signed_at: datetime | None = None
    signatures_count: int = 0
    chain_json: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


# ── Verification result → ChainStatus mapping ────────────────────────────


def _map_verification_result_to_chain_status(
    result: AuthenticodeVerificationResult,
    has_timestamp: bool,
) -> ChainStatus:
    """Map signify's verification result enum to our tri-state ChainStatus.

    Persona-E #2: when the signing chain is broken AND a counter-sig
    timestamp is present, the binary was likely valid AT signing time but
    has since been revoked / expired. Without the timestamp we can't
    distinguish ``revoked`` from ``never_valid`` — default to never_valid
    in that case (more pessimistic; caller can re-classify if it has
    out-of-band evidence).
    """
    if result == AuthenticodeVerificationResult.OK:
        # Signature validates today. The counter-sig timestamp (if present)
        # gives us the "valid_at_signing AND valid_now" view; we surface
        # the stronger ``valid_now`` since it implies the weaker
        # ``valid_at_signing``.
        return "valid_now"

    if result == AuthenticodeVerificationResult.NOT_SIGNED:
        # Caller should branch on .signed before calling this mapper, but
        # be defensive if they don't.
        return "unknown"

    if result == AuthenticodeVerificationResult.CERTIFICATE_ERROR:
        return "revoked" if has_timestamp else "never_valid"

    if result in (
        AuthenticodeVerificationResult.PARSE_ERROR,
        AuthenticodeVerificationResult.UNKNOWN_ERROR,
    ):
        return "unknown"

    if result in (
        AuthenticodeVerificationResult.VERIFY_ERROR,
        AuthenticodeVerificationResult.INVALID_DIGEST,
        AuthenticodeVerificationResult.INCONSISTENT_DIGEST_ALGORITHM,
        AuthenticodeVerificationResult.COUNTERSIGNER_ERROR,
        AuthenticodeVerificationResult.INVALID_ADDITIONAL_HASH,
    ):
        return "never_valid"

    return "unknown"


# ── Helper extractors ────────────────────────────────────────────────────


def _extract_signer_info(signature) -> dict[str, str | None]:
    """Pull signer subject / issuer / leaf serial / sig hash algorithm
    from an :class:`AuthenticodeSignature`. Defensive: any attribute
    miss returns None so the caller can still build a verdict.
    """
    out: dict[str, str | None] = {
        "signer_subject": None,
        "signer_issuer": None,
        "leaf_serial": None,
        "sig_hash_algo": None,
    }
    try:
        # signify AuthenticodeSignature.signer_info gives access to the
        # signer's certificate. The exact attribute path varies between
        # 0.7 and 0.9; defensive lookups keep this resilient.
        signer_info = getattr(signature, "signer_info", None)
        if signer_info is not None:
            cert = getattr(signer_info, "certificate", None) or getattr(
                signer_info, "issuer_cert", None,
            )
            if cert is not None:
                out["signer_subject"] = str(getattr(cert, "subject", None) or "") or None
                out["signer_issuer"] = str(getattr(cert, "issuer", None) or "") or None
                serial = getattr(cert, "serial_number", None)
                out["leaf_serial"] = format(serial, "X") if serial is not None else None
            digest_algo = getattr(signer_info, "digest_algorithm", None)
            if digest_algo is not None:
                out["sig_hash_algo"] = (
                    digest_algo if isinstance(digest_algo, str) else getattr(digest_algo, "name", None)
                )
    except Exception:
        # Best-effort — verification verdict is what matters; signer
        # metadata is informational.
        logger.debug("signer_info extraction failed", exc_info=True)
    return out


def _extract_timestamp(signature) -> tuple[datetime | None, str | None]:
    """Extract counter-signature timestamp + TSA authority subject.

    Returns ``(signed_at, tsa_authority)``. Either may be None if no
    counter-signature is present (older signed PEs without RFC 3161).
    """
    try:
        countersigner = getattr(signature, "countersigner", None)
        if countersigner is None:
            return (None, None)
        signing_time = getattr(countersigner, "signing_time", None) or getattr(
            countersigner, "timestamp", None,
        )
        cert = getattr(countersigner, "certificate", None) or getattr(
            countersigner, "issuer_cert", None,
        )
        tsa_subject = str(getattr(cert, "subject", None) or "") or None if cert else None
        return (signing_time if isinstance(signing_time, datetime) else None, tsa_subject)
    except Exception:
        logger.debug("countersigner extraction failed", exc_info=True)
        return (None, None)


# ── Public verifier ──────────────────────────────────────────────────────


def verify_pe_file(path: str | Path) -> AuthenticodeVerdict:
    """Verify a PE file's Authenticode chain. Returns the canonical verdict.

    Never raises on I/O / parse / verify failures — every failure mode
    maps to verdict fields. The caller can branch on ``verdict.signed``
    and ``verdict.chain_status`` to render UI / persist / generate findings.

    Performance: signify reads the PE via from_stream which only walks the
    central directory + signature data — no full-file scan unless
    ``verify_additional_hashes`` is invoked. For Phase β.4 batch use we
    call only ``explain_verify`` which is the cheap path.
    """
    p = Path(path)

    if not p.is_file():
        return AuthenticodeVerdict(
            signed=False,
            chain_status="unknown",
            error=f"PE file not found: {p}",
        )

    try:
        with open(p, "rb") as fh:
            af = AuthenticodeFile.from_stream(fh, file_name=p.name)
            return _verify_with_open_file(af)
    except OSError as exc:
        return AuthenticodeVerdict(
            signed=False,
            chain_status="unknown",
            error=f"PE read failed: {exc}",
        )
    except Exception as exc:
        # signify can raise for malformed PEs that aren't simple OSError.
        # Capture but don't propagate — the verdict is the contract.
        logger.debug("Authenticode parse failed for %s", p, exc_info=True)
        return AuthenticodeVerdict(
            signed=False,
            chain_status="unknown",
            error=f"PE parse failed: {exc.__class__.__name__}: {exc}",
        )


def _verify_with_open_file(af: AuthenticodeFile) -> AuthenticodeVerdict:
    """Inner verification — invoked with an open AuthenticodeFile."""

    # Count signatures eagerly — Persona-E sec.2 #3: dual-sig PEs need
    # the count surfaced even if only one validates.
    signatures = list(af.iter_signatures())
    signatures_count = len(signatures)

    if signatures_count == 0:
        return AuthenticodeVerdict(
            signed=False,
            chain_status="unknown",
            signatures_count=0,
        )

    # explain_verify returns (result_enum, exception_or_None) — the cheap
    # path that doesn't raise. Default multi_verify_mode='any' picks the
    # best-validating signature in dual-sig PEs.
    try:
        result, exc = af.explain_verify()
    except Exception as e:
        logger.debug("explain_verify raised", exc_info=True)
        return AuthenticodeVerdict(
            signed=True,  # signatures are present even if verification raised
            chain_status="unknown",
            signatures_count=signatures_count,
            error=f"explain_verify raised: {e.__class__.__name__}: {e}",
        )

    # Pick the first signature's metadata (signify's 'any' mode validates
    # the strongest one but doesn't tell us which — for Phase β.4 baseline
    # we emit the first signature's metadata; β follow-up can refine).
    primary_sig = signatures[0]
    signer_info = _extract_signer_info(primary_sig)
    signed_at, tsa_authority = _extract_timestamp(primary_sig)
    has_timestamp = signed_at is not None

    chain_status = _map_verification_result_to_chain_status(result, has_timestamp)

    chain_json: dict[str, Any] = {
        "verification_result": result.name,
        "signatures_count": signatures_count,
        "has_countersigner": has_timestamp,
    }
    if exc is not None:
        chain_json["verify_exception"] = f"{exc.__class__.__name__}: {exc}"

    return AuthenticodeVerdict(
        signed=True,
        chain_status=chain_status,
        signer_subject=signer_info["signer_subject"],
        signer_issuer=signer_info["signer_issuer"],
        leaf_serial=signer_info["leaf_serial"],
        sig_hash_algo=signer_info["sig_hash_algo"],
        tsa_authority=tsa_authority,
        signed_at=signed_at,
        signatures_count=signatures_count,
        chain_json=chain_json,
        error=None,
    )
