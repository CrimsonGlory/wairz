"""Phase θ.C — EFI System Partition (ESP) `.efi` PE chain walker.

Walks the EFI System Partition of a firmware capture and validates
every `.efi` PE32+ file against the β.4 signify Authenticode chain +
β.10 DBX revocation list + pefile COFF metadata. Each `.efi` becomes
one ``WindowsEspEntry`` row for downstream finding-emit hooks (θ.C.D).

**Rule #39 inner/outer/safe runner triplet** (γ.4 + δ.5 + ε.1.b.3 +
ζ.2.B + ζ.3.B + η.B.C + η.C.C + η.A.C + θ.A.C + θ.B.D + θ.C.C =
Rule-of-Eleven):

- :func:`_do_esp_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every `.efi` candidate under detection roots,
  computes SHA256 + size, calls signify ``verify_pe_file`` for
  Authenticode + β.10 DBX (the verifier returns a verdict that
  already includes the DBX match), persists per-entry
  ``WindowsEspEntry`` rows, returns aggregate dict UNSTAMPED.
- :func:`run_esp_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer
  guard catches escapes; failure persistence on a fresh session.
- :func:`auto_esp_walk_firmware_safe` — UNPACK-POST-DETECTION hook.
  Runs the inner orchestrator + emit hook but does NOT mutate
  ``esp_walk_status`` (leaves ``idle`` so manual re-trigger works
  without 409 conflict).

**Rule #36 no-execute discipline.** `.efi` files are PE32+ binaries.
The walker calls signify (which reads the certificate table AS
DATA), pefile (which reads the COFF header AS DATA), and the β.10
DBX matcher (which compares hashes / serial numbers). NO codepath
in this walker invokes wine / mono / qemu-system / chainloader /
``rundll32`` / any process-spawn primitive against the `.efi`
files. The test gate
``tests/test_esp_walker.py::test_esp_no_efi_execution`` asserts this
structurally. The PEs are surfaced as DATA in
``WindowsEspEntry.authenticode_chain`` + Finding evidence; operator
review only.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare
``firmware.extracted_path``) so multi-archive Windows extracts
surface every ESP root candidate (FAT32 mount, raw partition image,
``EFI/`` directory at the root of an extracted UEFI capsule, etc.).

**Performance**. signify cold-imports in ~200 ms (TRUSTED_CERTIFICATE_STORE
is the heavy bit); subsequent ``verify_pe_file`` calls are sub-second
per PE. A typical ESP has 3-15 `.efi` files (bootmgfw / bootmgr / shimx64 /
grubx64 / per-vendor / fbx64 etc.) — iteration runs in single-digit
seconds per firmware. We cap at 200 persisted entries per firmware
(``_DEFAULT_MAX_ENTRIES_PER_FIRMWARE``) defensive against attacker-
planted ESP with thousands of bogus `.efi` files.

**Cross-firmware fingerprint**. ``WindowsEspEntry.fingerprint_sha256``
is SHA256 of ``(file_path_lower + "|" + file_sha256 + "|" +
authenticode_state)`` — same fingerprint across firmware ⇒ same
`.efi` shape was planted. Surfaces via the θ.C.F
``lookup_esp_chain`` MCP tool for cross-corpus bootkit hunt.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_esp_entry import WindowsEspEntry
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_esp_walk_result,
    _stamp_windows_esp_entries_anomaly_flags,
    _stamp_windows_esp_entries_authenticode_chain,
    _stamp_windows_esp_entries_dbx_revocation_match,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum `.efi` entries persisted per firmware. A typical ESP has
# 3-15 .efi files; 200 covers attacker-DoS / vendor-bloated cases.
_DEFAULT_MAX_ENTRIES_PER_FIRMWARE: int = 200

# Cap on .efi file size to validate. Real bootloaders are 100 KB – 8 MB
# (winload.efi reaches ~6 MB on recent Windows). 256 MB is a hard
# safety bound; anything larger is bogus.
_DEFAULT_MAX_FILE_BYTES: int = 256 * 1024 * 1024

# File-size threshold below which we flag is_suspiciously_small.
# Legitimate .efi binaries are virtually never < 4 KB; below this is
# typically a 0-byte placeholder OR an attacker-planted decoy.
_SUSPICIOUSLY_SMALL_BYTES: int = 4 * 1024


# ── Path heuristics for ESP discovery + anomaly classification ──────────────

# Canonical OS-bootloader paths (case-insensitive). A `.efi` file in
# any of these locations is a known-bootloader; replacement with an
# unsigned binary is a strong bootkit signal.
_KNOWN_BOOTLOADER_PATHS = (
    "efi/boot/bootx64.efi",
    "efi/boot/bootia32.efi",
    "efi/boot/bootaa64.efi",
    "efi/microsoft/boot/bootmgfw.efi",
    "efi/microsoft/boot/bootmgr.efi",
    "efi/microsoft/boot/memtest.efi",
    "efi/microsoft/recovery/bootmgfw.efi",
    "efi/redhat/shimx64.efi",
    "efi/redhat/grubx64.efi",
    "efi/ubuntu/shimx64.efi",
    "efi/ubuntu/grubx64.efi",
    "efi/debian/shimx64.efi",
    "efi/debian/grubx64.efi",
    "efi/suse/shimx64.efi",
    "efi/suse/grubx64.efi",
    "efi/fedora/shimx64.efi",
    "efi/fedora/grubx64.efi",
)

# Vendor path prefixes — `.efi` files under these get is_vendor_path=True
# (still notable but lower priority than canonical bootloader paths).
_VENDOR_PATH_PREFIXES = (
    "efi/microsoft/",
    "efi/redhat/",
    "efi/ubuntu/",
    "efi/debian/",
    "efi/suse/",
    "efi/fedora/",
    "efi/dell/",
    "efi/hp/",
    "efi/lenovo/",
    "efi/asus/",
    "efi/acer/",
    "efi/msi/",
    "efi/intel/",
    "efi/amd/",
)

# Signer-subject substrings indicating Microsoft / known-Linux-vendor
# chain. Case-insensitive substring match.
_KNOWN_GOOD_SIGNER_SUBSTRINGS = (
    "microsoft corporation",
    "microsoft windows",
    "microsoft windows production",
    "red hat",
    "canonical",
    "debian",
    "suse",
    "linux foundation",
)


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_signify_available() -> bool:
    """Return True iff ``signify`` is importable in this process.

    Mirrors the dissect.ntfs / LnkParse3 / python-evtx /
    windowsprefetch / regipy graceful-degrade probes. Probe runs in
    <1 ms after first call (Python's import cache).
    """
    try:
        import signify.authenticode  # noqa: F401 — import-only probe
    except ImportError:
        return False
    return True


SIGNIFY_UNAVAILABLE: dict[str, Any] = {
    "status": "unavailable",
    "reason": "signify not installed — see backend/pyproject.toml",
    "entries": 0,
}


# ── ESP `.efi` file candidate enumeration ───────────────────────────────────


def walk_esp_efi_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return candidate `.efi` file paths.

    ESP partitions surface differently across unpackers:
    - FAT32 mount: ``/boot/efi/EFI/...`` under the rootfs.
    - Raw partition image: ``EFI/`` at the root of the extracted dir.
    - UEFI capsule extraction: nested ``EFI/`` subdirectories.

    The walker accepts ANY file whose lowercased name ends with ``.efi``
    AND whose path contains the ``efi/`` directory component (case-
    insensitive) — this catches all three layouts.

    Sync I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    Defensive against missing roots, permission errors — every error
    path is swallowed at the per-root / per-file level so one
    corrupted detection root doesn't abort the entire walk.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots` — NEVER ``firmware.extracted_path``
    alone.
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
        except OSError:
            continue
        if not os.path.isdir(real_root):  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            continue
        for dirpath, _dirnames, filenames in os.walk(  # noqa: ASYNC240 — bounded loop over ≤3 detection roots
            real_root, followlinks=False
        ):
            # Restrict to paths under an EFI/ subdir (case-insensitive)
            # to avoid scanning the entire firmware for ``.efi`` files
            # that may have nothing to do with the boot chain (some
            # unrelated apps ship .efi extensions).
            lower_dir = dirpath.lower()
            if "/efi/" not in lower_dir and not lower_dir.endswith("/efi"):
                continue
            for name in filenames:
                if not name.lower().endswith(".efi"):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math + one realpath per candidate
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                try:
                    if not os.path.isfile(real_full):  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
                        continue
                except OSError:
                    continue
                hits.append(real_full)
    return hits


def looks_like_pe(path: str) -> bool:
    """Return True iff the file at ``path`` has the MZ magic
    signature (``MZ`` at byte offset 0).

    `.efi` files are PE32+ binaries with the standard MZ DOS-header
    prefix. The richer PE-magic check (``PE\\0\\0`` at e_lfanew) is
    deferred to signify/pefile — this is a fast pre-flight only.

    Defensive against unreadable files (OSError) → False.
    Cheap — reads only the first 2 bytes.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(2)
    except OSError:
        return False
    return head == b"MZ"


def _compute_file_sha256(path: str) -> str:
    """Compute SHA256 of the file at ``path``. Streams the file in
    64 KB chunks. Defensive against I/O errors → returns empty
    string."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(64 * 1024), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


# ── Anomaly classification helpers ──────────────────────────────────────────


def is_known_bootloader_path(file_path_lower: str) -> bool:
    """Return True iff ``file_path_lower`` matches one of the canonical
    OS-bootloader paths (case-insensitive). Normalises backslashes
    to forward slashes first."""
    normalised = file_path_lower.replace("\\", "/")
    for known in _KNOWN_BOOTLOADER_PATHS:
        if normalised.endswith(known):
            return True
    return False


def is_vendor_path(file_path_lower: str) -> bool:
    """Return True iff ``file_path_lower`` is under a vendor-specific
    EFI subdirectory."""
    normalised = file_path_lower.replace("\\", "/")
    return any(prefix in normalised for prefix in _VENDOR_PATH_PREFIXES)


def is_non_microsoft_signer(signer_subject: str | None) -> bool:
    """Return True iff ``signer_subject`` does NOT match any known-good
    Microsoft / Linux-vendor signer substring. NULL → False (no
    signer info = no claim either way; the is_unsigned flag covers
    that case)."""
    if not signer_subject:
        return False
    lower = signer_subject.lower()
    return not any(sub in lower for sub in _KNOWN_GOOD_SIGNER_SUBSTRINGS)


def build_anomaly_flags(
    *,
    file_path: str,
    file_size: int,
    authenticode_state: str,
    signer_subject: str | None,
) -> dict:
    """Construct the anomaly_flags payload from extracted fields.

    Pure function — same inputs always produce the same output.
    Caller stamps the schema_version via
    ``_stamp_windows_esp_entries_anomaly_flags``."""
    lower_path = file_path.lower()
    return {
        "is_unsigned": authenticode_state == "unsigned",
        "is_expired": authenticode_state == "signed_expired",
        "is_revoked": authenticode_state == "signed_revoked",
        "is_non_microsoft_signer": (
            authenticode_state in ("signed_valid", "signed_expired")
            and is_non_microsoft_signer(signer_subject)
        ),
        "is_known_bootloader_path": is_known_bootloader_path(lower_path),
        "is_vendor_path": is_vendor_path(lower_path),
        "is_suspiciously_small": file_size < _SUSPICIOUSLY_SMALL_BYTES,
    }


def compute_entry_fingerprint(
    *,
    file_path: str,
    file_sha256: str,
    authenticode_state: str,
) -> str:
    """Compute SHA256(file_path_lower + "|" + file_sha256 + "|" +
    authenticode_state). Same fingerprint across firmware ⇒ same
    `.efi` shape was planted (cross-firmware aggregation surface)."""
    payload = f"{file_path.lower()}|{file_sha256}|{authenticode_state}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── Verdict → authenticode_state mapping ────────────────────────────────────


def map_verdict_to_authenticode_state(verdict: Any) -> str:
    """Map a β.4 :class:`AuthenticodeVerdict` to the
    ``WindowsEspEntry.authenticode_state`` 5-state enum.

    The mapping is:
    - dbx_revoked=True (β.10 hit)             → ``signed_revoked``
    - signed=False                            → ``unsigned`` (no sig)
    - chain_status='valid_now' or
      'valid_at_signing'                      → ``signed_valid``
    - chain_status='revoked'                  → ``signed_revoked``
    - chain_status='never_valid' or
      'unknown' with signed=True              → ``signed_expired``
        (best-effort — the binary IS signed but the chain doesn't
        validate today; could be revoked, expired, or never_valid.
        DBX is the durable revocation signal; this state covers the
        "untrusted today" case without claiming explicit revocation.)
    - error present and chain_status='unknown'
      with signed=False                       → ``parse_failed``

    Pure function. Returns one of the 5 enum values; never raises.
    """
    if getattr(verdict, "dbx_revoked", False):
        return "signed_revoked"

    signed = getattr(verdict, "signed", False)
    chain_status = getattr(verdict, "chain_status", "unknown")
    error = getattr(verdict, "error", None)

    if not signed:
        # Unsigned vs parse-failed — both have signed=False.
        # Distinguish by error string presence: parse-failed verdicts
        # carry a non-None error.
        if error:
            return "parse_failed"
        return "unsigned"

    if chain_status in ("valid_now", "valid_at_signing"):
        return "signed_valid"
    if chain_status == "revoked":
        return "signed_revoked"

    # signed=True but chain doesn't validate cleanly: never_valid,
    # unknown, or any other → signed_expired.
    return "signed_expired"


def verdict_to_chain_dict(verdict: Any) -> dict:
    """Project a β.4 :class:`AuthenticodeVerdict` to the canonical
    ``authenticode_chain`` JSONB shape.

    Pure function. Pulls every signify-derived field as a JSON-safe
    value (datetime → ISO-8601 string)."""
    signed_at_val = getattr(verdict, "signed_at", None)
    signed_at_iso: str | None = None
    if signed_at_val is not None:
        try:
            signed_at_iso = signed_at_val.isoformat()
        except Exception:  # noqa: BLE001 — defensive boundary
            signed_at_iso = str(signed_at_val)

    return {
        "signed": bool(getattr(verdict, "signed", False)),
        "chain_status": str(getattr(verdict, "chain_status", "unknown")),
        "signer_subject": getattr(verdict, "signer_subject", None),
        "signer_issuer": getattr(verdict, "signer_issuer", None),
        "leaf_serial": getattr(verdict, "leaf_serial", None),
        "sig_hash_algo": getattr(verdict, "sig_hash_algo", None),
        "tsa_authority": getattr(verdict, "tsa_authority", None),
        "signed_at": signed_at_iso,
        "signatures_count": int(getattr(verdict, "signatures_count", 0)),
        "error": getattr(verdict, "error", None),
    }


def verdict_to_dbx_match_dict(verdict: Any) -> dict | None:
    """Project the β.10 DBX revocation match onto the canonical
    ``dbx_revocation_match`` JSONB shape — OR ``None`` if no match.

    Pure function. The β.4 verifier already populates
    ``verdict.dbx_revoked`` + ``verdict.dbx_revocation_kb`` from the
    β.10 ``match_dbx_revocation`` call; we surface those onto the
    canonical dict only when a positive match was made.
    """
    revoked = bool(getattr(verdict, "dbx_revoked", False))
    if not revoked:
        return None
    return {
        "revoked": True,
        "revocation_kb": getattr(verdict, "dbx_revocation_kb", None),
        "leaf_serial_normalized": getattr(verdict, "leaf_serial", None),
        "match_kind": "x509_serial",
        # bundle_entries + bundle_path aren't surfaced through the
        # verdict; defaults are best-effort. The β.10
        # match_dbx_revocation returns these in the raw match dict,
        # but the verdict only carries the bool + KB. Future work:
        # plumb the full match dict through the verdict.
        "bundle_entries": 0,
        "bundle_path": "",
    }


# ── Per-`.efi` walk ─────────────────────────────────────────────────────────


def _walk_one_efi(
    efi_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
) -> tuple[WindowsEspEntry | None, dict]:
    """Open one `.efi` file, validate via β.4 verify_pe_file +
    β.10 DBX, build the WindowsEspEntry row.

    Returns ``(entry_or_None, per_file_aggregate)``. ``entry`` is the
    SQLAlchemy ORM instance ready for ``db.add()``; the aggregate
    summary tells the caller what state was determined + the
    associated counters.

    Defensive boundary:
    - file size > max_file_bytes → status="skipped"
    - file doesn't pass the MZ magic check → status="not_pe"
    - verifier raises → status="error" with first 500 chars
    """
    aggregate: dict = {
        "path": relative_source,
        "status": "ok",
        "authenticode_state": "parse_failed",
        "is_unsigned": False,
        "is_revoked": False,
        "is_known_bootloader_path": False,
        "is_non_microsoft_signer": False,
        "error": None,
    }

    try:
        size = os.path.getsize(efi_path)  # noqa: ASYNC240 — pre-flight stat before bounded sync parse
    except OSError as exc:
        aggregate["status"] = "error"
        aggregate["error"] = (
            f"stat failed: {type(exc).__name__}: {str(exc)[:200]}"
        )
        return None, aggregate

    if size > max_file_bytes:
        aggregate["status"] = "skipped"
        aggregate["error"] = (
            f".efi file size {size} exceeds max {max_file_bytes} "
            f"(attacker-DoS / runaway-walk protection); operator can "
            f"re-walk via MCP tool"
        )
        return None, aggregate

    if not looks_like_pe(efi_path):
        aggregate["status"] = "not_pe"
        aggregate["error"] = "MZ magic signature not found"
        return None, aggregate

    file_sha = _compute_file_sha256(efi_path)
    if not file_sha:
        aggregate["status"] = "error"
        aggregate["error"] = "SHA256 hash computation failed"
        return None, aggregate

    # β.4 signify Authenticode + β.10 DBX. verify_pe_file NEVER raises
    # on parse failure — it returns a verdict with the error field
    # populated. Wrap in a defensive try/except anyway in case signify
    # itself has an unhandled corner.
    try:
        from app.services.authenticode_service import verify_pe_file

        verdict = verify_pe_file(efi_path)
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        aggregate["status"] = "error"
        aggregate["error"] = f"{type(exc).__name__}: {msg}"
        return None, aggregate

    state = map_verdict_to_authenticode_state(verdict)
    chain_dict = verdict_to_chain_dict(verdict)
    dbx_dict = verdict_to_dbx_match_dict(verdict)
    anomaly = build_anomaly_flags(
        file_path=relative_source,
        file_size=size,
        authenticode_state=state,
        signer_subject=chain_dict.get("signer_subject"),
    )

    aggregate["authenticode_state"] = state
    aggregate["is_unsigned"] = anomaly["is_unsigned"]
    aggregate["is_revoked"] = anomaly["is_revoked"]
    aggregate["is_known_bootloader_path"] = anomaly["is_known_bootloader_path"]
    aggregate["is_non_microsoft_signer"] = anomaly["is_non_microsoft_signer"]

    fingerprint = compute_entry_fingerprint(
        file_path=relative_source,
        file_sha256=file_sha,
        authenticode_state=state,
    )

    stamped_chain = _stamp_windows_esp_entries_authenticode_chain(chain_dict)
    stamped_dbx = (
        _stamp_windows_esp_entries_dbx_revocation_match(dbx_dict)
        if dbx_dict is not None
        else None
    )
    stamped_anomaly = _stamp_windows_esp_entries_anomaly_flags(anomaly)

    entry = WindowsEspEntry(
        firmware_id=firmware_id,
        file_path=relative_source[:2048],
        file_sha256=file_sha,
        file_size=size,
        authenticode_state=state,
        authenticode_chain=stamped_chain,
        dbx_revocation_match=stamped_dbx,
        anomaly_flags=stamped_anomaly,
        fingerprint_sha256=fingerprint,
    )
    return entry, aggregate


# ── Aggregate helpers ───────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "efi_files_scanned": 0,
        "efi_files_persisted": 0,
        "signed_valid_count": 0,
        "signed_expired_count": 0,
        "signed_revoked_count": 0,
        "unsigned_count": 0,
        "parse_failed_count": 0,
        "dbx_revoked_count": 0,
        "non_microsoft_signer_count": 0,
        "known_bootloader_anomaly_count": 0,
        "errors": [],
        "per_root": [],
    }


def _relativize_path(full_path: str, roots: list[str]) -> str:
    """Compute path relative to whichever detection root contains it."""
    try:
        real_full = os.path.realpath(full_path)
    except OSError:
        return os.path.basename(full_path)
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if real_full == real_root or real_full.startswith(real_root + os.sep):
            return (
                real_full[len(real_root) + 1 :]
                if real_full != real_root
                else "."
            )
    return os.path.basename(full_path)


async def _walk_esp_efi_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_esp_efi_files` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_esp_efi_files, roots)


async def _walk_one_efi_async(
    efi_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
) -> tuple[WindowsEspEntry | None, dict]:
    """Async wrapper around :func:`_walk_one_efi` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_efi(
            efi_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
        ),
    )


# ── Inner orchestrator (Rule #39 inner; accepts db) ─────────────────────────


async def _do_esp_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_entries: int = _DEFAULT_MAX_ENTRIES_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every `.efi` candidate in ``firmware_id``'s extracted tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for ``.efi`` files under ``EFI/`` subdirectories
       (case-insensitive).
    3. For each candidate: pre-flight MZ magic check + size check;
       call β.4 ``verify_pe_file`` (runs signify Authenticode + β.10
       DBX; pure Python; no subprocess); construct + bulk-add
       WindowsEspEntry rows.
    4. Aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per Rule #39 — accepts ``db`` so tier-1 live
    canary tests (Rule #35b) can drive the FULL walk against a real
    test DB without DNS resolution issues from
    ``async_session_factory()``.
    """
    started = time.monotonic()

    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        return _empty_walk_result(0.0)

    roots = await get_detection_roots(firmware, db=db)
    if not roots:
        return _empty_walk_result(time.monotonic() - started)

    efi_paths = await _walk_esp_efi_files_async(roots)
    if not efi_paths:
        return _empty_walk_result(time.monotonic() - started)

    efi_files_scanned = 0
    efi_files_persisted = 0
    signed_valid_count = 0
    signed_expired_count = 0
    signed_revoked_count = 0
    unsigned_count = 0
    parse_failed_count = 0
    dbx_revoked_count = 0
    non_microsoft_signer_count = 0
    known_bootloader_anomaly_count = 0
    errors: list[str] = []
    per_root: list[dict] = []

    persist_budget = max_entries

    for efi_path in efi_paths:
        if persist_budget <= 0:
            efi_files_scanned += 1
            continue

        relative = _relativize_path(efi_path, roots)
        try:
            entry, agg = await _walk_one_efi_async(
                efi_path,
                firmware_id=firmware_id,
                relative_source=relative,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = (
                f"walk failed for {efi_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_root.append({
                "path": relative,
                "status": "error",
                "authenticode_state": "parse_failed",
                "is_unsigned": False,
                "is_revoked": False,
                "is_known_bootloader_path": False,
                "is_non_microsoft_signer": False,
                "error": err,
            })
            efi_files_scanned += 1
            continue

        efi_files_scanned += 1

        if entry is not None:
            db.add(entry)
            await db.flush()
            efi_files_persisted += 1
            persist_budget -= 1

            state = agg["authenticode_state"]
            if state == "signed_valid":
                signed_valid_count += 1
            elif state == "signed_expired":
                signed_expired_count += 1
            elif state == "signed_revoked":
                signed_revoked_count += 1
            elif state == "unsigned":
                unsigned_count += 1
            elif state == "parse_failed":
                parse_failed_count += 1

            if agg["is_revoked"]:
                dbx_revoked_count += 1
            if agg["is_non_microsoft_signer"]:
                non_microsoft_signer_count += 1
            if agg["is_known_bootloader_path"] and (
                agg["is_unsigned"] or agg["is_revoked"]
            ):
                known_bootloader_anomaly_count += 1

        per_root.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "efi_files_scanned": efi_files_scanned,
        "efi_files_persisted": efi_files_persisted,
        "signed_valid_count": signed_valid_count,
        "signed_expired_count": signed_expired_count,
        "signed_revoked_count": signed_revoked_count,
        "unsigned_count": unsigned_count,
        "parse_failed_count": parse_failed_count,
        "dbx_revoked_count": dbx_revoked_count,
        "non_microsoft_signer_count": non_microsoft_signer_count,
        "known_bootloader_anomaly_count": known_bootloader_anomaly_count,
        "errors": errors,
        "per_root": per_root,
    }


# ── Outer wrapper (Rule #33 .a state machine) ───────────────────────────────


async def run_esp_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the ESP walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back. Mirrors the
    θ.B.D WMI walker shape.

    Status transitions: idle → running → completed | failed. The
    queued state belongs to the trigger router (idempotent POST +
    409-on-conflict per Rule #33 .a).
    """
    try:
        async with async_session_factory() as db:
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is None:
                logger.warning(
                    "esp_walk: firmware %s not found", firmware_id
                )
                return

            row.esp_walk_status = "running"
            row.esp_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_esp_walk(db, firmware_id)
                row.esp_walk_status = "completed"
                row.esp_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.esp_walk_result = _stamp_firmware_esp_walk_result(result)
                project_id = row.project_id
                await db.commit()

                # θ.C.E — emit windows_esp_* Finding rows alongside
                # the status transition. Lazy import per Rule #30 to
                # avoid esp_walker ↔ finding_service circular at
                # module load.
                if result["efi_files_persisted"] > 0:
                    try:
                        from app.services.finding_service import (
                            FindingService,
                        )

                        service = FindingService(db=db)
                        emitted = (
                            await service.emit_esp_findings_from_walk(
                                project_id, firmware_id
                            )
                        )
                        await db.commit()
                        logger.info(
                            "esp_walk: firmware %s emitted %d Finding rows",
                            firmware_id,
                            len(emitted),
                        )
                    except Exception:
                        await db.rollback()
                        logger.warning(
                            "esp_walk: firmware %s Finding emit failed",
                            firmware_id,
                            exc_info=True,
                        )

                logger.info(
                    "esp_walk: firmware %s completed in %.2fs (%d "
                    "scanned, %d persisted, %d unsigned, %d revoked, "
                    "%d non-MS, %d known-bootloader anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["efi_files_scanned"],
                    result["efi_files_persisted"],
                    result["unsigned_count"],
                    result["signed_revoked_count"],
                    result["non_microsoft_signer_count"],
                    result["known_bootloader_anomaly_count"],
                )
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(
                        type(exc), exc, exc.__traceback__
                    )
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(
                                Firmware.id == firmware_id
                            )
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.esp_walk_status = "failed"
                        fail_row.esp_walk_finished_at = _dt.datetime.now(
                            _dt.UTC
                        )
                        fail_row.esp_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "esp_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "esp_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_esp_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as θ.B.D
    auto_wmi_walk_firmware_safe wrapper.

    Distinct from :func:`run_esp_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-
    triggered walks. The auto-walk-on-unpack flow runs the SAME
    orchestrator (``_do_esp_walk``) but DOES NOT transition the
    status column — it stays ``idle`` until an operator explicitly
    triggers a re-walk via the trigger MCP tool, which resets and
    runs again.

    Wired to FindingService.emit_esp_findings_from_walk in θ.C.E so
    auto-walks produce both the per-`.efi` landing-zone rows AND the
    bootkit-precursor Finding rows in a single pass.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_esp_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            project_id: uuid.UUID | None = None
            if row is not None:
                row.esp_walk_result = _stamp_firmware_esp_walk_result(result)
                project_id = row.project_id
                await db.commit()

            # θ.C.E — emit windows_esp_* Finding rows for each
            # WindowsEspEntry persisted by the inner runner.
            if project_id is not None and result["efi_files_persisted"] > 0:
                try:
                    from app.services.finding_service import FindingService

                    service = FindingService(db=db)
                    emitted = await service.emit_esp_findings_from_walk(
                        project_id, firmware_id
                    )
                    await db.commit()
                    logger.info(
                        "esp_walk auto: firmware %s emitted %d Finding rows",
                        firmware_id,
                        len(emitted),
                    )
                except Exception:
                    # Emit failure must NOT roll back the walk-result
                    # persistence — leave the windows_esp_entries rows
                    # + esp_walk_result aggregate in place even if the
                    # downstream Finding emit raises. Operators can
                    # re-run via the trigger MCP tool to retry.
                    await db.rollback()
                    logger.warning(
                        "esp_walk auto: firmware %s Finding emit failed",
                        firmware_id,
                        exc_info=True,
                    )

            logger.info(
                "esp_walk auto: firmware %s walked %d .efi files in %.2fs",
                firmware_id,
                result["efi_files_scanned"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "esp_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "SIGNIFY_UNAVAILABLE",
    "_do_esp_walk",
    "auto_esp_walk_firmware_safe",
    "build_anomaly_flags",
    "compute_entry_fingerprint",
    "is_known_bootloader_path",
    "is_non_microsoft_signer",
    "is_signify_available",
    "is_vendor_path",
    "looks_like_pe",
    "map_verdict_to_authenticode_state",
    "run_esp_walk_background",
    "verdict_to_chain_dict",
    "verdict_to_dbx_match_dict",
    "walk_esp_efi_files",
]
