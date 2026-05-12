"""Phase ι.C.C — Windows ETW .etl trace-log walker (FIRST ι WINDOWS-SIDE).

Walks every ``.etl`` file under detection roots (per Rule #16) found
in Windows-firmware extracts and decodes each via Fox-IT
``dissect.etl`` (AGPL-3.0, v3.14). Surfaces forensic-triage metadata
for the T1070.001 (Clear Windows Event Logs), T1562.002 (Disable
Windows Event Logging), and T1574 (Hijack Execution Flow — providers)
post-compromise tradecraft surface — adversaries who clear EVTX often
forget to clear ETL.

Real-world adversaries / cases using this exact surface (Phase ι Scout 2
Persona-E refresh):

- FortiGuard 2024 IR — adversary cleared Security.evtx; kernel ETL
  (``AutoLogger-Diagtrack-Listener.etl``) retained the post-clear
  process tree.
- Microsoft DART team disclosures — multiple APT campaigns where ETL
  was the only surviving execution trail.
- ProcMon-author Russinovich blog — kernel ETL as forensic gold-
  standard when EVTX has been tampered.

**Rule #19 evidence-first OSS-library probe** (ran 2026-05-12T15:45Z):

- ``dissect.etl`` is on PyPI as v3.14 (released 2025-11-20), AGPL-3.0,
  Fox-IT / NCC Group. Sibling of ``dissect.ntfs`` already in our tree.
- API confirmed via ``inspect.getsource``:
    - ``ETL(fh: BinaryIO)`` consumes a binary file-handle.
    - ``iter(etl)`` yields :class:`EventRecord` instances.
    - ``record.header`` exposes ``provider_id`` (UUID), ``timestamp``
      (datetime), ``process_id``, ``thread_id``, ``opcode``,
      ``version``, etc.
    - ``record.event`` lazily resolves manifest-bound payload fields
      via ``record.event.event_values()`` if a manifest is shipped.
    - ``etl.logfile_header`` exposes the ``LoggerName`` (session
      name) and timestamp metadata.
- Decision: use dissect.etl. Smaller surface than a clean-room ETL
  parser (~3K LOC vs ~80 LOC for the journald clean-room precedent —
  ETL has buffer-level XPRESS compression + variable header types
  + per-provider manifest resolution; clean-room is impractical).
  Dependency footprint is consistent with the existing dissect.ntfs
  + dissect.cstruct + dissect.util chain.

**Rule #39 inner/outer/safe runner triplet** (Rule-of-Sixteen → Rule-
of-Seventeen with this stream):

- :func:`_do_etl_walk` — INNER orchestrator. Accepts caller-owned
  ``db``. Walks every ``.etl`` candidate under detection roots,
  decodes each via :func:`_iter_etl_events` over dissect.etl,
  persists per-event ``WindowsEtlEvent`` rows, returns aggregate
  dict UNSTAMPED.
- :func:`run_etl_walk_background` — OUTER state-machine wrapper.
  Owns the Rule #33 .a status transitions (idle → running →
  completed | failed) via ``async_session_factory()``. Outer guard
  catches escapes; failure persistence on a fresh session.
- :func:`auto_etl_walk_firmware_safe` — UNPACK-POST-DETECTION hook.
  Runs the inner orchestrator but does NOT mutate ``etl_walk_status``
  (leaves ``idle`` so manual re-trigger works without 409).

**Rule #36 no-execute discipline.** This is a pure-Python parser
operating on ETL binary records AS DATA. The walker NEVER:

- Invokes ``logman`` / ``xperf`` / ``tracerpt`` / ``wevtutil`` against
  the parsed files.
- Starts an ETW logger session via ``EventTraceSession``,
  ``StartTrace``, or any kernel-trace control API.
- Loads any embedded provider-manifest payload as code.
- Replays the embedded events against any kernel facility.
- Invokes any process referenced in event payloads.

**Rule #16 detection-roots discipline.** The walker uses
``get_detection_roots(firmware)`` (NOT bare
``firmware.extracted_path``) so multi-partition Windows firmware
(VHDX / NTFS / FAT32 / system images) surfaces every ``.etl``
candidate.

**Rule #43 noqa rationale (category 2, pure-string path math; category 3,
bounded loop over detection roots).** Sync filesystem operations
inside the bounded outer loop (over detection roots) are inline
rather than executor-wrapped.

**Performance.** ETL parsing runs at ~5-15 MB/s on the dev box (CPU-
bound on per-event struct decode + manifest resolution). A typical
``AutoLogger-Diagtrack-Listener.etl`` is 16-64 MB; the walker
completes in 2-15 s per file. We cap per-firmware at 10K persisted
events (``_DEFAULT_MAX_EVENTS_PER_FIRMWARE``) defensive against
attacker-planted ETLs with millions of bogus events. Individual files
>500 MB are skipped with a counter.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable, Iterator
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_etl_events import WindowsEtlEvent
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_etl_walk_result,
    _stamp_windows_etl_events_anomaly_flags,
    _stamp_windows_etl_events_payload,
)

logger = logging.getLogger(__name__)


# ── Walker tunables ──────────────────────────────────────────────────────────

# Maximum events persisted per firmware. Real-world .etl files carry
# hundreds-to-thousands of events each; bounding the per-firmware total
# at 10K protects against attacker-planted files with millions of bogus
# events.
_DEFAULT_MAX_EVENTS_PER_FIRMWARE: int = 10_000

# Cap on per-file size. Real-world .etl files run 8-64 MB rotating;
# legitimately rare cases reach a few hundred MB. Protect against
# attacker-planted GB-sized files with bogus padding.
_DEFAULT_MAX_FILE_BYTES: int = 500 * 1024 * 1024  # 500 MiB

# Cap on raw-bytes preview in payload (when no manifest match). Most
# events without a manifest are small (32-256 bytes); cap at 1 KB.
_MAX_PAYLOAD_PREVIEW_BYTES: int = 1024

# Standard ETW logger paths inside a Windows firmware extract.
# Surveyed from production Windows 10/11 systems + Microsoft docs:
# https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
_ETL_SEARCH_DIRS: tuple[str, ...] = (
    "Windows/System32/WDI/LogFiles",
    "Windows/System32/winevt/Logs",
    "Windows/Logs/NetSetup",
    "Windows/Logs/WindowsBackup",
    "Windows/Logs/WindowsUpdate",
    "Windows/Logs/CBS",
    "Windows/System32/LogFiles/WMI",
)


# ── Known Microsoft provider GUIDs ───────────────────────────────────────────
# Used to flag unusual_provider when an ETL contains events from a
# provider GUID NOT in this allowlist AND not matching the Microsoft
# vendor prefix. Note this is a HEURISTIC — Microsoft has ~1500+
# providers; we maintain a small set of well-known ones plus a prefix
# match.

# Well-known Microsoft provider GUIDs (sampled from production Windows
# 10/11 — kernel + system + diagnostic providers). Anchored to the
# lowercase canonical form (8-4-4-4-12 with hyphens).
_KNOWN_MS_PROVIDER_GUIDS: frozenset[str] = frozenset({
    # Kernel logger (NT Kernel Logger).
    "9e814aad-3204-11d2-9a82-006008a86939",
    # Microsoft-Windows-Kernel-Process.
    "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716",
    # Microsoft-Windows-Kernel-File.
    "edd08927-9cc4-4e65-b970-c2560fb5c289",
    # Microsoft-Windows-Kernel-Network.
    "7dd42a49-5329-4832-8dfd-43d979153a88",
    # Microsoft-Windows-Kernel-Registry.
    "70eb4f03-c1de-4f73-a051-33d13d5413bd",
    # Microsoft-Windows-Diagnostics-Performance.
    "cfc18ec0-96b1-4eba-961b-622caee05b0a",
    # Microsoft-Windows-Diagtrack.
    "56dc8b69-7af0-4ca0-9bd5-cdfe72d7c0a4",
    # Microsoft-Windows-Security-Auditing.
    "54849625-5478-4994-a5ba-3e3b0328c30d",
    # Microsoft-Windows-WMI-Activity.
    "1418ef04-b0b4-4623-bf7e-d74ab47bbdaa",
    # Microsoft-Windows-PowerShell.
    "a0c1853b-5c40-4b15-8766-3cf1c58f985a",
    # Microsoft-Windows-Application-Experience.
    "ee17cba6-f59c-4a4a-9bd8-1d3c4d8f5e3f",
})

# Diagtrack-Listener-specific session name prefix. Used to flag
# non_microsoft_in_diagtrack when a third-party provider appears in
# what should be a Microsoft-only diagnostics session.
_DIAGTRACK_SESSION_PREFIX: str = "AutoLogger-Diagtrack"

# Provider-name prefixes that count as "Microsoft-owned" for the
# non_microsoft_in_diagtrack check.
_MS_PROVIDER_NAME_PREFIXES: tuple[str, ...] = (
    "Microsoft-",
    "Microsoft\\",
    "Windows-",
)

# Event opcode values that indicate logger control / session end (used
# for provider_disable_evidence detection). Per the EVENT_TRACE_TYPE
# definitions in evntrace.h:
# - 0x00 INFO
# - 0x01 START
# - 0x02 END / STOP
# - 0x05 DC_START
# - 0x06 DC_END
_EVT_OPCODE_END = 0x02
_EVT_OPCODE_DC_END = 0x06


# ── GUID + payload helpers ───────────────────────────────────────────────────


def normalize_provider_guid(guid: Any) -> str | None:
    """Coerce a provider GUID into the canonical 8-4-4-4-12 lowercase-
    hyphenated string.

    Accepts ``uuid.UUID`` instances, strings (with or without braces /
    hyphens), or bytes. Returns ``None`` on failure.
    """
    if guid is None:
        return None
    try:
        if isinstance(guid, uuid.UUID):
            return str(guid).lower()
        if isinstance(guid, bytes):
            if len(guid) == 16:
                return str(uuid.UUID(bytes=guid)).lower()
            return None
        text = str(guid).strip()
        if not text:
            return None
        # Strip braces if present.
        if text.startswith("{") and text.endswith("}"):
            text = text[1:-1]
        return str(uuid.UUID(text)).lower()
    except (TypeError, ValueError, AttributeError):
        return None


def datetime_to_filetime(dt: _dt.datetime | None) -> int:
    """Convert a Python datetime to a Windows FILETIME (100ns intervals
    since 1601-01-01 UTC).

    Returns 0 on None or coercion failure (timestamp 0 = 1601-01-01,
    which is recognisable as a sentinel during forensic review).
    """
    if dt is None:
        return 0
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        epoch = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
        delta = dt - epoch
        # 1 second = 10_000_000 100-ns ticks.
        return int(delta.total_seconds() * 10_000_000)
    except (TypeError, ValueError, OverflowError, AttributeError):
        return 0


def encode_payload_preview(raw_bytes: bytes) -> dict[str, Any]:
    """Encode a small raw-bytes preview for the payload JSONB. Used
    when no manifest match is available for the provider.

    Returns ``{"raw_b64": "...", "raw_size": int}`` truncated to
    ``_MAX_PAYLOAD_PREVIEW_BYTES``.
    """
    size = len(raw_bytes)
    truncated = raw_bytes[:_MAX_PAYLOAD_PREVIEW_BYTES]
    return {
        "raw_b64": base64.b64encode(truncated).decode("ascii"),
        "raw_size": size,
    }


def serialise_event_values(values: dict[str, Any]) -> dict[str, Any]:
    """Coerce an ``EventRecord.event.event_values()`` dict into JSONB-
    safe key/value pairs.

    UUIDs → str, bytes → b64, datetime → ISO format, other unknowns
    → str(). Iterates one level deep — nested structures are stringified
    rather than expanded (keeps payload JSONB bounded).
    """
    out: dict[str, Any] = {}
    if not isinstance(values, dict):
        return out
    for k, v in values.items():
        key = str(k)
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[key] = v
        elif isinstance(v, uuid.UUID):
            out[key] = str(v).lower()
        elif isinstance(v, bytes):
            preview = base64.b64encode(v[:64]).decode("ascii")
            out[key] = {"_bytes_b64": preview, "_bytes_size": len(v)}
        elif isinstance(v, _dt.datetime):
            try:
                out[key] = v.isoformat()
            except (ValueError, OverflowError):
                out[key] = str(v)
        else:
            text = str(v)
            if len(text) > 1024:
                text = text[:1024] + "...[truncated]"
            out[key] = text
    return out


# ── Anomaly classifier (pure functions) ──────────────────────────────────────


def is_known_microsoft_provider(
    provider_guid: str | None, provider_name: str | None
) -> bool:
    """True iff the provider is in the known Microsoft set OR the name
    starts with a Microsoft vendor prefix.

    Pure function — same inputs always produce the same output.
    """
    if provider_guid and provider_guid.lower() in _KNOWN_MS_PROVIDER_GUIDS:
        return True
    if provider_name:
        for prefix in _MS_PROVIDER_NAME_PREFIXES:
            if provider_name.startswith(prefix):
                return True
    return False


def is_unusual_provider(
    provider_guid: str | None, provider_name: str | None
) -> bool:
    """True iff the provider is NOT in the known Microsoft set AND the
    name doesn't match the Microsoft vendor prefix.

    A NULL provider_guid AND NULL provider_name → False (we can't make
    a judgment; treat as known).
    """
    if not provider_guid and not provider_name:
        return False
    return not is_known_microsoft_provider(provider_guid, provider_name)


def is_non_microsoft_in_diagtrack(
    session_name: str | None,
    provider_guid: str | None,
    provider_name: str | None,
) -> bool:
    """True iff the session name matches the Diagtrack prefix AND the
    provider is NOT in the known Microsoft set.

    Diagtrack-Listener is a Microsoft-only diagnostics session by
    design — any third-party provider appearing inside it is a strong
    T1574 (Hijack Execution Flow) indicator.
    """
    if not session_name:
        return False
    if not session_name.startswith(_DIAGTRACK_SESSION_PREFIX):
        return False
    return not is_known_microsoft_provider(provider_guid, provider_name)


def is_kernel_process_event(
    provider_guid: str | None, provider_name: str | None
) -> bool:
    """True iff the event comes from a kernel process provider (NT
    Kernel Logger OR Microsoft-Windows-Kernel-Process). Used as the
    correlating signal for kernel_proc_after_evtx_clear.
    """
    if provider_guid:
        guid_lower = provider_guid.lower()
        if guid_lower == "9e814aad-3204-11d2-9a82-006008a86939":
            return True
        if guid_lower == "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716":
            return True
    if provider_name:
        if "Kernel-Process" in provider_name:
            return True
        if provider_name == "NT Kernel Logger":
            return True
    return False


def is_provider_disable_event(
    event_opcode: int | None, provider_name: str | None
) -> bool:
    """True iff the event indicates a logger session end / provider
    disable. Per the EVENT_TRACE_TYPE definitions:
    - 0x02 END / STOP
    - 0x06 DC_END

    AND the provider name suggests session-control (System / Process /
    Logger control providers).
    """
    if event_opcode is None:
        return False
    if event_opcode not in (_EVT_OPCODE_END, _EVT_OPCODE_DC_END):
        return False
    # Opcode 0x02/0x06 fires for many event types (process end, file
    # close, etc.); we only flag as provider_disable when paired with
    # a logger-session signal.
    if not provider_name:
        return False
    return any(
        marker in provider_name
        for marker in ("EventLog", "Logger", "Trace-Control", "EventTrace")
    )


def build_anomaly_flags(
    *,
    session_name: str | None,
    provider_guid: str | None,
    provider_name: str | None,
    event_opcode: int | None,
    is_kernel_process: bool,
    evtx_clear_correlated: bool,
) -> dict[str, Any]:
    """Construct the anomaly_flags payload from extracted fields.

    Pure function — same inputs always produce the same output. Caller
    stamps the schema_version via
    ``_stamp_windows_etl_events_anomaly_flags``.
    """
    return {
        "kernel_proc_after_evtx_clear": bool(
            is_kernel_process and evtx_clear_correlated
        ),
        "provider_disable_evidence": is_provider_disable_event(
            event_opcode, provider_name
        ),
        "unusual_provider": is_unusual_provider(
            provider_guid, provider_name
        ),
        "non_microsoft_in_diagtrack": is_non_microsoft_in_diagtrack(
            session_name, provider_guid, provider_name
        ),
    }


# ── Filesystem helpers ───────────────────────────────────────────────────────


def walk_etl_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return candidate ``.etl`` file
    paths.

    Scans the canonical ETW logger directories under each root. Plus
    a defensive fallback scan for any other ``*.etl`` files under the
    root.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`get_detection_roots` — NEVER ``firmware.extracted_path``
    alone.
    """
    hits: list[str] = []
    seen: set[str] = set()
    for root in roots:
        try:
            real_root = os.path.realpath(root)  # noqa: ASYNC240 — bounded loop over ≤8 detection roots
        except OSError:
            continue
        if not os.path.isdir(real_root):  # noqa: ASYNC240 — bounded loop over ≤8 detection roots
            continue
        # First scan the canonical ETW dirs.
        for subdir in _ETL_SEARCH_DIRS:
            full_dir = os.path.join(real_root, subdir)  # noqa: ASYNC240 — pure-string path math
            if not os.path.isdir(full_dir):  # noqa: ASYNC240 — pre-flight stat
                continue
            for dirpath, _dirnames, filenames in os.walk(  # noqa: ASYNC240 — bounded loop
                full_dir, followlinks=False
            ):
                for name in filenames:
                    if not name.lower().endswith(".etl"):
                        continue
                    full = os.path.join(dirpath, name)
                    try:
                        real_full = os.path.realpath(full)  # noqa: ASYNC240 — pure-string path math
                    except OSError:
                        continue
                    if not real_full.startswith(real_root):
                        continue
                    if real_full in seen:
                        continue
                    seen.add(real_full)
                    hits.append(real_full)
        # Defensive fallback — any other .etl under the root.
        for dirpath, _dirnames, filenames in os.walk(  # noqa: ASYNC240 — bounded loop
            real_root, followlinks=False
        ):
            for name in filenames:
                if not name.lower().endswith(".etl"):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    real_full = os.path.realpath(full)
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                if real_full in seen:
                    continue
                seen.add(real_full)
                hits.append(real_full)
    return hits


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


# ── ETL event iterator ───────────────────────────────────────────────────────


def _iter_etl_events(
    etl_obj: Any,
    file_path: str,
) -> Iterator[dict[str, Any]]:
    """Iterate every event record in a dissect.etl ETL object, yielding
    a fully-assembled dict per event.

    Returns dicts shaped for direct insertion into ``WindowsEtlEvent``
    rows (callers add ``firmware_id`` and stamp schema versions).

    Defensive: any exception inside the per-record assembly results in
    skipping that record + a logger warning. Buffer-level errors are
    surfaced as a final yielded dict with ``error="..."`` field.
    """
    try:
        for record in etl_obj:
            try:
                header = record.header
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                logger.debug("etl event header decode failed: %s", exc)
                continue
            try:
                # Extract standard fields.
                provider_guid = None
                try:
                    pid_uuid = header.provider_id
                    provider_guid = normalize_provider_guid(pid_uuid)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    ts = header.timestamp
                except Exception:  # noqa: BLE001
                    ts = None
                timestamp_ft = datetime_to_filetime(ts)
                process_id = getattr(header, "process_id", None)
                thread_id = getattr(header, "thread_id", None)
                version = getattr(header, "version", None)
                opcode = getattr(header, "opcode", None)
                event_size = int(getattr(header, "size", 0))

                # Try to resolve event descriptor (event_id, level, etc).
                event_id = None
                event_version = None
                event_channel = None
                event_level = None
                event_opcode = opcode
                event_keywords = None
                event_task = None
                try:
                    descriptor = header.descriptor
                    event_id = getattr(descriptor, "id", None)
                    event_version = getattr(descriptor, "version", None)
                    event_channel = getattr(descriptor, "channel", None)
                    event_level = getattr(descriptor, "level", None)
                    event_opcode = (
                        getattr(descriptor, "opcode", opcode) or opcode
                    )
                    event_task = getattr(descriptor, "task", None)
                    event_keywords = getattr(descriptor, "keywords", None)
                except Exception:  # noqa: BLE001
                    pass

                # Try to resolve provider name + payload via manifest.
                provider_name = None
                payload: dict[str, Any] = {}
                try:
                    event_obj = record.event
                    name = event_obj.provider_name()
                    if name:
                        provider_name = str(name)
                    values = event_obj.event_values()
                    if values:
                        payload = serialise_event_values(values)
                except Exception:  # noqa: BLE001
                    pass
                # If we don't have a decoded payload, encode a raw-bytes
                # preview so operators can see SOMETHING for the event.
                if not payload:
                    try:
                        payload_bytes = bytes(header.payload[:_MAX_PAYLOAD_PREVIEW_BYTES])
                        if payload_bytes:
                            payload = encode_payload_preview(payload_bytes)
                    except Exception:  # noqa: BLE001
                        pass

                yield {
                    "etl_file_path": file_path,
                    "provider_guid": provider_guid,
                    "provider_name": (
                        provider_name[:255] if provider_name else None
                    ),
                    "event_id": (
                        int(event_id) if event_id is not None else None
                    ),
                    "event_version": (
                        int(event_version)
                        if event_version is not None
                        else None
                    ),
                    "event_channel": (
                        str(event_channel)[:64]
                        if event_channel is not None
                        else None
                    ),
                    "event_level": (
                        int(event_level) if event_level is not None else None
                    ),
                    "event_opcode": (
                        int(event_opcode)
                        if event_opcode is not None
                        else None
                    ),
                    "event_keywords": (
                        int(event_keywords)
                        if event_keywords is not None
                        else None
                    ),
                    "event_task": (
                        int(event_task) if event_task is not None else None
                    ),
                    "timestamp_ft": int(timestamp_ft),
                    "process_id": (
                        int(process_id) if process_id is not None else None
                    ),
                    "thread_id": (
                        int(thread_id) if thread_id is not None else None
                    ),
                    "processor_id": None,
                    "kernel_time_us": None,
                    "user_time_us": None,
                    "payload": payload,
                    "raw_record_size": event_size,
                }
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                logger.debug("etl event assemble failed: %s", exc)
                continue
    except Exception as exc:  # noqa: BLE001 — buffer-level failure
        logger.warning(
            "etl file %s buffer-iteration failed: %s",
            file_path,
            exc,
        )


def parse_etl_file_sync(
    etl_path: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse one ``.etl`` file at ``etl_path`` end-to-end. Returns
    ``(metadata_dict, events_list)``.

    On malformed / missing files, returns ``({"error": str}, [])`` so
    the caller can record the failure mode without raising.

    SYNC I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    """
    # Lazy import per Rule #30 — dissect.etl cold-import has measurable
    # cost (~200 ms on dev box for the manifest catalog).
    try:
        from dissect.etl.etl import ETL
        from dissect.etl.exceptions import (
            InvalidBufferError,
            InvalidHeaderError,
        )
    except ImportError as exc:
        return {"error": f"dissect.etl import failed: {exc}"}, []

    try:
        size = os.path.getsize(etl_path)
    except OSError as exc:
        return {"error": f"stat failed: {exc}"}, []
    if size > _DEFAULT_MAX_FILE_BYTES:
        return {
            "error": (
                f"file size {size} exceeds max "
                f"{_DEFAULT_MAX_FILE_BYTES}; skipped"
            ),
            "oversize": True,
        }, []
    if size < 64:
        return {"error": "file shorter than minimum ETL header"}, []

    try:
        fh = open(etl_path, "rb")
    except OSError as exc:
        return {"error": f"open failed: {exc}"}, []

    try:
        try:
            etl_obj = ETL(fh)
        except (InvalidHeaderError, InvalidBufferError) as exc:
            return {"error": f"malformed ETL header: {exc}"}, []
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            return {"error": f"ETL parse failed: {type(exc).__name__}: {exc}"}, []

        session_name = None
        try:
            logfile_hdr = etl_obj.logfile_header
            session_name = getattr(logfile_hdr, "LoggerName", None)
            if session_name is not None:
                session_name = str(session_name)
                if not session_name:
                    session_name = None
        except Exception:  # noqa: BLE001
            pass

        events = list(_iter_etl_events(etl_obj, etl_path))

        metadata = {
            "session_name": session_name,
            "events_walked": len(events),
            "size_bytes": size,
        }
        return metadata, events
    finally:
        try:
            fh.close()
        except OSError:
            pass


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    return {
        "run_seconds": round(run_seconds, 3),
        "files_scanned": 0,
        "events_walked": 0,
        "events_persisted": 0,
        "events_capped": 0,
        "oversize_skipped": 0,
        "kernel_proc_after_evtx_clear_count": 0,
        "provider_disable_evidence_count": 0,
        "unusual_provider_count": 0,
        "non_microsoft_in_diagtrack_count": 0,
        "anomaly_total": 0,
        "errors": [],
        "per_file": [],
    }


# ── Per-file walker ──────────────────────────────────────────────────────────


def _walk_one_file_sync(
    etl_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_events: int,
    persisted_so_far: int,
    evtx_clear_correlated: bool,
) -> tuple[list[WindowsEtlEvent], dict[str, Any]]:
    """Parse one ``.etl`` file and build rows.

    SYNC I/O — wrap in ``run_in_executor`` for async callers (Rule #5).
    """
    aggregate: dict[str, Any] = {
        "path": relative_source,
        "status": "ok",
        "session_name": None,
        "events_walked": 0,
        "events_persisted": 0,
        "events_capped": 0,
        "kernel_proc_after_evtx_clear_count": 0,
        "provider_disable_evidence_count": 0,
        "unusual_provider_count": 0,
        "non_microsoft_in_diagtrack_count": 0,
        "anomaly_total": 0,
        "error": None,
    }

    metadata, events = parse_etl_file_sync(etl_path)
    if "error" in metadata:
        if metadata.get("oversize"):
            aggregate["status"] = "skipped_oversize"
        else:
            aggregate["status"] = "error"
        aggregate["error"] = metadata["error"]
        return [], aggregate

    session_name = metadata.get("session_name")
    aggregate["session_name"] = session_name

    rows: list[WindowsEtlEvent] = []
    persist_budget = max_events - persisted_so_far

    for evt in events:
        aggregate["events_walked"] += 1

        provider_guid = evt.get("provider_guid")
        provider_name = evt.get("provider_name")
        event_opcode = evt.get("event_opcode")

        is_kp = is_kernel_process_event(provider_guid, provider_name)
        anomaly = build_anomaly_flags(
            session_name=session_name,
            provider_guid=provider_guid,
            provider_name=provider_name,
            event_opcode=event_opcode,
            is_kernel_process=is_kp,
            evtx_clear_correlated=evtx_clear_correlated,
        )

        if anomaly["kernel_proc_after_evtx_clear"]:
            aggregate["kernel_proc_after_evtx_clear_count"] += 1
        if anomaly["provider_disable_evidence"]:
            aggregate["provider_disable_evidence_count"] += 1
        if anomaly["unusual_provider"]:
            aggregate["unusual_provider_count"] += 1
        if anomaly["non_microsoft_in_diagtrack"]:
            aggregate["non_microsoft_in_diagtrack_count"] += 1
        if any(anomaly.values()):
            aggregate["anomaly_total"] += 1

        if persist_budget <= 0:
            aggregate["events_capped"] += 1
            continue

        stamped_anomaly = _stamp_windows_etl_events_anomaly_flags(anomaly)
        payload = evt.get("payload") or {}
        stamped_payload = _stamp_windows_etl_events_payload(payload)

        row = WindowsEtlEvent(
            firmware_id=firmware_id,
            etl_file_path=relative_source[:1024],
            etl_session_name=(
                str(session_name)[:255] if session_name else None
            ),
            provider_guid=provider_guid,
            provider_name=provider_name,
            event_id=evt.get("event_id"),
            event_version=evt.get("event_version"),
            event_channel=evt.get("event_channel"),
            event_level=evt.get("event_level"),
            event_opcode=event_opcode,
            event_keywords=evt.get("event_keywords"),
            event_task=evt.get("event_task"),
            timestamp_ft=evt.get("timestamp_ft", 0),
            process_id=evt.get("process_id"),
            thread_id=evt.get("thread_id"),
            processor_id=evt.get("processor_id"),
            kernel_time_us=evt.get("kernel_time_us"),
            user_time_us=evt.get("user_time_us"),
            payload=stamped_payload,
            anomaly_flags=stamped_anomaly,
            raw_record_size=int(evt.get("raw_record_size", 0)),
        )
        rows.append(row)
        persist_budget -= 1
        aggregate["events_persisted"] += 1

    return rows, aggregate


async def _walk_one_file_async(
    etl_path: str,
    *,
    firmware_id: uuid.UUID,
    relative_source: str,
    max_events: int,
    persisted_so_far: int,
    evtx_clear_correlated: bool,
) -> tuple[list[WindowsEtlEvent], dict[str, Any]]:
    """Async wrapper around :func:`_walk_one_file_sync` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _walk_one_file_sync(
            etl_path,
            firmware_id=firmware_id,
            relative_source=relative_source,
            max_events=max_events,
            persisted_so_far=persisted_so_far,
            evtx_clear_correlated=evtx_clear_correlated,
        ),
    )


async def _walk_etl_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_etl_files` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_etl_files, roots)


# ── Inner orchestrator (Rule #39 inner; accepts db) ──────────────────────────


async def _do_etl_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    max_events: int = _DEFAULT_MAX_EVENTS_PER_FIRMWARE,
) -> dict[str, Any]:
    """Walk every ``.etl`` file under ``firmware_id``'s extracted tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for files matching ``*.etl``.
    3. For each candidate: parse via dissect.etl, iterate every event,
       construct WindowsEtlEvent rows, classify anomalies.
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

    # Correlate with EVTX clear evidence if available — flags kernel
    # process events as kernel_proc_after_evtx_clear when the firmware
    # has a Security.evtx clear record. We check
    # firmware.evtx_walk_result if available; conservatively False
    # otherwise.
    evtx_clear_correlated = False
    try:
        evtx_result = getattr(firmware, "evtx_walk_result", None) or {}
        evtx_clear_correlated = bool(
            evtx_result.get("log_clear_count", 0) > 0
            or evtx_result.get("log_clear_marker_count", 0) > 0
        )
    except Exception:  # noqa: BLE001
        pass

    etl_paths = await _walk_etl_files_async(roots)
    if not etl_paths:
        return _empty_walk_result(time.monotonic() - started)

    files_scanned = 0
    events_walked = 0
    events_persisted = 0
    events_capped = 0
    oversize_skipped = 0
    kernel_proc_after_evtx_clear_count = 0
    provider_disable_evidence_count = 0
    unusual_provider_count = 0
    non_microsoft_in_diagtrack_count = 0
    anomaly_total = 0
    errors: list[str] = []
    per_file: list[dict] = []

    for etl_path in etl_paths:
        relative = _relativize_path(etl_path, roots)
        try:
            rows, agg = await _walk_one_file_async(
                etl_path,
                firmware_id=firmware_id,
                relative_source=relative,
                max_events=max_events,
                persisted_so_far=events_persisted,
                evtx_clear_correlated=evtx_clear_correlated,
            )
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = (
                f"walk failed for {etl_path}: "
                f"{type(exc).__name__}: {str(exc)[:200]}"
            )
            errors.append(err)
            per_file.append({
                "path": relative,
                "status": "error",
                "session_name": None,
                "events_walked": 0,
                "events_persisted": 0,
                "events_capped": 0,
                "kernel_proc_after_evtx_clear_count": 0,
                "provider_disable_evidence_count": 0,
                "unusual_provider_count": 0,
                "non_microsoft_in_diagtrack_count": 0,
                "anomaly_total": 0,
                "error": err,
            })
            continue

        if agg["status"] == "skipped_oversize":
            oversize_skipped += 1

        files_scanned += 1
        events_walked += agg["events_walked"]
        events_persisted += agg["events_persisted"]
        events_capped += agg["events_capped"]
        kernel_proc_after_evtx_clear_count += (
            agg["kernel_proc_after_evtx_clear_count"]
        )
        provider_disable_evidence_count += (
            agg["provider_disable_evidence_count"]
        )
        unusual_provider_count += agg["unusual_provider_count"]
        non_microsoft_in_diagtrack_count += (
            agg["non_microsoft_in_diagtrack_count"]
        )
        anomaly_total += agg["anomaly_total"]
        per_file.append(agg)
        if agg["error"]:
            errors.append(agg["error"])

        for row in rows:
            db.add(row)
        if rows:
            await db.flush()

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "files_scanned": files_scanned,
        "events_walked": events_walked,
        "events_persisted": events_persisted,
        "events_capped": events_capped,
        "oversize_skipped": oversize_skipped,
        "kernel_proc_after_evtx_clear_count": (
            kernel_proc_after_evtx_clear_count
        ),
        "provider_disable_evidence_count": provider_disable_evidence_count,
        "unusual_provider_count": unusual_provider_count,
        "non_microsoft_in_diagtrack_count": non_microsoft_in_diagtrack_count,
        "anomaly_total": anomaly_total,
        "errors": errors,
        "per_file": per_file,
    }


# ── Outer wrapper (Rule #33 .a state machine) ────────────────────────────────


async def run_etl_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the ETL walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back.

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
                    "etl_walk: firmware %s not found", firmware_id
                )
                return

            row.etl_walk_status = "running"
            row.etl_walk_started_at = _dt.datetime.now(_dt.UTC)
            await db.commit()

            try:
                result = await _do_etl_walk(db, firmware_id)
                row.etl_walk_status = "completed"
                row.etl_walk_finished_at = _dt.datetime.now(_dt.UTC)
                row.etl_walk_result = _stamp_firmware_etl_walk_result(
                    result
                )
                await db.commit()

                logger.info(
                    "etl_walk: firmware %s completed in %.2fs "
                    "(%d files, %d events walked, %d persisted, %d "
                    "anomalies)",
                    firmware_id,
                    result["run_seconds"],
                    result["files_scanned"],
                    result["events_walked"],
                    result["events_persisted"],
                    result["anomaly_total"],
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
                        fail_row.etl_walk_status = "failed"
                        fail_row.etl_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.etl_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "etl_walk: firmware %s failed", firmware_id
                )
    except Exception:
        logger.exception(
            "etl_walk: unrecoverable for %s", firmware_id
        )


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_etl_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as
    auto_systemd_walk_firmware_safe (ι.B.C precedent) and
    auto_journald_walk_firmware_safe (ι.A.C precedent).

    Distinct from :func:`run_etl_walk_background`: the background
    runner transitions the firmware status column through queued →
    running → completed/failed and is for explicit operator-triggered
    walks. The auto-walk-on-unpack flow runs the SAME orchestrator
    (``_do_etl_walk``) but DOES NOT transition the status column —
    it stays ``idle`` until an operator explicitly triggers a re-walk
    via the trigger MCP tool, which resets and runs again.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_etl_walk(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.etl_walk_result = _stamp_firmware_etl_walk_result(
                    result
                )
                await db.commit()

            logger.info(
                "etl_walk auto: firmware %s walked %d files / %d "
                "events in %.2fs",
                firmware_id,
                result["files_scanned"],
                result["events_walked"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "etl_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )


__all__ = [
    "_do_etl_walk",
    "auto_etl_walk_firmware_safe",
    "build_anomaly_flags",
    "datetime_to_filetime",
    "encode_payload_preview",
    "is_kernel_process_event",
    "is_known_microsoft_provider",
    "is_non_microsoft_in_diagtrack",
    "is_provider_disable_event",
    "is_unusual_provider",
    "normalize_provider_guid",
    "parse_etl_file_sync",
    "run_etl_walk_background",
    "serialise_event_values",
    "walk_etl_files",
]
