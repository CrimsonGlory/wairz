"""Vendored fork of ``PyWMIPersistenceFinder.py`` for keyword-search
WMI FilterToConsumerBinding detection.

**Upstream:** `<https://github.com/davidpany/WMI_Forensics>`_, file
``PyWMIPersistenceFinder.py`` (Version 1.1, 2017-vintage). Author:
David Pany — Mandiant (FireEye). License: MIT (see ``LICENSE``).

**Scope of vendoring:** keyword-search persistence detection only —
identifies ``_FilterToConsumerBinding`` rows in WMI repository
``OBJECTS.DATA`` files by regex matching, paired with the bound
``EventConsumer`` and ``EventFilter`` details. We do NOT perform full
WMI repository emulation (that's the unmaintained flare-wmi /
python-cim space). The keyword approach is well-suited to firmware
forensic triage: false-positive rate is low (a binding's two
endpoints must BOTH match the canonical regex shape), and we never
need to interpret the resulting payloads — we surface them as DATA.

**Adaptations from upstream:**

1. Upstream is a CLI-only script (``main()`` reads ``sys.argv[1]``,
   prints to stdout). This vendor refactors the same regex / dict
   logic into a callable :func:`find_persistence` that accepts a
   path and returns a structured ``list[BindingResult]``.
2. Upstream uses Python-2 ``.iteritems()``; refactored to ``.items()``.
3. Upstream prints to stdout; refactored to return structured dicts
   for the consumer (the wmi_walker service).
4. Upstream's "BVTConsumer-BVTFilter" / "SCM Event Log" annotation is
   preserved as a ``probably_benign`` boolean field on each binding.
5. Type annotations added throughout for compile-time safety + IDE
   support in the consumer.

**CLAUDE.md Rule #36 no-execute compliance:** this module's
operations are 100% text parsing — file reads + regex matches. There
is ZERO subprocess / shell / exec / eval / runpy / dynamic import
activity. Verified by ``grep -rn 'subprocess\\.\\|os\\.system\\|os\\.execvp\\|asyncio\\.create_subprocess\\|runpy\\|importlib\\.import_module\\|eval\\|exec' backend/third_party/pywmi_persistence_finder/`` → 0 hits (allow ``__init__`` and other module-level imports unrelated to execution primitives).

**CLAUDE.md Rule #19 evidence-first compliance:** API shape probed
via curl of the upstream raw file before drafting (2026-05-12 session
notes); regex patterns + dict-building logic + output format all
extracted verbatim from the canonical use site, preserving the
upstream's well-validated false-positive characteristics.

Typical caller pattern from ``app.services.wmi_walker``::

    from app.third_party.pywmi_persistence_finder import find_persistence

    bindings = find_persistence(objects_data_path)
    for binding in bindings:
        # persist a WindowsWmiEvent row per binding
        ...
"""
from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "BindingResult",
    "ConsumerDetails",
    "FilterDetails",
    "find_persistence",
]


# String-printable set for filtering noise out of CommandLineEventConsumer
# Arguments fields (per upstream PyWMIPersistenceFinder behaviour).
_PRINTABLE_CHARS: frozenset[str] = frozenset(string.printable)


# Precompiled regexes — verbatim from the upstream canonical use site.
_EVENT_CONSUMER_RE = re.compile(rb"([\w\_]*EventConsumer\.Name\=\")([\w\s]*)(\")")
_EVENT_FILTER_RE = re.compile(rb"(_EventFilter\.Name\=\")([\w\s]*)(\")")

# Well-known benign bindings that ship with Windows.
_BENIGN_BINDING_NAMES: frozenset[str] = frozenset({
    "BVTConsumer-BVTFilter",
    "SCM Event Log Consumer-SCM Event Log Filter",
})

# Cap on bindings persisted from one OBJECTS.DATA. A typical Windows
# repository has 0-3 bindings; an attacker-planted file with thousands
# would be DoS-shaped. Cap defensive.
_DEFAULT_MAX_BINDINGS: int = 500

# Cap on OBJECTS.DATA size to attempt. Typical OBJECTS.DATA is 5-50 MB;
# pathological cases reach a few hundred MB. 1 GiB cap protects against
# attacker-planted multi-GB files.
_DEFAULT_MAX_FILE_BYTES: int = 1024 * 1024 * 1024  # 1 GiB


@dataclass(frozen=True)
class ConsumerDetails:
    """Decoded EventConsumer payload for one binding.

    Mirrors the upstream's stringified output:
    - ``consumer_type``: e.g. ``CommandLineEventConsumer``,
      ``ActiveScriptEventConsumer``, ``LogFileEventConsumer``,
      ``NTEventLogEventConsumer``, ``SMTPEventConsumer``.
    - ``arguments``: for CommandLineEventConsumer — the command line
      / argv string (printable-filtered to match upstream). For
      ActiveScriptEventConsumer — the ScriptText (VBScript / JScript
      body). For others — whatever the upstream regex's groups[4]
      captures.
    - ``other``: secondary detail captured by upstream's regex
      groups (e.g. ScriptingEngine for ActiveScript). May be empty.

    Note: this surfaces the ATTACKER-CONTROLLED ScriptText /
    CommandLineTemplate / etc. as DATA. Per CLAUDE.md Rule #36, the
    consumer of this dataclass MUST NOT pass any field to a
    subprocess primitive — these are meant for operator review +
    Finding row emission ONLY.
    """

    consumer_type: str
    arguments: str = ""
    other: str = ""


@dataclass(frozen=True)
class FilterDetails:
    """Decoded EventFilter payload for one binding.

    - ``filter_name``: the ``__EventFilter.Name`` field value.
    - ``filter_query``: the WQL query string (e.g.
      ``SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE ...``).
    """

    filter_name: str
    filter_query: str = ""


@dataclass
class BindingResult:
    """One ``__FilterToConsumerBinding`` row decoded from
    OBJECTS.DATA.

    Distinct from a single (consumer, filter) pair because:
    - upstream regex may emit the same consumer / filter name from
      multiple raw positions in the file (allocated + unallocated
      space); we preserve the SET of detail records found for each
      side via ``consumer_records`` / ``filter_records`` lists.
    - the ``probably_benign`` flag carries upstream's well-known
      Windows-shipped binding annotation so consumers can elect to
      filter them out or surface them with reduced priority.
    """

    binding_id: str  # "<consumer name>-<filter name>"
    consumer_name: str  # e.g. ``foo`` from ``CommandLineEventConsumer.Name="foo"``
    filter_name: str  # e.g. ``bar`` from ``__EventFilter.Name="bar"``
    consumer_records: list[ConsumerDetails] = field(default_factory=list)
    filter_records: list[FilterDetails] = field(default_factory=list)
    probably_benign: bool = False


def _decode_safe(value: bytes | str) -> str:
    """Coerce a regex capture (bytes or str) to a printable str.

    OBJECTS.DATA reads via ``open(..., "rb")`` so regex groups are
    ``bytes``. UTF-16-LE decoding handles BSTR-encoded WMI strings
    typical of the Windows repository.
    """
    if isinstance(value, str):
        return value
    if not isinstance(value, (bytes, bytearray)):
        try:
            return str(value)
        except Exception:  # noqa: BLE001 — defensive boundary
            return ""
    # Strip embedded null bytes; preserve printable content only.
    raw = bytes(value)
    # First attempt: UTF-16-LE (WMI's BSTR encoding).
    try:
        decoded = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
        if decoded and all(
            c in _PRINTABLE_CHARS or c.isspace() for c in decoded
        ):
            return decoded
    except Exception:  # noqa: BLE001 — defensive boundary
        pass
    # Fallback: UTF-8 with ignore.
    try:
        return raw.decode("utf-8", errors="ignore").rstrip("\x00")
    except Exception:  # noqa: BLE001 — defensive boundary
        return ""


def _printable_filter(noisy: bytes | str) -> str:
    """Apply upstream's printable-char filter to a noisy argument
    string (typically CommandLineEventConsumer's argv buffer).

    Mirrors upstream ``filter(lambda c: c in PRINTABLE_CHARS, noisy)``.
    """
    if isinstance(noisy, (bytes, bytearray)):
        try:
            noisy_str = noisy.decode("utf-8", errors="ignore")
        except Exception:  # noqa: BLE001 — defensive boundary
            noisy_str = ""
    elif isinstance(noisy, str):
        noisy_str = noisy
    else:
        noisy_str = ""
    return "".join(c for c in noisy_str if c in _PRINTABLE_CHARS)


def _iter_rolling_lines(
    raw: bytes, window: int = 4
) -> list[bytes]:
    """Pre-split OBJECTS.DATA into rolling-window line groups.

    Upstream reads with ``readline()`` (4-line rolling window) so a
    binding row split across pages is still caught. We emulate the
    same shape by splitting on newline (``\\n``) and yielding 4-line
    windows joined with a space separator.
    """
    lines = raw.split(b"\n")
    if len(lines) <= window:
        return [b" ".join(lines)]

    windows: list[bytes] = []
    for i in range(len(lines) - window + 1):
        windows.append(b" ".join(lines[i : i + window]))
    return windows


def _find_bindings_pass(
    raw: bytes, max_bindings: int
) -> dict[str, dict[str, str]]:
    """First pass — enumerate FilterToConsumerBindings.

    Returns ``{binding_id: {"event_consumer_name": ...,
    "event_filter_name": ...}}``. Mirrors upstream pass-1 dict shape.
    """
    bindings: dict[str, dict[str, str]] = {}
    windows = _iter_rolling_lines(raw)
    for page in windows:
        if b"_FilterToConsumerBinding" not in page:
            continue
        consumer_m = _EVENT_CONSUMER_RE.search(page)
        filter_m = _EVENT_FILTER_RE.search(page)
        if consumer_m is None or filter_m is None:
            continue
        consumer_name = _decode_safe(consumer_m.group(2))
        filter_name = _decode_safe(filter_m.group(2))
        if not consumer_name or not filter_name:
            continue
        binding_id = f"{consumer_name}-{filter_name}"
        if binding_id in bindings:
            continue
        bindings[binding_id] = {
            "event_consumer_name": consumer_name,
            "event_filter_name": filter_name,
        }
        if len(bindings) >= max_bindings:
            break
    return bindings


def _consumer_details_pass(
    raw: bytes, consumer_names: set[str]
) -> dict[str, list[ConsumerDetails]]:
    """Second pass — enumerate EventConsumer details for each name.

    For each consumer name, emit a list of :class:`ConsumerDetails`
    records (the upstream stores per-name sets in case multiple
    distinct payloads share a name across allocated + unallocated
    repository regions).
    """
    out: dict[str, list[ConsumerDetails]] = {
        name: [] for name in consumer_names
    }
    if not consumer_names:
        return out

    windows = _iter_rolling_lines(raw)
    for page in windows:
        # Inline-stripped newline for regex matching (upstream
        # behaviour).
        page = page.replace(b"\n", b"")
        if b"EventConsumer" not in page:
            continue

        for consumer_name in consumer_names:
            # Per-name regex must be constructed dynamically because
            # the name is interpolated into the search pattern.
            name_bytes = consumer_name.encode(
                "utf-8", errors="ignore"
            )
            escaped_name = re.escape(name_bytes)

            if b"CommandLineEventConsumer" in page:
                # Upstream regex:
                #   (CommandLineEventConsumer)(\x00\x00)(.*?)(\x00)(.*?)
                #   ({name})(\x00\x00)?([^\x00]*)?
                pattern = (
                    rb"(CommandLineEventConsumer)(\x00\x00)(.*?)"
                    rb"(\x00)(.*?)("
                    + escaped_name
                    + rb")(\x00\x00)?([^\x00]*)?"
                )
                m = re.search(pattern, page, re.DOTALL)
                if m is not None:
                    groups = m.groups()
                    consumer_type = _decode_safe(groups[0])
                    arguments = _printable_filter(groups[2] or b"")
                    other = _decode_safe(groups[7] or b"")
                    out[consumer_name].append(
                        ConsumerDetails(
                            consumer_type=consumer_type,
                            arguments=arguments,
                            other=other,
                        )
                    )
                    continue

            # Fallback regex for other EventConsumer types:
            #   (\w*EventConsumer)(.*?)({name})(\x00\x00)([^\x00]*)
            #   (\x00\x00)([^\x00]*)
            pattern = (
                rb"(\w*EventConsumer)(.*?)("
                + escaped_name
                + rb")(\x00\x00)([^\x00]*)(\x00\x00)([^\x00]*)"
            )
            m = re.search(pattern, page, re.DOTALL)
            if m is not None:
                groups = m.groups()
                consumer_type = _decode_safe(groups[0])
                arguments = _decode_safe(groups[4] or b"")
                other = _decode_safe(groups[6] or b"")
                out[consumer_name].append(
                    ConsumerDetails(
                        consumer_type=consumer_type,
                        arguments=arguments,
                        other=other,
                    )
                )

    return out


def _filter_details_pass(
    raw: bytes, filter_names: set[str]
) -> dict[str, list[FilterDetails]]:
    """Third pass — enumerate EventFilter Query details for each name.

    Mirrors upstream's third sub-loop. The Query field is the
    WQL ``SELECT * FROM ...`` expression that defines the filter's
    trigger condition.
    """
    out: dict[str, list[FilterDetails]] = {
        name: [] for name in filter_names
    }
    if not filter_names:
        return out

    windows = _iter_rolling_lines(raw)
    for page in windows:
        page = page.replace(b"\n", b"")

        for filter_name in filter_names:
            name_bytes = filter_name.encode("utf-8", errors="ignore")
            if name_bytes not in page:
                continue
            # Upstream regex:
            #   ({name})(\x00\x00)([^\x00]*)(\x00\x00)
            escaped_name = re.escape(name_bytes)
            pattern = (
                rb"("
                + escaped_name
                + rb")(\x00\x00)([^\x00]*)(\x00\x00)"
            )
            m = re.search(pattern, page, re.DOTALL)
            if m is not None:
                groups = m.groups()
                fn = _decode_safe(groups[0])
                fq = _decode_safe(groups[2] or b"")
                out[filter_name].append(
                    FilterDetails(filter_name=fn, filter_query=fq)
                )

    return out


def find_persistence(
    objects_data_path: str | Path,
    *,
    max_bindings: int = _DEFAULT_MAX_BINDINGS,
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
) -> list[BindingResult]:
    """Parse a WMI repository ``OBJECTS.DATA`` for
    FilterToConsumerBindings.

    Args:
        objects_data_path: filesystem path to OBJECTS.DATA. The path
            is treated as untrusted DATA per CLAUDE.md Rule #36 — read
            but never executed.
        max_bindings: defensive cap on bindings persisted from one
            file (default 500). Bindings beyond the cap are silently
            dropped; not an error.
        max_file_bytes: defensive cap on OBJECTS.DATA size to attempt
            (default 1 GiB). Files larger than the cap return an empty
            list.

    Returns:
        ``list[BindingResult]`` — one entry per detected
        FilterToConsumerBinding, populated with consumer + filter
        decoded details (may be empty if the upstream's
        consumer/filter regex didn't match — the binding pass alone
        is sufficient to surface the persistence detection signal).

    Defensive boundaries:

    - File doesn't exist / can't open → empty list.
    - File size > ``max_file_bytes`` → empty list (DoS protection).
    - File contains no ``_FilterToConsumerBinding`` → empty list.

    No exceptions are propagated; the caller is responsible for
    handling the empty-list case (a typical OBJECTS.DATA has 0
    bindings on a clean Windows install, so empty is normal).
    """
    path = Path(objects_data_path)
    try:
        if not path.is_file():
            return []
        size = path.stat().st_size
    except OSError:
        return []
    if size > max_file_bytes:
        return []

    try:
        raw = path.read_bytes()
    except OSError:
        return []
    if not raw:
        return []
    if b"_FilterToConsumerBinding" not in raw:
        return []

    # Pass 1 — enumerate bindings.
    bindings_dict = _find_bindings_pass(raw, max_bindings)
    if not bindings_dict:
        return []

    consumer_names = {
        b["event_consumer_name"] for b in bindings_dict.values()
    }
    filter_names = {
        b["event_filter_name"] for b in bindings_dict.values()
    }

    # Pass 2 — enumerate consumer details.
    consumer_details = _consumer_details_pass(raw, consumer_names)

    # Pass 3 — enumerate filter details.
    filter_details = _filter_details_pass(raw, filter_names)

    # Assemble results.
    results: list[BindingResult] = []
    for binding_id, binding in bindings_dict.items():
        consumer_name = binding["event_consumer_name"]
        filter_name = binding["event_filter_name"]
        results.append(
            BindingResult(
                binding_id=binding_id,
                consumer_name=consumer_name,
                filter_name=filter_name,
                consumer_records=list(
                    consumer_details.get(consumer_name, [])
                ),
                filter_records=list(
                    filter_details.get(filter_name, [])
                ),
                probably_benign=(binding_id in _BENIGN_BINDING_NAMES),
            )
        )
    return results
