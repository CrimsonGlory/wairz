"""Volatility 3 subprocess runner (Phase λ.α.D — memory-forensic-godmode).

Pure subprocess wrapper around the upstream ``vol`` CLI installed via the
``INCLUDE_VOL3=1`` Dockerfile gate (λ.α.C). Builds the canonical argv per
the λ-research scout-1 + scout-3 synthesis, invokes
``asyncio.create_subprocess_exec`` with a Rule #29 timeout, parses the
``-r jsonl`` stream into a list of records, and returns a
:class:`Vol3RunResult` dataclass.

The runner is **plugin-agnostic** — callers (``windows_info_walker``,
``windows_processes_walker`` in λ.β, …) pass the plugin name as a string
and parse the resulting records themselves. Each walker owns its own
Rule #33 .a state machine + Rule #39 inner/outer/safe triplet against
``firmware.<plugin>_walk_*`` columns. The runner has no DB awareness.

Per CLAUDE.md Rule #29 timeout discipline: every invocation gets
:data:`VOL3_PLUGIN_TIMEOUT_SECONDS` (600 s, matching ``mobsfscan``'s
synchronous ceiling). Pathological plugins
(``windows.malware.unhooked_system_calls`` on a multi-GB Win11 image,
``windows.poolscanner`` on a fragmented 32 GB image) need the full
window. Frontend axios timeouts derive per Rule #29 ``×1200`` —
``VOL3_PLUGIN_TIMEOUT_SECONDS * 1200 = 720_000 ms``, **above the 100 s
reverse-proxy ceiling**, so any operator-facing endpoint MUST use the
202+polling pattern per Rule #33. Internal walkers run as detached
``asyncio.create_task`` background jobs and never sit on the request
thread.

Per CLAUDE.md Rule #33 .a state machine: the runner does NOT own the
state machine — the walker that calls it does (see
``windows_info_walker.py`` for the canonical Rule #39 triplet shape).
This module returns a pure result aggregate; callers transition the
firmware's per-walker status column.

Per CLAUDE.md Rule #36 no-execute discipline: ``argv[0]`` is HARD-PINNED
to the image-shipped trusted ``vol`` binary (default
:data:`VOL3_DEFAULT_BIN` = ``/app/.venv/bin/vol``). The image path is a
DATA argument under ``-f``; the trusted CLI parses it via Vol3's
pure-Python framework (struct unpack + read-only layered file open) and
NEVER passes control to any binary inside the image. The argv builder
refuses to construct an argv where ``argv[0]`` is a relative path or
contains a shell metachar — bypassing the discipline is impossible
through any caller-facing API.

Per CLAUDE.md Rule #37 offline-trust-anchor discipline:
:data:`VOL3_SYMBOLS_PATH` is the image-baked ISF bundle root
(``/opt/wairz/vol3-symbols`` under ``INCLUDE_VOL3=1``); ``--offline`` is
hard-coded into the argv, so Vol3 NEVER reaches out to
``msdl.microsoft.com`` or ``downloads.volatilityfoundation.org`` at scan
time. The test gate ``test_build_vol3_argv_offline_always_set`` enforces
this contract.

Per CLAUDE.md Rule #45 metadata-walker discipline: a runner-level
:data:`_FORBIDDEN_PLUGINS` guard rejects credential-extraction plugins
(``windows.hashdump`` / ``windows.lsadump`` / ``windows.cachedump`` /
``windows.truecrypt`` and their package-path variants). Operators who
need credential walks must explicitly remove the guard with documented
sign-off — the runner refuses by default.

Per CLAUDE.md Rule #46 canary discipline: the test suite includes the
gate-canary ``test_forbidden_plugins_guard_canary_fires`` that confirms
the deny-list machinery actually rejects synthetic forbidden names.
Without the canary, a future refactor that drains
:data:`_FORBIDDEN_PLUGINS` would silently re-enable credential
extraction.

The :func:`volatility3.framework.require_interface_version` call sits at
module top, gated by an ``ImportError`` ``try`` so non-``INCLUDE_VOL3``
builds keep importing cleanly. If Vol3 ships a 3.x interface bump, this
module fails to import on the next worker rebuild and the operator gets
a fail-fast signal instead of a runtime mystery — per the λ Scout 1
pin-slip-guard recommendation.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Configuration constants ──────────────────────────────────────────────────

# Trusted argv[0] per CLAUDE.md Rule #36 no-execute discipline. The wairz
# worker image installs Vol3 into the uv-managed virtualenv at
# ``/app/.venv`` (Dockerfile under ``ARG INCLUDE_VOL3=1``; see λ.α.C).
# The path is constant across rebuilds; operators on a non-standard
# layout can override via ``VOL3_BIN`` but the override is rare.
VOL3_DEFAULT_BIN: str = "/app/.venv/bin/vol"
VOL3_BIN: str = os.environ.get("VOL3_BIN", VOL3_DEFAULT_BIN)

# Symbol bundle directory baked in at image build time per CLAUDE.md
# Rule #37 offline-trust-anchor discipline. The λ.α.C Dockerfile gate
# copies ``backend/vol3-symbols/{windows,linux,mac}.zip`` into
# ``/opt/wairz/vol3-symbols`` at build time after ``sha256sum -c``.
# Vol3's automagic LayerStacker reads ISFs from this path; ``--offline``
# keeps Vol3 from reaching out to Microsoft / Volatility Foundation
# servers at scan time even when a needed ISF is missing locally.
VOL3_SYMBOLS_PATH: str = os.environ.get(
    "VOL3_SYMBOLS_PATH", "/opt/wairz/vol3-symbols"
)

# Subprocess timeout per CLAUDE.md Rule #29. Pathological Vol3 plugins
# (``windows.malware.unhooked_system_calls`` on a Win11 16 GB image;
# ``windows.poolscanner`` on a fragmented 32 GB image) need the full
# 600 s window. Smaller plugins typically complete in <60 s. Tuned to
# match the mobsfscan pipeline's ``_PIPELINE_BUDGET_SECONDS = 600``
# tier (the longest synchronous tier compatible with axios's 100 s
# reverse-proxy ceiling via the 202+polling pattern callers use).
VOL3_PLUGIN_TIMEOUT_SECONDS: int = 600

# Lines retained from each stream when truncating subprocess stderr for
# the result aggregate. 40 lines captures a Python traceback end + the
# immediately-preceding plugin context without bloating the JSONB row.
_STDERR_TAIL_LINES: int = 40

# Hard cap on records returned from a single plugin invocation. Real
# Win10 ``windows.pslist`` returns ~50-200 entries; ``windows.handles``
# can return 100K+ on a busy system. 100K bounds the record list at a
# JSONB-sane size (~10-50 MB serialised) while still capturing the
# 99.9th percentile of legitimate Vol3 output.
_STDOUT_RECORD_HARD_CAP: int = 100_000


# Plugins that EXTRACT credentials / decrypt protected payloads — per
# CLAUDE.md Rule #45 metadata-walker discipline, wairz refuses to invoke
# these by default. Future operator opt-in (with documented sign-off
# per the rule) would lift the guard. Stored both as canonical package
# paths AND short names because Vol3 accepts both
# (``windows.hashdump.Hashdump`` and ``hashdump`` resolve to the same
# plugin via its automagic CLI dispatcher).
_FORBIDDEN_PLUGINS: frozenset[str] = frozenset(
    {
        # Windows credential extraction
        "windows.hashdump",
        "windows.hashdump.Hashdump",
        "hashdump",
        "windows.lsadump",
        "windows.lsadump.Lsadump",
        "lsadump",
        "windows.cachedump",
        "windows.cachedump.Cachedump",
        "cachedump",
        # Truecrypt passphrase extraction
        "windows.truecrypt",
        "windows.truecrypt.Passphrase",
        "truecrypt",
        # Linux equivalents (Vol3 roadmap 3.x; pre-empt the guard)
        "linux.hashdump",
        "linux.lsadump",
    }
)


# ── Pin-slip guard (per λ Scout 1) ───────────────────────────────────────────
#
# At module import: if Vol3 is installed, confirm it speaks interface
# version 2.0.0. A 3.x or back-revved Vol3 fails this and the module
# fails to import — the operator gets a fail-fast signal at rebuild
# rather than a runtime mystery on the first plugin invocation.
#
# Non-``INCLUDE_VOL3=1`` builds: the import block silently sets the
# sentinel ``_VOL3_INSTALLED = False``; :func:`_require_vol3_available`
# raises :class:`Vol3NotInstalled` at invocation time with a clear
# operator-actionable error.
try:
    from volatility3 import framework as _vol3_framework

    _vol3_framework.require_interface_version(2, 0, 0)
    _VOL3_INSTALLED: bool = True
except ImportError:
    _vol3_framework = None  # type: ignore[assignment]
    _VOL3_INSTALLED = False
# NOTE: any non-ImportError exception from ``require_interface_version``
# (e.g. a future ``VersionMismatchException``) deliberately propagates
# and fails module import — the fail-fast signal the pin-slip guard
# exists to deliver.


# ── Exceptions ───────────────────────────────────────────────────────────────


class Vol3NotInstalled(RuntimeError):
    """Raised when Vol3 is not available in the image (INCLUDE_VOL3=0).

    Callers should catch this and surface a clear "rebuild with
    ``--build-arg INCLUDE_VOL3=1``" message to the operator. The Rule
    #33 walker outer-wrapper converts this to a ``failed`` row state
    with the message in ``Firmware.<plugin>_walk_error``.
    """


class Vol3Timeout(RuntimeError):
    """Raised when a Vol3 invocation exceeds :data:`VOL3_PLUGIN_TIMEOUT_SECONDS`.

    The runner SIGKILLs the subprocess before raising so no orphaned
    ``vol`` processes remain. Callers transition the firmware row to
    ``failed`` with the timeout duration in the error column.
    """


class Vol3InvocationFailed(RuntimeError):
    """Raised on non-zero exit code from Vol3 OR on pre-flight refusal
    (argv discipline / nonexistent image).

    Carries the stderr tail (last :data:`_STDERR_TAIL_LINES` lines) for
    diagnosis. Callers transition the firmware row to ``failed``.
    """


class Vol3PluginForbidden(Vol3InvocationFailed):
    """Raised when a caller requests a plugin in :data:`_FORBIDDEN_PLUGINS`.

    Per CLAUDE.md Rule #45 metadata-walker discipline: credential
    extraction plugins (``hashdump`` / ``lsadump`` / ``cachedump`` /
    ``truecrypt``) are deferred beyond the λ campaign pending explicit
    operator sign-off. The guard fires before any subprocess is spawned.
    """


# ── Result dataclass ─────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Vol3RunResult:
    """Parsed result of a single Vol3 plugin invocation.

    Frozen because callers stamp the records into JSONB columns and we
    want to prevent post-return mutation. ``stderr_tail`` is the last
    :data:`_STDERR_TAIL_LINES` lines of stderr (decoded, newline-joined)
    — useful for diagnosis without bloating the JSONB.
    """

    plugin: str
    image_path: str
    records: list[dict[str, Any]] = field(default_factory=list)
    elapsed_s: float = 0.0
    exit_code: int = 0
    stderr_tail: str = ""


# ── Pre-flight guards ────────────────────────────────────────────────────────


def _require_vol3_available() -> None:
    """Raise :class:`Vol3NotInstalled` if the runtime can't invoke Vol3.

    Two failure conditions, either fatal: (1) the ``vol`` binary at
    :data:`VOL3_BIN` doesn't exist (``INCLUDE_VOL3=0`` build);
    (2) ``volatility3`` Python package isn't importable (sentinel
    ``_VOL3_INSTALLED`` is ``False``).
    """
    if not _VOL3_INSTALLED:
        raise Vol3NotInstalled(
            "volatility3 Python package not installed — rebuild the worker "
            "with --build-arg INCLUDE_VOL3=1 to enable Vol3 walkers."
        )
    if not os.path.isfile(VOL3_BIN):
        raise Vol3NotInstalled(
            f"Volatility 3 binary not found at {VOL3_BIN!r} — rebuild the "
            "worker with --build-arg INCLUDE_VOL3=1 to install."
        )


def _check_plugin_allowed(plugin: str) -> None:
    """Raise :class:`Vol3PluginForbidden` if ``plugin`` is in the deny-list.

    Matches both canonical package paths (``windows.hashdump.Hashdump``)
    and short names (``hashdump``) — Vol3 accepts both at the CLI.
    Per CLAUDE.md Rule #45.
    """
    if plugin in _FORBIDDEN_PLUGINS:
        raise Vol3PluginForbidden(
            f"plugin {plugin!r} is on the credential-extraction deny-list — "
            "Rule #45 metadata-walker discipline requires explicit operator "
            "sign-off before enabling. Edit _FORBIDDEN_PLUGINS in "
            "vol3_runner.py with a documented rationale."
        )


def _validate_argv0(bin_path: str) -> None:
    """Enforce CLAUDE.md Rule #36 argv discipline on argv[0].

    ``argv[0]`` MUST be an absolute path with no shell metachars. The
    image-build pinning of ``/app/.venv/bin/vol`` is the actual trust
    anchor; this function is a belt-and-suspenders guard against a
    misconfigured ``VOL3_BIN`` env override.
    """
    if not bin_path.startswith("/"):
        raise Vol3InvocationFailed(
            f"refusing to invoke Vol3 with non-absolute argv[0] "
            f"{bin_path!r} — Rule #36 argv discipline."
        )
    if any(ch in bin_path for ch in (";", "&", "|", "$", "`", "\n", "\r", "\t", " ")):
        raise Vol3InvocationFailed(
            f"refusing to invoke Vol3 with metachar-bearing argv[0] "
            f"{bin_path!r} — Rule #36 argv discipline."
        )


# ── Argv builder ─────────────────────────────────────────────────────────────


def build_vol3_argv(
    image_path: str,
    plugin: str,
    *,
    tmp_dir: str,
    symbols_path: str = VOL3_SYMBOLS_PATH,
    renderer: str = "jsonl",
    offline: bool = True,
    bin_path: str = "",
) -> list[str]:
    """Compose the canonical Vol3 argv list per the λ Scout 1+3 synthesis.

    Shape::

        vol --offline -q -f <image> -s <symbols> -o <out>
            --cache-path <out>/cache -l <out>/vol.log -r jsonl <plugin>

    ``--offline`` is the default and **MUST** stay on per CLAUDE.md
    Rule #37 (Vol3 reaches out to Microsoft and Volatility Foundation
    symbol servers without it). The ``offline=False`` parameter is
    test-only — production callers never pass it.

    The argv builder enforces argv[0] discipline via
    :func:`_validate_argv0` and the plugin guard via
    :func:`_check_plugin_allowed`. Both fire BEFORE any subprocess is
    spawned, so the discipline is enforceable through the runner's
    only public-facing argv-construction path.
    """
    actual_bin = bin_path or VOL3_BIN
    _validate_argv0(actual_bin)
    _check_plugin_allowed(plugin)

    argv: list[str] = [actual_bin]
    if offline:
        argv.append("--offline")
    argv += [
        "-q",  # quiet (suppresses banners and progress bars)
        "-f", image_path,
        "-s", symbols_path,
        "-o", tmp_dir,
        "--cache-path", os.path.join(tmp_dir, "cache"),
        "-l", os.path.join(tmp_dir, "vol.log"),
        "-r", renderer,
        plugin,
    ]
    return argv


# ── Output parsers ───────────────────────────────────────────────────────────


def _parse_jsonl_stream(stdout_bytes: bytes) -> list[dict[str, Any]]:
    """Parse Vol3's ``-r jsonl`` stream into a list of records.

    Vol3's JsonRenderer emits one self-contained JSON object per line.
    Malformed lines are logged + skipped — partial output is better
    than no output on transient pickling glitches in the framework.
    Bounded by :data:`_STDOUT_RECORD_HARD_CAP` to protect against
    runaway memory on pathological plugin output. Array-rooted output
    is flattened (some Vol3 renderers emit a single ``[…]`` line).
    """
    records: list[dict[str, Any]] = []
    text = stdout_bytes.decode("utf-8", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if len(records) >= _STDOUT_RECORD_HARD_CAP:
            logger.warning(
                "vol3_runner: dropping records past cap %d — investigate "
                "plugin output for unbounded growth",
                _STDOUT_RECORD_HARD_CAP,
            )
            break
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning(
                "vol3_runner: skipped malformed jsonl line: %s",
                line[:200],
            )
            continue
        if isinstance(obj, dict):
            records.append(obj)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    records.append(item)
                    if len(records) >= _STDOUT_RECORD_HARD_CAP:
                        break
    return records


def _tail_stderr(stderr_bytes: bytes, max_lines: int = _STDERR_TAIL_LINES) -> str:
    """Return the last ``max_lines`` lines of stderr (decoded, newline-joined)."""
    text = stderr_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()
    return "\n".join(lines[-max_lines:])


# ── Async filesystem helpers (Rule #5) ──────────────────────────────────────


async def _mkdtemp_async(prefix: str) -> str:
    """Async wrapper around ``tempfile.mkdtemp`` (Rule #5 sync-I/O wrap)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, tempfile.mkdtemp, "", prefix)


async def _rmtree_async(path: str) -> None:
    """Async wrapper around ``shutil.rmtree`` (Rule #5 sync-I/O wrap).

    ``ignore_errors=True`` because the tempdir cleanup is best-effort —
    a missing file or open handle should not cascade into a walker
    failure.
    """
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None, lambda: shutil.rmtree(path, ignore_errors=True)
    )


# ── Public runner API ────────────────────────────────────────────────────────


async def run_vol3_plugin(
    image_path: str,
    plugin: str,
    *,
    timeout: float = VOL3_PLUGIN_TIMEOUT_SECONDS,  # noqa: ASYNC109 — caller-supplied timeout per Rule #29 contract
    symbols_path: str = VOL3_SYMBOLS_PATH,
    bin_path: str = "",
) -> Vol3RunResult:
    """Run a Vol3 plugin against a memory image and return parsed records.

    Per CLAUDE.md Rule #29: ``timeout`` defaults to
    :data:`VOL3_PLUGIN_TIMEOUT_SECONDS` (600 s). On exceeding, the
    subprocess is SIGKILL-ed and :class:`Vol3Timeout` is raised.

    Per CLAUDE.md Rule #36: ``argv[0]`` is HARD-PINNED to the trusted
    :data:`VOL3_BIN`; image_path is a DATA argument under ``-f``. The
    subprocess parses the image via Vol3's pure-Python framework
    (struct unpack + read-only layered file open) and NEVER executes
    any binary embedded inside the image.

    Per CLAUDE.md Rule #45: the plugin name is checked against
    :data:`_FORBIDDEN_PLUGINS` before the subprocess is spawned;
    credential-extraction plugins raise :class:`Vol3PluginForbidden`.
    """
    # Rule #45 deny-list refusal fires FIRST — independent of Vol3 install
    # state. An operator trying ``hashdump`` should see "credential-extraction
    # deny-list" regardless of whether the worker has Vol3 installed; the
    # alternate message "Vol3 not installed" misleadingly implies the only
    # thing blocking the request is the install.
    _check_plugin_allowed(plugin)
    _require_vol3_available()
    if not os.path.isfile(image_path):  # noqa: ASYNC240 — single pre-flight stat before bounded sync subprocess; cheap fail-fast on missing image
        raise Vol3InvocationFailed(
            f"image_path does not exist: {image_path!r}"
        )

    actual_bin = bin_path or VOL3_BIN

    tmp_dir = await _mkdtemp_async(prefix=f"vol3-{plugin.replace('.', '_')}-")
    started = time.monotonic()
    proc: asyncio.subprocess.Process | None = None
    try:
        argv = build_vol3_argv(
            image_path,
            plugin,
            tmp_dir=tmp_dir,
            symbols_path=symbols_path,
            bin_path=actual_bin,
        )
        logger.info(
            "vol3_runner: invoking %s on %s (timeout=%.0fs)",
            plugin,
            image_path,
            timeout,
        )
        # Sanitised env — Vol3 is fully self-contained when given
        # ``--cache-path`` + ``-s`` explicitly. Minimal env reduces the
        # attack surface for any Vol3 plugin that might shell out
        # (currently none in the metadata-walker subset do; this is
        # defense-in-depth).
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": tmp_dir,
            "XDG_CACHE_HOME": os.path.join(tmp_dir, "cache"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=tmp_dir,
            env=env,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except TimeoutError as exc:
            # SIGKILL hard-kill — ``vol --offline`` can ignore SIGTERM
            # in the middle of e.g. ``unhooked_system_calls``'s O(N²)
            # walk. Suppress ProcessLookupError because the process may
            # have already exited between the timeout firing and the
            # kill call.
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
                await proc.wait()
            raise Vol3Timeout(
                f"vol3 plugin {plugin!r} on {image_path!r} exceeded "
                f"timeout {timeout}s"
            ) from exc

        elapsed = time.monotonic() - started
        stderr_tail = _tail_stderr(stderr_bytes)
        exit_code = proc.returncode if proc.returncode is not None else -1
        if exit_code != 0:
            raise Vol3InvocationFailed(
                f"vol3 plugin {plugin!r} exited {exit_code}: "
                f"{stderr_tail[-500:]}"
            )

        records = _parse_jsonl_stream(stdout_bytes)
        return Vol3RunResult(
            plugin=plugin,
            image_path=image_path,
            records=records,
            elapsed_s=round(elapsed, 3),
            exit_code=exit_code,
            stderr_tail=stderr_tail,
        )
    finally:
        await _rmtree_async(tmp_dir)


__all__ = [
    "VOL3_BIN",
    "VOL3_DEFAULT_BIN",
    "VOL3_PLUGIN_TIMEOUT_SECONDS",
    "VOL3_SYMBOLS_PATH",
    "Vol3InvocationFailed",
    "Vol3NotInstalled",
    "Vol3PluginForbidden",
    "Vol3RunResult",
    "Vol3Timeout",
    "build_vol3_argv",
    "run_vol3_plugin",
]
