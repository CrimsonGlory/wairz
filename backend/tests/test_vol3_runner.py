"""Tests for ``app.services.vol3_runner`` (Phase λ.α.D).

Covers:

- :func:`build_vol3_argv` — canonical Vol3 CLI shape per λ Scout 1+3
  synthesis: ``--offline`` always set (Rule #37), argv[0] absolute-path
  + no metachars (Rule #36), correct flag ordering, plugin at the end.
- ``_FORBIDDEN_PLUGINS`` deny-list — Rule #45 metadata-walker
  discipline: credential-extraction plugins (hashdump / lsadump /
  cachedump / truecrypt) are rejected by both the public-facing
  :func:`run_vol3_plugin` AND the lower-level :func:`build_vol3_argv`.
- Rule #46 canary — the forbidden-plugin guard ACTUALLY fires on a
  synthetic violation. Without this canary, a refactor that drained
  the deny-list would silently re-enable credential extraction.
- :func:`_parse_jsonl_stream` — handles dict/list/malformed/empty lines
  and respects the ``_STDOUT_RECORD_HARD_CAP`` bound.
- :func:`_require_vol3_available` — raises :class:`Vol3NotInstalled`
  when the Vol3 install sentinel is ``False`` OR the ``vol`` binary
  is missing.
- :func:`run_vol3_plugin` — Rule #29 timeout enforcement via mocked
  subprocess (the real Vol3 invocation is exercised only on a build
  with ``INCLUDE_VOL3=1`` — see the Rule #11 import smoke at session
  close).
- Rule #36 + Rule #45 source-scan gate over ``vol3_runner.py`` — assert
  the SERVICE module contains no decryption / spawn primitives outside
  the docstring-mentioned discipline references.
- Rule #46 canary for the source-scan gate — confirm the gate fires
  on a synthetic violation injected as concatenated CODE tokens
  (NOT a string literal, to survive docstring/comment stripping).
"""
from __future__ import annotations

import asyncio
import io
import pathlib
import re
import tokenize
from typing import Any
from unittest.mock import patch

import pytest

from app.services.vol3_runner import (
    _FORBIDDEN_PLUGINS,
    _STDOUT_RECORD_HARD_CAP,
    VOL3_BIN,
    VOL3_DEFAULT_BIN,
    VOL3_PLUGIN_TIMEOUT_SECONDS,
    VOL3_SYMBOLS_PATH,
    Vol3InvocationFailed,
    Vol3NotInstalled,
    Vol3PluginForbidden,
    Vol3RunResult,
    Vol3Timeout,
    _check_plugin_allowed,
    _parse_jsonl_stream,
    _require_vol3_available,
    _tail_stderr,
    _validate_argv0,
    build_vol3_argv,
    run_vol3_plugin,
)

# ── Argv builder (Rule #36 argv discipline + Rule #37 offline) ──────────────


def test_build_vol3_argv_canonical_shape() -> None:
    """Argv matches the λ Scout 1+3 synthesis baseline shape."""
    argv = build_vol3_argv(
        "/data/mem.raw",
        "windows.info",
        tmp_dir="/tmp/vol3-test",
        bin_path="/app/.venv/bin/vol",
    )
    assert argv[0] == "/app/.venv/bin/vol"
    assert argv[-1] == "windows.info"
    assert "--offline" in argv
    assert "-q" in argv
    assert "-f" in argv
    assert "/data/mem.raw" in argv
    assert "-s" in argv
    assert "/opt/wairz/vol3-symbols" in argv  # default VOL3_SYMBOLS_PATH
    assert "-o" in argv
    assert "/tmp/vol3-test" in argv
    assert "--cache-path" in argv
    assert "/tmp/vol3-test/cache" in argv
    assert "-l" in argv
    assert "/tmp/vol3-test/vol.log" in argv
    assert "-r" in argv
    assert "jsonl" in argv


def test_build_vol3_argv_offline_always_set_by_default() -> None:
    """Rule #37 — ``--offline`` MUST be in argv unless explicitly disabled."""
    argv = build_vol3_argv(
        "/data/mem.raw",
        "windows.info",
        tmp_dir="/tmp/vol3-test",
        bin_path="/app/.venv/bin/vol",
    )
    assert "--offline" in argv


def test_build_vol3_argv_offline_can_be_disabled_for_testing() -> None:
    """``offline=False`` is test-only — production callers never pass it."""
    argv = build_vol3_argv(
        "/data/mem.raw",
        "windows.info",
        tmp_dir="/tmp/vol3-test",
        bin_path="/app/.venv/bin/vol",
        offline=False,
    )
    assert "--offline" not in argv


def test_build_vol3_argv_uses_custom_symbols_path() -> None:
    """``symbols_path`` is wired through to ``-s``."""
    argv = build_vol3_argv(
        "/data/mem.raw",
        "windows.info",
        tmp_dir="/tmp/vol3-test",
        symbols_path="/custom/symbols",
        bin_path="/app/.venv/bin/vol",
    )
    assert "/custom/symbols" in argv


def test_build_vol3_argv_uses_custom_renderer() -> None:
    """``renderer`` wires through to ``-r``."""
    argv = build_vol3_argv(
        "/data/mem.raw",
        "windows.info",
        tmp_dir="/tmp/vol3-test",
        renderer="csv",
        bin_path="/app/.venv/bin/vol",
    )
    assert "csv" in argv
    assert "jsonl" not in argv


# ── Rule #36 argv[0] discipline ─────────────────────────────────────────────


def test_validate_argv0_rejects_relative_path() -> None:
    """Rule #36 — argv[0] must be absolute."""
    with pytest.raises(Vol3InvocationFailed, match="non-absolute"):
        _validate_argv0("vol")


def test_validate_argv0_rejects_metachar_bearing_path() -> None:
    """Rule #36 — argv[0] must contain no shell metachars."""
    metachar_cases = [
        "/app/.venv/bin/vol;rm",
        "/app/.venv/bin/vol&background",
        "/app/.venv/bin/vol|pipe",
        "/app/.venv/bin/vol$VAR",
        "/app/.venv/bin/vol`cmd`",
        "/app/.venv/bin/vol\nnewline",
        "/app/.venv/bin/vol with space",
    ]
    for bad in metachar_cases:
        with pytest.raises(Vol3InvocationFailed, match="metachar"):
            _validate_argv0(bad)


def test_validate_argv0_accepts_canonical_path() -> None:
    """The canonical /app/.venv/bin/vol path passes validation."""
    _validate_argv0("/app/.venv/bin/vol")  # should not raise


def test_build_vol3_argv_rejects_relative_bin() -> None:
    """build_vol3_argv enforces argv[0] discipline before plugin check."""
    with pytest.raises(Vol3InvocationFailed):
        build_vol3_argv(
            "/data/mem.raw",
            "windows.info",
            tmp_dir="/tmp/vol3-test",
            bin_path="vol",
        )


# ── Rule #45 forbidden plugins + Rule #46 canary ────────────────────────────


@pytest.mark.parametrize(
    "plugin",
    [
        "hashdump",
        "windows.hashdump",
        "windows.hashdump.Hashdump",
        "lsadump",
        "windows.lsadump",
        "windows.lsadump.Lsadump",
        "cachedump",
        "windows.cachedump",
        "windows.cachedump.Cachedump",
        "truecrypt",
        "windows.truecrypt",
        "windows.truecrypt.Passphrase",
        "linux.hashdump",
        "linux.lsadump",
    ],
)
def test_check_plugin_allowed_rejects_credential_extraction(plugin: str) -> None:
    """Rule #45 — every credential-extraction plugin variant is rejected."""
    with pytest.raises(Vol3PluginForbidden, match="credential-extraction"):
        _check_plugin_allowed(plugin)


def test_check_plugin_allowed_permits_metadata_plugins() -> None:
    """Sanity — known-good metadata plugins pass."""
    # Each of these is a metadata-surfacing plugin used in λ.β-ε wiring.
    for plugin in (
        "windows.info",
        "windows.pslist",
        "windows.psscan",
        "windows.netstat",
        "windows.malware.malfind",
        "linux.banners",
        "linux.pslist",
    ):
        _check_plugin_allowed(plugin)  # should not raise


def test_build_vol3_argv_rejects_forbidden_plugin() -> None:
    """build_vol3_argv layers the Rule #45 guard atop argv discipline."""
    with pytest.raises(Vol3PluginForbidden):
        build_vol3_argv(
            "/data/mem.raw",
            "hashdump",
            tmp_dir="/tmp/vol3-test",
            bin_path="/app/.venv/bin/vol",
        )


def test_forbidden_plugins_guard_canary_fires() -> None:
    """Rule #46 — confirm the forbidden-plugin guard ACTUALLY rejects
    every name in :data:`_FORBIDDEN_PLUGINS`.

    Without this canary, a refactor that drained or renamed the
    deny-list would silently re-enable credential extraction. The
    canary iterates the deny-list and asserts each entry raises.
    """
    assert len(_FORBIDDEN_PLUGINS) > 0, (
        "Rule #46 canary: _FORBIDDEN_PLUGINS was emptied — credential "
        "extraction would now be silently allowed. Restore the deny-list."
    )
    for fake_forbidden in _FORBIDDEN_PLUGINS:
        with pytest.raises(Vol3PluginForbidden):
            _check_plugin_allowed(fake_forbidden)


def test_forbidden_plugins_deny_list_covers_known_credential_families() -> None:
    """Rule #46 — every credential-family short name is in the deny-list.

    A refactor that added a new credential family but forgot to add it
    to ``_FORBIDDEN_PLUGINS`` would slip past the guard. This test
    enumerates the canonical short names and confirms each is in the
    set.
    """
    must_be_blocked = {
        "hashdump",
        "lsadump",
        "cachedump",
        "truecrypt",
    }
    missing = must_be_blocked - _FORBIDDEN_PLUGINS
    assert not missing, (
        f"Rule #46 canary: {sorted(missing)} fell out of "
        "_FORBIDDEN_PLUGINS — credential extraction would be allowed."
    )


# ── jsonl parser ────────────────────────────────────────────────────────────


def test_parse_jsonl_stream_one_object_per_line() -> None:
    """Vol3's JsonRenderer emits one object per line."""
    text = b'{"PID": 4, "Name": "System"}\n{"PID": 364, "Name": "smss"}\n'
    records = _parse_jsonl_stream(text)
    assert records == [
        {"PID": 4, "Name": "System"},
        {"PID": 364, "Name": "smss"},
    ]


def test_parse_jsonl_stream_skips_malformed_lines() -> None:
    """Malformed lines are tolerated (logged + skipped)."""
    text = b'{"a": 1}\nnot-json\n{"b": 2}\n'
    records = _parse_jsonl_stream(text)
    assert records == [{"a": 1}, {"b": 2}]


def test_parse_jsonl_stream_flattens_array_root() -> None:
    """Single-line array output is flattened into individual records."""
    text = b'[{"a": 1}, {"b": 2}, {"c": 3}]\n'
    records = _parse_jsonl_stream(text)
    assert records == [{"a": 1}, {"b": 2}, {"c": 3}]


def test_parse_jsonl_stream_skips_non_dict_scalars() -> None:
    """Scalar JSON values (numbers, strings, nulls) are dropped — we
    only persist dict records into JSONB."""
    text = b'42\n"string"\nnull\n{"valid": true}\n'
    records = _parse_jsonl_stream(text)
    assert records == [{"valid": True}]


def test_parse_jsonl_stream_handles_empty_stream() -> None:
    """Empty stdout produces empty record list."""
    assert _parse_jsonl_stream(b"") == []
    assert _parse_jsonl_stream(b"\n\n\n") == []


def test_parse_jsonl_stream_respects_hard_cap() -> None:
    """Bounded by :data:`_STDOUT_RECORD_HARD_CAP` to protect memory."""
    # Build a stream JUST past the cap and confirm exactly _STDOUT_RECORD_HARD_CAP
    # records are returned.
    one_line = b'{"x": 1}\n'
    text = one_line * (_STDOUT_RECORD_HARD_CAP + 10)
    records = _parse_jsonl_stream(text)
    assert len(records) == _STDOUT_RECORD_HARD_CAP


# ── stderr tail ─────────────────────────────────────────────────────────────


def test_tail_stderr_returns_last_n_lines() -> None:
    """Last N lines, newline-joined."""
    stderr = b"\n".join(f"line {i}".encode() for i in range(100))
    tail = _tail_stderr(stderr, max_lines=5)
    assert tail == "line 95\nline 96\nline 97\nline 98\nline 99"


def test_tail_stderr_handles_short_stream() -> None:
    """Stream shorter than max_lines returns everything decoded."""
    stderr = b"only line"
    assert _tail_stderr(stderr, max_lines=10) == "only line"


# ── Vol3 availability guard ─────────────────────────────────────────────────


def test_require_vol3_available_raises_when_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """:func:`_require_vol3_available` fails fast when Vol3 isn't installed."""
    monkeypatch.setattr("app.services.vol3_runner._VOL3_INSTALLED", False)
    with pytest.raises(Vol3NotInstalled, match="not installed"):
        _require_vol3_available()


def test_require_vol3_available_raises_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even if the Python package is importable, a missing CLI binary
    blocks invocation with a clear message."""
    monkeypatch.setattr("app.services.vol3_runner._VOL3_INSTALLED", True)
    monkeypatch.setattr(
        "app.services.vol3_runner.VOL3_BIN", "/nonexistent/vol"
    )
    with pytest.raises(Vol3NotInstalled, match="not found"):
        _require_vol3_available()


# ── run_vol3_plugin Rule #29 timeout + Rule #36 image-path-exists check ─────


def test_run_vol3_plugin_raises_not_installed_when_missing() -> None:
    """The public runner refuses to run on a build without Vol3."""
    # _VOL3_INSTALLED is False on the host (INCLUDE_VOL3=0); the guard
    # fires before any subprocess work.
    with pytest.raises(Vol3NotInstalled):
        asyncio.run(run_vol3_plugin("/data/mem.raw", "windows.info"))


def test_run_vol3_plugin_rejects_forbidden_plugin_before_subprocess() -> None:
    """Rule #45 guard fires before any subprocess work."""
    with pytest.raises(Vol3PluginForbidden):
        asyncio.run(run_vol3_plugin("/data/mem.raw", "hashdump"))


def test_run_vol3_plugin_raises_invocation_failed_on_missing_image(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path,
) -> None:
    """Missing image path → Vol3InvocationFailed with the path in the message."""
    # Bypass the Vol3-not-installed guard so we reach the image_path check.
    monkeypatch.setattr("app.services.vol3_runner._VOL3_INSTALLED", True)
    bin_path = tmp_path / "vol"
    bin_path.write_bytes(b"")
    monkeypatch.setattr("app.services.vol3_runner.VOL3_BIN", str(bin_path))

    with pytest.raises(Vol3InvocationFailed, match="image_path does not exist"):
        asyncio.run(run_vol3_plugin("/nonexistent.raw", "windows.info"))


def test_run_vol3_plugin_times_out_and_kills_subprocess(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path,
) -> None:
    """Rule #29 — exceeding the timeout SIGKILLs the subprocess and raises Vol3Timeout."""
    monkeypatch.setattr("app.services.vol3_runner._VOL3_INSTALLED", True)
    bin_path = tmp_path / "vol"
    bin_path.write_bytes(b"#!/bin/sh\nsleep 100\n")
    bin_path.chmod(0o755)
    monkeypatch.setattr("app.services.vol3_runner.VOL3_BIN", str(bin_path))

    image = tmp_path / "fake.raw"
    image.write_bytes(b"\x00" * 16)

    kill_called: dict[str, int] = {"count": 0}

    class _FakeProc:
        returncode = None

        async def communicate(self) -> tuple[bytes, bytes]:
            # Hang indefinitely — wait_for fires TimeoutError.
            await asyncio.sleep(10)
            return (b"", b"")

        def kill(self) -> None:
            kill_called["count"] += 1
            # Pretend the kill is visible to wait().
            self.__class__.returncode = -9

        async def wait(self) -> int:
            return -9

    async def fake_create_subprocess_exec(*args: Any, **kwargs: Any) -> _FakeProc:
        return _FakeProc()

    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )

    with pytest.raises(Vol3Timeout, match="exceeded timeout"):
        asyncio.run(
            run_vol3_plugin(str(image), "windows.info", timeout=0.1)
        )
    assert kill_called["count"] >= 1, (
        "SIGKILL must be issued on Vol3Timeout — orphaned vol processes "
        "would otherwise accumulate on the worker."
    )


def test_run_vol3_plugin_invocation_failed_carries_stderr_tail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path,
) -> None:
    """Non-zero exit raises Vol3InvocationFailed with stderr tail in the message."""
    monkeypatch.setattr("app.services.vol3_runner._VOL3_INSTALLED", True)
    bin_path = tmp_path / "vol"
    bin_path.write_bytes(b"")
    monkeypatch.setattr("app.services.vol3_runner.VOL3_BIN", str(bin_path))

    image = tmp_path / "fake.raw"
    image.write_bytes(b"\x00" * 16)

    class _FakeProc:
        returncode = 2

        async def communicate(self) -> tuple[bytes, bytes]:
            return (b"", b"FATAL: unable to find ISF for kernel banner\n")

        def kill(self) -> None:
            pass

        async def wait(self) -> int:
            return 2

    async def fake_create_subprocess_exec(*args: Any, **kwargs: Any) -> _FakeProc:
        return _FakeProc()

    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )

    with pytest.raises(Vol3InvocationFailed, match="FATAL: unable to find ISF"):
        asyncio.run(run_vol3_plugin(str(image), "windows.info"))


def test_run_vol3_plugin_returns_parsed_records_on_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path,
) -> None:
    """Success path — exit code 0, jsonl output → :class:`Vol3RunResult`."""
    monkeypatch.setattr("app.services.vol3_runner._VOL3_INSTALLED", True)
    bin_path = tmp_path / "vol"
    bin_path.write_bytes(b"")
    monkeypatch.setattr("app.services.vol3_runner.VOL3_BIN", str(bin_path))

    image = tmp_path / "fake.raw"
    image.write_bytes(b"\x00" * 16)

    expected_stdout = (
        b'{"Variable": "Kernel Base", "Value": "0xfffff80000000000"}\n'
        b'{"Variable": "DTB", "Value": "0x1aa000"}\n'
    )

    class _FakeProc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return (expected_stdout, b"")

        def kill(self) -> None:
            pass

        async def wait(self) -> int:
            return 0

    async def fake_create_subprocess_exec(*args: Any, **kwargs: Any) -> _FakeProc:
        return _FakeProc()

    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )

    result = asyncio.run(run_vol3_plugin(str(image), "windows.info"))
    assert isinstance(result, Vol3RunResult)
    assert result.plugin == "windows.info"
    assert result.image_path == str(image)
    assert result.exit_code == 0
    assert result.records == [
        {"Variable": "Kernel Base", "Value": "0xfffff80000000000"},
        {"Variable": "DTB", "Value": "0x1aa000"},
    ]
    assert result.elapsed_s >= 0.0
    assert result.stderr_tail == ""


# ── Module-level configuration sanity ──────────────────────────────────────


def test_default_bin_is_image_shipped_path() -> None:
    """Rule #36 — the default trusted argv[0] is the wairz worker image's
    uv-managed virtualenv path. A regression that moves this elsewhere
    would silently swap in a less-trusted binary."""
    assert VOL3_DEFAULT_BIN == "/app/.venv/bin/vol"


def test_default_symbols_path_is_image_baked() -> None:
    """Rule #37 — symbols come from /opt/wairz/vol3-symbols at build time,
    NOT a network fetch at scan time."""
    # The runtime ENV may override; this asserts the module-level default.
    from app.services.vol3_runner import VOL3_SYMBOLS_PATH as runtime_path
    # Either the default OR an explicitly-set env override is acceptable.
    assert runtime_path  # non-empty
    if "VOL3_SYMBOLS_PATH" not in __import__("os").environ:
        assert runtime_path == "/opt/wairz/vol3-symbols"


def test_plugin_timeout_matches_rule_29_ceiling() -> None:
    """Rule #29 — the runner's timeout matches mobsfscan's 600 s synchronous
    ceiling. A regression that lowers this would prematurely fail
    long-running plugins (unhooked_system_calls, poolscanner)."""
    assert VOL3_PLUGIN_TIMEOUT_SECONDS == 600


# ── Rule #36 + Rule #45 source-scan gate over vol3_runner.py ────────────────


def _strip_docstrings_and_comments(source: str) -> str:
    """Strip docstrings, ``#`` comments, and string literals from Python
    source so the gate scans only CODE tokens.

    Returns the surviving tokens joined with single spaces — which is
    what the gate's whitespace-tolerant regexes are calibrated against
    (per κ.D's tokenize-whitespace canary).
    """
    out_tokens: list[str] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenizeError:
        return source

    for tok in tokens:
        if tok.type == tokenize.STRING:
            continue
        if tok.type == tokenize.COMMENT:
            continue
        out_tokens.append(tok.string)
    return " ".join(out_tokens)


# Synthetic-violation sentinel for the Rule #46 canary. The string never
# appears unwrapped in vol3_runner.py code. The canary test injects this
# into a synthesized source and confirms the gate's regex catches it.
_FORBIDDEN_CANARY = "decrypt"


# Forbidden-token list — calibrated against the OUTPUT of
# :func:`_strip_docstrings_and_comments`, which space-joins tokens.
# Patterns must be whitespace-tolerant where tokens are adjacent in source.
_FORBIDDEN_SPAWN_TOKENS: tuple[str, ...] = (
    # Rule #36 — spawning attacker-controlled bytes. The runner DOES use
    # ``asyncio.create_subprocess_exec``, but argv[0] is HARD-PINNED to
    # the trusted ``/app/.venv/bin/vol`` and the image is a DATA argument.
    # We DON'T scan for create_subprocess_exec here because the runner's
    # legitimate use of it is the whole point of this module — the gate
    # below only checks for OTHER spawn primitives (shell, system, etc.)
    # that would indicate accidental injection.
    r"asyncio\s*\.\s*create_subprocess_shell\s*\(",
    r"os\s*\.\s*system\s*\(",
    r"os\s*\.\s*execvp\s*\(",
    r"os\s*\.\s*execve\s*\(",
    r"os\s*\.\s*spawnvp\s*\(",
    r"\brunpy\s*\.\s*run_path\b",
    r"\beval\s*\(",
)

_FORBIDDEN_DECRYPT_TOKENS: tuple[str, ...] = (
    # Rule #45 — no decryption invocation. The runner is plugin-agnostic
    # but the deny-list guards credential-extraction plugins; we want a
    # belt-and-suspenders source-level check that no decrypt CODE exists
    # in the runner itself.
    r"\.\s*decrypt\s*\(",
    r"\bCryptUnprotectData\b",
    r"\bCryptProtectData\b",
    r"from\s+cryptography\s*\.\s*fernet",
    r"cryptography\s*\.\s*fernet\s*\.",
    r"\bpyDes\b",
    r"from\s+Crypto\s*\.\s*Cipher",
    r"Crypto\s*\.\s*Cipher\s*\.",
)


def _runner_source() -> str:
    return (
        pathlib.Path(__file__).parent.parent
        / "app"
        / "services"
        / "vol3_runner.py"
    ).read_text()


def test_runner_no_forbidden_spawn_primitives() -> None:
    """Rule #36 — vol3_runner.py CODE (not docstrings/comments) MUST NOT
    invoke shell, system, exec, eval, or other spawn primitives outside
    the controlled ``asyncio.create_subprocess_exec`` path.
    """
    source = _strip_docstrings_and_comments(_runner_source())
    for pattern in _FORBIDDEN_SPAWN_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #36 violation in vol3_runner.py — found {matches} "
            f"matching {pattern!r}; runner CODE must only invoke vol "
            "via asyncio.create_subprocess_exec with a pinned argv[0]."
        )


def test_runner_no_decrypt_invocation() -> None:
    """Rule #45 — vol3_runner.py CODE must contain no decryption tokens.

    The deny-list rejects credential plugins by name; this gate ensures
    no decrypt invocation slipped in at the CODE level (e.g. a future
    refactor that tried to inline-decrypt blobs from a plugin's output).
    """
    source = _strip_docstrings_and_comments(_runner_source())
    for pattern in _FORBIDDEN_DECRYPT_TOKENS:
        matches = re.findall(pattern, source)
        assert not matches, (
            f"Rule #45 violation in vol3_runner.py — found {matches} "
            f"matching {pattern!r}; runner CODE must NEVER decrypt."
        )


def test_runner_source_scan_gate_canary_fires() -> None:
    """Rule #46 — confirm the source-scan gate actually fires on a synthetic violation.

    Without this canary, the ``test_runner_no_decrypt_invocation`` and
    ``test_runner_no_forbidden_spawn_primitives`` tests could silently
    pass on real violations if the regex was miscalibrated or the
    tokenize stripping was overzealous. The synthetic source is
    constructed via CONCATENATION (not an f-string) so the forbidden
    token is real CODE — not a string literal that
    ``_strip_docstrings_and_comments`` would drop entirely.
    """
    line_a = "def bad_runner():\n"
    line_b = "    obj = SomeClass()\n"
    # The CODE token below — ``obj.decrypt(b"x")`` — survives stripping
    # because ``obj`` / ``.`` / ``decrypt`` / ``(`` are NAME/OP tokens,
    # not strings.
    line_c = "    obj." + _FORBIDDEN_CANARY + '(b"x")\n'
    line_d = "    return None\n"
    synthetic_source = line_a + line_b + line_c + line_d

    stripped = _strip_docstrings_and_comments(synthetic_source)

    # The gate scans for ``\.\s*decrypt\s*\(`` (whitespace-tolerant per
    # κ.D's tokenize-whitespace fix). Verify it matches the synthetic.
    pattern = r"\.\s*decrypt\s*\("
    matches = re.findall(pattern, stripped)
    assert matches, (
        f"Rule #46 canary FAILED — the synthetic violation "
        f"'{_FORBIDDEN_CANARY}' did NOT trigger the source-scan regex "
        f"{pattern!r}. stripped={stripped!r}. The gate is broken or "
        "miscalibrated. Without a working canary, "
        "test_runner_no_decrypt_invocation could silently pass on real "
        "violations."
    )
    # And confirm the exact regex from _FORBIDDEN_DECRYPT_TOKENS[0] also
    # matches the canary — this is what the production gate uses.
    assert re.findall(_FORBIDDEN_DECRYPT_TOKENS[0], stripped), (
        "Rule #46 canary FAILED — the first forbidden-token regex must "
        "match the synthetic violation."
    )


def test_runner_source_scan_gate_excludes_docstring_mentions() -> None:
    """Sanity — docstrings mentioning forbidden tokens DO NOT cause the
    gate to fire (false-positive guard for Rule #46).

    The runner's docstrings legitimately mention ``decrypt`` /
    ``Hashdump`` / ``Lsadump`` as part of the Rule #45 documentation.
    Tokenize-based stripping must drop these before the regex scan.
    """
    synthetic_docstring_source = '''
def safe_runner():
    """This module NEVER invokes CryptUnprotectData and NEVER tries to
    decrypt anything — Rule #45 PARSE-ONLY discipline."""
    return None
'''
    stripped = _strip_docstrings_and_comments(synthetic_docstring_source)
    pattern = r"\bCryptUnprotectData\b"
    matches = re.findall(pattern, stripped)
    assert not matches, (
        "Rule #46 false-positive guard FAILED — a docstring mention of "
        "'CryptUnprotectData' survived stripping. The gate would "
        "false-positive on legitimate documentation."
    )


# ── Argv discipline: regression — no shell-execution opportunity ────────────


def test_argv_passes_image_path_as_data_argument_only() -> None:
    """Rule #36 — image_path must ONLY appear in argv as the operand of ``-f``.

    A regression that made image_path argv[0] (or any non-``-f`` slot)
    would let an attacker-controlled path become the spawned binary.
    This test enumerates the argv slots and asserts the image_path is
    only ever in the slot directly after ``-f``.
    """
    image_path = "/data/attacker-controlled/path with $vars/file.raw"
    # Even though the path contains shell-metachars, the argv builder
    # treats it as DATA — exec doesn't go through a shell.
    argv = build_vol3_argv(
        image_path,
        "windows.info",
        tmp_dir="/tmp/vol3-test",
        bin_path="/app/.venv/bin/vol",
    )
    # The image_path appears EXACTLY once, immediately after ``-f``.
    f_index = argv.index("-f")
    assert argv[f_index + 1] == image_path
    # And nowhere else in the argv.
    occurrences = [i for i, a in enumerate(argv) if a == image_path]
    assert occurrences == [f_index + 1], (
        f"image_path appeared at unexpected positions in argv: "
        f"{occurrences} (expected exactly one, right after -f at "
        f"index {f_index})"
    )


# ── Unused-import suppression for `patch` ───────────────────────────────────
# ``patch`` is imported for future use by walker tests that mock the runner
# directly; the current test file uses monkeypatch consistently. Reference
# it here to keep ruff F401 happy.
_ = patch
