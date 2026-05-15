"""Unit + regression backstops for the hardware-firmware detector's
NUL-byte sanitizers.

Surfaced on the DS1 Moto-G32 firmware (2026-05-14) — the bulk-insert
of 313 detected blobs failed with::

    sqlalchemy.exc.DBAPIError: ...CharacterNotInRepertoireError:
        invalid byte sequence for encoding "UTF8": 0x00

Root cause: ELF / PE parsers (LIEF, pyelftools, pefile) sometimes
return strings extracted from raw binary segments that contain
embedded NUL bytes. PostgreSQL TEXT / VARCHAR / JSONB reject these.

Fix: ``_sanitize_text`` and ``_sanitize_jsonb`` strip NUL bytes (and
C0 control chars except tab/LF/CR) at the boundary before the bulk
insert. These tests pin the boundary behavior.
"""
from __future__ import annotations

import pytest

from app.services.hardware_firmware.detector import (
    _sanitize_jsonb,
    _sanitize_text,
)

# ── _sanitize_text ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,max_len,expected",
    [
        # Happy path — no NULs, no clipping needed.
        ("hello", 1024, "hello"),
        ("foo", None, "foo"),

        # NUL byte gets stripped.
        ("foo\x00bar", None, "foobar"),
        ("\x00\x00abc\x00def\x00", None, "abcdef"),

        # Other C0 control chars stripped, except tab/LF/CR which are kept.
        ("abc\x01def", None, "abcdef"),
        ("line1\nline2", None, "line1\nline2"),
        ("tab\there", None, "tab\there"),
        ("cr\rhere", None, "cr\rhere"),

        # Length clipping after sanitization.
        ("a" * 100 + "\x00" + "b" * 100, 50, ("a" * 50)),
        ("a\x00b\x00c", 2, "ab"),

        # None pass-through.
        (None, None, None),
        (None, 1024, None),

        # Non-str gets coerced.
        (42, None, "42"),
        (b"bytes-shape", None, "b'bytes-shape'"),

        # Empty / all-NUL strings become None (Rule #35c-style: "empty after
        # sanitization is semantically empty — let the column be NULL").
        ("", None, None),
        ("\x00\x00\x00", None, None),
    ],
)
def test_sanitize_text(raw, max_len, expected):
    """Sanitizer strips NULs + control chars + clips length."""
    assert _sanitize_text(raw, max_len) == expected


def test_sanitize_text_long_input_clipped_after_nul_strip():
    """When max_len is set, the slice happens AFTER NUL stripping so the
    operator gets at least max_len real chars (not pre-strip noise)."""
    raw = "\x00" * 50 + "a" * 100  # 50 NULs + 100 'a' chars
    result = _sanitize_text(raw, 100)
    assert result == "a" * 100, f"Expected 100 'a' chars; got {result!r}"


# ── _sanitize_jsonb ──────────────────────────────────────────────────────────


def test_sanitize_jsonb_scalar_string_nul_strip():
    assert _sanitize_jsonb("foo\x00bar") == "foobar"
    assert _sanitize_jsonb("\x00abc") == "abc"
    assert _sanitize_jsonb("no_nul") == "no_nul"


def test_sanitize_jsonb_none_passthrough():
    assert _sanitize_jsonb(None) is None


def test_sanitize_jsonb_non_string_scalars_passthrough():
    """ints, floats, bools, etc. flow through unchanged — they can't carry NULs."""
    assert _sanitize_jsonb(42) == 42
    assert _sanitize_jsonb(3.14) == 3.14
    assert _sanitize_jsonb(True) is True
    assert _sanitize_jsonb(False) is False


def test_sanitize_jsonb_dict_recurses():
    raw = {
        "schema_version": 1,
        "cert_subject": "CN=foo\x00bar",
        "imphash": "abc123",
        "nested": {"key\x00with_nul": "value\x00with_nul"},
    }
    cleaned = _sanitize_jsonb(raw)
    assert cleaned["schema_version"] == 1
    assert cleaned["cert_subject"] == "CN=foobar"
    assert cleaned["imphash"] == "abc123"
    assert cleaned["nested"]["key\x00with_nul"] == "valuewith_nul"
    # NOTE — dict KEYS aren't sanitized (Postgres JSONB does allow NULs
    # in object keys via escape sequences). If a future regression
    # surfaces from a NUL-keyed dict, extend this test to confirm.


def test_sanitize_jsonb_list_recurses():
    raw = ["clean", "with\x00nul", {"k": "v\x00x"}, None, 42]
    cleaned = _sanitize_jsonb(raw)
    assert cleaned == ["clean", "withnul", {"k": "vx"}, None, 42]


def test_sanitize_jsonb_preserves_structure():
    """The shape (dict / list / scalars) of the input is preserved end-to-end."""
    raw = {"a": [1, "two\x00", {"b": "three\x00\x00"}]}
    cleaned = _sanitize_jsonb(raw)
    assert cleaned == {"a": [1, "two", {"b": "three"}]}
    assert isinstance(cleaned["a"], list)
    assert isinstance(cleaned["a"][2], dict)


def test_sanitize_jsonb_unknown_types_passthrough():
    """Tuples / sets / custom classes pass through unchanged — JSONB
    encoding will reject them elsewhere if it can't serialize."""
    class _Sentinel:
        pass

    sentinel = _Sentinel()
    # Tuples should pass through (json.dumps will convert to list).
    assert _sanitize_jsonb((1, 2, 3)) == (1, 2, 3)
    # Custom objects pass through unchanged.
    assert _sanitize_jsonb(sentinel) is sentinel
