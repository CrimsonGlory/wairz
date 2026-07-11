"""Unit tests for ``app.utils.log_sanitize.sanitize_for_log``."""

from __future__ import annotations

from app.utils.log_sanitize import sanitize_for_log


def test_strips_newlines_and_cr() -> None:
    assert sanitize_for_log("a\nb\rc") == "a\\nb\\rc"


def test_strips_control_chars() -> None:
    out = sanitize_for_log("x\x00y\x1bz")
    assert "\x00" not in out
    assert "\x1b" not in out
    assert out.startswith("x")


def test_truncates_long_values() -> None:
    out = sanitize_for_log("A" * 1000, max_len=50)
    assert len(out) == 53  # 50 + "..."
    assert out.endswith("...")


def test_accepts_non_str() -> None:
    assert sanitize_for_log(42) == "42"


def test_idempotent_on_clean_uuid() -> None:
    uid = "6f8f9cc2-1234-5678-9abc-def012345678"
    assert sanitize_for_log(uid) == uid
