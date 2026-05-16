"""Tests for the generic MtimeCachedYamlLoader hot-reload contract +
its five concrete applications across patterns_loader.py +
cve_matcher.py.

The contract has four invariants the user prompt (2026-05-18) called
out explicitly:

  1. Hot-reload picks up new entries within ONE accessor call after the
     YAML's stat().st_mtime_ns changes.
  2. Unchanged mtime → cached path; second call does NOT re-parse
     (verified via the loader's ``reload_count`` instrumentation).
  3. Malformed reload → keeps the PREVIOUS valid state + emits a WARN
     log (does NOT regress to defaults).
  4. Thread-safety: concurrent accessors during a reload either see the
     full previous state or the full new state, never a torn partial.

Plus an adaptability invariant from the multi-persona review concern
("don't hard-code strict formats"):

  5. The loader handles missing files (FileNotFoundError), file
     deletion AFTER successful load (vanish-while-running), and an empty
     YAML doc (``---``) without crashing.
"""

from __future__ import annotations

import os
import textwrap
import threading
import time
from pathlib import Path

import pytest

from app.utils import yaml_cache as YC
from app.services.hardware_firmware import cve_matcher as CM
from app.services.hardware_firmware import patterns_loader as PL


# ---------------------------------------------------------------------------
# A tiny self-contained loader for the generic-contract tests so they
# don't carry parser-shape baggage from the five concrete YAMLs.
# ---------------------------------------------------------------------------


def _identity_parser(raw: dict) -> dict:
    """Parser that returns the YAML dict unchanged.

    Used by the generic tests so we exercise the cache logic, not any
    specific schema validation.
    """
    return dict(raw)


def _identity_summary(value: dict) -> str:
    return f"{len(value)} keys"


@pytest.fixture
def generic_loader(tmp_path: Path) -> YC.MtimeCachedYamlLoader[dict]:
    """A fresh loader bound to a tmp YAML path with identity parser."""
    yaml_path = tmp_path / "loader_test.yaml"
    yaml_path.write_text("foo: 1\nbar: 2\n", encoding="utf-8")
    loader: YC.MtimeCachedYamlLoader[dict] = YC.MtimeCachedYamlLoader(
        path=yaml_path,
        parser=_identity_parser,
        defaults={"_default": True},
        name="test-loader",
        summary=_identity_summary,
    )
    return loader


def _bump_mtime(path: Path) -> None:
    """Advance st_mtime_ns past the cache's recorded value.

    pathlib's `.touch()` uses millisecond-resolution on some filesystems;
    explicitly call os.utime with a +1-second future timestamp so the
    bump is unambiguous across ext4 / btrfs / tmpfs / docker overlay.
    """
    now = time.time()
    os.utime(path, (now + 1.0, now + 1.0))


# ---------------------------------------------------------------------------
# Invariant 1 — hot-reload within one accessor call.
# ---------------------------------------------------------------------------


def test_hot_reload_picks_up_new_entries_within_one_get_call(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
) -> None:
    """After the YAML's mtime changes, the very next .get() call must
    return the new contents."""
    initial = generic_loader.get()
    assert initial == {"foo": 1, "bar": 2}

    generic_loader.path.write_text("foo: 1\nbar: 2\nbaz: 3\n", encoding="utf-8")
    _bump_mtime(generic_loader.path)

    after = generic_loader.get()
    assert after == {"foo": 1, "bar": 2, "baz": 3}
    assert generic_loader.reload_count == 2  # initial + after-bump


# ---------------------------------------------------------------------------
# Invariant 2 — mtime unchanged → cached path (no re-parse).
# ---------------------------------------------------------------------------


def test_unchanged_mtime_returns_cached_without_re_parse(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
) -> None:
    """A second .get() against an unchanged file must hit the cached
    branch — verified via reload_count instrumentation."""
    first = generic_loader.get()
    reload_after_first = generic_loader.reload_count

    second = generic_loader.get()
    assert second is first  # same cached object
    assert generic_loader.reload_count == reload_after_first
    # stat_count increments on every call (we always stat to check mtime).
    assert generic_loader.stat_count >= 2


def test_repeated_get_does_not_re_parse_when_file_static(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
) -> None:
    """100 .get() calls against a static file produce exactly 1 reload."""
    for _ in range(100):
        generic_loader.get()
    assert generic_loader.reload_count == 1
    assert generic_loader.stat_count == 100


# ---------------------------------------------------------------------------
# Invariant 3 — malformed reload keeps PREVIOUS valid state + WARN log.
# ---------------------------------------------------------------------------


def test_malformed_reload_keeps_previous_valid_state(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A YAML syntax error on reload must NOT regress to defaults — the
    last good state stays cached and a WARN log surfaces the failure."""
    good = generic_loader.get()
    assert good == {"foo": 1, "bar": 2}

    # Write a YAML syntax error.
    generic_loader.path.write_text(
        "foo: 1\n  bar: [unclosed\n", encoding="utf-8"
    )
    _bump_mtime(generic_loader.path)

    with caplog.at_level("WARNING", logger="app.utils.yaml_cache"):
        after = generic_loader.get()
    assert after == {"foo": 1, "bar": 2}, (
        "malformed reload should keep previous state, NOT regress to defaults"
    )
    # WARN log surfaced the failure.
    warn_messages = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert any(
        "failed to read/parse" in m or "structural validation failed" in m
        for m in warn_messages
    ), f"expected a WARN log; got: {warn_messages}"


def test_structural_validation_failure_keeps_previous_state(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A parser that raises on the second load must trigger keep-previous,
    not silent regression to defaults."""
    yaml_path = tmp_path / "strict.yaml"
    yaml_path.write_text("count: 5\n", encoding="utf-8")

    call_count = {"n": 0}

    def _strict_parser(raw: dict) -> int:
        call_count["n"] += 1
        c = raw.get("count")
        if not isinstance(c, int):
            raise ValueError(f"count must be int; got {type(c).__name__}")
        return c

    loader: YC.MtimeCachedYamlLoader[int] = YC.MtimeCachedYamlLoader(
        path=yaml_path,
        parser=_strict_parser,
        defaults=-1,
        name="strict-test",
        summary=lambda v: f"count={v}",
    )

    first = loader.get()
    assert first == 5

    # Trigger structural validation failure.
    yaml_path.write_text("count: not-an-int\n", encoding="utf-8")
    _bump_mtime(yaml_path)

    with caplog.at_level("WARNING", logger="app.utils.yaml_cache"):
        second = loader.get()
    assert second == 5, "structural failure should keep previous state, not regress to defaults"
    assert any(
        "structural validation failed" in r.message
        for r in caplog.records if r.levelname == "WARNING"
    )

    # A subsequent valid reload should succeed and update state.
    yaml_path.write_text("count: 9\n", encoding="utf-8")
    _bump_mtime(yaml_path)
    third = loader.get()
    assert third == 9


def test_malformed_mtime_advanced_so_no_retry_storm(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
) -> None:
    """After a failed reload, subsequent .get()s should NOT re-attempt
    parsing on every call — the mtime cursor is advanced so retries
    only happen when the operator saves the file again."""
    generic_loader.get()
    initial_reload = generic_loader.reload_count

    generic_loader.path.write_text("bad: [unclosed\n", encoding="utf-8")
    _bump_mtime(generic_loader.path)
    generic_loader.get()  # one failed reload attempt
    after_fail = generic_loader.reload_count
    assert after_fail == initial_reload  # no successful reload happened

    # 50 subsequent calls against the still-broken file should NOT
    # re-attempt parsing — the mtime cursor was advanced.
    for _ in range(50):
        generic_loader.get()
    assert generic_loader.reload_count == after_fail


# ---------------------------------------------------------------------------
# last_warning observability surface — operator-queryable via MCP.
#
# Paired-canary discipline per Rule #46: every "asserts ABSENCE of X"
# gate ships with a paired canary that synthesizes a violation and
# confirms the gate fires. Here the gate IS the absence-on-success
# behaviour — `assert last_warning is None` after a clean load — and
# the canary IS the populated-on-malformed test which proves the
# absence-assertion would catch a real malformed-YAML regression.
# ---------------------------------------------------------------------------


def test_last_warning_is_none_initially(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
) -> None:
    """A freshly-constructed loader with valid YAML has last_warning=None."""
    assert generic_loader.last_warning is None
    generic_loader.get()
    assert generic_loader.last_warning is None


def test_last_warning_populated_on_malformed_yaml(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
) -> None:
    """CANARY — malformed YAML on reload populates last_warning with a
    string containing the exception type name.

    Pairs with test_last_warning_is_none_initially: this canary proves
    that the "None after success" assertion in other tests would catch
    a regression where last_warning failed to clear on the success path.
    """
    generic_loader.get()
    assert generic_loader.last_warning is None

    # Synthesize a malformed YAML reload.
    generic_loader.path.write_text("bad: [unclosed\n", encoding="utf-8")
    _bump_mtime(generic_loader.path)
    result = generic_loader.get()

    # Previous-state contract still holds — kept the old dict.
    assert result == {"foo": 1, "bar": 2}
    # AND last_warning is now populated with a one-line "<Type>: <msg>".
    assert generic_loader.last_warning is not None
    assert isinstance(generic_loader.last_warning, str)
    # YAMLError surfaces as some subclass-name (ScannerError / ParserError);
    # accept any yaml.*Error class name so we're robust to libyaml vs
    # pure-python YAML lib differences across Python versions.
    assert "Error" in generic_loader.last_warning


def test_last_warning_cleared_on_successful_reload(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
) -> None:
    """After a malformed reload sets last_warning, a subsequent
    successful reload (operator fixes the YAML) clears it back to None."""
    # Start with a clean load.
    generic_loader.get()
    assert generic_loader.last_warning is None

    # Break the YAML.
    generic_loader.path.write_text("bad: [unclosed\n", encoding="utf-8")
    _bump_mtime(generic_loader.path)
    generic_loader.get()
    assert generic_loader.last_warning is not None
    failed_reload_count = generic_loader.reload_count

    # Fix the YAML.
    generic_loader.path.write_text("foo: 1\nbar: 2\nbaz: 3\n", encoding="utf-8")
    _bump_mtime(generic_loader.path)
    result = generic_loader.get()

    assert result == {"foo": 1, "bar": 2, "baz": 3}
    assert generic_loader.last_warning is None
    assert generic_loader.reload_count == failed_reload_count + 1


def test_last_warning_populated_on_structural_validation_failure(
    tmp_path: Path,
) -> None:
    """Structural validation failure (parser raises) also populates
    last_warning — separate path from the YAML-parse failure."""
    yaml_path = tmp_path / "loader_test.yaml"
    yaml_path.write_text("foo: 1\n", encoding="utf-8")

    def _strict_parser(raw: dict) -> dict:
        if "required_key" not in raw:
            raise ValueError("required_key absent")
        return dict(raw)

    loader: YC.MtimeCachedYamlLoader[dict] = YC.MtimeCachedYamlLoader(
        path=yaml_path,
        parser=_strict_parser,
        defaults={"_default": True},
        name="strict-test-loader",
        summary=lambda v: f"{len(v)} keys",
    )

    # First call falls back to defaults because the strict parser
    # rejects the YAML's shape — last_warning populated with the
    # ValueError message.
    result = loader.get()
    assert result == {"_default": True}
    assert loader.last_warning is not None
    assert "ValueError" in loader.last_warning
    assert "required_key" in loader.last_warning


def test_last_warning_cleared_by_cache_clear(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
) -> None:
    """cache_clear() resets last_warning to None (pytest-friendly reset)."""
    generic_loader.path.write_text("bad: [unclosed\n", encoding="utf-8")
    _bump_mtime(generic_loader.path)
    generic_loader.get()
    assert generic_loader.last_warning is not None

    generic_loader.cache_clear()
    assert generic_loader.last_warning is None


# ---------------------------------------------------------------------------
# YAML loader registry — operator-queryable MCP surface.
# ---------------------------------------------------------------------------


def test_register_loader_makes_loader_discoverable(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
) -> None:
    """register_loader() adds the loader to the registry under its name;
    list_registered_loaders() returns a dict-snapshot containing it."""
    surface_name = "test-registry-surface-canary"
    # Defensive — clean any prior test residue (registry is module-level).
    YC._yaml_loader_registry.pop(surface_name, None)
    assert surface_name not in YC.list_registered_loaders()

    YC.register_loader(surface_name, generic_loader)
    snap = YC.list_registered_loaders()
    assert surface_name in snap
    assert snap[surface_name] is generic_loader

    # Cleanup — registry is module-level so we don't leak into other tests.
    YC._yaml_loader_registry.pop(surface_name, None)


def test_list_registered_loaders_excludes_unregistered(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
) -> None:
    """NEGATIVE CANARY — a loader created but never registered does NOT
    appear in list_registered_loaders(). Confirms the registry isn't
    discovering loaders via some unintended mechanism (e.g. instance
    tracking via __init_subclass__)."""
    surface_name = "test-registry-negative-canary"
    YC._yaml_loader_registry.pop(surface_name, None)
    # generic_loader exists but was never registered under this name.
    snap = YC.list_registered_loaders()
    assert surface_name not in snap


def test_register_loader_is_idempotent(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
    tmp_path: Path,
) -> None:
    """Re-registering the same surface_name replaces the prior reference
    (pytest-safe under module reload)."""
    surface_name = "test-registry-idempotent-canary"
    YC._yaml_loader_registry.pop(surface_name, None)
    YC.register_loader(surface_name, generic_loader)

    other_yaml = tmp_path / "other.yaml"
    other_yaml.write_text("x: 1\n", encoding="utf-8")
    other_loader: YC.MtimeCachedYamlLoader[dict] = YC.MtimeCachedYamlLoader(
        path=other_yaml,
        parser=lambda raw: dict(raw),
        defaults={},
        name="other-test-loader",
        summary=lambda v: f"{len(v)} keys",
    )
    YC.register_loader(surface_name, other_loader)

    snap = YC.list_registered_loaders()
    assert snap[surface_name] is other_loader
    assert snap[surface_name] is not generic_loader

    YC._yaml_loader_registry.pop(surface_name, None)


# ---------------------------------------------------------------------------
# Invariant 4 — thread-safety: concurrent accessors don't see torn state.
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` via tmp-then-rename atomic swap.

    Matches real-operator editor behaviour (vim's default writeback). A
    non-atomic write_text() briefly leaves the file empty after
    truncate-before-write — that's an EDITOR concern, not a loader
    contract violation. The loader's job is to never tear when reading;
    the writer's job is to never leave a partial file visible.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def test_concurrent_accessors_dont_see_torn_state(tmp_path: Path) -> None:
    """N threads hammer .get() while a writer thread bumps the YAML.

    The contract: every returned dict is either the FULL previous state
    or the FULL new state — never a mix. The dict must always have
    EITHER {a:1,b:2} OR {a:1,b:2,c:3} as its complete contents (the
    test parser fills out both deterministically — no partial dicts).

    Writer uses atomic rename (matches vim/editor behaviour). A
    non-atomic truncate-then-write briefly leaves an empty file on
    disk; that's an EDITOR concern, not a loader thread-safety bug.
    """
    yaml_path = tmp_path / "concurrent.yaml"
    _atomic_write(yaml_path, "a: 1\nb: 2\n")

    loader: YC.MtimeCachedYamlLoader[dict] = YC.MtimeCachedYamlLoader(
        path=yaml_path,
        parser=_identity_parser,
        defaults={},
        name="concurrent-test",
        summary=_identity_summary,
    )

    # Prime the cache.
    initial = loader.get()
    assert initial == {"a": 1, "b": 2}

    valid_observed: list[dict] = []
    torn_observed: list[dict] = []
    errors: list[Exception] = []
    stop = threading.Event()

    def _reader() -> None:
        while not stop.is_set():
            try:
                snap = loader.get()
                # Acceptable shapes:
                if snap == {"a": 1, "b": 2} or snap == {"a": 1, "b": 2, "c": 3}:
                    valid_observed.append(snap)
                else:
                    torn_observed.append(snap)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    def _writer() -> None:
        # Cycle the YAML state several times via atomic rename.
        for i in range(5):
            time.sleep(0.01)
            _atomic_write(yaml_path, "a: 1\nb: 2\nc: 3\n")
            _bump_mtime(yaml_path)
            time.sleep(0.01)
            _atomic_write(yaml_path, "a: 1\nb: 2\n")
            _bump_mtime(yaml_path)

    readers = [threading.Thread(target=_reader) for _ in range(8)]
    writer = threading.Thread(target=_writer)
    for t in readers:
        t.start()
    writer.start()
    writer.join()
    stop.set()
    for t in readers:
        t.join()

    assert not errors, f"reader threads raised: {errors[:3]}"
    assert torn_observed == [], (
        f"observed torn snapshots — concurrent accessor read a "
        f"partial state during reload: {torn_observed[:3]}"
    )
    assert valid_observed, "no reads observed — readers didn't run"


def test_loader_keeps_previous_state_during_non_atomic_writer_window(
    tmp_path: Path,
) -> None:
    """When an operator uses a non-atomic editor (truncate-then-write),
    the loader must NOT crash and must keep emitting a usable state.

    An empty file IS a structurally valid YAML doc (parses to {}); the
    loader's contract is to keep emitting THAT (or the previous state
    if the parser rejects empty), never to raise or hang.
    """
    yaml_path = tmp_path / "non_atomic.yaml"
    yaml_path.write_text("a: 1\nb: 2\n", encoding="utf-8")

    def _strict_parser(raw: dict) -> dict:
        if not raw:
            raise ValueError("empty doc not accepted")
        return dict(raw)

    loader: YC.MtimeCachedYamlLoader[dict] = YC.MtimeCachedYamlLoader(
        path=yaml_path,
        parser=_strict_parser,
        defaults={},
        name="non-atomic-test",
        summary=_identity_summary,
    )
    assert loader.get() == {"a": 1, "b": 2}

    # Simulate non-atomic writer: truncate, then later write content.
    # Between the two operations, the file is empty — loader must keep
    # previous state via the structural-validation-fails-keep-previous
    # path.
    yaml_path.write_text("", encoding="utf-8")
    _bump_mtime(yaml_path)
    after_truncate = loader.get()
    assert after_truncate == {"a": 1, "b": 2}, (
        "empty file should keep previous valid state (parser rejects empty)"
    )

    # Writer finishes the write.
    yaml_path.write_text("a: 1\nb: 2\nc: 3\n", encoding="utf-8")
    _bump_mtime(yaml_path)
    after_finish = loader.get()
    assert after_finish == {"a": 1, "b": 2, "c": 3}


# ---------------------------------------------------------------------------
# Invariant 5 — adaptability: missing file, vanish-after-load, empty doc.
# ---------------------------------------------------------------------------


def test_missing_file_returns_defaults_first_time(tmp_path: Path) -> None:
    """A loader against a non-existent path should return defaults +
    log INFO once (not WARN — missing-on-first-call is graceful)."""
    nonexistent = tmp_path / "never_existed.yaml"
    loader: YC.MtimeCachedYamlLoader[dict] = YC.MtimeCachedYamlLoader(
        path=nonexistent,
        parser=_identity_parser,
        defaults={"_default": True},
        name="missing-test",
        summary=_identity_summary,
    )
    assert loader.get() == {"_default": True}
    # Calling repeatedly is safe and stays on defaults.
    for _ in range(5):
        assert loader.get() == {"_default": True}


def test_file_vanish_after_successful_load_keeps_previous_state(
    generic_loader: YC.MtimeCachedYamlLoader[dict],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A successful load followed by file deletion should KEEP the
    previously loaded state (not regress to defaults) and WARN.

    This is the "operator deleted their YAML; don't silently lose
    all the entries they had loaded" graceful-degrade guarantee.
    """
    loaded = generic_loader.get()
    assert loaded == {"foo": 1, "bar": 2}

    generic_loader.path.unlink()

    with caplog.at_level("WARNING", logger="app.utils.yaml_cache"):
        after = generic_loader.get()
    assert after == {"foo": 1, "bar": 2}, (
        "file vanish should keep previously loaded state"
    )
    assert any(
        "vanished after a successful load" in r.message
        for r in caplog.records if r.levelname == "WARNING"
    )


def test_empty_yaml_doc_does_not_crash(tmp_path: Path) -> None:
    """An empty YAML doc (``---`` or just whitespace) must parse to {}
    and not raise — the parser receives an empty dict."""
    yaml_path = tmp_path / "empty.yaml"
    yaml_path.write_text("---\n", encoding="utf-8")

    loader: YC.MtimeCachedYamlLoader[dict] = YC.MtimeCachedYamlLoader(
        path=yaml_path,
        parser=_identity_parser,
        defaults={"_default": True},
        name="empty-test",
        summary=_identity_summary,
    )
    result = loader.get()
    # Empty doc parses to None → loader normalises to {} → parser
    # returns {} unchanged.
    assert result == {}


def test_path_resolver_callable_supports_test_monkeypatch(tmp_path: Path) -> None:
    """A loader configured with a callable path-resolver should pick up
    path changes on the next get() — the contract that lets existing
    test fixtures monkeypatch ``PL._BT_QCA_CODENAMES_YAML`` keep
    working."""
    path_a = tmp_path / "a.yaml"
    path_b = tmp_path / "b.yaml"
    path_a.write_text("which: a\n", encoding="utf-8")
    path_b.write_text("which: b\n", encoding="utf-8")

    current = {"path": path_a}
    loader: YC.MtimeCachedYamlLoader[dict] = YC.MtimeCachedYamlLoader(
        path=lambda: current["path"],
        parser=_identity_parser,
        defaults={},
        name="resolver-test",
        summary=_identity_summary,
    )
    assert loader.get() == {"which": "a"}

    current["path"] = path_b
    assert loader.get() == {"which": "b"}


# ---------------------------------------------------------------------------
# End-to-end: each of the five concrete YAML surfaces hot-reloads.
# These are smaller integration tests — they verify the loader is wired
# correctly to each accessor, not that the parsers themselves are right
# (those have their own test suites: test_bt_qca_codenames_loader.py
# + test_bt_banner_cve_pins_loader.py + test_hardware_firmware_classifier_patterns.py
# + test_hardware_firmware_cve_matcher.py).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_all_caches() -> None:
    """Clear every patterns_loader + cve_matcher cache around each test."""
    PL.clear_all_caches()
    CM._KNOWN_FIRMWARE_LOADER.cache_clear()
    yield
    PL.clear_all_caches()
    CM._KNOWN_FIRMWARE_LOADER.cache_clear()


def test_bt_qca_codenames_yaml_hot_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Editing bt_qca_codenames.yaml lands within one get_qca_codename_map() call."""
    yaml_path = tmp_path / "bt_qca_codenames.yaml"
    yaml_path.write_text(
        textwrap.dedent(
            """\
            codenames:
              - codename: ZZZ
                chipset: wcn9999
                display: Zenith
            braktooth_chipsets: []
            mtk_known_chips: []
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(PL, "_BT_QCA_CODENAMES_YAML", yaml_path)
    PL.clear_all_caches()

    assert PL.get_qca_codename_map() == {"ZZZ": "wcn9999"}

    # Hot-reload: add a second codename.
    yaml_path.write_text(
        textwrap.dedent(
            """\
            codenames:
              - codename: ZZZ
                chipset: wcn9999
                display: Zenith
              - codename: AAA
                chipset: wcn0001
                display: Apex
            braktooth_chipsets: []
            mtk_known_chips: []
            """
        ),
        encoding="utf-8",
    )
    _bump_mtime(yaml_path)
    assert PL.get_qca_codename_map() == {"ZZZ": "wcn9999", "AAA": "wcn0001"}


def test_bt_banner_cve_pins_yaml_hot_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Editing bt_banner_cve_pins.yaml lands within one get_banner_cve_pins() call."""
    yaml_path = tmp_path / "bt_banner_cve_pins.yaml"
    # Each pin pairs family with a narrowing gate per the F-FORENSIC-10
    # invariant (2026-05-18): family alone is insufficient.
    yaml_path.write_text(
        textwrap.dedent(
            """\
            pins:
              - id: test-pin-1
                description: Synthetic test pin
                family: qca_rome
                chipset_target_in: [wcn3950]
                cves:
                  - id: CVE-9999-0001
                    severity: low
                    rationale: synthetic
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(PL, "_BT_BANNER_CVE_PINS_YAML", yaml_path)
    PL.clear_all_caches()

    pins = PL.get_banner_cve_pins()
    assert len(pins) == 1
    assert pins[0].pin_id == "test-pin-1"

    yaml_path.write_text(
        textwrap.dedent(
            """\
            pins:
              - id: test-pin-1
                description: Synthetic test pin
                family: qca_rome
                chipset_target_in: [wcn3950]
                cves:
                  - id: CVE-9999-0001
                    severity: low
                    rationale: synthetic
              - id: test-pin-2
                description: Second synthetic
                family: broadcom_hcd
                chipset_target_in: [bcm4345c0]
                cves:
                  - id: CVE-9999-0002
                    severity: low
                    rationale: synthetic
            """
        ),
        encoding="utf-8",
    )
    _bump_mtime(yaml_path)
    pins_after = PL.get_banner_cve_pins()
    assert len(pins_after) == 2
    assert {p.pin_id for p in pins_after} == {"test-pin-1", "test-pin-2"}


def test_vendor_prefixes_yaml_hot_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Editing vendor_prefixes.yaml lands within one resolve_vendor() call."""
    yaml_path = tmp_path / "vendor_prefixes.yaml"
    yaml_path.write_text(
        textwrap.dedent(
            """\
            vendors:
              - prefix: testvendor
                display: Test Vendor Inc.
                aliases:
                  - tvi
                  - testv
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(PL, "_VENDOR_YAML", yaml_path)
    PL.clear_all_caches()

    # First load: tvi alias resolves to testvendor.
    assert PL.resolve_vendor("tvi") == "testvendor"
    assert PL.get_vendor_display().get("testvendor") == "Test Vendor Inc."

    # Hot-reload: add a new alias.
    yaml_path.write_text(
        textwrap.dedent(
            """\
            vendors:
              - prefix: testvendor
                display: Test Vendor Inc.
                aliases:
                  - tvi
                  - testv
                  - newalias
            """
        ),
        encoding="utf-8",
    )
    _bump_mtime(yaml_path)
    assert PL.resolve_vendor("newalias") == "testvendor"


def test_firmware_patterns_yaml_hot_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Editing firmware_patterns.yaml lands within one match() call."""
    yaml_path = tmp_path / "firmware_patterns.yaml"
    yaml_path.write_text(
        textwrap.dedent(
            """\
            patterns:
              - pattern: '^foo_fw\\.bin$'
                vendor: testvendor
                category: bluetooth
                product: foo_fw
                confidence: high
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(PL, "_PATTERNS_YAML", yaml_path)
    PL.clear_all_caches()

    m = PL.match("foo_fw.bin")
    assert m is not None
    assert m.vendor == "testvendor"
    assert m.product == "foo_fw"

    # Hot-reload: add a new pattern.
    yaml_path.write_text(
        textwrap.dedent(
            """\
            patterns:
              - pattern: '^foo_fw\\.bin$'
                vendor: testvendor
                category: bluetooth
                product: foo_fw
                confidence: high
              - pattern: '^bar_fw\\.bin$'
                vendor: testvendor
                category: wifi
                product: bar_fw
                confidence: medium
            """
        ),
        encoding="utf-8",
    )
    _bump_mtime(yaml_path)
    m2 = PL.match("bar_fw.bin")
    assert m2 is not None
    assert m2.product == "bar_fw"
    assert m2.category == "wifi"


def test_known_firmware_yaml_hot_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Editing known_firmware.yaml lands within one _load_known_firmware() call."""
    yaml_path = tmp_path / "known_firmware.yaml"
    yaml_path.write_text(
        textwrap.dedent(
            """\
            families:
              - name: synthetic-family-1
                vendor: testvendor
                cves:
                  - id: CVE-9999-1111
                    severity: low
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(CM, "_YAML_PATH", yaml_path)
    # The loader's path resolver reads CM._YAML_PATH on every call, so
    # the monkeypatch above is sufficient. Clear cache to drop the
    # cached state from the previous (real-yaml) load.
    CM._KNOWN_FIRMWARE_LOADER.cache_clear()

    fams = CM._load_known_firmware()
    assert len(fams) == 1
    assert fams[0]["name"] == "synthetic-family-1"

    yaml_path.write_text(
        textwrap.dedent(
            """\
            families:
              - name: synthetic-family-1
                vendor: testvendor
                cves:
                  - id: CVE-9999-1111
                    severity: low
              - name: synthetic-family-2
                vendor: testvendor2
                cves:
                  - id: CVE-9999-2222
                    severity: medium
            """
        ),
        encoding="utf-8",
    )
    _bump_mtime(yaml_path)
    fams_after = CM._load_known_firmware()
    assert len(fams_after) == 2
    assert {f["name"] for f in fams_after} == {
        "synthetic-family-1",
        "synthetic-family-2",
    }
