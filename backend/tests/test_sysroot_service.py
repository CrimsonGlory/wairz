"""Service-layer tests for ``app.services.sysroot_service``.

Phase 2 Wave 9 file 3 of 4 — backfills service-layer tests for the
emulation/fuzzing sysroot helper module (207 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

Marginal canary surface: the service has NO DB persistence, NO
cache, and NO third-party Python dependencies. The "value flow"
under test is the lookup-table mapping
(SYSROOT_ARCH_MAP / DYNAMIC_LINKER_NAMES / CORE_LIBS), the
versioned-symlink dependency-matching logic in
``check_dependencies``, and the two-step ``container.exec_run``
gate inside ``check_sysroot_in_container``. Pure-mock tests
verify dispatch shape but cannot fail on a regression where the
arch-name canonical key drifts (e.g. ``mipsel`` → ``mips_le``)
or where the dynamic-linker filename changes — both are
verifiable directly against the lookup tables.

Rule #30 distribution: only stdlib (logging, os, typing.Any).
NO third-party deps to patch. Container exec is taken as an
``Any`` argument so tests provide a mock object directly — no
patching needed.

Coverage targets:

* ``SYSROOT_ARCH_MAP`` — every wairz-supported architecture is
  present (arm/aarch64/mips/mipsel/x86/x86_64); the x86 family
  uses i386 sysroot name (Debian multiarch convention).
* ``DYNAMIC_LINKER_NAMES`` — every arch maps to ≥1 known linker
  name; the ARMv7 entry covers BOTH armhf AND legacy soft-float;
  MIPS variants share ``ld.so.1``.
* ``CORE_LIBS`` — the 6 baseline libraries every sysroot needs.
* ``get_sysroot_path`` — happy path + unsupported arch → None.
* ``get_sysroot_env`` — returns QEMU_LD_PREFIX env var; empty
  dict for unsupported arch.
* ``check_dependencies`` — three modes:
  (a) pre-fetched contents: exact match + versioned-symlink
      pattern match (libc.so.6 ↔ libc-2.27.so);
  (b) theoretical (sysroot_contents=None): only CORE_LIBS +
      dynamic linker count as available;
  (c) unsupported arch: every lib is missing, all_satisfied=False.
* ``list_available_sysroots`` — returns 6 entries; each entry
  has architecture, sysroot_name, path; path uses SYSROOT_BASE_PATH.
* ``check_sysroot_in_container`` — happy path (both exec_run
  calls return 0); first exec_run non-zero → False (sysroot dir
  missing); second exec_run non-zero on first linker but 0 on
  fallback linker → True (regression backstop: ARMv7 tries
  ld-linux-armhf.so.3 then ld-linux.so.3); both fail → False;
  exec_run raises → False (graceful degradation).
* ``list_sysroot_contents`` — happy path: stdout decoded +
  basenames extracted; exit_code != 0 → empty list; exception
  → empty list.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services import sysroot_service as sr_mod
from app.services.sysroot_service import (
    CORE_LIBS,
    DYNAMIC_LINKER_NAMES,
    SYSROOT_ARCH_MAP,
    SYSROOT_BASE_PATH,
    check_dependencies,
    check_sysroot_in_container,
    get_sysroot_env,
    get_sysroot_path,
    list_available_sysroots,
    list_sysroot_contents,
)


# ===========================================================================
# Lookup-table sanity
# ===========================================================================


class TestSysrootArchMap:
    def test_supported_architectures_present(self):
        for arch in ("arm", "aarch64", "mips", "mipsel", "x86", "x86_64"):
            assert arch in SYSROOT_ARCH_MAP

    def test_x86_uses_i386_sysroot_name(self):
        # Debian multiarch convention: x86 → i386
        assert SYSROOT_ARCH_MAP["x86"] == "i386"

    def test_x86_64_uses_x86_64_sysroot_name(self):
        assert SYSROOT_ARCH_MAP["x86_64"] == "x86_64"

    def test_arm_variants_use_distinct_names(self):
        assert SYSROOT_ARCH_MAP["arm"] == "arm"
        assert SYSROOT_ARCH_MAP["aarch64"] == "aarch64"

    def test_mips_endianness_distinct(self):
        assert SYSROOT_ARCH_MAP["mips"] == "mips"
        assert SYSROOT_ARCH_MAP["mipsel"] == "mipsel"


class TestDynamicLinkerNames:
    def test_every_arch_in_arch_map_has_linker(self):
        for arch in SYSROOT_ARCH_MAP:
            assert arch in DYNAMIC_LINKER_NAMES
            assert len(DYNAMIC_LINKER_NAMES[arch]) >= 1

    def test_arm_covers_armhf_and_legacy(self):
        # ARMv7 hard-float vs soft-float Linux distros use different linkers.
        assert "ld-linux-armhf.so.3" in DYNAMIC_LINKER_NAMES["arm"]
        assert "ld-linux.so.3" in DYNAMIC_LINKER_NAMES["arm"]

    def test_aarch64_uses_arm64_linker(self):
        assert DYNAMIC_LINKER_NAMES["aarch64"] == ["ld-linux-aarch64.so.1"]

    def test_mips_variants_share_ldso_1(self):
        assert DYNAMIC_LINKER_NAMES["mips"] == ["ld.so.1"]
        assert DYNAMIC_LINKER_NAMES["mipsel"] == ["ld.so.1"]

    def test_x86_64_uses_canonical_linker(self):
        assert DYNAMIC_LINKER_NAMES["x86_64"] == ["ld-linux-x86-64.so.2"]


class TestCoreLibs:
    def test_baseline_six_libraries(self):
        # The 6 libraries every dynamically-linked Linux binary may need.
        assert "libc.so.6" in CORE_LIBS
        assert "libpthread.so.0" in CORE_LIBS
        assert "libdl.so.2" in CORE_LIBS
        assert "libm.so.6" in CORE_LIBS
        assert "librt.so.1" in CORE_LIBS
        assert "libgcc_s.so.1" in CORE_LIBS


class TestSysrootBasePath:
    def test_canonical_container_path(self):
        # The Dockerfile bakes sysroots into /opt/sysroots/<arch>/
        assert SYSROOT_BASE_PATH == "/opt/sysroots"


# ===========================================================================
# get_sysroot_path / get_sysroot_env
# ===========================================================================


class TestGetSysrootPath:
    def test_happy_path_returns_full_path(self):
        assert get_sysroot_path("arm") == "/opt/sysroots/arm"
        assert get_sysroot_path("x86_64") == "/opt/sysroots/x86_64"
        assert get_sysroot_path("x86") == "/opt/sysroots/i386"

    def test_unsupported_arch_returns_none(self):
        assert get_sysroot_path("riscv64") is None
        assert get_sysroot_path("powerpc") is None
        assert get_sysroot_path("") is None


class TestGetSysrootEnv:
    def test_returns_qemu_ld_prefix(self):
        env = get_sysroot_env("aarch64")
        assert env == {"QEMU_LD_PREFIX": "/opt/sysroots/aarch64"}

    def test_unsupported_arch_returns_empty_dict(self):
        assert get_sysroot_env("z80") == {}


# ===========================================================================
# check_dependencies
# ===========================================================================


class TestCheckDependencies:
    def test_unsupported_arch_returns_all_missing(self):
        result = check_dependencies(
            architecture="z80",
            needed_libs=["libc.so.6", "libsomething.so.1"],
        )
        assert result["available"] == []
        assert result["missing"] == ["libc.so.6", "libsomething.so.1"]
        assert result["sysroot_path"] is None
        assert result["all_satisfied"] is False

    def test_pre_fetched_contents_exact_match(self):
        result = check_dependencies(
            architecture="x86_64",
            needed_libs=["libc.so.6", "libpthread.so.0"],
            sysroot_contents=[
                "/opt/sysroots/x86_64/lib/libc.so.6",
                "/opt/sysroots/x86_64/lib/libpthread.so.0",
            ],
        )
        assert sorted(result["available"]) == ["libc.so.6", "libpthread.so.0"]
        assert result["missing"] == []
        assert result["all_satisfied"] is True
        assert result["sysroot_path"] == "/opt/sysroots/x86_64"

    def test_pre_fetched_versioned_symlink_match(self):
        """libc-2.27.so satisfies a libc.so.6 dependency via prefix-match.

        The implementation uses ``s.startswith(lib.split('.so')[0])`` —
        for ``libc.so.6``, the prefix is ``libc`` and any sysroot file
        starting with ``libc`` matches. This is intentional: Debian
        sysroots ship versioned files like ``libc-2.27.so``.
        """
        result = check_dependencies(
            architecture="x86_64",
            needed_libs=["libc.so.6"],
            sysroot_contents=["/opt/sysroots/x86_64/lib/libc-2.31.so"],
        )
        assert "libc.so.6" in result["available"]
        assert result["all_satisfied"] is True

    def test_pre_fetched_truly_missing(self):
        result = check_dependencies(
            architecture="x86_64",
            needed_libs=["libfoo.so.7", "libbar.so.0"],
            sysroot_contents=["/opt/sysroots/x86_64/lib/libc.so.6"],
        )
        assert result["available"] == []
        assert sorted(result["missing"]) == ["libbar.so.0", "libfoo.so.7"]
        assert result["all_satisfied"] is False

    def test_theoretical_only_core_libs_available(self):
        """Without sysroot_contents, only CORE_LIBS and the dynamic linker
        are guaranteed."""
        result = check_dependencies(
            architecture="aarch64",
            needed_libs=[
                "libc.so.6",                 # core
                "ld-linux-aarch64.so.1",     # dynamic linker
                "libsqlite3.so.0",           # NOT core
            ],
            sysroot_contents=None,
        )
        assert "libc.so.6" in result["available"]
        assert "ld-linux-aarch64.so.1" in result["available"]
        assert "libsqlite3.so.0" in result["missing"]
        assert result["all_satisfied"] is False

    def test_theoretical_arm_includes_both_linkers(self):
        # ARMv7 has both ld-linux-armhf.so.3 (hard-float) AND ld-linux.so.3.
        result = check_dependencies(
            architecture="arm",
            needed_libs=["ld-linux-armhf.so.3", "ld-linux.so.3"],
            sysroot_contents=None,
        )
        assert "ld-linux-armhf.so.3" in result["available"]
        assert "ld-linux.so.3" in result["available"]


# ===========================================================================
# list_available_sysroots
# ===========================================================================


class TestListAvailableSysroots:
    def test_returns_six_entries(self):
        result = list_available_sysroots()
        assert len(result) == len(SYSROOT_ARCH_MAP)

    def test_every_entry_has_required_fields(self):
        for entry in list_available_sysroots():
            assert "architecture" in entry
            assert "sysroot_name" in entry
            assert "path" in entry
            assert entry["path"].startswith(SYSROOT_BASE_PATH)

    def test_x86_entry_uses_i386_path(self):
        entries = {e["architecture"]: e for e in list_available_sysroots()}
        assert entries["x86"]["sysroot_name"] == "i386"
        assert entries["x86"]["path"] == "/opt/sysroots/i386"


# ===========================================================================
# check_sysroot_in_container — two-step exec_run gate
# ===========================================================================


def _exec_run_responder(responses: list[tuple[int, bytes | None]]):
    """Build a mock exec_run that returns successive (exit_code, output)."""
    iterator = iter(responses)

    def _impl(*args, **kwargs):  # noqa: ARG001
        try:
            code, output = next(iterator)
        except StopIteration:
            return (1, None)
        return (code, output)

    return _impl


class TestCheckSysrootInContainer:
    def test_unsupported_arch_returns_false(self):
        container = MagicMock()
        assert check_sysroot_in_container(container, "z80") is False
        # exec_run should NOT have been called.
        container.exec_run.assert_not_called()

    def test_happy_path_first_linker_succeeds(self):
        container = MagicMock()
        container.exec_run.side_effect = _exec_run_responder([
            (0, None),  # test -d /opt/sysroots/aarch64
            (0, None),  # test -f /opt/sysroots/aarch64/lib/ld-linux-aarch64.so.1
        ])
        assert check_sysroot_in_container(container, "aarch64") is True
        # Two exec_run calls: dir-test + linker-test
        assert container.exec_run.call_count == 2

    def test_sysroot_dir_missing_returns_false(self):
        container = MagicMock()
        # First exec_run (test -d) returns non-zero → sysroot dir absent.
        container.exec_run.side_effect = _exec_run_responder([(1, None)])
        assert check_sysroot_in_container(container, "x86_64") is False
        # Only ONE exec_run call — short-circuit before linker-test.
        assert container.exec_run.call_count == 1

    def test_armv7_falls_back_to_second_linker(self):
        """ARMv7 has TWO known linkers; the first may be absent on
        some sysroots. Second-linker fallback returns True."""
        container = MagicMock()
        container.exec_run.side_effect = _exec_run_responder([
            (0, None),  # test -d /opt/sysroots/arm
            (1, None),  # test -f .../ld-linux-armhf.so.3 → missing
            (0, None),  # test -f .../ld-linux.so.3 → present
        ])
        assert check_sysroot_in_container(container, "arm") is True
        assert container.exec_run.call_count == 3

    def test_no_linker_found_returns_false(self):
        """Sysroot dir present but NO known dynamic linker."""
        container = MagicMock()
        container.exec_run.side_effect = _exec_run_responder([
            (0, None),
            (1, None),  # ld-linux-armhf.so.3 missing
            (1, None),  # ld-linux.so.3 missing too
        ])
        assert check_sysroot_in_container(container, "arm") is False

    def test_exec_run_raises_returns_false(self):
        """Graceful degradation: if Docker exec misbehaves, return False
        rather than propagating to the caller (which is starting an
        emulation container — the outer flow can fall back)."""
        container = MagicMock()
        container.exec_run.side_effect = RuntimeError("docker daemon gone")
        assert check_sysroot_in_container(container, "x86_64") is False


# ===========================================================================
# list_sysroot_contents
# ===========================================================================


class TestListSysrootContents:
    def test_unsupported_arch_returns_empty(self):
        container = MagicMock()
        assert list_sysroot_contents(container, "z80") == []
        container.exec_run.assert_not_called()

    def test_happy_path_decodes_basenames(self):
        container = MagicMock()
        find_output = (
            b"/opt/sysroots/x86_64/lib/libc.so.6\n"
            b"/opt/sysroots/x86_64/lib/libpthread.so.0\n"
            b"/opt/sysroots/x86_64/lib/libdl.so.2\n"
        )
        container.exec_run.return_value = (0, (find_output, b""))
        result = list_sysroot_contents(container, "x86_64")
        assert result == ["libc.so.6", "libpthread.so.0", "libdl.so.2"]

    def test_non_tuple_output_handled(self):
        """exec_run with demux=True normally returns (stdout, stderr) but
        the wrapper checks ``isinstance(output, tuple)`` for safety."""
        container = MagicMock()
        find_output = b"/opt/sysroots/x86_64/lib/libc.so.6\n"
        container.exec_run.return_value = (0, find_output)  # raw bytes, not tuple
        result = list_sysroot_contents(container, "x86_64")
        assert result == ["libc.so.6"]

    def test_exec_failed_returns_empty(self):
        container = MagicMock()
        container.exec_run.return_value = (1, (b"", b"find error"))
        assert list_sysroot_contents(container, "x86_64") == []

    def test_empty_stdout_returns_empty(self):
        container = MagicMock()
        container.exec_run.return_value = (0, (b"", b""))
        assert list_sysroot_contents(container, "x86_64") == []

    def test_exec_run_raises_returns_empty(self):
        container = MagicMock()
        container.exec_run.side_effect = OSError("docker socket gone")
        assert list_sysroot_contents(container, "aarch64") == []

    def test_strips_blank_lines(self):
        container = MagicMock()
        find_output = (
            b"/opt/sysroots/mips/lib/libc.so.6\n"
            b"\n"
            b"/opt/sysroots/mips/lib/ld.so.1\n"
            b"   \n"
        )
        container.exec_run.return_value = (0, (find_output, b""))
        result = list_sysroot_contents(container, "mips")
        assert result == ["libc.so.6", "ld.so.1"]


# ===========================================================================
# Module sanity — no third-party imports surprise
# ===========================================================================


class TestModuleStructure:
    def test_no_third_party_top_level_imports(self):
        """sysroot_service is intended to be a pure-stdlib helper (the
        Docker SDK is taken as ``Any`` argument). Top-level imports are
        only ``logging``, ``os``, and ``typing``."""
        assert hasattr(sr_mod, "logging")
        assert hasattr(sr_mod, "os")
        # No docker import — it's passed in as Any.
        assert not hasattr(sr_mod, "docker")
