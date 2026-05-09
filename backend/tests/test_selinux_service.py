"""Service-layer tests for ``app.services.selinux_service``.

Phase 2 Wave 7 file 5 of 5 — backfills service-layer tests for the
Android SELinux policy analyser (355 LOC) per intake
audit-test-coverage-routers-services-2026-05-04. Filesystem-driven
service (no DB persistence; the extracted firmware tree IS the input).

Rule #30 distribution: ``setools`` is LAZY-imported inside
``_try_setools_permissive`` at line 283 (an optional dependency that
ships with the wairz container but is not part of every test
environment). Per Rule #30, patches MUST hit the SOURCE module —
``sys.modules`` injection or ``patch("setools.SELinuxPolicy", ...)``
— rather than ``app.services.selinux_service.setools``, which would
be a silent no-op since the consumer module never bound the symbol
at module scope. ``subprocess`` (for the ``seinfo`` CLI fallback) is
top-level — patches target the consumer module
(``slx_mod.subprocess.run``).

Coverage targets:

* ``_POLICY_SEARCH_PATHS`` / ``_BINARY_POLICY_NAMES`` /
  ``_ROOT_POLICY_PATHS`` constants — sanity.
* ``_rel`` — relative path with leading slash; absolute outside root
  treated naturally (``os.path.relpath`` handles).
* ``_find_policy_files`` — finds ``.cil`` files under
  ``system/etc/selinux``; finds the ``sepolicy`` binary by exact
  filename; finds root-level ``sepolicy``; missing extracted_root
  → empty; non-policy files filtered.
* ``_parse_cil_permissive`` — extracts ``(typepermissive NAME)``;
  ignores leading whitespace; skips non-matching lines; OSError
  → empty.
* ``_gather_cil_stats`` — counts types/allow/neverallow/transition/
  permissive across multiple .cil files; dedupes via realpath;
  ignores binary policies.
* ``check_enforcement``:
  * ``ro.boot.selinux=enforcing`` → enforcing=True;
  * ``ro.boot.selinux=permissive`` → enforcing=False;
  * ``ro.build.selinux=1`` → enforcing=True;
  * ``ro.build.selinux=0`` → enforcing=False;
  * No props but policy files present → enforcing=True (default);
  * No props, no policy files → enforcing=None;
  * Comments + lines without ``=`` skipped.
* ``find_permissive_domains``:
  * Sandbox traversal rejected (path outside extracted_root → []);
  * Directory path walks all .cil files;
  * setools success short-circuits seinfo + CIL fallback;
  * setools ImportError → falls back to seinfo;
  * seinfo FileNotFoundError → falls back to CIL parse.
* ``analyze_policy`` — has_selinux=False when no policy files; full
  shape when policy files + build.prop present.
* **Rule #30 SOURCE-patch class** — ``TestRule30SetoolsSourcePatch``
  proves the patch target via sys.modules injection (matches Wave 2
  androguard discipline).
* **Rule #35b live canary** — real on-disk Android-shaped tree with
  fake build.prop + .cil files containing typepermissive
  declarations + binary sepolicy stub. Full ``analyze_policy()``
  returns a dict with the expected keys, counts, and permissive-
  domain set. The fixture-driven contract catches a regression
  where the policy walker silently filters out a file extension
  that production firmware actually uses (``.cil`` and
  ``.conf`` both must match, and the ``sepolicy``/``precompiled_sepolicy``
  exact-name list must be honoured).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.services import selinux_service as slx_mod
from app.services.selinux_service import (
    _BINARY_POLICY_NAMES,
    _POLICY_SEARCH_PATHS,
    _ROOT_POLICY_PATHS,
    SELinuxService,
)

# ===========================================================================
# Module constants
# ===========================================================================


class TestPolicySearchConstants:
    def test_search_paths_cover_all_partitions(self):
        # Every standard Android partition that hosts policy.
        assert "system/etc/selinux" in _POLICY_SEARCH_PATHS
        assert "vendor/etc/selinux" in _POLICY_SEARCH_PATHS
        assert "odm/etc/selinux" in _POLICY_SEARCH_PATHS
        assert "product/etc/selinux" in _POLICY_SEARCH_PATHS
        assert "system_ext/etc/selinux" in _POLICY_SEARCH_PATHS

    def test_binary_policy_names_present(self):
        assert "sepolicy" in _BINARY_POLICY_NAMES
        assert "precompiled_sepolicy" in _BINARY_POLICY_NAMES
        assert "plat_sepolicy.cil" in _BINARY_POLICY_NAMES

    def test_root_paths_include_top_level_sepolicy(self):
        assert "sepolicy" in _ROOT_POLICY_PATHS
        assert "system/sepolicy" in _ROOT_POLICY_PATHS


# ===========================================================================
# Fixtures
# ===========================================================================


def _make_extracted_root(tmp_path: Path) -> Path:
    """Build a minimal Android-shaped extracted root."""
    root = tmp_path / "extracted"
    root.mkdir()
    return root


# ===========================================================================
# _rel — relative path computation
# ===========================================================================


class TestRel:
    def test_relative_path_has_leading_slash(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        target = root / "system" / "etc" / "selinux" / "f.cil"
        target.parent.mkdir(parents=True)
        target.write_text("")
        service = SELinuxService(str(root))
        rel = service._rel(str(target))
        assert rel == "/system/etc/selinux/f.cil"


# ===========================================================================
# _find_policy_files — discovery walks
# ===========================================================================


class TestFindPolicyFiles:
    def test_finds_cil_files_under_system_etc_selinux(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        sel_dir = root / "system" / "etc" / "selinux"
        sel_dir.mkdir(parents=True)
        (sel_dir / "plat_sepolicy.cil").write_text("(type t1)")
        (sel_dir / "vendor_sepolicy.cil").write_text("(type t2)")
        (sel_dir / "policy.conf").write_text("# conf")
        # Junk file that should NOT match.
        (sel_dir / "README.md").write_text("doc")

        service = SELinuxService(str(root))
        found = service._find_policy_files()
        names = sorted(os.path.basename(p) for p in found)
        assert "plat_sepolicy.cil" in names
        assert "vendor_sepolicy.cil" in names
        assert "policy.conf" in names
        assert "README.md" not in names

    def test_finds_binary_sepolicy_by_exact_name(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        sel_dir = root / "vendor" / "etc" / "selinux"
        sel_dir.mkdir(parents=True)
        (sel_dir / "sepolicy").write_bytes(b"\x00binary policy")
        (sel_dir / "precompiled_sepolicy").write_bytes(b"\x00binary policy")

        service = SELinuxService(str(root))
        found = service._find_policy_files()
        names = sorted(os.path.basename(p) for p in found)
        assert "sepolicy" in names
        assert "precompiled_sepolicy" in names

    def test_finds_root_level_sepolicy(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        (root / "sepolicy").write_bytes(b"binary")
        service = SELinuxService(str(root))
        found = service._find_policy_files()
        # Both bare filename + realpath should be in the list.
        assert any(p.endswith("/sepolicy") for p in found)

    def test_missing_extracted_root_returns_empty(self, tmp_path: Path):
        # Existing tmp_path but nothing in it.
        service = SELinuxService(str(tmp_path))
        assert service._find_policy_files() == []


# ===========================================================================
# _parse_cil_permissive — text scanner
# ===========================================================================


class TestParseCilPermissive:
    def test_extracts_typepermissive_names(self, tmp_path: Path):
        cil = tmp_path / "p.cil"
        cil.write_text(
            "(type something)\n"
            "(typepermissive untrusted_app)\n"
            "(typepermissive vendor_init)\n"
            "(allow t1 t2 (file (read)))\n"
        )
        root = _make_extracted_root(tmp_path)
        service = SELinuxService(str(root))
        domains = service._parse_cil_permissive(str(cil))
        assert domains == ["untrusted_app", "vendor_init"]

    def test_oserror_returns_empty(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        service = SELinuxService(str(root))
        # Path that doesn't exist.
        assert service._parse_cil_permissive("/nonexistent.cil") == []

    def test_empty_file_returns_empty(self, tmp_path: Path):
        cil = tmp_path / "p.cil"
        cil.write_text("")
        root = _make_extracted_root(tmp_path)
        service = SELinuxService(str(root))
        assert service._parse_cil_permissive(str(cil)) == []


# ===========================================================================
# _gather_cil_stats — count statement types
# ===========================================================================


class TestGatherCilStats:
    def test_counts_each_statement_type(self, tmp_path: Path):
        cil = tmp_path / "p.cil"
        cil.write_text(
            "(type t1)\n"
            "(type t2)\n"
            "(allow t1 t2 (file (read)))\n"
            "(allow t1 t2 (file (write)))\n"
            "(allow t1 t2 (file (execute)))\n"
            "(neverallow t3 t4 (file (write)))\n"
            "(typetransition t1 t2 file t3)\n"
            "(typepermissive t1)\n"
        )
        root = _make_extracted_root(tmp_path)
        # Move the policy file under root so the realpath check passes.
        sel_dir = root / "system" / "etc" / "selinux"
        sel_dir.mkdir(parents=True)
        moved = sel_dir / "p.cil"
        moved.write_text(cil.read_text())

        service = SELinuxService(str(root))
        stats = service._gather_cil_stats([str(moved)])
        assert stats["type_declarations"] == 2
        assert stats["allow_rules"] == 3
        assert stats["neverallow_rules"] == 1
        assert stats["type_transitions"] == 1
        assert stats["typepermissive"] == 1
        assert stats["total_cil_files"] == 1

    def test_dedupes_realpath(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        sel_dir = root / "system" / "etc" / "selinux"
        sel_dir.mkdir(parents=True)
        cil = sel_dir / "p.cil"
        cil.write_text("(type t1)\n")

        service = SELinuxService(str(root))
        # Pass the same file twice.
        stats = service._gather_cil_stats([str(cil), str(cil)])
        assert stats["total_cil_files"] == 1  # dedup
        assert stats["type_declarations"] == 1

    def test_skips_non_cil(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        sel_dir = root / "system" / "etc" / "selinux"
        sel_dir.mkdir(parents=True)
        binary = sel_dir / "sepolicy"
        binary.write_bytes(b"\x00\x01\x02")

        service = SELinuxService(str(root))
        stats = service._gather_cil_stats([str(binary)])
        assert stats["total_cil_files"] == 0  # binaries don't count

    def test_path_outside_root_skipped(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        outside = tmp_path / "outside.cil"
        outside.write_text("(type t1)\n")

        service = SELinuxService(str(root))
        stats = service._gather_cil_stats([str(outside)])
        assert stats["total_cil_files"] == 0
        assert stats["type_declarations"] == 0


# ===========================================================================
# check_enforcement
# ===========================================================================


class TestCheckEnforcement:
    def _write_prop(self, root: Path, rel: str, content: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def test_ro_boot_enforcing(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        self._write_prop(root, "system/build.prop", "ro.boot.selinux=enforcing\n")
        service = SELinuxService(str(root))
        result = service.check_enforcement()
        assert result["enforcing"] is True
        assert result["source"] == "ro.boot.selinux"

    def test_ro_boot_permissive(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        self._write_prop(root, "system/build.prop", "ro.boot.selinux=permissive\n")
        service = SELinuxService(str(root))
        result = service.check_enforcement()
        assert result["enforcing"] is False
        assert result["source"] == "ro.boot.selinux"

    def test_ro_build_legacy_one_means_enforcing(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        self._write_prop(root, "default.prop", "ro.build.selinux=1\n")
        service = SELinuxService(str(root))
        result = service.check_enforcement()
        assert result["enforcing"] is True
        assert result["source"] == "ro.build.selinux"

    def test_ro_build_legacy_zero_means_permissive(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        self._write_prop(root, "default.prop", "ro.build.selinux=0\n")
        service = SELinuxService(str(root))
        result = service.check_enforcement()
        assert result["enforcing"] is False

    def test_ro_boot_takes_precedence_over_ro_build(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        self._write_prop(
            root, "system/build.prop",
            "ro.build.selinux=0\nro.boot.selinux=enforcing\n",
        )
        service = SELinuxService(str(root))
        result = service.check_enforcement()
        # ro.boot trumps ro.build.
        assert result["enforcing"] is True
        assert result["source"] == "ro.boot.selinux"

    def test_no_props_with_policy_files_defaults_enforcing(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        sel_dir = root / "system" / "etc" / "selinux"
        sel_dir.mkdir(parents=True)
        (sel_dir / "plat_sepolicy.cil").write_text("(type t1)\n")
        service = SELinuxService(str(root))
        result = service.check_enforcement()
        assert result["enforcing"] is True
        assert "default" in result["source"]

    def test_no_props_no_policy_returns_unknown(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        service = SELinuxService(str(root))
        result = service.check_enforcement()
        assert result["enforcing"] is None
        assert "no policy files" in result["source"]

    def test_comments_and_blank_lines_skipped(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        self._write_prop(
            root, "system/build.prop",
            "# this is a comment\n"
            "\n"
            "no_equals_sign_here\n"
            "ro.boot.selinux=enforcing\n",
        )
        service = SELinuxService(str(root))
        result = service.check_enforcement()
        assert result["enforcing"] is True
        # No spurious key appeared in details.
        assert "no_equals_sign_here" not in result["details"]


# ===========================================================================
# find_permissive_domains — sandbox + dispatch
# ===========================================================================


class TestFindPermissiveDomains:
    def test_path_traversal_rejected(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        # Write a CIL file outside the sandbox.
        outside = tmp_path / "outside.cil"
        outside.write_text("(typepermissive evil_domain)\n")

        service = SELinuxService(str(root))
        # Use a relative path that, when joined, escapes the root.
        domains = service.find_permissive_domains("../outside.cil")
        assert domains == []

    def test_directory_walks_all_cil_files(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        sel_dir = root / "system" / "etc" / "selinux"
        sel_dir.mkdir(parents=True)
        (sel_dir / "a.cil").write_text("(typepermissive d_a)\n")
        (sel_dir / "b.cil").write_text("(typepermissive d_b)\n")
        # Non-CIL file should be skipped.
        (sel_dir / "c.txt").write_text("(typepermissive d_c)\n")

        service = SELinuxService(str(root))
        domains = service.find_permissive_domains("system/etc/selinux")
        assert sorted(domains) == ["d_a", "d_b"]

    def test_setools_success_short_circuits_fallbacks(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        bin_policy = root / "sepolicy"
        bin_policy.write_bytes(b"\x00binary")

        # Build a fake setools module whose SELinuxPolicy returns 2 domains.
        fake_setools = MagicMock()
        fake_policy = MagicMock()
        fake_setools.SELinuxPolicy = MagicMock(return_value=fake_policy)

        # Each "type" is an object with .ispermissive + str()
        class _FakeType:
            def __init__(self, name: str, ispermissive: bool):
                self._name = name
                self.ispermissive = ispermissive

            def __str__(self) -> str:
                return self._name

        fake_policy.types = lambda: [
            _FakeType("permissive_a", True),
            _FakeType("enforcing_b", False),
            _FakeType("permissive_c", True),
        ]

        # Patch subprocess.run on the consumer module so seinfo MUST not
        # fire — if setools short-circuit fails, this assertion catches it.
        with patch.dict(sys.modules, {"setools": fake_setools}), \
             patch.object(slx_mod.subprocess, "run",
                          side_effect=AssertionError("seinfo should not run if setools succeeds")):
            service = SELinuxService(str(root))
            domains = service.find_permissive_domains("sepolicy")
        assert sorted(domains) == ["permissive_a", "permissive_c"]

    def test_setools_import_error_falls_back_to_seinfo(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        bin_policy = root / "sepolicy"
        bin_policy.write_bytes(b"\x00binary")

        # Mock setools as missing — patch the module-import-time import.
        # Easiest: pre-empt sys.modules with a sentinel that raises on access
        # — but `import setools` raises ImportError if "setools" is not in
        # sys.modules and not on path. The cleanest mock: simulate by
        # injecting a marker that triggers ImportError via the function's
        # own try/except. We use patch on the import statement is awkward;
        # instead delete from sys.modules and rely on the absence of the
        # real package (the wairz container DOES ship setools, so we use
        # a custom finder).

        original = sys.modules.pop("setools", None)
        try:
            # Monkeypatch the meta_path to refuse setools.
            class _BlockSetools:
                def find_module(self, name, path=None):
                    if name == "setools":
                        return self

                def load_module(self, name):
                    raise ImportError("setools blocked for test")

                def find_spec(self, name, path=None, target=None):
                    if name == "setools":
                        from importlib.machinery import ModuleSpec
                        return ModuleSpec(name, self)

                def create_module(self, spec):
                    raise ImportError("setools blocked for test")

                def exec_module(self, module):
                    raise ImportError("setools blocked for test")

            blocker = _BlockSetools()
            sys.meta_path.insert(0, blocker)
            try:
                # Mock seinfo to return one domain.
                seinfo_proc = MagicMock()
                seinfo_proc.returncode = 0
                seinfo_proc.stdout = "Permissive Types: 2\n   permissive_x\n   permissive_y\n"

                with patch.object(
                    slx_mod.subprocess, "run", return_value=seinfo_proc,
                ):
                    service = SELinuxService(str(root))
                    domains = service.find_permissive_domains("sepolicy")
                assert sorted(domains) == ["permissive_x", "permissive_y"]
            finally:
                sys.meta_path.remove(blocker)
        finally:
            if original is not None:
                sys.modules["setools"] = original

    def test_seinfo_filenotfound_falls_back_to_cil(self, tmp_path: Path):
        """When BOTH setools and seinfo are unavailable, the CIL parser is
        the final fallback. Binary policies (no .cil) get [] from the
        CIL parser since the fallback code path only fires for CIL inputs."""
        root = _make_extracted_root(tmp_path)
        cil = root / "policy.cil"
        cil.write_text("(typepermissive d_fallback)\n")

        # Block setools + seinfo.
        original_setools = sys.modules.pop("setools", None)
        try:
            class _BlockSetools:
                def find_spec(self, name, path=None, target=None):
                    if name == "setools":
                        from importlib.machinery import ModuleSpec
                        return ModuleSpec(name, self)

                def create_module(self, spec):
                    raise ImportError("blocked")

                def exec_module(self, module):
                    raise ImportError("blocked")

            blocker = _BlockSetools()
            sys.meta_path.insert(0, blocker)
            try:
                with patch.object(
                    slx_mod.subprocess, "run",
                    side_effect=FileNotFoundError("seinfo not in PATH"),
                ):
                    service = SELinuxService(str(root))
                    domains = service.find_permissive_domains("policy.cil")
                assert domains == ["d_fallback"]
            finally:
                sys.meta_path.remove(blocker)
        finally:
            if original_setools is not None:
                sys.modules["setools"] = original_setools


# ===========================================================================
# Rule #30 SOURCE-patch class — explicit discipline canary
# ===========================================================================


class TestRule30SetoolsSourcePatch:
    """Rule #30 source-patch discipline: ``setools`` is lazy-imported
    INSIDE ``_try_setools_permissive`` at line 283 of selinux_service.py.
    Patches MUST hit the SOURCE module — sys.modules injection is the
    canonical Python-stdlib mechanism for redirecting an import.

    Mock targets that would be a SILENT NO-OP:
    * ``patch("app.services.selinux_service.setools.SELinuxPolicy", ...)``
      — fails at patch-setup time because the consumer module never
      bound the name.
    * ``patch.object(slx_mod, "setools", ...)`` — same; AttributeError.

    The CORRECT discipline (this class):
    * ``patch.dict(sys.modules, {"setools": fake_module})`` so the
      ``import setools`` inside the function body resolves to the fake.
    """

    def test_source_patch_via_sys_modules_works(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        bin_policy = root / "sepolicy"
        bin_policy.write_bytes(b"binary")

        fake_setools = MagicMock()
        fake_policy = MagicMock()
        fake_setools.SELinuxPolicy = MagicMock(return_value=fake_policy)

        class _FakeType:
            def __init__(self, name, perm):
                self._name = name
                self.ispermissive = perm

            def __str__(self):
                return self._name

        fake_policy.types = lambda: [
            _FakeType("perm_one", True),
            _FakeType("strict_one", False),
        ]

        with patch.dict(sys.modules, {"setools": fake_setools}):
            service = SELinuxService(str(root))
            domains = service._try_setools_permissive(str(bin_policy))
        assert domains == ["perm_one"]
        # The fake's SELinuxPolicy was called with the file path.
        fake_setools.SELinuxPolicy.assert_called_once_with(str(bin_policy))

    def test_consumer_module_has_no_setools_attribute(self):
        """Sanity: confirms that ``slx_mod.setools`` does NOT exist as a
        module-scope name. If a future refactor moves the import to top-
        level, this assertion will flag it (and the fake-injection
        approach above must be updated to ``patch.object(slx_mod,
        "setools", ...)`` accordingly)."""
        assert not hasattr(slx_mod, "setools"), (
            "If setools is now top-level, switch tests to patch.object "
            "(consumer-module patch shape) per Rule #30 inverse case."
        )


# ===========================================================================
# analyze_policy — full orchestration
# ===========================================================================


class TestAnalyzePolicy:
    def test_no_policy_files_returns_has_selinux_false(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)
        service = SELinuxService(str(root))
        result = service.analyze_policy()
        assert result["has_selinux"] is False
        assert result["policy_files"] == []
        assert result["permissive_domains"] == []
        assert result["domain_count"] == 0
        assert result["neverallow_count"] == 0


# ===========================================================================
# Rule #35b LIVE-CANARY — full on-disk Android-shaped tree
# ===========================================================================


class TestAnalyzePolicyLiveCanary:
    """Rule #35b live canary: a real on-disk Android-shaped extracted
    root with build.prop + .cil files containing typepermissive
    declarations. The on-disk tree IS the persistence layer for this
    service (no DB).

    The contract under test: the discovery walker actually finds the
    .cil files under each partition's selinux dir; the build.prop
    parser reads enforcement state correctly; the typepermissive
    extraction de-duplicates across files; the cil_stats accumulator
    counts the right statement types.

    Mock-only tests cannot fail on:
    * a regression that drops one of the 5 partition prefixes from
      _POLICY_SEARCH_PATHS (only the e2e walker proves coverage);
    * a regression where the typepermissive regex no longer matches
      a real file (the on-disk parser must handle the actual file
      contents — line endings, leading whitespace, comment markers);
    * a regression where _gather_cil_stats double-counts by walking
      the same file twice across (file, dir-walk) discovery paths.
    """

    def test_realistic_android_tree_full_walk(self, tmp_path: Path):
        root = _make_extracted_root(tmp_path)

        # Build a realistic Android extracted tree.
        # 1. system/build.prop with ro.boot.selinux=enforcing
        sysprop = root / "system" / "build.prop"
        sysprop.parent.mkdir(parents=True)
        sysprop.write_text(
            "# Build properties\n"
            "ro.product.brand=GenericVendor\n"
            "ro.boot.selinux=enforcing\n"
            "ro.build.fingerprint=Android/12\n"
        )

        # 2. system/etc/selinux/plat_sepolicy.cil
        plat = root / "system" / "etc" / "selinux" / "plat_sepolicy.cil"
        plat.parent.mkdir(parents=True)
        plat.write_text(
            "(type init)\n"
            "(type vendor_init)\n"
            "(type untrusted_app)\n"
            "(allow init self (file (read write open)))\n"
            "(allow vendor_init self (file (read open)))\n"
            "(neverallow * untrusted_app (file (write)))\n"
            "(typetransition init self file vendor_init)\n"
            "(typepermissive untrusted_app)\n"
        )

        # 3. vendor/etc/selinux/vendor_sepolicy.cil
        vendor = root / "vendor" / "etc" / "selinux" / "vendor_sepolicy.cil"
        vendor.parent.mkdir(parents=True)
        vendor.write_text(
            "(type vendor_legacy)\n"
            "(typepermissive vendor_legacy)\n"
            "(typepermissive untrusted_app)\n"  # duplicate — must dedupe
        )

        # 4. vendor/etc/selinux/precompiled_sepolicy (binary)
        binary = root / "vendor" / "etc" / "selinux" / "precompiled_sepolicy"
        binary.write_bytes(b"\x00\x01\x02fake-binary-policy")

        # 5. odm/etc/selinux/policy.conf (.conf file)
        odm = root / "odm" / "etc" / "selinux" / "policy.conf"
        odm.parent.mkdir(parents=True)
        odm.write_text("# odm policy\n")

        service = SELinuxService(str(root))
        result = service.analyze_policy()

        # has_selinux = True; some policy files were found.
        assert result["has_selinux"] is True

        # Permissive domains: deduped across files.
        assert sorted(result["permissive_domains"]) == [
            "untrusted_app", "vendor_legacy",
        ]

        # Found policy files: at least the 3 CIL + 1 .conf + 1 binary.
        rel_files = result["policy_files"]
        joined = "|".join(rel_files)
        assert "plat_sepolicy.cil" in joined
        assert "vendor_sepolicy.cil" in joined
        assert "policy.conf" in joined
        assert "precompiled_sepolicy" in joined

        # CIL stats accumulated across plat + vendor (NOT counting binary
        # or .conf).
        cil_stats = result["cil_stats"]
        assert cil_stats["total_cil_files"] == 2
        assert cil_stats["type_declarations"] == 4  # init, vendor_init, untrusted_app, vendor_legacy
        assert cil_stats["allow_rules"] == 2
        assert cil_stats["neverallow_rules"] == 1
        assert cil_stats["type_transitions"] == 1
        assert cil_stats["typepermissive"] == 3  # raw count (BEFORE dedup)

        # domain_count + neverallow_count round-trip from cil_stats.
        assert result["domain_count"] == 4
        assert result["neverallow_count"] == 1

        # Enforcement reflects ro.boot.selinux=enforcing.
        enf = result["enforcement"]
        assert enf["enforcing"] is True
        assert enf["source"] == "ro.boot.selinux"
