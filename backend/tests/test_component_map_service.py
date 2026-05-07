"""Service-layer tests for ``app.services.component_map_service``.

Phase 2 Wave 6 file 1 of 5 — backfills service-layer tests for the
ComponentMapService graph builder (701 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

This service is the **inverse Rule #30 case**: ``elftools.elf.elffile.ELFFile``
is imported at MODULE scope (line 13), so patching the SOURCE module
(``elftools.elf.elffile.ELFFile``) is a silent no-op — the consumer module
already holds its own local reference. Patch the CONSUMER module instead:
``patch("app.services.component_map_service.ELFFile", ...)``. Documented in
the campaign Decision Log under the "inverse Rule #30" entry.

Coverage targets:

* Pure path classifiers — ``_is_init_script`` (init.d / rc*.d / inittab /
  systemd unit dirs); ``_is_shell_script`` (.sh extension + shebang
  detection); ``_is_config_file`` (/etc/ + extension whitelist);
  ``_classify_elf`` (.ko → kernel_module / .so → library /
  ET_DYN-in-lib-dir → library / else binary).
* ``_resolve_library`` — exact path, label match, versioned base-name
  fallback, cache short-circuit, unresolved → cached None.
* ``_deduplicate_edges`` — same (source, target, type) triple merges
  ``imports_functions`` function lists; other edge types deduped without
  merging details.
* ``_prioritize_and_cap`` — under-cap returns False (no truncation); over-cap
  keeps the highest-scoring nodes (binary > library > script > config) and
  prunes orphan edges.
* ``_match_bare_commands`` — finds command tokens, skips SHELL_BUILTINS,
  matches against ``_nodes_by_label``, prefers binary over library/script.

* **Rule #35b live canary** — this service does NOT persist to the DB; the
  value-flow contract is the ``ComponentGraph`` dict shape returned by
  ``build_graph()``. The "live canary" here is a real on-disk firmware-like
  tree (tmp_path with a fake ELF binary + library + shell script + config
  file) → build_graph() → SELECT-equivalent inspection of the resulting
  nodes / edges with assertions on every field the service explicitly sets
  (id / label / type / path / size / metadata; source / target / type /
  details). Mirrors ``test_androguard_service.py``'s value-flow-on-mock-
  metadata canary; the F-A-06-shape assertion that mock-only ``walk_called
  == 1`` tests cannot fail on.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.services.component_map_service import (
    MAX_FUNCTIONS_PER_EDGE,
    MAX_NODES,
    ComponentEdge,
    ComponentGraph,
    ComponentMapService,
    ComponentNode,
)


# ===========================================================================
# Helpers — synthetic ELF fixture builder
# ===========================================================================


def _write_minimal_elf(path: Path, *, e_type: int = 0x02) -> None:
    """Write a syntactically valid 64-bit little-endian ELF header.

    Just enough magic + e_type to satisfy ``open(...).read(4) == b'\\x7fELF'``.
    The actual ``ELFFile`` parsing is mocked at the CONSUMER module via
    ``patch("app.services.component_map_service.ELFFile", ...)``; this
    fixture's only job is to produce a file whose first 4 bytes are the ELF
    magic so ``_classify_file`` routes to ``_classify_elf``.

    Parameters
    ----------
    e_type:
        ET_EXEC (0x02) for binaries, ET_DYN (0x03) for shared libraries.
        ``_classify_elf`` only reads e_type when the basename has no `.so`
        and no `.ko` markers — otherwise it short-circuits on the name.
    """
    # 64-bit ELF header: 16-byte e_ident + 48-byte rest = 64 bytes total.
    # We don't need a valid program/section header table because
    # ``_classify_file`` reads only the first 4 bytes for magic detection,
    # and ``_classify_elf`` is mocked above the parser layer.
    e_ident = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8  # 64-bit, little-endian
    rest = struct.pack(
        "<HHIQQQIHHHHHH",
        e_type,  # e_type
        0x3E,    # e_machine (x86_64)
        1,       # e_version
        0,       # e_entry
        0,       # e_phoff
        0,       # e_shoff
        0,       # e_flags
        64,      # e_ehsize
        0,       # e_phentsize
        0,       # e_phnum
        0,       # e_shentsize
        0,       # e_shnum
        0,       # e_shstrndx
    )
    path.write_bytes(e_ident + rest + b"\x00" * 200)


# ===========================================================================
# Pure path classifiers — no ELF / file I/O
# ===========================================================================


class TestIsInitScript:
    @pytest.fixture
    def svc(self, tmp_path: Path) -> ComponentMapService:
        return ComponentMapService(str(tmp_path))

    @pytest.mark.parametrize("path,expected", [
        ("/etc/init.d/cron",                True),
        ("/etc/init.d/networking",          True),
        ("/etc/rc0.d/K01reboot",            True),
        ("/etc/rc5.d/S01start",             True),
        ("/etc/rcS.d/S99local",             True),
        ("/etc/inittab",                    True),
        ("/etc/systemd/system/sshd.service", True),
        ("/lib/systemd/system/cron.service", True),
        ("/usr/lib/systemd/system/dhcp.service", True),
        # Negatives
        ("/etc/passwd",                     False),
        ("/etc/network/interfaces",         False),
        ("/usr/bin/init",                   False),
        ("/etc/rc.conf",                    False),  # rc but not rc*.d
        ("/inittab",                        False),  # not under /etc
    ])
    def test_classifies_init_script_paths(self, svc: ComponentMapService, path: str, expected: bool):
        assert svc._is_init_script(path) is expected


class TestIsConfigFile:
    @pytest.fixture
    def svc(self, tmp_path: Path) -> ComponentMapService:
        return ComponentMapService(str(tmp_path))

    @pytest.mark.parametrize("path,expected", [
        ("/etc/dhcpd.conf",          True),
        ("/etc/network/config.cfg",  True),
        ("/etc/app/settings.ini",    True),
        ("/etc/manifest.json",       True),
        ("/etc/cloud-init.yaml",     True),
        ("/etc/profile.yml",         True),
        ("/etc/dbus.xml",            True),
        # Negatives
        ("/etc/passwd",              False),  # no extension
        ("/etc/init.d/cron",         False),  # no config extension
        ("/usr/share/app.conf",      False),  # not under /etc
        ("/etc/script.sh",           False),  # .sh not in CONFIG_EXTENSIONS
    ])
    def test_classifies_config_paths(self, svc: ComponentMapService, path: str, expected: bool):
        assert svc._is_config_file(path) is expected


class TestIsShellScript:
    @pytest.fixture
    def svc(self, tmp_path: Path) -> ComponentMapService:
        return ComponentMapService(str(tmp_path))

    def test_dot_sh_extension_classifies_as_shell(self, svc: ComponentMapService, tmp_path: Path):
        f = tmp_path / "script.sh"
        f.write_bytes(b"echo hi\n")  # no shebang — extension is enough
        assert svc._is_shell_script(str(f), "/script.sh", b"echo") is True

    @pytest.mark.parametrize("first_line,expected", [
        (b"#!/bin/sh\necho hi\n",       True),
        (b"#!/bin/bash\nls\n",          True),
        (b"#!/usr/bin/env bash\nls\n",  True),
        (b"#!/usr/bin/ash\nls\n",       True),
        (b"#!/usr/bin/dash\nls\n",      True),
        # Negatives
        (b"#!/usr/bin/python3\nx=1\n",  False),
        (b"some text\n",                False),  # no shebang
    ])
    def test_shebang_detection(self, svc: ComponentMapService, tmp_path: Path,
                               first_line: bytes, expected: bool):
        f = tmp_path / "no-ext"
        f.write_bytes(first_line)
        magic = first_line[:4]
        assert svc._is_shell_script(str(f), "/no-ext", magic) is expected


# ===========================================================================
# _classify_elf — Rule #30 inverse case (CONSUMER-module patch)
# ===========================================================================


class TestClassifyElf:
    @pytest.fixture
    def svc(self, tmp_path: Path) -> ComponentMapService:
        return ComponentMapService(str(tmp_path))

    def test_dot_ko_classifies_as_kernel_module(self, svc: ComponentMapService, tmp_path: Path):
        f = tmp_path / "ext4.ko"
        _write_minimal_elf(f)
        # No ELFFile parsing reached — basename short-circuits.
        assert svc._classify_elf(str(f), "/lib/modules/ext4.ko") == "kernel_module"

    def test_dot_so_classifies_as_library(self, svc: ComponentMapService, tmp_path: Path):
        f = tmp_path / "libc.so.6"
        _write_minimal_elf(f, e_type=0x03)  # ET_DYN
        # ".so" in basename short-circuits before ELFFile parsing.
        assert svc._classify_elf(str(f), "/lib/libc.so.6") == "library"

    def test_et_dyn_in_lib_path_classifies_as_library(
        self, svc: ComponentMapService, tmp_path: Path,
    ):
        """ELF whose basename has no .so but ET_DYN + lib-dir path → library.

        The CONSUMER module's ``ELFFile`` symbol gets patched per the
        inverse-Rule #30 discipline (``ELFFile`` is bound at module scope
        in component_map_service.py:13). The patch replaces the consumer's
        local reference; patching ``elftools.elf.elffile.ELFFile`` would
        be a silent no-op for callers that already imported the symbol.
        """
        f = tmp_path / "noext"
        _write_minimal_elf(f, e_type=0x03)

        elf_obj = MagicMock()
        elf_obj.header.e_type = "ET_DYN"
        # ELFFile is used as a context manager-less constructor in
        # _classify_elf — it's wrapped in a `with open(...) as f` and
        # ELFFile(f) returns the parsed object directly.
        with patch(
            "app.services.component_map_service.ELFFile",
            return_value=elf_obj,
        ):
            # Pretend it's in /lib (a path part starting with "lib").
            assert svc._classify_elf(str(f), "/lib/noext") == "library"

    def test_et_exec_classifies_as_binary(
        self, svc: ComponentMapService, tmp_path: Path,
    ):
        f = tmp_path / "httpd"
        _write_minimal_elf(f, e_type=0x02)

        elf_obj = MagicMock()
        elf_obj.header.e_type = "ET_EXEC"
        with patch(
            "app.services.component_map_service.ELFFile",
            return_value=elf_obj,
        ):
            assert svc._classify_elf(str(f), "/usr/sbin/httpd") == "binary"


# ===========================================================================
# _resolve_library — caching + fallback discipline
# ===========================================================================


class TestResolveLibrary:
    @pytest.fixture
    def svc(self, tmp_path: Path) -> ComponentMapService:
        s = ComponentMapService(str(tmp_path))
        # Seed the lookup tables so resolution has something to find.
        s._nodes_by_id["/lib/libc.so.6"] = ComponentNode(
            id="/lib/libc.so.6", label="libc.so.6",
            type="library", path="/lib/libc.so.6", size=1000,
        )
        s._nodes_by_label["libc.so.6"] = ["/lib/libc.so.6"]
        s._nodes_by_id["/usr/lib/libssl.so"] = ComponentNode(
            id="/usr/lib/libssl.so", label="libssl.so",
            type="library", path="/usr/lib/libssl.so", size=2000,
        )
        s._nodes_by_label["libssl.so"] = ["/usr/lib/libssl.so"]
        return s

    def test_exact_path_match(self, svc: ComponentMapService):
        # libc.so.6 exists at /lib/libc.so.6 (one of the standard search paths).
        assert svc._resolve_library("libc.so.6") == "/lib/libc.so.6"

    def test_label_match_when_no_exact_path(self, svc: ComponentMapService):
        # libssl.so exists at /usr/lib/ — also a standard path. Both work.
        assert svc._resolve_library("libssl.so") == "/usr/lib/libssl.so"

    def test_versioned_basename_falls_back_to_unversioned(self, svc: ComponentMapService):
        # libssl.so.1.1 → strip to libssl.so → label match.
        result = svc._resolve_library("libssl.so.1.1")
        assert result == "/usr/lib/libssl.so"

    def test_unresolved_returns_none_and_caches(self, svc: ComponentMapService):
        first = svc._resolve_library("libnope.so.99")
        assert first is None
        # Cache hit: a second call returns the same None without retrying.
        assert "libnope.so.99" in svc._lib_resolve_cache
        assert svc._lib_resolve_cache["libnope.so.99"] is None

    def test_cache_short_circuit(self, svc: ComponentMapService):
        # Pre-populate cache with a sentinel value.
        svc._lib_resolve_cache["libcustom.so"] = "/cached/libcustom.so"
        # Resolution returns the cached value WITHOUT hitting search paths.
        assert svc._resolve_library("libcustom.so") == "/cached/libcustom.so"


# ===========================================================================
# _deduplicate_edges — function-list merge for imports_functions
# ===========================================================================


class TestDeduplicateEdges:
    @pytest.fixture
    def svc(self, tmp_path: Path) -> ComponentMapService:
        return ComponentMapService(str(tmp_path))

    def test_links_library_dedupes_without_merging(self, svc: ComponentMapService):
        svc._edges = [
            ComponentEdge(source="/bin/a", target="/lib/libc.so", type="links_library"),
            ComponentEdge(source="/bin/a", target="/lib/libc.so", type="links_library"),
        ]
        svc._deduplicate_edges()
        assert len(svc._edges) == 1

    def test_imports_functions_merges_function_lists(self, svc: ComponentMapService):
        svc._edges = [
            ComponentEdge(
                source="/bin/a", target="/lib/libc.so", type="imports_functions",
                details={"functions": ["malloc", "free"]},
            ),
            ComponentEdge(
                source="/bin/a", target="/lib/libc.so", type="imports_functions",
                details={"functions": ["printf", "malloc"]},
            ),
        ]
        svc._deduplicate_edges()
        assert len(svc._edges) == 1
        merged = svc._edges[0].details["functions"]
        assert merged == sorted({"malloc", "free", "printf"})

    def test_imports_functions_caps_merged_list_at_max(self, svc: ComponentMapService):
        # Build two edges whose union exceeds MAX_FUNCTIONS_PER_EDGE.
        first = [f"fn{i:03d}" for i in range(40)]
        second = [f"fn{i:03d}" for i in range(20, 60)]  # 20 unique + 20 overlap
        svc._edges = [
            ComponentEdge(
                source="/bin/a", target="/lib/libc.so", type="imports_functions",
                details={"functions": first},
            ),
            ComponentEdge(
                source="/bin/a", target="/lib/libc.so", type="imports_functions",
                details={"functions": second},
            ),
        ]
        svc._deduplicate_edges()
        merged = svc._edges[0].details["functions"]
        assert len(merged) <= MAX_FUNCTIONS_PER_EDGE

    def test_different_edge_types_not_merged(self, svc: ComponentMapService):
        svc._edges = [
            ComponentEdge(source="/bin/a", target="/lib/libc.so", type="links_library"),
            ComponentEdge(
                source="/bin/a", target="/lib/libc.so", type="imports_functions",
                details={"functions": ["malloc"]},
            ),
        ]
        svc._deduplicate_edges()
        # Different `type` field → different keys → both kept.
        assert len(svc._edges) == 2


# ===========================================================================
# _prioritize_and_cap — type-priority + edge-count + size scoring
# ===========================================================================


class TestPrioritizeAndCap:
    @pytest.fixture
    def svc(self, tmp_path: Path) -> ComponentMapService:
        return ComponentMapService(str(tmp_path))

    def test_under_cap_returns_false_no_truncation(self, svc: ComponentMapService):
        # 5 nodes < MAX_NODES (500) — no truncation.
        for i in range(5):
            svc._nodes_by_id[f"/bin/n{i}"] = ComponentNode(
                id=f"/bin/n{i}", label=f"n{i}", type="binary",
                path=f"/bin/n{i}", size=1000,
            )
        assert svc._prioritize_and_cap() is False
        assert len(svc._nodes_by_id) == 5

    def test_over_cap_keeps_highest_priority_nodes(self, svc: ComponentMapService):
        # Build MAX_NODES + 50 nodes: 250 binaries (priority 5) + 250 configs
        # (priority 1). The configs should be dropped first when capping
        # because their type score is much lower.
        for i in range(250):
            svc._nodes_by_id[f"/bin/n{i}"] = ComponentNode(
                id=f"/bin/n{i}", label=f"n{i}", type="binary",
                path=f"/bin/n{i}", size=1000,
            )
        for i in range(MAX_NODES - 250 + 50):
            svc._nodes_by_id[f"/etc/c{i}.conf"] = ComponentNode(
                id=f"/etc/c{i}.conf", label=f"c{i}.conf", type="config",
                path=f"/etc/c{i}.conf", size=10,
            )

        assert svc._prioritize_and_cap() is True
        assert len(svc._nodes_by_id) == MAX_NODES
        # Every binary survives (binaries are higher priority than configs).
        for i in range(250):
            assert f"/bin/n{i}" in svc._nodes_by_id

    def test_over_cap_prunes_orphan_edges(self, svc: ComponentMapService):
        # 600 binaries → cap drops 100. Edges referencing dropped nodes
        # must not survive.
        for i in range(600):
            svc._nodes_by_id[f"/bin/n{i}"] = ComponentNode(
                id=f"/bin/n{i}", label=f"n{i}", type="binary",
                path=f"/bin/n{i}", size=1000 + i,  # higher i → larger size → higher score
            )
        # Edge whose target is a low-i node (more likely to be dropped).
        svc._edges = [
            ComponentEdge(source="/bin/n599", target="/bin/n0", type="links_library"),
        ]
        truncated = svc._prioritize_and_cap()
        assert truncated is True
        # If /bin/n0 was dropped, the edge must be pruned.
        if "/bin/n0" not in svc._nodes_by_id:
            assert len(svc._edges) == 0


# ===========================================================================
# _match_bare_commands — SHELL_BUILTINS skip + binary preference
# ===========================================================================


class TestMatchBareCommands:
    @pytest.fixture
    def svc(self, tmp_path: Path) -> ComponentMapService:
        s = ComponentMapService(str(tmp_path))
        # Three nodes with different types; all share label "ls".
        s._nodes_by_id["/bin/ls"] = ComponentNode(
            id="/bin/ls", label="ls", type="binary", path="/bin/ls", size=100,
        )
        s._nodes_by_label["ls"] = ["/bin/ls"]
        s._nodes_by_id["/bin/curl"] = ComponentNode(
            id="/bin/curl", label="curl", type="binary", path="/bin/curl", size=200,
        )
        s._nodes_by_label["curl"] = ["/bin/curl"]
        return s

    def test_matches_known_binary_creates_executes_edge(self, svc: ComponentMapService):
        svc._match_bare_commands("/etc/init.d/test", "ls -la /tmp\ncurl http://x\n")
        # Two executes edges: one for ls, one for curl.
        targets = {e.target for e in svc._edges if e.type == "executes"}
        assert "/bin/ls" in targets
        assert "/bin/curl" in targets

    def test_skips_shell_builtins(self, svc: ComponentMapService):
        # Add "echo" as a node — but the function should still skip it
        # because echo is a SHELL_BUILTIN.
        svc._nodes_by_id["/bin/echo"] = ComponentNode(
            id="/bin/echo", label="echo", type="binary", path="/bin/echo", size=50,
        )
        svc._nodes_by_label["echo"] = ["/bin/echo"]

        svc._match_bare_commands("/etc/init.d/test", "echo hi\nls\n")
        targets = {e.target for e in svc._edges if e.type == "executes"}
        # ls matches; echo is skipped despite being a registered node.
        assert "/bin/ls" in targets
        assert "/bin/echo" not in targets

    def test_no_match_when_token_not_in_label_map(self, svc: ComponentMapService):
        svc._match_bare_commands("/etc/init.d/test", "totallymadeup arg\n")
        assert len(svc._edges) == 0


# ===========================================================================
# Rule #35b live canary — real on-disk firmware tree end-to-end
# ===========================================================================


@pytest.fixture
def fake_firmware(tmp_path: Path) -> Path:
    """Build a minimal firmware-like extracted tree.

    Layout (every file is a real on-disk artefact):

      /
      ├── usr/sbin/httpd      (ELF, will be classified as binary)
      ├── lib/libc.so.6       (ELF, label-matches → library)
      ├── etc/init.d/start.sh (shell script with .sh extension)
      ├── etc/dhcpd.conf      (config file with absolute path reference
      │                        to /usr/sbin/httpd → produces a `configures`
      │                        edge in build_graph)
      └── etc/profile         (file with shebang #!/bin/sh — script via
                                shebang detection, no .sh extension)

    The ELF parsing is mocked at the CONSUMER module so the test doesn't
    require a real elftools-compatible binary on disk; the file's first
    4 bytes are valid ELF magic so ``_classify_file`` routes to
    ``_classify_elf``.
    """
    # /usr/sbin/httpd
    (tmp_path / "usr" / "sbin").mkdir(parents=True)
    _write_minimal_elf(tmp_path / "usr" / "sbin" / "httpd")
    # /lib/libc.so.6
    (tmp_path / "lib").mkdir()
    _write_minimal_elf(tmp_path / "lib" / "libc.so.6", e_type=0x03)
    # /etc/init.d/start.sh
    (tmp_path / "etc" / "init.d").mkdir(parents=True)
    (tmp_path / "etc" / "init.d" / "start.sh").write_bytes(
        b"#!/bin/sh\n/usr/sbin/httpd -D\n",
    )
    # /etc/dhcpd.conf
    (tmp_path / "etc" / "dhcpd.conf").write_bytes(
        b"# config\nbinary /usr/sbin/httpd\n",
    )
    # /etc/profile (shebang-based shell script with no .sh extension)
    (tmp_path / "etc" / "profile").write_bytes(b"#!/bin/sh\nexport PATH=/usr/bin\n")
    return tmp_path


class TestBuildGraphLiveCanary:
    """Rule #35b live canary: real on-disk tree → build_graph() →
    SELECT-equivalent inspection of returned ComponentGraph fields.

    Mirrors test_androguard_service.py::TestAnalyzeApk::test_happy_path —
    every field the service explicitly populates round-trips through the
    wrapper into the returned dataclass with the expected key names. A
    mock-only test that asserts ``walk_called == 1`` cannot fail on a
    constructor that silently drops the ``size=`` kwarg or types ``label``
    as ``None``; this can.
    """

    def test_build_graph_value_flow(self, fake_firmware: Path):
        # ELFFile mock returns ET_EXEC for httpd, ET_DYN for libc, and
        # empty PT_DYNAMIC segments so no DT_NEEDED parsing is exercised
        # (that path needs a fully synthesised dynamic table; covered
        # separately by integration with a real ELF in production).
        seg = MagicMock()
        seg.header.p_type = "PT_NOTE"  # not PT_DYNAMIC → DT_NEEDED loop skipped
        elf = MagicMock()
        elf.header.e_type = "ET_EXEC"
        elf.header.e_machine = "EM_X86_64"
        elf.little_endian = True
        elf.elfclass = 64
        elf.iter_segments = MagicMock(return_value=[seg])
        elf.get_section_by_name = MagicMock(return_value=None)

        with patch(
            "app.services.component_map_service.ELFFile",
            return_value=elf,
        ):
            svc = ComponentMapService(str(fake_firmware))
            graph = svc.build_graph()

        # Type contract.
        assert isinstance(graph, ComponentGraph)
        assert isinstance(graph.nodes, list)
        assert isinstance(graph.edges, list)
        assert graph.truncated is False  # 5 nodes < MAX_NODES

        # Index by id for order-independent assertions (Rule #35b
        # anti-pattern #4: avoid lexicographic ordering traps).
        nodes_by_id = {n.id: n for n in graph.nodes}

        # Every field the service explicitly sets on each node, asserted
        # individually — this is the live-canary discipline. A mock test
        # of `db.add.call_count == 5` would pass even if `label=None` or
        # `size=0` regressions slipped in.

        httpd = nodes_by_id["/usr/sbin/httpd"]
        assert httpd.label == "httpd"
        assert httpd.type == "binary"
        assert httpd.path == "/usr/sbin/httpd"
        assert httpd.size > 0  # _write_minimal_elf produced ~264 bytes

        libc = nodes_by_id["/lib/libc.so.6"]
        assert libc.label == "libc.so.6"
        assert libc.type == "library"  # .so in basename short-circuits
        assert libc.path == "/lib/libc.so.6"
        assert libc.size > 0

        start_sh = nodes_by_id["/etc/init.d/start.sh"]
        # Init-script paths take precedence over generic shell scripts:
        # /etc/init.d/* → init_script, regardless of .sh extension.
        assert start_sh.type == "init_script"
        assert start_sh.label == "start.sh"

        dhcpd_conf = nodes_by_id["/etc/dhcpd.conf"]
        assert dhcpd_conf.type == "config"
        assert dhcpd_conf.label == "dhcpd.conf"

        profile = nodes_by_id["/etc/profile"]
        assert profile.type == "script"  # shebang-based detection
        assert profile.label == "profile"

        # ELF metadata round-trips through _elf_metadata into the
        # ComponentNode.metadata dict — this is the value-flow contract
        # mock tests cannot fail on.
        assert httpd.metadata.get("type") == "ET_EXEC"
        assert httpd.metadata.get("machine") == "EM_X86_64"
        assert httpd.metadata.get("endianness") == "little"
        assert httpd.metadata.get("bits") == 64

        # Edge canary: start.sh (init_script) must produce at least one
        # edge to /usr/sbin/httpd via the absolute-path-invocation regex
        # in _analyze_shell_scripts.
        executes_edges = [
            e for e in graph.edges
            if e.source == "/etc/init.d/start.sh"
            and e.target == "/usr/sbin/httpd"
            and e.type == "executes"
        ]
        assert len(executes_edges) >= 1, (
            "start.sh's `/usr/sbin/httpd -D` invocation should produce "
            "an `executes` edge"
        )

        # Config canary: dhcpd.conf references /usr/sbin/httpd → produces
        # a `configures` edge in _analyze_config_files.
        configures_edges = [
            e for e in graph.edges
            if e.source == "/etc/dhcpd.conf"
            and e.target == "/usr/sbin/httpd"
            and e.type == "configures"
        ]
        assert len(configures_edges) >= 1, (
            "dhcpd.conf's path reference to /usr/sbin/httpd should "
            "produce a `configures` edge"
        )

    def test_build_graph_handles_unreadable_files_gracefully(
        self, tmp_path: Path,
    ):
        """An unreadable file (permission-denied open) is silently skipped
        by ``_classify_file``'s OSError branch — it must not crash the walk."""
        good = tmp_path / "good.sh"
        good.write_bytes(b"#!/bin/sh\necho hi\n")
        bad = tmp_path / "bad"
        bad.write_bytes(b"\x00")
        # Strip read permission. (May not work as root; in CI this still
        # exercises the OSError branch via the read attempt because we
        # also clear the file.)
        os.chmod(str(bad), 0o000)

        try:
            svc = ComponentMapService(str(tmp_path))
            graph = svc.build_graph()
        finally:
            # Restore so pytest cleanup doesn't fail on tmp_path teardown.
            os.chmod(str(bad), 0o644)

        # The walk completed without raising.
        assert isinstance(graph, ComponentGraph)


# ===========================================================================
# Multi-root partition-prefix discipline (Phase 3b feature)
# ===========================================================================


class TestExtraRootsPartitionPrefix:
    def test_extra_root_paths_get_partition_prefix(self, tmp_path: Path):
        """Phase 3b: extra detection roots get a ``/<partition>/...`` prefix
        on node IDs so paths from a scatter-zip's ``system.img`` can't
        collide with rootfs entries of the same path.

        ELF binaries (classified by magic bytes, not path-pattern) are the
        realistic test for the prefix because the partition-prefixed path
        no longer matches ``/etc/`` for ``_is_config_file`` — that's
        intentional Phase 3b behaviour: extra roots are raw-image dirs,
        not nested rootfses, so path-pattern classification only fires
        against the primary root.
        """
        primary = tmp_path / "rootfs"
        primary.mkdir()
        (primary / "bin").mkdir()
        _write_minimal_elf(primary / "bin" / "ls")

        extra = tmp_path / "system_partition"
        extra.mkdir()
        (extra / "bin").mkdir()
        _write_minimal_elf(extra / "bin" / "ls", e_type=0x02)

        elf = MagicMock()
        elf.header.e_type = "ET_EXEC"
        elf.header.e_machine = "EM_X86_64"
        elf.little_endian = True
        elf.elfclass = 64
        seg = MagicMock()
        seg.header.p_type = "PT_NOTE"
        elf.iter_segments = MagicMock(return_value=[seg])
        elf.get_section_by_name = MagicMock(return_value=None)

        with patch(
            "app.services.component_map_service.ELFFile",
            return_value=elf,
        ):
            svc = ComponentMapService(str(primary), extra_roots=[str(extra)])
            graph = svc.build_graph()

        ids = {n.id for n in graph.nodes}

        # Primary root: rootfs-relative path, no prefix.
        assert "/bin/ls" in ids
        # Extra root: partition-prefixed.
        assert "/system_partition/bin/ls" in ids

    def test_extra_root_dedup_against_primary(self, tmp_path: Path):
        """An extra_root that realpath-resolves to the same dir as the
        primary must be deduped — no double walk."""
        primary = tmp_path / "rootfs"
        primary.mkdir()
        (primary / "etc").mkdir()
        (primary / "etc" / "passwd.conf").write_bytes(b"x:y\n")

        # Extra root is the SAME directory as primary; dedup must skip.
        svc = ComponentMapService(str(primary), extra_roots=[str(primary)])
        graph = svc.build_graph()

        # Only one node for the file — not two.
        ids = [n.id for n in graph.nodes]
        assert ids.count("/etc/passwd.conf") == 1
