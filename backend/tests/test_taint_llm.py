"""Tests for the LATTE-style LLM taint analysis MCP tools.

Focus: the composition layer (pipeline ordering, prompt shape, cache
keying, path traversal). The DVRF 80% recall target is an integration
test that requires real Ghidra + real binary and is deferred to the
integration suite (see `.planning/intake/feature-latte-llm-taint-analysis.md`).

Unit tests mock the Ghidra cache so we don't depend on a compiled ELF.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.ai.tools.taint_llm import (
    _apply_confidence_gate,
    _compose_deepdive_prompt,
    _compose_scan_prompt,
    _load_sinks_yaml,
    _load_sources_yaml,
    _rank_candidates,
    _sink_name_set,
    _sink_to_cwe,
    _source_name_set,
    _truncate_decomp,
    register_taint_llm_tools,
)

# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


class TestYamlLoading:
    def test_sinks_yaml_parses(self):
        data = _load_sinks_yaml()
        assert "families" in data
        assert isinstance(data["families"], dict)
        # Core families present
        for fam in ("command_injection", "buffer_overflow", "format_string"):
            assert fam in data["families"], f"missing family {fam}"

    def test_sources_yaml_parses(self):
        data = _load_sources_yaml()
        assert "families" in data
        assert isinstance(data["families"], dict)
        for fam in ("network", "environment", "nvram"):
            assert fam in data["families"], f"missing family {fam}"

    def test_sink_name_set_coverage(self):
        names = _sink_name_set()
        # Known classics
        for name in ("system", "strcpy", "sprintf", "popen", "execve"):
            assert name in names

    def test_source_name_set_coverage(self):
        names = _source_name_set()
        for name in ("recv", "getenv", "fgets", "nvram_get"):
            assert name in names

    def test_sink_to_cwe_mapping(self):
        mapping = _sink_to_cwe()
        assert mapping.get("system") == "CWE-78"
        assert mapping.get("strcpy") == "CWE-120"
        assert mapping.get("printf") == "CWE-134"


# ---------------------------------------------------------------------------
# Ranking / filtering
# ---------------------------------------------------------------------------


class TestRanking:
    @staticmethod
    def _mk_xrefs(graph: dict[str, dict[str, list]]) -> dict:
        """Build a fake xrefs structure:
        graph = {
            "func_name": {
                "calls": ["to_func_1", "to_func_2"],
                "callers": ["caller_1", ...]
            }
        }
        """
        xrefs: dict[str, dict] = {}
        for func, edges in graph.items():
            xrefs[func] = {
                "from": [
                    {"to_func": t, "to": "0x1000", "type": "CALL"}
                    for t in edges.get("calls", [])
                ],
                "to": [
                    {"from_func": c, "from": "0x2000", "type": "CALL"}
                    for c in edges.get("callers", [])
                ],
            }
        return xrefs

    def test_function_calling_two_sinks_ranks_higher_than_one(self):
        xrefs = self._mk_xrefs({
            "dangerous_fn": {"calls": ["strcpy", "sprintf"]},
            "boring_fn": {"calls": ["strcpy"]},
        })
        imports = [{"name": "strcpy"}, {"name": "sprintf"}]
        ranked = _rank_candidates(
            xrefs, imports, _sink_name_set(), _source_name_set()
        )
        names = [c["function"] for c in ranked]
        assert names.index("dangerous_fn") < names.index("boring_fn")

    def test_source_adjacency_boosts_score(self):
        xrefs = self._mk_xrefs({
            "has_source_too": {"calls": ["recv", "strcpy"]},
            "sink_only": {"calls": ["strcpy"]},
        })
        imports = [{"name": "strcpy"}, {"name": "recv"}]
        ranked = _rank_candidates(
            xrefs, imports, _sink_name_set(), _source_name_set()
        )
        by_name = {c["function"]: c for c in ranked}
        assert by_name["has_source_too"]["score"] > by_name["sink_only"]["score"]
        assert "recv" in by_name["has_source_too"]["sources"]

    def test_centrality_bonus_for_many_callers(self):
        xrefs = self._mk_xrefs({
            "popular_fn": {
                "calls": ["strcpy"],
                "callers": ["a", "b", "c", "d"],  # >=3
            },
            "obscure_fn": {
                "calls": ["strcpy"],
                "callers": ["x"],
            },
        })
        imports = [{"name": "strcpy"}]
        ranked = _rank_candidates(
            xrefs, imports, _sink_name_set(), _source_name_set()
        )
        by_name = {c["function"]: c for c in ranked}
        assert by_name["popular_fn"]["score"] > by_name["obscure_fn"]["score"]

    def test_empty_when_no_sinks_imported(self):
        xrefs = self._mk_xrefs({
            "not_vulnerable": {"calls": ["printf"]},
        })
        imports = [{"name": "harmless_fn"}]  # no sinks
        ranked = _rank_candidates(
            xrefs, imports, _sink_name_set(), _source_name_set()
        )
        assert ranked == []

    def test_primary_cwe_assigned(self):
        xrefs = self._mk_xrefs({"cmd_fn": {"calls": ["system"]}})
        imports = [{"name": "system"}]
        ranked = _rank_candidates(
            xrefs, imports, _sink_name_set(), _source_name_set()
        )
        assert ranked[0]["primary_cwe"] == "CWE-78"

    def test_stable_ordering(self):
        """Same inputs → identical ranked list (secondary sort by name)."""
        xrefs = self._mk_xrefs({
            "b_fn": {"calls": ["strcpy"]},
            "a_fn": {"calls": ["strcpy"]},
        })
        imports = [{"name": "strcpy"}]
        r1 = _rank_candidates(
            xrefs, imports, _sink_name_set(), _source_name_set()
        )
        r2 = _rank_candidates(
            xrefs, imports, _sink_name_set(), _source_name_set()
        )
        assert [c["function"] for c in r1] == [c["function"] for c in r2]
        # Same score → alphabetical
        assert [c["function"] for c in r1] == ["a_fn", "b_fn"]


class TestConfidenceGate:
    def _mk(self, sinks_count: int, sources_count: int):
        return {
            "function": "f",
            "score": 2 * sinks_count + sources_count,
            "sinks": [f"s{i}" for i in range(sinks_count)],
            "sources": [f"u{i}" for i in range(sources_count)],
            "incoming_callers": 0,
            "primary_cwe": "CWE-120",
        }

    def test_low_keeps_everything_with_any_sink(self):
        cands = [self._mk(1, 0), self._mk(2, 0), self._mk(1, 1)]
        assert len(_apply_confidence_gate(cands, "low")) == 3

    def test_medium_requires_2_sinks_or_1sink_plus_1source(self):
        cands = [
            self._mk(1, 0),  # fail
            self._mk(2, 0),  # pass
            self._mk(1, 1),  # pass
        ]
        out = _apply_confidence_gate(cands, "medium")
        assert len(out) == 2

    def test_high_requires_both(self):
        cands = [
            self._mk(2, 0),  # fail (no source)
            self._mk(1, 1),  # fail (only 1 sink)
            self._mk(2, 1),  # pass
        ]
        out = _apply_confidence_gate(cands, "high")
        assert len(out) == 1
        assert out[0]["sinks"] == ["s0", "s1"]
        assert out[0]["sources"] == ["u0"]

    def test_invalid_confidence_defaults_to_medium(self):
        cands = [self._mk(2, 0)]
        out = _apply_confidence_gate(cands, "wibble")
        assert len(out) == 1


# ---------------------------------------------------------------------------
# Prompt composition
# ---------------------------------------------------------------------------


class TestTruncateDecomp:
    def test_short_passes_through(self):
        body = "int main() { return 0; }"
        assert _truncate_decomp(body, 1000) == body

    def test_long_truncated_with_middle_marker(self):
        body = "line\n" * 2000  # ~10KB
        out = _truncate_decomp(body, 500)
        assert "[middle elided" in out
        assert len(out.encode()) < 700  # some slack for marker

    def test_empty_body(self):
        assert _truncate_decomp("", 100) == ""


class TestScanPrompt:
    def _cand(self, name: str, sinks=None, sources=None, score=3):
        return {
            "function": name,
            "score": score,
            "sinks": sinks or ["strcpy"],
            "sources": sources or [],
            "incoming_callers": 1,
            "primary_cwe": "CWE-120",
        }

    def test_scan_prompt_contains_header_sections(self):
        prompt = _compose_scan_prompt(
            binary_path="/bin/httpd",
            min_confidence="medium",
            focus_cwe=None,
            candidates=[self._cand("handle_req")],
            decomps={"handle_req": "void handle_req() { strcpy(dst, src); }"},
            imports_count=42,
        )
        assert "LATTE-Style Binary Taint Analysis" in prompt
        assert "/bin/httpd" in prompt
        assert "Sink inventory" in prompt
        assert "Candidate functions" in prompt
        assert "Your task" in prompt
        assert "Output schema" in prompt
        assert "handle_req" in prompt

    def test_scan_prompt_embeds_decomp(self):
        body = "int main() { strcpy(a, b); system(cmd); }"
        prompt = _compose_scan_prompt(
            binary_path="/bin/ex",
            min_confidence="low",
            focus_cwe=None,
            candidates=[self._cand("main", ["strcpy", "system"], ["recv"])],
            decomps={"main": body},
            imports_count=5,
        )
        assert body in prompt

    def test_scan_prompt_under_30kb_with_max_candidates(self):
        # Simulate 50 candidates each with ~2KB decomp
        fake_body = "int fn() {\n    strcpy(dst, src);\n    system(cmd);\n}\n" * 50
        cands = [self._cand(f"fn_{i}", ["strcpy"], []) for i in range(50)]
        decomps = {f"fn_{i}": fake_body for i in range(50)}
        prompt = _compose_scan_prompt(
            binary_path="/bin/big",
            min_confidence="low",
            focus_cwe=None,
            candidates=cands,
            decomps=decomps,
            imports_count=100,
        )
        # After per-candidate truncation, prompt is bounded.
        # 50 * 1.5KB = 75KB; the registry.execute layer truncates to 30KB,
        # but the raw output of compose itself is also bounded because
        # per-candidate decomp is capped.
        assert len(prompt.encode()) < 200 * 1024

    def test_scan_prompt_focus_cwe_note(self):
        prompt = _compose_scan_prompt(
            binary_path="/bin/ex",
            min_confidence="medium",
            focus_cwe=["CWE-78"],
            candidates=[self._cand("f")],
            decomps={"f": ""},
            imports_count=1,
        )
        assert "CWE-78" in prompt
        assert "Focus on CWE" in prompt


class TestDeepDivePrompt:
    def test_deepdive_prompt_has_4_stages(self):
        prompt = _compose_deepdive_prompt(
            binary_path="/bin/x",
            function_name="vuln_fn",
            decomp="void vuln_fn(char *input) { strcpy(buf, input); }",
            callers=[{"from_func": "main", "from": "0x400"}],
            callees=[{"to_func": "strcpy", "to": "0x500"}],
            caller_classifications={"main": ""},
            callee_classifications={"strcpy": "POTENTIAL SINK"},
            neighbour_decomps={},
            focus_cwe=None,
        )
        assert "Stage 1" in prompt
        assert "Stage 2" in prompt
        assert "Stage 3" in prompt
        assert "Stage 4" in prompt
        assert "Sink identification" in prompt
        assert "Source identification" in prompt
        assert "Dataflow" in prompt
        assert "CWE classification" in prompt

    def test_deepdive_includes_target_decomp(self):
        body = "void f(char *p) { sprintf(out, p); }"
        prompt = _compose_deepdive_prompt(
            binary_path="/bin/x",
            function_name="f",
            decomp=body,
            callers=[],
            callees=[],
            caller_classifications={},
            callee_classifications={},
            neighbour_decomps={},
            focus_cwe=None,
        )
        assert body in prompt

    def test_deepdive_marks_sinks_and_sources(self):
        prompt = _compose_deepdive_prompt(
            binary_path="/bin/x",
            function_name="target",
            decomp="void target() {}",
            callers=[{"from_func": "recv_handler", "from": "0x1"}],
            callees=[{"to_func": "system", "to": "0x2"}],
            caller_classifications={"recv_handler": "POTENTIAL SOURCE"},
            callee_classifications={"system": "POTENTIAL SINK"},
            neighbour_decomps={},
            focus_cwe=None,
        )
        assert "POTENTIAL SOURCE" in prompt
        assert "POTENTIAL SINK" in prompt

    def test_deepdive_output_schema_present(self):
        prompt = _compose_deepdive_prompt(
            binary_path="/bin/x",
            function_name="f",
            decomp="void f() {}",
            callers=[],
            callees=[],
            caller_classifications={},
            callee_classifications={},
            neighbour_decomps={},
            focus_cwe=None,
        )
        assert "stages" in prompt
        assert "sink_id" in prompt
        assert "source_id" in prompt
        assert "dataflow" in prompt
        assert "classification" in prompt


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_both_tools_registered(self):
        reg = ToolRegistry()
        register_taint_llm_tools(reg)
        names = {t["name"] for t in reg.get_anthropic_tools()}
        assert names == {"scan_taint_analysis", "deep_dive_taint_analysis"}

    def test_tool_schemas_shape(self):
        reg = ToolRegistry()
        register_taint_llm_tools(reg)
        for tool in reg.get_anthropic_tools():
            assert tool["input_schema"]["type"] == "object"
            assert "binary_path" in tool["input_schema"]["properties"]
            assert "binary_path" in tool["input_schema"]["required"]

    def test_scan_optional_params(self):
        reg = ToolRegistry()
        register_taint_llm_tools(reg)
        scan = next(
            t for t in reg.get_anthropic_tools()
            if t["name"] == "scan_taint_analysis"
        )
        props = scan["input_schema"]["properties"]
        for p in ("min_confidence", "max_candidates", "focus_cwe"):
            assert p in props
            assert p not in scan["input_schema"].get("required", [])

    def test_deepdive_requires_function_name(self):
        reg = ToolRegistry()
        register_taint_llm_tools(reg)
        deep = next(
            t for t in reg.get_anthropic_tools()
            if t["name"] == "deep_dive_taint_analysis"
        )
        assert "function_name" in deep["input_schema"]["required"]

    def test_taint_tools_present_in_full_registry(self):
        """Defence in depth: the create_tool_registry() factory wires both."""
        from app.ai import create_tool_registry
        reg = create_tool_registry()
        names = {t["name"] for t in reg.get_anthropic_tools()}
        assert "scan_taint_analysis" in names
        assert "deep_dive_taint_analysis" in names


# ---------------------------------------------------------------------------
# Handler integration — path traversal + error paths
# ---------------------------------------------------------------------------


@pytest.fixture
def firmware_with_binary(tmp_path: Path) -> Path:
    (tmp_path / "bin").mkdir()
    elf = tmp_path / "bin" / "vuln"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 60)
    return tmp_path


@pytest.fixture
def tool_context_for_taint(firmware_with_binary: Path) -> ToolContext:
    return ToolContext(
        project_id=uuid4(),
        firmware_id=uuid4(),
        extracted_path=str(firmware_with_binary),
        db=MagicMock(),
    )


@pytest.fixture
def registry_for_taint() -> ToolRegistry:
    reg = ToolRegistry()
    register_taint_llm_tools(reg)
    return reg


class TestPathTraversal:
    @pytest.mark.asyncio
    async def test_scan_rejects_traversal(
        self, registry_for_taint, tool_context_for_taint
    ):
        result = await registry_for_taint.execute(
            "scan_taint_analysis",
            {"binary_path": "/../../../etc/passwd"},
            tool_context_for_taint,
        )
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_deepdive_rejects_traversal(
        self, registry_for_taint, tool_context_for_taint
    ):
        result = await registry_for_taint.execute(
            "deep_dive_taint_analysis",
            {
                "binary_path": "/../../../etc/passwd",
                "function_name": "main",
            },
            tool_context_for_taint,
        )
        assert "Error" in result


class TestHandlerErrors:
    @pytest.mark.asyncio
    async def test_scan_rejects_bad_confidence(
        self, registry_for_taint, tool_context_for_taint
    ):
        result = await registry_for_taint.execute(
            "scan_taint_analysis",
            {"binary_path": "/bin/vuln", "min_confidence": "ultimate"},
            tool_context_for_taint,
        )
        assert "Error" in result
        assert "min_confidence" in result

    @pytest.mark.asyncio
    async def test_scan_missing_binary(
        self, registry_for_taint, tool_context_for_taint
    ):
        result = await registry_for_taint.execute(
            "scan_taint_analysis",
            {"binary_path": "/bin/does_not_exist"},
            tool_context_for_taint,
        )
        assert "Error" in result
        assert "not found" in result.lower()

    @pytest.mark.asyncio
    async def test_deepdive_requires_function_name(
        self, registry_for_taint, tool_context_for_taint
    ):
        result = await registry_for_taint.execute(
            "deep_dive_taint_analysis",
            {"binary_path": "/bin/vuln"},
            tool_context_for_taint,
        )
        assert "Error" in result
        assert "function_name" in result.lower()


class TestScanIntegrationMocked:
    """End-to-end: mock cache + decompile, assert prompt shape."""

    @pytest.mark.asyncio
    async def test_scan_produces_prompt_with_mocked_cache(
        self, registry_for_taint, tool_context_for_taint, firmware_with_binary
    ):
        fake_cache = MagicMock()
        fake_cache.ensure_analysis = AsyncMock(return_value="sha256_fake")

        # Two get_cached calls: (1) initial lookup for the scan-prompt cache
        # key (returns None → miss), (2) xref pull.
        xref_data = {
            "xrefs": {
                "vuln_handler": {
                    "from": [
                        {"to_func": "strcpy", "to": "0x100"},
                        {"to_func": "sprintf", "to": "0x200"},
                        {"to_func": "recv", "to": "0x50"},
                    ],
                    "to": [
                        {"from_func": "main", "from": "0x10"},
                        {"from_func": "dispatch", "from": "0x20"},
                        {"from_func": "loop", "from": "0x30"},
                    ],
                },
            }
        }

        async def mock_get_cached(fid, sha, op, db):
            if op == "xrefs":
                return xref_data
            return None  # first-time scan: no cached prompt

        fake_cache.get_cached = AsyncMock(side_effect=mock_get_cached)
        fake_cache.get_imports = AsyncMock(
            return_value=[
                {"name": "strcpy"},
                {"name": "sprintf"},
                {"name": "recv"},
            ]
        )
        fake_cache.store_cached = AsyncMock(return_value=None)

        async def fake_decompile(**kwargs):
            return (
                f"void {kwargs['function_name']}(char *in) {{\n"
                f"    char buf[64];\n"
                f"    strcpy(buf, in);\n"
                f"    sprintf(cmd, \"%s\", buf);\n"
                f"}}"
            )

        with patch(
            "app.ai.tools.taint_llm.ghidra_service", fake_cache
        ), patch(
            "app.ai.tools.taint_llm.decompile_function", side_effect=fake_decompile
        ):
            result = await registry_for_taint.execute(
                "scan_taint_analysis",
                {
                    "binary_path": "/bin/vuln",
                    "min_confidence": "medium",
                    "max_candidates": 10,
                },
                tool_context_for_taint,
            )

        assert "LATTE-Style Binary Taint Analysis" in result
        assert "vuln_handler" in result
        assert "strcpy" in result
        # Prompt was composed + cached
        assert fake_cache.store_cached.await_count == 1

    @pytest.mark.asyncio
    async def test_scan_cache_hit_returns_cached_prompt(
        self, registry_for_taint, tool_context_for_taint
    ):
        fake_cache = MagicMock()
        fake_cache.ensure_analysis = AsyncMock(return_value="sha_hit")
        cached_prompt = "CACHED: pre-built prompt"

        async def mock_get_cached(fid, sha, op, db):
            if op.startswith("taint_scan:"):
                return {"prompt": cached_prompt}
            return None

        fake_cache.get_cached = AsyncMock(side_effect=mock_get_cached)
        fake_cache.get_imports = AsyncMock(return_value=[])
        fake_cache.store_cached = AsyncMock()

        with patch(
            "app.ai.tools.taint_llm.ghidra_service", fake_cache
        ):
            result = await registry_for_taint.execute(
                "scan_taint_analysis",
                {"binary_path": "/bin/vuln"},
                tool_context_for_taint,
            )

        assert cached_prompt in result
        # cache hit → no write
        assert fake_cache.store_cached.await_count == 0


class TestDeepDiveIntegrationMocked:
    @pytest.mark.asyncio
    async def test_deepdive_produces_4stage_prompt(
        self, registry_for_taint, tool_context_for_taint
    ):
        fake_cache = MagicMock()
        fake_cache.ensure_analysis = AsyncMock(return_value="sha_dd")

        xref_data = {
            "xrefs": {
                "target_fn": {
                    "from": [{"to_func": "system", "to": "0x1"}],
                    "to": [{"from_func": "recv_handler", "from": "0x2"}],
                },
                "recv_handler": {
                    "from": [{"to_func": "recv", "to": "0x3"}],
                    "to": [],
                },
            }
        }

        async def mock_get_cached(fid, sha, op, db):
            if op == "xrefs":
                return xref_data
            return None

        fake_cache.get_cached = AsyncMock(side_effect=mock_get_cached)
        fake_cache.store_cached = AsyncMock(return_value=None)

        async def fake_decompile(**kwargs):
            return (
                "void target_fn(char *input) {\n"
                "    char cmd[128];\n"
                "    snprintf(cmd, 128, \"echo %s\", input);\n"
                "    system(cmd);\n"
                "}"
            )

        with patch(
            "app.ai.tools.taint_llm.ghidra_service", fake_cache
        ), patch(
            "app.ai.tools.taint_llm.decompile_function", side_effect=fake_decompile
        ):
            result = await registry_for_taint.execute(
                "deep_dive_taint_analysis",
                {
                    "binary_path": "/bin/vuln",
                    "function_name": "target_fn",
                },
                tool_context_for_taint,
            )

        assert "Stage 1" in result
        assert "Stage 4" in result
        assert "target_fn" in result
        assert "POTENTIAL SOURCE" in result or "POTENTIAL SINK" in result
