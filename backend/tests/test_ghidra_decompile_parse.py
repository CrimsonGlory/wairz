"""Decompile parsers must strip Ghidra's headless log wrapper.

DecompileFunction.java output comes back with each println wrapped as
"INFO  DecompileFunction.java> <text> (GhidraScript)". Only the first physical
line of a multi-line println is wrapped, so real output is a mix of prefixed,
bare, and suffix-only lines. Both single and batch parsers must return clean C.
"""

from app.services.ghidra_service import (
    _parse_batch_decompile_output,
    _parse_decompile_output,
    _strip_ghidra_log_line,
    _strip_ghidra_log_wrapper,
)

# Mirrors what the live cloud worker actually emitted for httpd handle_request.
RAW = """\
Some headless preamble noise
===DECOMPILE_START===
(GhidraScript)
INFO  DecompileFunction.java> // Function: handle_request (GhidraScript)
INFO  DecompileFunction.java> // Address:  000263d0 (GhidraScript)
INFO  DecompileFunction.java>  (GhidraScript)
INFO  DecompileFunction.java>
void handle_request(int param_1)
{
  int local_10;
  local_10 = param_1 + 1;
  return;
}
===DECOMPILE_END===
trailing noise
"""

# Fully-wrapped format: every println() CALL is wrapped (Ghidra 12.x headless).
# Multi-line println(code) yields prefix-only first line, bare middle lines,
# and a lone ' (GhidraScript)' suffix line.
_PREFIX = "INFO  DecompileFunction.java> "
_SUFFIX = " (GhidraScript)  "


def _wrap(content: str) -> str:
    """One fully-wrapped single-line println()."""
    return f"{_PREFIX}{content}{_SUFFIX}"


def _make_real_ghidra_block(name: str) -> str:
    """A single decompile block exactly as Ghidra headless emits it."""
    return "\n".join(
        [
            _wrap("===DECOMPILE_START==="),
            _wrap(f"// Function: {name}"),
            _wrap("// Address:  8005b79c"),
            _wrap("// Size:     312 bytes"),
            _wrap(""),  # println("")
            _PREFIX,  # prefix-only: start of multi-line println(code)
            f"void {name}(void)",  # bare code lines (no prefix/suffix)
            "{",
            "  return;",
            "}",
            _SUFFIX.rstrip() + "  ",  # lone-suffix line ending the multi-line println
            _wrap("===DECOMPILE_END==="),
        ]
    ) + "\n"


def test_strips_prefix_and_suffix():
    out = _parse_decompile_output(RAW)
    assert out is not None
    # No log wrapper survives.
    assert "GhidraScript" not in out
    assert "DecompileFunction.java>" not in out
    assert "INFO" not in out
    # Wrapped comment lines are cleaned...
    assert "// Function: handle_request" in out
    assert "// Address:  000263d0" in out
    # ...and bare code lines pass through untouched.
    assert "void handle_request(int param_1)" in out
    assert "  local_10 = param_1 + 1;" in out


def test_bare_content_unchanged():
    bare = "int foo(void)\n{\n  return 0;\n}"
    assert _strip_ghidra_log_wrapper(bare) == bare


def test_missing_markers_returns_none():
    assert _parse_decompile_output("no markers here") is None


def test_strips_ghidra_log_wrapping_from_individual_output():
    """Real fully-wrapped headless block must parse without log leakage."""
    raw = _make_real_ghidra_block("FUN_8005b79c")
    result = _parse_decompile_output(raw)
    assert result is not None
    assert "void FUN_8005b79c" in result
    assert "GhidraScript" not in result
    assert "INFO  DecompileFunction.java>" not in result


class TestStripGhidraLogLine:
    def test_strips_fully_wrapped_line(self):
        assert _strip_ghidra_log_line(_wrap("===DECOMPILE_START===")) == "===DECOMPILE_START==="

    def test_strips_prefix_only_line(self):
        assert _strip_ghidra_log_line(_PREFIX) == ""

    def test_strips_suffix_only_line(self):
        assert _strip_ghidra_log_line(_SUFFIX) == ""

    def test_leaves_bare_code_line_untouched(self):
        assert _strip_ghidra_log_line("  return;") == "  return;"

    def test_noop_on_clean_marker(self):
        assert _strip_ghidra_log_line("===DECOMPILE_END===") == "===DECOMPILE_END==="


class TestParseBatchDecompileOutput:
    def test_clean_output(self):
        """Baseline: clean markers (no log wrapping) still parse."""
        raw = (
            "===DECOMPILE_START===\n"
            "// Function: foo\n"
            "// Address:  0x1000\n"
            "\n"
            "void foo(void) { return; }\n"
            "===DECOMPILE_END===\n"
        )
        results = _parse_batch_decompile_output(raw)
        assert results.get("foo") is not None
        assert "void foo" in results["foo"]

    def test_live_cloud_worker_format(self):
        """Live cloud fixture (markers bare, metadata wrapped) must parse."""
        results = _parse_batch_decompile_output(RAW)
        assert results.get("handle_request") is not None, (
            "batch parser must handle live worker log-wrapped Function: lines"
        )
        code = results["handle_request"]
        assert "void handle_request" in code
        assert "GhidraScript" not in code
        assert "INFO  DecompileFunction.java>" not in code

    def test_real_ghidra_wrapped_single(self):
        """Fully-wrapped headless format must parse — the reported 0/N bug."""
        raw = _make_real_ghidra_block("FUN_8005b79c")
        results = _parse_batch_decompile_output(raw)
        assert results.get("FUN_8005b79c") is not None, (
            "batch parser must handle real Ghidra log-wrapped output"
        )
        code = results["FUN_8005b79c"]
        assert "void FUN_8005b79c" in code
        assert "GhidraScript" not in code
        assert "INFO  DecompileFunction.java>" not in code

    def test_real_ghidra_wrapped_ten_functions(self):
        """Ten wrapped blocks, every one must be found (the 0/10 symptom)."""
        names = [f"func_{i}" for i in range(10)]
        raw = "".join(_make_real_ghidra_block(n) for n in names)
        results = _parse_batch_decompile_output(raw)
        for name in names:
            assert results.get(name) is not None, f"missing: {name}"
            assert f"void {name}" in results[name]
            assert "GhidraScript" not in results[name]
