"""_parse_decompile_output must strip Ghidra's headless log wrapper.

DecompileFunction.java output (used for on-demand single-function decompiles)
comes back with each println wrapped as "INFO  DecompileFunction.java> <text>
(GhidraScript)". Only the first physical line of a multi-line println is
wrapped, so real output is a mix of prefixed and bare lines. The parser must
return clean C either way.
"""

from app.services.ghidra_service import (
    _parse_decompile_output,
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
