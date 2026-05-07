"""Service-layer tests for ``app.services.analysis_service``.

Phase 2 Wave 10 file 1 of 2 — backfills service-layer tests for the
ELF protection checker (83 LOC) per intake
audit-test-coverage-routers-services-2026-05-04.

Triage shape (Rule #19 evidence-first):

* No persistence — pure function returning a dict.
* No lazy imports — ``elftools.elf.elffile.ELFFile`` is bound at the
  top of the module.
* External boundary is ``open(binary_path, "rb")`` + ``ELFFile`` parser.
* Strong canary value: shape verification of the returned dict
  ("nx", "relro", "canary", "pie", "fortify", "stripped") for both
  the success and parse-error paths. The function's flag computation
  is non-trivial (NX from PT_GNU_STACK + PF_X bit, RELRO from
  PT_GNU_RELRO + DT_BIND_NOW interaction, canary/fortify from
  .dynsym scanning).

Rule #30 distribution: ``elftools.elf.elffile.ELFFile`` is TOP-LEVEL
imported on line 3. The inverse-Rule-30 shape applies — patches MUST
hit the CONSUMER module
(``app.services.analysis_service.ELFFile``), not the source library.

Coverage targets:

* ``check_binary_protections`` — invalid ELF returns ``{"error": ...}``
* ``check_binary_protections`` — NX enabled (PF_X bit clear)
* ``check_binary_protections`` — NX disabled (PF_X bit set)
* ``check_binary_protections`` — full RELRO (PT_GNU_RELRO + DT_BIND_NOW)
* ``check_binary_protections`` — partial RELRO (PT_GNU_RELRO only)
* ``check_binary_protections`` — full RELRO via DT_FLAGS DF_BIND_NOW
* ``check_binary_protections`` — no RELRO (no segments)
* ``check_binary_protections`` — PIE detected (e_type=ET_DYN)
* ``check_binary_protections`` — non-PIE (e_type=ET_EXEC)
* ``check_binary_protections`` — canary detected via __stack_chk_fail
* ``check_binary_protections`` — fortify detected via __memcpy_chk
* ``check_binary_protections`` — stripped binary (no .symtab)
* ``check_binary_protections`` — non-stripped binary (.symtab present)
* ``check_binary_protections`` — ELFFile constructor exception path
* **Rule #30 inverse-consumer-patch sentinels** — ELFFile is bound at
  consumer module scope.
"""
from __future__ import annotations

from unittest.mock import MagicMock, mock_open, patch

from app.services import analysis_service as analysis_mod
from app.services.analysis_service import check_binary_protections


# ===========================================================================
# Helpers — minimal fakes that mimic the pyelftools ELFFile surface used.
# ===========================================================================


def _make_segment(p_type: str, p_flags: int = 0, tags: list | None = None):
    """Fabricate a fake ELF segment object.

    Mirrors the pyelftools surface used by ``check_binary_protections``:
    ``seg.header.p_type`` / ``.p_flags`` and ``seg.iter_tags()`` for
    PT_DYNAMIC.
    """
    seg = MagicMock()
    seg.header.p_type = p_type
    seg.header.p_flags = p_flags

    if tags is None:
        seg.iter_tags = MagicMock(side_effect=Exception("not dynamic"))
    else:
        seg.iter_tags = MagicMock(return_value=tags)
    return seg


def _make_dynamic_tag(d_tag: str, d_val: int = 0):
    """Fabricate a PT_DYNAMIC tag entry with the .entry.d_tag/.d_val shape."""
    t = MagicMock()
    t.entry.d_tag = d_tag
    t.entry.d_val = d_val
    return t


def _make_symbol(name: str):
    s = MagicMock()
    s.name = name
    return s


def _make_elf(
    *,
    segments: list | None = None,
    e_type: str = "ET_EXEC",
    dynsym_symbols: list | None = None,
    has_symtab: bool = True,
):
    """Build a fake ELFFile object."""
    elf = MagicMock()
    elf.iter_segments.return_value = segments or []
    elf.header.e_type = e_type

    sections = {}
    if dynsym_symbols is not None:
        dynsym = MagicMock()
        dynsym.iter_symbols.return_value = dynsym_symbols
        sections[".dynsym"] = dynsym
    if has_symtab:
        sections[".symtab"] = MagicMock()

    elf.get_section_by_name.side_effect = lambda name: sections.get(name)
    return elf


# ===========================================================================
# Tests
# ===========================================================================


class TestInvalidELF:
    def test_elffile_constructor_raises_returns_error_dict(self):
        """If pyelftools can't parse the file, we return an error dict."""
        with patch("builtins.open", mock_open(read_data=b"not an elf")):
            with patch.object(analysis_mod, "ELFFile", side_effect=Exception("bad elf")):
                result = check_binary_protections("/path/to/notelf")
        assert result == {"error": "Not a valid ELF file"}


class TestNXFlag:
    def test_nx_enabled_when_pf_x_bit_clear(self):
        elf = _make_elf(
            segments=[_make_segment("PT_GNU_STACK", p_flags=0b110)],  # PF_R | PF_W, no PF_X
        )
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["nx"] is True

    def test_nx_disabled_when_pf_x_bit_set(self):
        elf = _make_elf(
            segments=[_make_segment("PT_GNU_STACK", p_flags=0b111)],  # PF_R | PF_W | PF_X
        )
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["nx"] is False

    def test_nx_default_false_when_no_gnu_stack_segment(self):
        elf = _make_elf(segments=[])
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["nx"] is False


class TestRELROFlag:
    def test_full_relro_with_pt_gnu_relro_and_dt_bind_now(self):
        elf = _make_elf(
            segments=[
                _make_segment("PT_GNU_RELRO"),
                _make_segment("PT_DYNAMIC", tags=[_make_dynamic_tag("DT_BIND_NOW")]),
            ],
        )
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["relro"] == "full"

    def test_full_relro_via_dt_flags_df_bind_now_bit(self):
        elf = _make_elf(
            segments=[
                _make_segment("PT_GNU_RELRO"),
                _make_segment(
                    "PT_DYNAMIC",
                    tags=[_make_dynamic_tag("DT_FLAGS", d_val=0x8)],  # DF_BIND_NOW
                ),
            ],
        )
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["relro"] == "full"

    def test_partial_relro_without_bind_now(self):
        elf = _make_elf(
            segments=[
                _make_segment("PT_GNU_RELRO"),
                _make_segment("PT_DYNAMIC", tags=[_make_dynamic_tag("DT_NULL")]),
            ],
        )
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["relro"] == "partial"

    def test_no_relro_when_no_segments(self):
        elf = _make_elf(segments=[])
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["relro"] == "none"

    def test_dynamic_iter_tags_exception_swallowed(self):
        """Defensive: PT_DYNAMIC with iter_tags() that raises must not
        propagate — the function silently treats it as "no BIND_NOW found".
        """
        elf = _make_elf(
            segments=[
                _make_segment("PT_GNU_RELRO"),
                _make_segment("PT_DYNAMIC"),  # no tags → iter_tags raises
            ],
        )
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["relro"] == "partial"


class TestPIEFlag:
    def test_pie_true_when_et_dyn(self):
        elf = _make_elf(segments=[], e_type="ET_DYN")
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["pie"] is True

    def test_pie_false_when_et_exec(self):
        elf = _make_elf(segments=[], e_type="ET_EXEC")
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["pie"] is False


class TestCanaryFortify:
    def test_canary_detected_via_stack_chk_fail(self):
        elf = _make_elf(
            segments=[],
            dynsym_symbols=[_make_symbol("__stack_chk_fail")],
        )
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["canary"] is True

    def test_fortify_detected_via_chk_suffixed_symbol(self):
        elf = _make_elf(
            segments=[],
            dynsym_symbols=[
                _make_symbol("__memcpy_chk"),
                _make_symbol("__strcpy_chk"),
            ],
        )
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["fortify"] is True

    def test_canary_and_fortify_false_when_no_dynsym_section(self):
        """No .dynsym → both flags stay at default False."""
        elf = _make_elf(segments=[], dynsym_symbols=None)
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["canary"] is False
        assert result["fortify"] is False

    def test_unrelated_symbols_do_not_trigger_canary_or_fortify(self):
        elf = _make_elf(
            segments=[],
            dynsym_symbols=[
                _make_symbol("printf"),
                _make_symbol("malloc"),
                _make_symbol("strlen"),
            ],
        )
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["canary"] is False
        assert result["fortify"] is False


class TestStrippedFlag:
    def test_stripped_true_when_no_symtab(self):
        elf = _make_elf(segments=[], has_symtab=False)
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["stripped"] is True

    def test_stripped_false_when_symtab_present(self):
        elf = _make_elf(segments=[], has_symtab=True)
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result["stripped"] is False


class TestReturnedShape:
    def test_returns_all_six_keys(self):
        """Sanity: the success path always yields the documented dict shape."""
        elf = _make_elf(segments=[])
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert set(result.keys()) == {"nx", "relro", "canary", "pie", "fortify", "stripped"}

    def test_combined_hardened_binary(self):
        """Realistic scenario: a fully-hardened binary trips every flag."""
        elf = _make_elf(
            segments=[
                _make_segment("PT_GNU_STACK", p_flags=0b110),  # NX
                _make_segment("PT_GNU_RELRO"),
                _make_segment("PT_DYNAMIC", tags=[_make_dynamic_tag("DT_BIND_NOW")]),
            ],
            e_type="ET_DYN",  # PIE
            dynsym_symbols=[
                _make_symbol("__stack_chk_fail"),
                _make_symbol("__printf_chk"),
            ],
            has_symtab=False,  # stripped
        )
        with patch("builtins.open", mock_open()):
            with patch.object(analysis_mod, "ELFFile", return_value=elf):
                result = check_binary_protections("/x")
        assert result == {
            "nx": True,
            "relro": "full",
            "canary": True,
            "pie": True,
            "fortify": True,
            "stripped": True,
        }


# ===========================================================================
# Rule #30 inverse-consumer-patch sentinels
# ===========================================================================


class TestRule30InverseConsumerPatch:
    """Document that analysis_service binds ELFFile at module scope;
    patches MUST hit the consumer module.
    """

    def test_consumer_module_binds_elffile(self):
        # ``from elftools.elf.elffile import ELFFile`` at line 3.
        assert hasattr(analysis_mod, "ELFFile")

    def test_consumer_module_does_not_lazy_import_elffile(self):
        """If a future refactor moves ``ELFFile`` inside the function body,
        every test in this file's patch.object(analysis_mod, "ELFFile") will
        become a silent no-op (Rule #30). Sentinel: the module-level binding
        must remain.
        """
        import inspect
        src = inspect.getsource(check_binary_protections)
        # If a lazy import slips in, this assertion catches it.
        assert "from elftools" not in src
        assert "import elftools" not in src
