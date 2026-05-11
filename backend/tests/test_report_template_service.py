"""Tests for the YAML report template loader."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from app.services import report_template_service as rts


@pytest.fixture
def template_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the loader at an isolated template directory and clear its cache."""
    monkeypatch.setattr(rts, "TEMPLATE_DIR", tmp_path)
    rts.get_templates.cache_clear()
    yield tmp_path
    rts.get_templates.cache_clear()


def _write_template(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")


class TestTemplateLoader:
    def test_loads_valid_template(self, template_dir: Path):
        _write_template(template_dir / "minimal.yaml", """
            id: minimal_v1
            name: Minimal
            version: 1
            findings_order: 50
            sections:
              - slug: intro
                title: Intro
                required: true
                order: 10
              - slug: outro
                title: Outro
                required: false
                order: 60
        """)
        templates = rts.get_templates()
        assert "minimal_v1" in templates
        tpl = rts.get_template("minimal_v1")
        assert tpl.name == "Minimal"
        assert [s.slug for s in tpl.sections] == ["intro", "outro"]

    def test_rejects_duplicate_slugs(self, template_dir: Path):
        _write_template(template_dir / "dup.yaml", """
            id: dup_v1
            name: Dup
            sections:
              - slug: a
                title: A
                order: 10
              - slug: a
                title: A again
                order: 20
        """)
        with pytest.raises(RuntimeError, match="duplicate slugs"):
            rts.get_templates()

    def test_rejects_section_with_findings_order(self, template_dir: Path):
        _write_template(template_dir / "collide.yaml", """
            id: collide_v1
            name: Collide
            findings_order: 50
            sections:
              - slug: bad
                title: Bad
                order: 50
        """)
        with pytest.raises(RuntimeError, match="reserved for findings"):
            rts.get_templates()

    def test_rejects_duplicate_template_id(self, template_dir: Path):
        for name in ("a.yaml", "b.yaml"):
            _write_template(template_dir / name, """
                id: same_id
                name: Same
                sections:
                  - slug: only
                    title: Only
                    order: 10
            """)
        with pytest.raises(RuntimeError, match="duplicate template id"):
            rts.get_templates()

    def test_unknown_id_raises_template_not_found(self, template_dir: Path):
        _write_template(template_dir / "ok.yaml", """
            id: ok_v1
            name: OK
            sections:
              - slug: only
                title: Only
                order: 10
        """)
        with pytest.raises(rts.TemplateNotFoundError):
            rts.get_template("missing")

    def test_default_template_id_picks_standard_when_present(
        self, template_dir: Path
    ):
        _write_template(template_dir / "standard.yaml", """
            id: standard_iot_pentest_v1
            name: Standard
            sections:
              - slug: only
                title: Only
                order: 10
        """)
        _write_template(template_dir / "other.yaml", """
            id: other_v1
            name: Other
            sections:
              - slug: only
                title: Only
                order: 10
        """)
        assert rts.default_template_id() == "standard_iot_pentest_v1"


class TestShippedTemplate:
    """Smoke test for the actual standard_iot_pentest_v1.yaml file we ship."""

    def test_standard_template_is_valid(self):
        # Hit the real template dir, not the monkeypatched one.
        rts.get_templates.cache_clear()
        try:
            tpl = rts.get_template("standard_iot_pentest_v1")
            slugs = [s.slug for s in tpl.sections]
            for required in ("executive_summary", "scope", "methodology",
                             "risk_summary", "conclusion"):
                assert required in slugs, f"missing required slug {required}"
            assert tpl.findings_order == 50
        finally:
            rts.get_templates.cache_clear()
