"""Loads and validates report templates from YAML.

Templates live as YAML files in ``backend/report_templates/`` and are loaded
once on first access. Each template defines an ordered list of typed
sections; the renderer auto-injects the findings section at the
``findings_order`` slot, so templates do not declare findings explicitly.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator


class TemplateSection(BaseModel):
    slug: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=255)
    required: bool = False
    order: int
    max_words: int | None = None
    guidance: str = ""


class ReportTemplate(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    name: str
    version: int = 1
    language: str = "en"
    findings_order: int = 50
    sections: list[TemplateSection]

    @model_validator(mode="after")
    def _validate_unique_slugs(self) -> "ReportTemplate":
        slugs = [s.slug for s in self.sections]
        if len(set(slugs)) != len(slugs):
            raise ValueError(f"duplicate slugs in template {self.id}: {slugs}")
        if any(s.order == self.findings_order for s in self.sections):
            raise ValueError(
                f"section order {self.findings_order} is reserved for findings"
            )
        return self

    def section_for_slug(self, slug: str) -> TemplateSection | None:
        for section in self.sections:
            if section.slug == slug:
                return section
        return None


class TemplateNotFoundError(KeyError):
    """Raised when a caller asks for a template id that wasn't loaded."""


TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent / "report_templates"


def _load_all() -> dict[str, ReportTemplate]:
    templates: dict[str, ReportTemplate] = {}
    if not TEMPLATE_DIR.is_dir():
        return templates
    for path in sorted(TEMPLATE_DIR.glob("*.yaml")):
        # Skip render-pipeline assets — only top-level YAMLs are templates.
        if path.parent != TEMPLATE_DIR:
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            template = ReportTemplate.model_validate(data)
        except (yaml.YAMLError, ValidationError) as exc:
            raise RuntimeError(f"invalid report template {path}: {exc}") from exc
        if template.id in templates:
            raise RuntimeError(
                f"duplicate template id {template.id!r} in {path.name}"
            )
        templates[template.id] = template
    return templates


@lru_cache(maxsize=1)
def get_templates() -> dict[str, ReportTemplate]:
    return _load_all()


def get_template(template_id: str) -> ReportTemplate:
    templates = get_templates()
    if template_id not in templates:
        raise TemplateNotFoundError(template_id)
    return templates[template_id]


def list_templates() -> list[ReportTemplate]:
    return list(get_templates().values())


def default_template_id() -> str:
    """The template_id new reports default to when the caller doesn't pick one."""
    templates = get_templates()
    if not templates:
        raise RuntimeError("no report templates loaded")
    if "standard_iot_pentest_v1" in templates:
        return "standard_iot_pentest_v1"
    return next(iter(templates))
