#!/usr/bin/env python3
"""Export file-format manifest JSON Schema for yaml-language-server LSP autocomplete.

Run from repo root:
    cd backend && uv run python ../scripts/export_file_format_schema.py

Output: backend/app/services/file_format_catalog/data/file_formats/.schema.json
Operator YAML files include this header for editor support:
    # yaml-language-server: $schema=../../.schema.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import TypeAdapter

from app.schemas.file_format import FileFormatManifest

OUTPUT_PATH = (
    Path(__file__).resolve().parent.parent
    / "backend"
    / "app"
    / "services"
    / "file_format_catalog"
    / "data"
    / "file_formats"
    / ".schema.json"
)


def main() -> int:
    adapter = TypeAdapter(FileFormatManifest)
    schema = adapter.json_schema(by_alias=False, ref_template="#/$defs/{model}")
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
