# Contributing a File-Format YAML

Submission discipline for file-format manifests destined for the in-tree
core catalog.

## PR shape

One manifest per commit, per Rule #25 single-slice cadence. Commit
message:

```
feat(file-format): <format_id> manifest

<one paragraph on the format, fingerprint source, compliance citations.>
```

Bundling multiple unrelated formats in a single commit makes
`git revert` per-format impossible and pollutes `git bisect` lanes.

## Fixture-attestation requirement

Each new manifest with a magic-byte signal SHOULD ship a fixture sample
under `backend/tests/fixtures/file_formats/<format_id>/` so the
schema-test suite can verify the manifest matches against real data.

Fixtures MUST be:

- ≤ 16 KB each (full firmware blobs go in shared test data, not the
  per-format fixture directory).
- Attributable: include a `<format_id>.attestation.md` declaring the
  fixture's provenance (vendor sample, intentionally-crafted artifact,
  randomised generation per spec).
- Free of customer data: no real device dumps; intentionally-crafted
  artifacts mimicking the format's documented header are preferred.

If the format is NDA-only and no public fixture can ship, document the
fact in the manifest's `notes` field. The schema-test suite will skip
fixture validation for manifests without a fixture directory.

## Magic-collision discipline

Before submitting, run the catalog load + check for A4 collisions:

```bash
( cd backend && uv run python -c "
from app.services.file_format_catalog.catalog import FormatCatalog
from pathlib import Path
c = FormatCatalog(
    root_resolver=lambda: Path('app/services/file_format_catalog/data/file_formats'),
    local_root_resolver=lambda: Path('app/services/file_format_catalog/data/file_formats.local'),
)
catalog = c.get_catalog()
if c.last_warning:
    raise SystemExit(f'last_warning: {c.last_warning}')
print(f'OK — {len(catalog)} manifests')
" )
```

If your manifest shares magic bytes + precedence + manifest_source with
an existing format, the loader will REJECT BOTH. Options:

1. **Bump precedence** if your format is genuinely more specific.
2. **Add a filename or path_context signal** to disambiguate.
3. **File a Rule #25 cross-stack alignment commit** if both formats
   are legitimate and the resolution belongs in the resolver layer
   (rare).

## Alignment-test expectations

Adding a value to a CLOSED Literal triggers Rule #25 Single-slice
exception #2 — bundle the schema change + DB CHECK migration +
frontend Record mirror in ONE atomic commit. The
`tests/test_finding_source_alignment.py`-style alignment test catches
drift if you forget; the cross-stack-alignment-test recipe is at
`.mex/patterns/cross-stack-alignment-test.md`.

Adding a FREE STRING (vendor / category / product) does NOT require
alignment.

## Review checklist for reviewers

- [ ] `manifest_source` matches the on-disk path tier (loader enforces).
- [ ] `format_id` matches `^[a-z][a-z0-9_]*$`, doesn't collide with
  existing entries.
- [ ] Magic-byte signal references a real spec / datasheet section, NOT
  guesswork from a single sample.
- [ ] `precedence` follows the table in `AUTHORING.md` Step 3.
- [ ] `notes` field cites the fingerprint source.
- [ ] `pre_upload` block aligns with `format_detection.detect_format`
  if the format is in the `DetectedFormat` Literal.
- [ ] Fixture-attestation present (or NDA exemption documented).
- [ ] Catalog load completes with `last_warning: None`.
- [ ] Test suite passes (`pytest tests/test_file_format_*.py -q`).
- [ ] CLAUDE.md Rule #52 + Rule #25 + Rule #46 disciplines followed.

## See also

- CLAUDE.md Rule #52 — schema-driven extensibility hard rule.
- CLAUDE.md Rule #25 — per-piece commit + single-slice exception.
- CLAUDE.md Rule #46 — META-CANARY for absence-asserting gates.
- `AUTHORING.md` — walkthrough.
- `SCHEMA_REFERENCE.md` — every Literal + constraint.
- `ERROR_GLOSSARY.md` — error-code → remediation mapping.
