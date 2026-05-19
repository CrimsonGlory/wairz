# Authoring a File-Format YAML

This walkthrough takes you from "I have a firmware format wairz doesn't
recognise" to a working YAML manifest the classifier picks up on next
invocation. The example uses the Medtronic MMTP medical-device firmware
shape that motivated Wave-1 S4 of the file-format registry campaign.

## Step 0 — Decide where to write

| Goal | Path | `manifest_source` |
|------|------|-------------------|
| Contribute to the in-tree core catalog | `backend/app/services/file_format_catalog/data/file_formats/<vendor>/<format>.yaml` | `core` |
| Local-only addition that should never leave your host | `backend/app/services/file_format_catalog/data/file_formats.local/<format>.yaml` | `operator` |
| Override an existing manifest | same as above, plus `mode: override` + `overrides: <relative path>` | `operator` or `core` |

The on-disk path tier is the source of truth for `manifest_source` —
the loader rejects manifests where the declared value doesn't match the
inferred tier.

## Step 1 — Gather the format's fingerprint

Before writing any YAML, answer these:

1. **Magic bytes**. What's at offset 0 (or some other small fixed offset)
   that uniquely identifies the format? Run `xxd <sample> | head` and
   capture the first 8-16 bytes. If the format uses ASCII magic
   (e.g. `MSCF` for CAB), the hex form is `4d534346`.
2. **Filename hints**. Does the format have a canonical extension or
   stem (`.tibx`, `boot.img`)? Strict-typed Literal enumeration in
   `stems_lower` / `extensions_lower`.
3. **Path-context hints**. Does the format only live under a specific
   tree (`/vendor/firmware/`, `/system/etc/firmware/`)? Use
   `path_substrings_any_of` (min 6 chars, must start with `/`).
4. **Container hint** — does the format wrap inner files? ZIP / TAR
   detection signals can match against inner filenames.

Document each fingerprint source — datasheet section, ghidra walkthrough,
strings command output, whatever — in the `notes` field of the eventual
YAML. Wave-1 S5 NDA discipline: `notes` is `max_length: 8192`,
sufficient for compliance citations + spec page references.

## Step 2 — Pick a `format_id`

The `format_id` is globally unique across the catalog and must match
`^[a-z][a-z0-9_]*$`. Convention is `<vendor>_<format>` for vendor-
specific formats (`qcom_mbn`, `mtk_lk`, `samsung_shannon_toc`) and
`<family>_<format>` for cross-vendor formats (`android_apk`,
`linux_squashfs`). Reserved namespaces: `linux_*`, `android_*`,
`windows_*`, `pe_*`, `qnx_*`.

## Step 3 — Pick a `precedence`

Lower numbers win. Within the same `manifest_source` tier, sort order
is:

| Range | When to use |
|-------|-------------|
| 0-9 | Reserved for `_system` sentinels (catch-all fallbacks). |
| 10-79 | High-specificity vendor formats (`mtk_lk` precedence 50). |
| 80-199 | Universal formats with strong magic (`linux_squashfs` 100). |
| 200-499 | Universal formats with weaker magic (`zip_archive` 500). |
| 500-4999 | Last-resort routing. |
| 5000-9999 | Negative-evidence formats (PE/MZ at 9000). |

Magic ≤ 2 bytes REQUIRES `precedence >= 5000` — the schema enforces this.

## Step 4 — Write the YAML

Worked example — Medtronic MMTP medical-device firmware:

```yaml
# yaml-language-server: $schema=../../.schema.json
schema_version: 1
format_id: medtronic_mmtp
manifest_source: core
precedence: 100
category: medical_device
vendor: medtronic
confidence: high
notes: |
  Medtronic MiniMed Mobile (MMTP) insulin-pump firmware. Magic
  'MMTP' (4 ASCII bytes) at offset 0. Documented under Medtronic
  PMA P140005 (FDA approval 2014); see Wave-1 S4 § "Medtronic
  Insulin Pump Firmware Shape" for the parser reference.
detection:
  combine: all_required
  signals:
    - kind: magic_bytes
      offset: 0
      bytes_hex: "4d4d5450"
      description: "'MMTP' magic at offset 0"
    - kind: filename
      extensions_lower: [".mmtp", ".bin"]
      description: "MMTP / bare bin extensions"
output:
  classifier_format: medtronic_mmtp
  classifier_category: medical_device
  classifier_vendor: medtronic
  classifier_product: minimed_770g
  confidence: high
pre_upload:
  detected_format: unknown   # not in the Literal yet — propose via Rule #25 alignment
  extraction_capability: none
  banner_note: |
    Medtronic MMTP insulin-pump firmware detected. Static analysis
    works; extraction requires a vendor-specific parser not yet
    shipped in wairz.
```

Save as
`backend/app/services/file_format_catalog/data/file_formats/medtronic/medtronic_mmtp.yaml`
(create the `medtronic/` directory first).

## Step 5 — Validate the YAML

Run the catalog loader against your edit:

```bash
( cd backend && uv run python -c "
from app.services.file_format_catalog.catalog import FormatCatalog
from pathlib import Path
c = FormatCatalog(
    root_resolver=lambda: Path('app/services/file_format_catalog/data/file_formats'),
    local_root_resolver=lambda: Path('app/services/file_format_catalog/data/file_formats.local'),
)
catalog = c.get_catalog()
print(f'{len(catalog)} manifests loaded')
print(f'last_warning: {c.last_warning}')
assert 'medtronic_mmtp' in catalog, 'manifest not loaded — check last_warning'
print('OK')
" )
```

Expected output:

```
48 manifests loaded
last_warning: None
OK
```

If `last_warning` is non-None, fix the YAML. The most common errors are:

- `mode=override requires overrides: <path>` — set `overrides:` to the
  prior manifest's relative path.
- `magic_bytes: bytes_hex must have even length` — count your hex chars;
  4 hex chars = 2 bytes, not 1.
- `magic_bytes <=2 bytes (e.g. PE/MZ) requires precedence >= 5000` —
  bump `precedence`.
- `precedence=N: range [0,9] is RESERVED for _system manifests` —
  `core` / `operator` manifests need `precedence >= 10`.

See `ERROR_GLOSSARY.md` for the full mapping.

## Step 6 — Run the test suite

```bash
( cd backend && uv run pytest tests/test_file_format_schema.py tests/test_file_format_catalog.py tests/test_file_format_tools.py -q )
```

All 118 tests should PASS. New format additions don't require new tests
(the existing suite exercises shape contracts, not per-format
coverage) — but if your format pioneers a new schema feature (a new
signal kind, a new dispatch kind, etc.), file a Rule #25 single-slice
cross-stack alignment commit that includes a Rule #46 META-CANARY.

## Step 7 — Cross-stack alignment (when needed)

Adding a value to a CLOSED Literal (e.g. a new `DetectionSignalKind`,
a new `DetectedFormat` enum value) requires alignment across the schema
+ the resolver + the frontend's mirror Record + the cross-stack
alignment test. See CLAUDE.md Rule #25 Single-slice exception #2 and
the recipe at `.mex/patterns/cross-stack-alignment-test.md`.

Adding a new FREE STRING (vendor / category / product) does NOT require
alignment — those are open by design.

## Step 8 — Commit per Rule #25

Add the YAML, run the catalog-load check, run the test suite, commit
once (one YAML = one commit, per Rule #25 single-slice cadence).
Commit message shape:

```
feat(file-format): <format_id> manifest

<one paragraph on what the format is, where it's seen, the
fingerprint chosen, and any compliance / NDA citations.>
```

## Pointers

- `SCHEMA_REFERENCE.md` — every closed Literal enumerated.
- `ERROR_GLOSSARY.md` — every `validate_file_format` error code.
- `CONTRIBUTING.md` — PR / review discipline.
- `README.md` — directory purpose + tier ranking.
