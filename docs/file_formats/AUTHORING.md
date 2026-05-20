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

**Lower numbers win.** The resolver sorts candidates by
`(tier_rank, -source_rank, precedence, -specificity, vendor, basename)`
in ascending order — so `precedence: 50` beats `precedence: 100`.
This matches the convention documented across all 47 in-tree manifest
notes (P3.2.a resolver-sort-direction reform, 2026-05-19; prior versions
of the resolver inverted the comparison, an inconsistency
[Wave-1 S2 audit](../../.planning/research/file-format-yaml-registry-p32-wave1-S2-precedence-partial-order-2026-05-19.md)
caught).

Within the same `manifest_source` tier, sort order is:

| Range | When to use |
|-------|-------------|
| 0-9 | Reserved for `_system` sentinels (catch-all fallbacks). |
| 10-79 | High-specificity vendor formats (`mtk_lk` precedence 50). |
| 80-199 | Universal formats with strong magic (`linux_squashfs` 100). |
| 200-499 | Universal formats with weaker magic (`zip_archive` 500). |
| 500-4999 | Last-resort routing. |
| 5000-9999 | Negative-evidence formats (PE/MZ at 9000). |

Magic ≤ 2 bytes REQUIRES `precedence >= 5000` — the schema enforces this.

## Step 3b — `detection.sort_tier` (advanced)

Most manifests don't need to touch this — leave it at the default
`general` and `precedence` carries the ordering. The three values:

| Tier | Reserved to | Semantic | Authored example |
|------|-------------|----------|-------|
| `ceiling` | `manifest_source: _system` | Invariants: ALWAYS wins among matched candidates regardless of operator precedence. **No current author** — slot reserved for future "THIS magic is ALWAYS this format" cases. | (none) |
| `general` | All sources | Default — sort by `source_rank` / `precedence` / `specificity`. | All in-tree `core` / `operator` / `_system` non-sentinel manifests. |
| `floor` | `manifest_source: _system` | Sentinel catch-alls: ALWAYS LOSE among matched candidates. Today: `_system/linux_blob_fallback.yaml` only. | `_system/linux_blob_fallback.yaml` |

The schema rejects `sort_tier: floor` and `sort_tier: ceiling` from
non-`_system` sources at parse time. Combined with the
`detection.always_matches=True ⇒ sort_tier='floor'` cross-field
validator, the operator cannot author a manifest that demotes the
sentinel or that wins over invariants. See
`backend/tests/test_file_format_sort_tier.py` for the regression battery
+ four paired Rule #46 META-CANARIES.

A `_system` manifest MAY use `general` (e.g. `_system/linux_squashfs.yaml`
declares its detection in normal sort space). The reserved tiers are
opt-in.

## Step 3c — Container precedence (more-specific wins over wrappers)

When a container format wraps another container (Windows installer ISO
wraps ISO-9660; MSU is a self-extracting CAB; ZIP-based APK/OTA wraps a
generic ZIP archive), the more-specific manifest should win when both
match.  Under the post-P3.2.a "lower precedence wins" semantic, this
means the more-specific manifest gets a **lower** numeric precedence.

Worked examples shipped in `_system/`:

| More-specific (wins) | Less-specific (loses) | Precedence pair | Discriminator |
|----------------------|------------------------|-----------------|---------------|
| `windows_msu`        | `windows_cab`          | 80 vs 100       | `.msu` extension on the MSU manifest |
| `windows_installer_iso` | `iso_9660`           | 100 vs 200      | `.iso` / `.img` extension *(see footnote)* |
| `android_apk`        | `zip_archive`          | (apk wins via filename + zip_markers inner-file walk) |
| `android_ota`        | `zip_archive`          | (ota wins via filename + zip_markers inner-file walk) |

**Footnote — windows_installer_iso vs iso_9660:** The current catalog
schema has no "head contains substring X" signal evaluator, so the
windows_installer_iso manifest can't yet require the `bootmgr` literal
inside the head bytes. As a result, the manifest matches bare ISO-9660
images with a `.iso` extension that aren't actually Windows installer
media.  The pre-upload `detect_format()` path bridges via
`_legacy_bridge_detect` to upgrade ISO → installer-ISO only when the
`bootmgr` substring is present.  When a `substring_in_head` signal kind
ships (P3.x), windows_installer_iso will declare it directly and the
bridge becomes redundant.

When picking a precedence for a new container-wrapping manifest, follow
the smaller-number-wins rule and leave headroom on each side:

* 50 — very specific, vendor + extension + inner-marker (e.g. `qcom_mbn` PIL).
* 100 — specific container (e.g. `linux_squashfs`).
* 200 — generic container (e.g. `iso_9660`, `zip_archive`).
* 500 — last-resort routing (e.g. `linux_uboot_uimage` when no header detected).
* 9000 — negative-evidence (e.g. PE / MZ with 2-byte magic).

## Step 3d — RTOS-family extension (P3.2.c — dispatch.by_rtos_family)

To classify a binary as a specific RTOS family (Zephyr / FreeRTOS /
VxWorks / etc.), the bundled `_system/rtos_dispatch.yaml` manifest uses
the `by_rtos_family` dispatch kind:

```yaml
# Operator-overlay manifest at data/file_formats.local/zephyr_specialised_elf.yaml
schema_version: 1
format_id: zephyr_specialised_elf
manifest_source: operator
precedence: 150
category: rtos
vendor: zephyrproject
confidence: high
detection:
  combine: any
  signals:
    - kind: filename
      extensions_lower: [".elf", ".bin"]
output:
  classifier_format: zephyr_specialised_elf
  classifier_category: rtos
  classifier_vendor: zephyrproject
  classifier_product: zephyr
  confidence: high
```

The `_system/rtos_dispatch.yaml`'s `dispatch.cases.zephyr: zephyr_elf`
case already points at the format_id `zephyr_elf`.  When the bundled
`rtos_detection_default` plugin (`backend/app/services/file_format_catalog/plugins/rtos_detection_default.py`)
detects a Zephyr binary, the catalog routes through the dispatch case
and emits the per-family format_id.  Operator-supplied per-family
manifests pick up the routing without touching the dispatch table.

For a NEW RTOS family the bundled plugin doesn't recognise (e.g. an
in-house RTOS), drop both a per-family manifest **and** a Python plugin
under `data/file_formats.local/` + (in-tree until P4 lands
`WAIRZ_FORMAT_PLUGIN_PATH`).  The plugin declares
`rtos_families: frozenset({"my_inhouse_rtos"})` and the dispatch table
extends via the same overlay path.  See `S3 §10` of
`.planning/research/file-format-yaml-registry-p32-wave1-S3-plugin-rtos-2026-05-19.md`.

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
