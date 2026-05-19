# File-Format YAML Registry

Operator-extensible classification surface for the wairz upload + walker
pipelines. Drop a YAML manifest under
`backend/app/services/file_format_catalog/data/file_formats/<vendor>/<format>.yaml`
(in-tree, contributor authority) or
`backend/app/services/file_format_catalog/data/file_formats.local/<format>.yaml`
(operator overlay) and the next walker invocation picks it up. No docker
restart. No code change.

This directory documents the registry. The CANONICAL source of truth is
the Pydantic schema at `backend/app/schemas/file_format.py`; everything
here is operator-facing reference.

## Why YAML, why closed-grammar

The file-format catalog is a Rule #52 (CLAUDE.md) application: extensible
SURFACES for new analysis behavior live in DATA, executable SEMANTICS in
Python plugins, the WALKER consumes data through closed dispatch tables.

The schema prohibits open-string fields that would require an interpreter:

- No `regex` (re-introduces the binwalk / yara / Velociraptor CVE class).
- No `script` / `template` / `vql` / `lua` / `expression` / `predicate`
  / `eval`.
- Plugin references are REGISTRY NAMES (validated at snapshot construction),
  never Python import paths.

The DATA surface is wide: vendor / category / format_id / product are FREE
STRINGS so partners contribute medical / ICS / automotive formats without
core merges. Closed Literals appear ONLY where the YAML maps to executable
Python semantics (signal kinds, dispatch kinds, plugin roles, etc.).
Extending a Literal requires Rule #25 single-slice cross-stack alignment
(DB CHECK + Pydantic Literal + frontend Record mirror).

## Schema version

P3.1 ships `schema_version: 1`. The version Literal is enforced; YAMLs
declaring any other value REJECT at load. Bumping the version is a Rule
#25 + Rule #46 META-CANARY operation — the migration discipline is in
`SCHEMA_REFERENCE.md`.

## Directory layout

```
backend/app/services/file_format_catalog/data/file_formats/
├── _system/                  # manifest_source: _system
│   ├── linux_squashfs.yaml
│   ├── ...                   # 27 baseline + universal-format manifests
│   └── intel_hex.yaml
├── <vendor>/                 # manifest_source: core
│   ├── qualcomm/
│   ├── mediatek/
│   ├── samsung/
│   ├── acronis/
│   ├── awinic/
│   ├── android/              # cross-vendor Android-only formats
│   ├── linux/                # cross-vendor Linux-only formats
│   └── misc/                 # cross-vendor unrooted formats
└── ...

backend/app/services/file_format_catalog/data/file_formats.local/
└── <format>.yaml             # manifest_source: operator
```

The on-disk PATH TIER is the source of truth for `manifest_source`. Any
mismatch between the manifest's declared `manifest_source` and the tier
inferred from the path is REJECTED at load with a clear error message.

## Tier ranking

Manifest source rank ALWAYS outranks numeric precedence:

| Tier | `manifest_source` | Rank | Path |
|------|-------------------|------|------|
| 1 | `_system` | 100 | `data/file_formats/_system/` |
| 2 | `core` | 80 | `data/file_formats/<vendor>/` |
| 3 | `operator` | 60 | `data/file_formats.local/` |
| 4 | `attested_external` | 40 | `data/file_formats.local/_attested_external/` (P4) |
| 5 | `unauthenticated_external` | 20 | P4 surface; REJECTED at load today |

An `operator`-tier manifest at `precedence: 200` STILL beats an
`unauthenticated_external` manifest at `precedence: 50`. Within a tier,
numeric precedence breaks ties; within the same precedence,
rule_specificity / vendor_lex / filename_lex break further ties.

## Magic-byte semantics

Magic-byte signals carry the verbatim head bytes plus an offset.
Constraints:

- `bytes_hex` is lowercase hex (`"68737173"`, not `"68 73 71 73"` or
  `"hsqs"`); the schema validates length and even-byte alignment.
- Magic ≤ 2 bytes (4 hex chars) requires `precedence >= 5000`. PE / MZ
  with `bytes_hex: "4d5a"` lives at precedence 9000 because the magic is
  so weak it MUST lose to every specific format.
- `mask_hex` (optional bitmask) MUST be the same length as `bytes_hex`
  and may NOT be all-zero (an all-zero mask matches everything; use
  `detection.always_matches: true` for catch-all formats, which is
  reserved for the single `_system/linux_blob_fallback.yaml` sentinel).
- Combine MUST be `all_required` (AND), `any` (OR), or `weighted` (sum
  of weighted scores must clear `min_confidence_score`).

## Hot-reload semantics

The catalog is wrapped in an `MtimeCachedYamlLoader` (mirrors
`ChipCatalog`'s shape) and re-stats on every `get_catalog()` call.

- Edit a YAML's content → mtime changes → reload on next call. No docker
  restart needed.
- Edit a YAML's comments only → mtime changes but the snapshot id
  (sha256 of canonical JSON) doesn't, so downstream consumers see the
  cached snapshot.
- Delete a YAML → its entry is dropped on next call (the path-tracker
  reaps it from the cache).
- Malformed YAML → kept-prior-valid-state: the malformed file is logged
  to `last_warning` and SKIPPED; previously-valid manifests stay in the
  catalog. Graceful-degrade per Rule #34.

## Local-overlay shape

Operator overlays live at
`backend/app/services/file_format_catalog/data/file_formats.local/`.
This directory is gitignored — operators can drop YAMLs without polluting
the repo.

To OVERRIDE a `core` or `_system` manifest from operator-overlay land:

```yaml
mode: override
overrides: "_system/linux_squashfs.yaml"  # relative path to the prior
                                          # manifest the override targets
manifest_source: operator
```

The loader's A1 validator enforces that the override's source rank is
≥ the override target's rank. An `operator` overlay CAN override a
`core` manifest (60 ≥ 80? no — operator < core; the override would
fail validation). Operators wanting to override a `core` manifest must
declare why in the manifest's `notes` and accept that running
`manifest_source: core` would short-circuit the override at load.

To EXTEND a manifest (P3.2 feature; today equivalent to override):

```yaml
mode: extend
overrides: "qualcomm/qcom_mbn.yaml"
manifest_source: operator
```

To declare a brand-new format (the default):

```yaml
mode: new   # implicit; rejects duplicate format_id at load
manifest_source: operator
```

## Cross-feature validators

The catalog runs A1-A5 cross-feature validators at load time:

- **A1** `mode=override` × authority — override source's rank must be ≥
  target's rank.
- **A2** `vendor_authority` derived from THIS manifest's
  `manifest_source` (NEVER read alias_of target's authority).
- **A3** `dispatch.cases.*` × deprecation — reject load if any dispatch
  target is `deprecation.status: removed`.
- **A4** Cross-vendor same-precedence same-magic collision — reject ALL
  conflicting entries; operator must reconcile.
- **A5** `dispatch.depth_max >= 2` × eager-expensive plugin — reject;
  require `bind: lazy` on the plugin reference.

Validator violations emit WARN to `last_warning` and SKIP the offending
manifest; the catalog returns the remaining valid manifests so a single
bad YAML never takes down the whole loader.

## Pointers

- `AUTHORING.md` — step-by-step "write your first YAML" walkthrough.
- `SCHEMA_REFERENCE.md` — every closed Literal enumerated.
- `ERROR_GLOSSARY.md` — every `validate_file_format` error code mapped
  to a paragraph explanation + remediation.
- `CONTRIBUTING.md` — PR shape; fixture-attestation; magic-collision
  discipline; alignment-test expectations.

## See also

- CLAUDE.md Rule #52 — schema-driven extensibility discipline.
- `.planning/research/file-format-yaml-registry-final-convergence-2026-05-19.md`
  — campaign convergence record.
- `backend/app/schemas/file_format.py` — Pydantic schema (canonical).
- `backend/app/services/file_format_catalog/data/file_formats/.schema.json`
  — JSON-Schema export for editor LSP autocomplete.
