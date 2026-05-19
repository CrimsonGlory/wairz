# Error Glossary

Every error the file-format catalog can raise at load or via the
`validate_file_format` MCP tool, mapped to a paragraph explanation
plus remediation.

## Schema validation errors

### `schema_version=N: unsupported`

Cause: the YAML declares a `schema_version` value other than `1`.
Today only schema version 1 ships; future versions will be added via
Rule #25 cross-stack alignment with explicit migration tooling.

Fix: set `schema_version: 1`.

---

### `format_id: <value>: pattern mismatch`

Cause: the `format_id` doesn't match `^[a-z][a-z0-9_]*$`. Common
mistakes: uppercase letters, hyphens, leading digits.

Fix: rename to all-lowercase, alphanumeric + underscore, first character
must be a letter.

---

### `magic_bytes signal: bytes_hex and offset are REQUIRED`

Cause: a `magic_bytes` signal omits `bytes_hex` or `offset`.

Fix: declare both. `offset: 0` is the common case; some formats live
at `offset: 32769` (ISO 9660), `offset: 257` (tar), or arbitrary
locations.

---

### `magic_bytes: bytes_hex must have even length`

Cause: odd hex string. A single byte is two hex chars (`"d0"`), two
bytes is four chars (`"d0cf"`), etc.

Fix: count your hex chars and pad / truncate as needed.

---

### `magic_bytes: minimum 2 bytes (4 hex chars). Negative-evidence formats (PE/MZ at 2 bytes) MUST set precedence >= 5000`

Cause: magic bytes are too short — 1 byte (2 hex chars) or empty — OR
the magic is 2 bytes AND the manifest's `precedence` is below 5000.

Fix: pick more bytes, or bump `precedence` to >= 5000 (PE/MZ at
precedence 9000 is the canonical example).

---

### `magic_bytes: mask_hex length mismatch`

Cause: `mask_hex` is set but isn't the same length as `bytes_hex`.

Fix: pad or truncate `mask_hex` to match. The mask is applied bit-wise
per byte.

---

### `magic_bytes: mask_hex all-zero matches everything; use detection.always_matches=True for catch-all formats`

Cause: `mask_hex` consists entirely of `"00"` bytes — every byte is
"don't care", so the signal matches any input.

Fix: if you genuinely want a catch-all, use
`detection.always_matches: true` and a single
`kind: always_matches` signal (this is reserved for the
`_system/linux_blob_fallback.yaml` sentinel only).

---

### `filename signal: at least one of stems_lower / extensions_lower`

Cause: a `filename` signal has neither `stems_lower` nor
`extensions_lower` populated.

Fix: declare at least one. `stems_lower` matches exact basenames
(`["boot.img", "vendor.img"]`); `extensions_lower` matches by extension
(`[".bin", ".img"]`).

---

### `filename.stems_lower[<entry>]: min 4 chars`

Cause: a stem entry is fewer than 4 characters (`"k.so"`).

Fix: use a more distinctive stem, or move the match to
`extensions_lower` which has a 2-char floor.

---

### `path_context: <value> must start with '/' (Wave-1 S3 §2)`

Cause: a `path_substrings_any_of` entry doesn't start with `/`.

Fix: prefix with `/`. Path matches are tree-rooted; bare-relative-path
matches are rejected to prevent over-broad coincidence with
filename-internal substrings.

---

### `path_context: <value> min 6 chars (Wave-1 S3 §2)`

Cause: a `path_substrings_any_of` entry is fewer than 6 characters.

Fix: use a more specific substring (`/usr/`, `/lib/`, etc. are too
broad; `/vendor/firmware/` is fine).

---

### `size_range: declare at least size_min or size_max`

Cause: a `size_range` signal omits both `size_min` and `size_max`.

Fix: declare one or both. Use `size_min` to require a minimum size
(blocks malformed truncated inputs); use `size_max` to reject
oversized files; declare both to express a range.

---

### `size_range: size_min > size_max`

Cause: the lower bound exceeds the upper bound.

Fix: swap them.

---

### `rtos_check: rtos_plugin_ref required`

Cause: an `rtos_check` signal omits `rtos_plugin_ref`.

Fix: declare a registered plugin reference (e.g.
`rtos_plugin_ref: rtos_detection_default`). The reference is
resolved at snapshot construction against
`PLUGIN_REGISTRY`.

---

### `zip_markers / tar_markers: declare inner_file_names or inner_basenames`

Cause: a `zip_markers` or `tar_markers` signal omits both
`inner_file_names` and `inner_basenames`.

Fix: declare at least one. `inner_file_names` matches the full
zip-entry path (`META-INF/com/google/android/updater-script`);
`inner_basenames` matches the basename only (`payload.bin`,
`system.img`).

---

### `detection.combine=weighted requires min_confidence_score`

Cause: `detection.combine: weighted` without `min_confidence_score`.

Fix: declare `min_confidence_score` (range 0.0-100.0). A signal
matches contributes `weight` to the total; the format matches when
the total reaches `min_confidence_score`.

---

### `detection.always_matches=True permits only signals of kind 'always_matches'`

Cause: `detection.always_matches: true` is set but a non-`always_matches`
signal is also declared.

Fix: drop the other signals, or set
`detection.always_matches: false` (the default).

---

### `dispatch.kind=none rejects cases/default`

Cause: `dispatch.kind: none` (or omitted) but `cases:` or `default:`
is populated.

Fix: pick a non-`none` `kind` (e.g. `by_partition_name`,
`by_zip_inner_file`) or drop the `cases` / `default` entries.

---

### `dispatch.kind=<kind>: declare at least cases or default`

Cause: a non-`none` dispatch kind without any cases or default target.

Fix: declare `cases:` (map of discriminator → format_id) or
`default:` (fallback format_id when no case matches).

---

### `mode=override requires overrides: <path>`

Cause: `mode: override` without `overrides:`.

Fix: set `overrides:` to the relative path of the prior manifest
this override targets (e.g. `"qualcomm/qcom_mbn.yaml"`).

---

### `mode=<other>: overrides field is permitted only when mode=override`

Cause: `overrides:` declared but `mode` is `new` or `extend`.

Fix: switch to `mode: override` if the intent was to override, or drop
the `overrides:` field.

---

### `precedence=<N>: range [0,9] is RESERVED for _system manifests`

Cause: a `core` / `operator` / etc. manifest declares `precedence`
below 10.

Fix: bump `precedence` to 10 or higher; the [0,9] range is reserved
for `_system` sentinels (catch-all fallbacks).

---

### `detection.always_matches=True is reserved for the _system linux_blob sentinel`

Cause: a non-`_system` manifest set `detection.always_matches: true`.

Fix: drop `always_matches` and declare real signals. Only the
`_system/linux_blob_fallback.yaml` sentinel ships with always-matches.

---

### `alias_of and dispatch.kind=<kind> are mutually exclusive`

Cause: a manifest sets `alias_of: <other>` AND `dispatch.kind`
to something other than `none`.

Fix: pick one. `alias_of` declares identity reuse (a manifest is the
same format as another); `dispatch` declares container fan-out (a
format wraps inner formats). They can't both be true at the same time.

---

## Catalog-load errors

### `path cross-check: file at <name> (tier '<tier>') declares manifest_source='<other>'`

Cause: the YAML's declared `manifest_source` doesn't match its on-disk
tier.

Fix: change the manifest_source to match the path, or move the file
to a path that matches the declared source.

---

### `duplicate format_id '<id>' with mode=new`

Cause: two manifests declare the same `format_id` and at least one is
`mode: new`. Silent-shadow is intentionally closed (Wave-1 S5 C).

Fix: rename one of them, OR pick `mode: override` on the second with an
explicit `overrides:` path.

---

### `A1 mode=override rejected — source rank <s_rank> < target rank <t_rank>`

Cause: a `mode: override` manifest from a lower-rank tier is trying to
override a higher-rank manifest (e.g. `operator` overriding `core`).

Fix: either move the override to a higher-rank tier (promote
operator → core via PR) or accept that the override won't apply.

---

### `A3 dispatch target '<id>' has deprecation.status=removed`

Cause: a manifest's `dispatch.cases.*` value points at a format whose
`deprecation.status` is `removed`.

Fix: update the dispatch case to point at the replacement format
(check the removed format's `deprecation.replaced_by`).

---

### `A4 cross-vendor collision at precedence=<p> offset=<o> bytes='<b>'`

Cause: two manifests with the SAME precedence and SAME magic_bytes
declare DIFFERENT vendors within the SAME manifest_source tier.

Fix: bump one manifest's precedence so the tie is broken, OR
disambiguate via filename / path_context, OR confirm the duplication
is correct and move one manifest to a different tier (operator
overlay).

---

### `A5 deep dispatch (depth_max=<n>) chains eager-expensive plugin '<ref>'`

Cause: a manifest sets `dispatch.depth_max >= 2` AND a downstream
manifest's `plugin.matcher.bind: eager` references an expensive plugin
(magic_bytes cost class or worse).

Fix: change the matcher's `bind` to `lazy`, OR reduce `dispatch.depth_max`
to 1.

---

### `sentinel-cardinality: multiple always_matches=True manifests`

Cause: more than one manifest in the catalog sets
`detection.always_matches: true`. Only the `_system/linux_blob_fallback.yaml`
should.

Fix: drop the duplicate.

---

## See also

- `SCHEMA_REFERENCE.md` — every Literal + constraint enumerated.
- `AUTHORING.md` — walkthrough with worked example.
- `README.md` — directory layout + tier ranking.
- CLAUDE.md Rule #34 — graceful-degrade on parse failure.
