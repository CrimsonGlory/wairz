# Extending Firmware Patterns

Wairz's hardware-firmware detection + CVE attribution pipeline is **YAML-driven**: most extensions don't require Python changes. Drop a new entry in the right YAML, rebuild the backend + worker, and Wairz starts classifying / matching your new firmware family or CVE.

This guide documents the **four YAML extension surfaces** that ship in `backend/app/services/hardware_firmware/data/`:

| File | Purpose | Loader entry-point |
|------|---------|--------------------|
| `vendor_prefixes.yaml` | Canonical vendor names + aliases + display strings | `patterns_loader._load_vendors` |
| `firmware_patterns.yaml` | Filename → (vendor, category, format) patterns AND path-context refinement rules | `patterns_loader._compile_patterns` / `_compile_path_contexts` |
| `bt_qca_codenames.yaml` | QCA Bluetooth codename → chipset map + BrakTooth scope + MediaTek BT/WiFi chip allowlist | `patterns_loader._load_bt_qca_codenames` |
| `bt_banner_cve_pins.yaml` | Banner-content → CVE rule engine (parser-confirmed Tier 0 attribution) | `patterns_loader._load_banner_cve_pins` |

A fifth surface — `backend/app/services/hardware_firmware/known_firmware.yaml` — drives the **curated CVE matcher** (firmware blob → CVE rules independent of the banner parser). It's documented in the [SBOM doc](sbom.md) for now; the schema also accepts `vendor_regex` and `category_regex` for cross-vendor advisories.

---

## Architecture Recap

Every blob inside an extracted firmware tree goes through three stages:

```
┌────────────────────────────────────────────────────────────────────┐
│ 1. Classifier (filename + path)                                    │
│    classifier.py reads firmware_patterns.yaml in order.            │
│    Returns Classification{vendor, category, format, confidence}    │
│    or "other" when nothing matches.                                │
└─────────────────────────────────────┬──────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────┐
│ 2. Parser (content)                                                │
│    A FORMAT-specific parser reads the blob bytes.                  │
│    parsers/bt_firmware_banner.py for FORMAT=bt_fw_banner; etc.     │
│    Returns ParsedBlob{version, signed, chipset_target, vendor,     │
│                       metadata}.                                   │
│    The parser MAY override Classification.vendor when content      │
│    evidence is stronger than filename evidence.                    │
└─────────────────────────────────────┬──────────────────────────────┘
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────┐
│ 3. CVE matching (curated + parser-pinned)                          │
│    cve_matcher.py reads known_firmware.yaml; banner-pinned CVEs    │
│    flow through ParsedBlob.metadata.known_vulnerabilities from     │
│    bt_banner_cve_pins.yaml.                                        │
│    Persisted to sbom_vulnerabilities table.                        │
└────────────────────────────────────────────────────────────────────┘
```

The **content evidence > filename evidence** rule is foundational. Filename heuristics produce confidently-wrong attribution often enough that wairz now ships a content parser for BT firmware specifically; the parser's `ParsedBlob.vendor` override (when set) wins over `Classification.vendor` in `detector.py`. See `parsers/base.py:22` for the contract.

---

## Surface 1 — `vendor_prefixes.yaml`

Canonical vendor names + the aliases that resolve to them.

```yaml
vendors:
  - prefix: qualcomm                    # lowercase canonical token
    display: "Qualcomm Technologies, Inc."
    aliases: [qcom]                     # alternate tokens; lowercased on load
  - prefix: mediatek
    display: "MediaTek Inc."
    aliases: [mtk]
```

When to add an entry:

- A new vendor appears in a firmware corpus (e.g. a startup silicon vendor).
- A new alias surfaces (e.g. `qct` for Qualcomm in some build manifests).

Where it's consumed:

- `classifier.py:apply_vendor_alias` normalises `qcom` → `qualcomm` before lookups.
- `patterns_loader.VENDORS` is the membership set; downstream services (`hbom_export`, `cve_matcher`) gate on it.

---

## Surface 2 — `firmware_patterns.yaml`

This is the most active extension surface — most firmware-coverage additions are filename or path patterns here. It has **two sections**.

### 2a. `patterns:` (filename-driven classification)

First-match-wins regex against the **basename** (not the full path):

```yaml
patterns:
  - pattern: "^cmbtfw[0-9]+\\.tlv$"
    vendor: qualcomm
    category: bluetooth
    product: "Qualcomm Atheros Rome BTFM (Comanche family)"
    confidence: high          # high|medium|low
    source: "linux-firmware /qca/cmbtfw*.tlv convention"
    format: bt_fw_banner      # routes the blob to parsers/bt_firmware_banner.py
```

Required fields: `pattern`, `vendor`, `category`. The `format:` field is the **dispatch key** that routes the blob to a specific parser — its value must match a `Parser.FORMAT` string in `parsers/<name>.py`.

How patterns are ordered: YAML insertion order. Put narrow patterns BEFORE broad ones so the narrow rule fires first. Each pattern compiles with `re.IGNORECASE`.

### 2b. `path_contexts:` (path-driven refinement)

Path-contexts run as a **refinement step** AFTER filename classification, but only when the filename classifier returned `category="other"`. This rescues files in a known partition tree (radio.img / BTFM.bin / dspso.bin / `/system/lib*/`) that filename heuristics missed.

```yaml
path_contexts:
  - path_pattern: "BTFM\\.bin_extract/"          # path substring match
    filename_pattern: ".*"                       # optional secondary basename gate
    vendor: qualcomm
    category: bluetooth
    product: "Qualcomm BTFM partition contents"
    confidence: medium
    priority: 100                                # higher = tried first
```

Required: `path_pattern`, `vendor`, `category`. Optional: `filename_pattern`, `priority` (default 0), `product`, `confidence`.

**Priority handling.** When two path-context rules fire on the same blob, the higher-priority one wins. Ties resolve deterministically by `(category, vendor, product)` — author-order accidents don't change classification (Reviewer A M5 2026-05-15 finding; see the `compiled.sort(...)` block at the end of `patterns_loader._compile_path_contexts`).

**Worked example — Bluedroid host-stack coverage (shipped 2026-05-16):**

```yaml
path_contexts:
  - path_pattern: "/(?:system|apex)/.*/lib[^/]*/(?:hw/)?libbluetooth(?:_jni|_qti)?\\.so$"
    filename_pattern: "^(?:libbluetooth(?:_jni|_qti)?|bluetooth\\.default)\\.so$"
    vendor: aosp
    category: bluetooth
    product: "AOSP Bluedroid / Fluoride host BT stack"
    confidence: high
    priority: 90
```

This routes Android `libbluetooth.so` and the Bluedroid HAL family into a single classification group that the curated CVE matcher (`known_firmware.yaml`) gates on via `vendor: aosp` + `category: bluetooth`. The split between filename + path lets the rule fire correctly whether the blob came out of `/system/lib64/`, `/apex/com.android.bluetooth/lib64/`, or a vendor-fork subtree.

### Format → Parser mapping

When `format:` is set in a pattern entry, the blob is routed to the matching parser via `parsers/__init__.py:PARSER_REGISTRY`. Current parsers in-tree:

| FORMAT | File | Handles |
|--------|------|---------|
| `bt_fw_banner` | `parsers/bt_firmware_banner.py` | QCA Rome BTFM, Broadcom HCD, MediaTek WMT |
| `qualcomm_mbn` | `parsers/qualcomm_mbn.py` | Qualcomm Modem MBN headers |
| `dtb` | `parsers/dtb.py` | Linux device-tree blobs |
| `elf_tee` | `parsers/elf_tee.py` | ELF-format TEE binaries (Kinibi, Trusty) |
| `kmod` | `parsers/kmod.py` | Linux kernel modules |
| `mediatek_*` | `parsers/mediatek_*.py` | ATF, GFH, LK, modem, preloader, tinysys, WiFi |
| `broadcom_wl` | `parsers/broadcom_wl.py` | Broadcom WiFi firmware blobs |
| `awinic_acf` | `parsers/awinic_acf.py` | Awinic ACF amplifier firmware |
| `raw_bin` | `parsers/raw_bin.py` | Fallback for unrecognised raw binary |

To add a new parser, see `parsers/base.py` for the `Parser` Protocol contract: implement `parse(path, magic, size) -> ParsedBlob` + call `register_parser(...)` at import time.

---

## Surface 3 — `bt_qca_codenames.yaml` (H1)

Externalized 2026-05-17. The QCA Bluetooth codename → chipset map + BrakTooth chipset scope + MediaTek BT/WiFi chip allowlist.

```yaml
codenames:
  - codename: CMC                       # 3-letter QCA codename (BTFM banner tag)
    chipset: wcn3950                    # canonical primary chipset
    display: Comanche                   # human-readable codename
    families: [Rome]                    # generation tag (informational)
  - codename: CHE
    chipset: wcn3990
    display: Cherokee
    families: [Rome]
    also_covers: [wcn3991, wcn3998]     # Cherokee covers 3 chipsets in the kernel

braktooth_chipsets:                     # ASSET BrakTooth Qualcomm DoS scope
  - wcn3950
  - wcn3990
  - wcn3991
  - wcn3998

mtk_known_chips:                        # MediaTek BT/WiFi chip-ID allowlist
  - MT7961
  - MT7921
  # ... 16 more entries
```

**When to extend:**

- A new QCA Rome / FastConnect codename appears in `linux-firmware/qca/`. Add the codename row; the parser picks it up next backend rebuild.
- A new MediaTek BT chip shows up in a corpus. Add it to `mtk_known_chips` for the lowest-false-positive content-scan path.
- A new chipset enters the BrakTooth scope per a future Qualcomm advisory. Add it to `braktooth_chipsets`.

**What you CANNOT add here:**

- New filename → codename prefix mappings (`cmbtfw` → `CMC` etc.). These live in `parsers/bt_firmware_banner.py` `_QCA_FILENAME_PREFIX_TO_CODENAME` because the **filename↔content mismatch flag** (Reviewer B M2 2026-05-16) is forensic-load-bearing and the small bespoke map keeps the link auditable. Extending the YAML to cover this would require a parser code change too.

**Graceful degrade** (Rule #34): if this YAML is missing the loader logs INFO; if it fails structural validation the loader logs WARN. In both cases the loader falls back to the in-tree `_BT_CODENAME_DEFAULTS` constant (`patterns_loader.py`). Detection keeps working; an operator log line surfaces the issue.

**Observability** (Reviewer C 2026-05-17 finding): every load — success OR fallback — emits one INFO line per file that operators can grep for. Tail backend logs after a Rule #8 rebuild:

```bash
docker compose logs backend | grep -E "patterns_loader: bt_qca_codenames"
# Expect on success: "bt_qca_codenames.yaml loaded — 5 codenames, 4 braktooth chipsets, 18 mtk chips (YAML, not defaults)"
# Expect on YAML loss: "bt_qca_codenames.yaml missing or unparseable — using in-tree _BT_CODENAME_DEFAULTS (...)"
```

---

## Surface 4 — `bt_banner_cve_pins.yaml` (H2)

Externalized 2026-05-17. The banner-pin → CVE rule engine that replaces the hardcoded `_maybe_pin_braktooth` function.

### Schema

```yaml
pins:
  - id: qualcomm-braktooth-qca-rome-dos-cve-2021-30348    # kebab-case stable ID
    description: |
      Qualcomm BrakTooth LLM utility-timer DoS (CVE-2021-30348) on
      Rome WCN3xx0 BT firmware

    # ---- Match conditions (logical AND of all present fields) ----
    family: qca_rome                                  # parser family verdict
    codename_in: [CMC, CHE, APA]                      # qca_rome only
    chipset_target_in: [wcn3950, wcn3990, wcn3991, wcn3998]
    banner_match: "BTFM\\.CMC\\.1\\."                 # regex against record.banner
    build_date_before: 2017-09-12                     # broadcom_hcd build date
    build_id_lt: 100                                  # qca_rome/mediatek integer
    signed_eq: signed                                 # "signed" | "unsigned"

    # ---- CVE list (required, non-empty) ----
    cves:
      - id: CVE-2021-30348
        severity: medium                              # critical|high|medium|low|info
        subcomponent: bluetooth                       # default "bluetooth"
        confidence: high                              # default "high"
        rationale: |
          BT firmware banner '{banner}' confirms {chipset_upper} (QCA
          Rome family). Per NVD CPE list (vendor=qualcomm), ...
        reference: https://nvd.nist.gov/vuln/detail/CVE-2021-30348
```

### Match conditions in detail

| Field | Type | Applies to | Behavior |
|-------|------|-----------|----------|
| `family` | enum | all | Must equal `record.family` (the parser verdict — `qca_rome`, `broadcom_hcd`, or `mediatek_bt`). |
| `codename_in` | list[str] | qca_rome | UPPERCASE 3-letter codenames the QCA banner regex extracted. |
| `chipset_target_in` | list[str] | all | Lowercase chipset names that `chipset_target` must match. |
| `banner_match` | regex | all | `re.IGNORECASE` regex against `record.banner`. Loader-side check: the regex MUST compile; uncompilable patterns reject the whole YAML to defaults. |
| `build_date_before` | YYYY-MM-DD | broadcom_hcd | `record.build_date` parsed as `MMM DD YYYY` must be strictly earlier. Fails closed on unparseable/missing dates (DEBUG-logged). |
| `build_id_lt` | int | qca_rome / mediatek_bt | Integer-head of `record.build_id` must be strictly less. Fails closed on non-int values (DEBUG-logged). NOTE: `build_id_lt: 0` with no other gate is rejected at load time as a likely-unfilled placeholder sentinel. |
| `signed_eq` | enum | qca_rome (signed/unsigned) | Match against `record.signed` ("signed" or "unsigned" — the QCA banner trailing "Z" indicates signed). Useful when an advisory applies only to dev/debug builds. broadcom_hcd always emits "unsigned"; mediatek_bt doesn't populate `signed`. |

A pin with **all** conditions absent is rejected at load time (it would fire on every BT blob). At least one condition is required.

### Rationale templating

`rationale:` is run through `str.format(**vars)` with these placeholders:

| Placeholder | Source | Example |
|-------------|--------|---------|
| `{banner}` | `record.banner` | `BTFM.CMC.1.3.0-00069-QCACHROMZ-1` |
| `{chipset}` | `record.chipset_target` | `wcn3950` |
| `{chipset_upper}` | `chipset.upper()` | `WCN3950` |
| `{codename}` | `record.codename` (qca_rome) | `CMC` |
| `{build_id}` | `record.build_id` (qca_rome / mediatek) | `00069` |
| `{build_date}` | `record.build_date` (broadcom_hcd) | `Sep 12 2017` |

Missing placeholders log a WARN and emit the raw template — the pin still fires, the operator just sees the un-substituted `{my_var}` in the finding.

### Multiple pins

The engine walks every pin and concatenates findings; multiple pins CAN fire on the same record. Each finding carries the pin's `pin_id` so operators can audit "which rule emitted this CVE attribution" without re-reading the YAML.

### The Reviewer B 2026-05-16 discipline

Every CVE entry in this file MUST have a `reference:` URL pointing to the NVD entry (or QSB / vendor advisory). **Before adding a pin, independently verify** that the NVD CPE list for each CVE contains every chipset in `chipset_target_in:`. The disclosure-batch attribution antipattern (extrapolating "all CVEs in disclosure X apply to all chipsets in disclosure X") is what this whole rule engine was built to prevent.

The canonical example: **CVE-2021-28139** is in the BrakTooth disclosure batch but its NVD CPE list contains only Espressif ESP-IDF / ESP32 — no Qualcomm. The shipped YAML deliberately omits CVE-2021-28139 from every `qca_rome`-family pin, and `test_shipped_yaml_does_not_contain_cve_2021_28139` is a canary that fails loud if a future YAML edit re-introduces it.

### Graceful degrade

Same shape as the H1 codename YAML: missing file / YAML syntax error / structural validation failure → log WARN + return `_BANNER_CVE_PIN_DEFAULTS` (in-tree copy of the BRAKTOOTH pin). Detection keeps working under YAML loss.

---

## Surface 5 (bonus) — `known_firmware.yaml` `vendor_regex` + `category_regex`

The curated CVE matcher (`cve_matcher.py:_match_curated`) supports two regex fields that let one advisory cover multiple vendors or categories:

```yaml
known_firmware:
  - id: ADV-BT-SPEC-KNOB-2019
    vendor_regex: "."                       # match ANY vendor
    category: bluetooth
    cves: [CVE-2019-9506]                   # KNOB attack — any BT firmware
    severity: medium
```

`vendor_regex` and `category_regex` are case-insensitive Python regexes. They're useful for **spec-level advisories** (KNOB, BLUFFS, BIAS, BLURtooth) that affect every BT controller regardless of vendor. Without them, the matcher's `vendor` field had to be a single exact-match string and these advisories only fired on `vendor=unknown` blobs — the H2 commit `88082f0` (2026-05-16) added the regex variants to make those advisories useful across the corpus.

---

## End-to-End Worked Example

Adding coverage for a hypothetical new Qualcomm BT codename **HEN / Hennessy / QCA6490** with one known DoS CVE.

**Step 1.** Add the codename to `bt_qca_codenames.yaml`:

```yaml
codenames:
  # ... existing entries unchanged ...
  - codename: HEN
    chipset: qca6490
    display: Hennessy
    families: [FastConnect]
```

**Step 2.** If your firmware filenames follow the QCA convention (`<prefix>btfw*.tlv`), the existing classifier rules in `firmware_patterns.yaml` already match — the parser will read the banner, extract the `HEN` codename, and resolve `chipset_target=qca6490` via the YAML accessor. No filename-pattern change needed.

**Caveat (Reviewer C 2026-05-17):** if you skip the `_QCA_FILENAME_PREFIX_TO_CODENAME` extension below, the filename↔content mismatch flag won't surface for the new family — content evidence still wins (the parser correctly trusts the banner over the filename), but operators lose the forensic mismatch metadata that's load-bearing for "is this BTFM blob in the right partition" audits. If you're sure the new family will only ship under one filename prefix, you can skip the parser edit; otherwise update both.

If the filename is novel (e.g. `henbtfw01.tlv`), add a filename pattern:

```yaml
patterns:
  - pattern: "^henbtfw[0-9]+\\.(tlv|ver)$"
    vendor: qualcomm
    category: bluetooth
    product: "Qualcomm Hennessy QCA6490 BT firmware"
    confidence: high
    format: bt_fw_banner
```

AND extend the filename-prefix map in `parsers/bt_firmware_banner.py:_QCA_FILENAME_PREFIX_TO_CODENAME` so the filename↔content mismatch flag fires correctly:

```python
_QCA_FILENAME_PREFIX_TO_CODENAME: dict[str, str] = {
    # ... existing entries ...
    "henbtfw": "HEN",   # Hennessy
}
```

This is the one place where a parser-code change is required when adding a new QCA codename.

**Step 3.** Add the CVE pin in `bt_banner_cve_pins.yaml`. **Verify the NVD CPE first.**

```yaml
pins:
  # ... existing entries unchanged ...
  - id: qualcomm-hennessy-qca6490-imagined-dos
    description: Hypothetical Hennessy QCA6490 DoS (worked example only)
    family: qca_rome
    chipset_target_in: [qca6490]
    cves:
      - id: CVE-9999-99999
        severity: medium
        confidence: high
        rationale: |
          BT firmware banner '{banner}' confirms {chipset_upper}
          (Hennessy). Hypothetical CVE for documentation purposes.
        reference: https://example.invalid/cve-9999-99999
```

**Step 4.** Rebuild backend + worker (Rule #8):

```bash
docker compose up -d --build backend worker migrator
```

Always rebuild **worker** AND **migrator** alongside **backend** — they share the same Dockerfile and codebase. A stale worker silently blocks all background jobs.

**Step 5.** Re-detect on a test firmware, then trigger CVE matching.

Hardware-firmware re-detection runs as part of the unpack worker — there is no standalone "detect-only" MCP tool. To re-trigger detection without re-uploading, re-run the unpack job (which clears `extracted_path` + `device_metadata.detection_roots`) via the wairz UI or call the firmware-unpack REST endpoint with the firmware ID. For inspection-only flows, the relevant MCP tools (verified against `backend/app/ai/tools/hardware_firmware.py` + `backend/app/ai/tools/sbom.py`):

```bash
# Inspect what hardware-firmware detection already found:
analyze_hardware_firmware(project_id=..., firmware_id=...)

# Inspect per-component CVE attribution against your shipped pin:
check_firmware_cves(project_id=..., firmware_id=...)

# Re-run the full SBOM-driven vulnerability scan (covers curated YAML
# matches AND the banner-pin engine's persisted CVE rows):
run_vulnerability_scan(project_id=..., firmware_id=...)
```

To re-run **just** the curated CVE matcher (faster than re-unpacking, persists banner-pin findings already in `metadata.known_vulnerabilities` into `sbom_vulnerabilities`), POST to the cve-match endpoint with idempotent-202 polling (Rule #33 .a):

```bash
# 202 + polling endpoint (decouples the work from any reverse-proxy timeout):
curl -X POST \
  -H "X-API-Key: $WAIRZ_API_KEY" \
  http://localhost:8000/api/v1/projects/$PROJECT_ID/hardware-firmware/cve-match

# Poll until status=completed:
curl -H "X-API-Key: $WAIRZ_API_KEY" \
  http://localhost:8000/api/v1/projects/$PROJECT_ID/hardware-firmware/cve-match/status
```

Then verify the Hennessy banner produced the expected attribution. SQL:

```sql
SELECT
  blob.path, blob.chipset_target, blob.metadata->'bt_fw_banner'->>'codename'
FROM hardware_firmware_blobs blob
WHERE firmware_id = '<test-firmware-uuid>'
  AND blob.metadata->'bt_fw_banner'->>'codename' = 'HEN';

SELECT sv.cve_id, sv.severity, sv.rationale
FROM sbom_vulnerabilities sv
JOIN hardware_firmware_blobs blob ON sv.blob_id = blob.id
WHERE blob.metadata->'bt_fw_banner'->>'codename' = 'HEN'
  AND sv.cve_id = 'CVE-9999-99999';
```

---

## Graceful-degrade behavior cheat-sheet

| YAML file | Missing file | YAML syntax error | Structural validation error | Per-load success log |
|-----------|--------------|-------------------|-----------------------------|----------------------|
| `vendor_prefixes.yaml` | Falls back to `_CORE_VENDORS` (qualcomm, mediatek, broadcom, …) + WARN | Same | Same | No explicit success log |
| `firmware_patterns.yaml` | Empty pattern list + WARN | Empty list + WARN | Per-entry skip + WARN; rest of YAML still loads | INFO: "loaded N firmware patterns" / "loaded N path_contexts entries" |
| `bt_qca_codenames.yaml` | `_BT_CODENAME_DEFAULTS` + INFO | INFO | All-or-nothing fallback to defaults + WARN | INFO: "bt_qca_codenames.yaml loaded — N codenames, M braktooth chipsets, K mtk chips (YAML, not defaults)" |
| `bt_banner_cve_pins.yaml` | `_BANNER_CVE_PIN_DEFAULTS` (BRAKTOOTH pin) + INFO | INFO | All-or-nothing fallback + WARN | INFO: "bt_banner_cve_pins.yaml loaded — N pins, M CVEs total (YAML, not defaults)" |

The H1 + H2 loaders use an **atomic fallback** (one structural error → entire YAML rejected, defaults fire) because partial-load semantics are subtle for these files — for an operator, "my new pin doesn't appear" is easier to diagnose than "my pin appears but with a silently-dropped chipset_target_in field." The classifier YAML uses **per-entry skip** because one broken regex among thousands of patterns shouldn't kill the rest of classification.

The **per-load success log** column (Reviewer C 2026-05-17) is the operator's positive-side signal — `grep -E "bt_(qca_codenames|banner_cve_pins).yaml loaded" backend.log` returns one line per backend boot when YAML was used; absence of that line means defaults fired.

---

## Where to look in code

- Loader entry points: `backend/app/services/hardware_firmware/patterns_loader.py`
- Classifier with path-context refinement: `backend/app/services/hardware_firmware/classifier.py`
- Parser registry + ParsedBlob contract: `backend/app/services/hardware_firmware/parsers/base.py`
- BT firmware banner parser: `backend/app/services/hardware_firmware/parsers/bt_firmware_banner.py`
- CVE matcher (curated + soft chipset + vendor_regex): `backend/app/services/hardware_firmware/cve_matcher.py`
- Detector (orchestrates classifier + parser + override): `backend/app/services/hardware_firmware/detector.py`

For the discipline expected of new pins and CVE attribution:

- `CLAUDE.md` Rule #19 — evidence-first; the spec describes intent, the DB describes truth.
- `CLAUDE.md` Rule #34 — graceful-degrade is the default; loud-on-bad-structure for high-leverage files.
- `.planning/postmortems/postmortem-bt-banner-parser-session-2026-05-16.md` — the Reviewer B / CVE-2021-28139 incident that motivated H2.
- `.planning/postmortems/postmortem-hw-firmware-adaptive-session-2026-05-15.md` — the BTFM → Broadcom misattribution that motivated the whole campaign.

---

## Surface 6 — `chip_families/*.yaml` (Rule #52 — bare-metal MCU/DSP audit)

**Status:** Phase 1 + 2 shipped 2026-05-19 (commits `f0bbb1f..11cbd9d`).
Two reference families ship in-tree: `ti/tms320f28066.yaml` (TI C28x DSP,
16-bit word-addressed, CSM password model) and `nxp/spc58.yaml` (PowerPC
e200z4, big-endian, lifecycle-register model). Adding a chip family is
**operator-extensible** — drop a YAML, the catalog hot-reloads, the
walker fires per next `audit_bare_metal_firmware` MCP call.

| Aspect | Value |
|---|---|
| Path | `backend/app/services/hardware_firmware/data/chip_families/<vendor>/<family>.yaml` |
| Schema | `backend/app/schemas/chip_family.py` — Pydantic v2 with closed Literals |
| Loader | `chip_catalog.ChipCatalog` (per-file mtime cache, mirrors `MtimeCachedYamlLoader`) |
| Walker | `bare_metal_walker.py` — Rule #39 inner/outer/safe triplet, closed `POLICY_EVALUATORS` |
| HTTP ingest | `POST /api/v1/projects/{p}/firmware/{f}/bare-metal-hint` |
| MCP tools | `list_chip_families`, `audit_bare_metal_firmware`, `submit_bare_metal_descriptor`, `lookup_bare_metal_findings_across_firmwares` |
| Hot-reload | Yes — edit YAML, next walker call picks up changes (no docker restart) |
| Rule #52 status | Rule-of-Two (2026-05-19) — F28066 + SPC58 cover orthogonal arch / endianness / packing / security model dimensions |

### Closed-grammar discipline (the user-stated direction)

The YAML is **DATA**, never code. Every extensible field is a closed
Pydantic `Literal`. **NO `regex` / `script` / `template` / `predicate` /
`lua` / `expression` keys EVER.** Pydantic `extra='forbid'` rejects
unknown keys at YAML-load time; Rule #46 META-CANARIES synthesize
forbidden inputs and confirm the gate fires.

Extending the grammar (adding a new `RegionSemantic` or `PolicyOperator`
or `Arch` value) requires a Rule #25 single-slice cross-stack alignment
commit (DB CHECK + Pydantic Literal + frontend Config mirror) — NOT a
YAML-only edit. The user-extensibility surface is the YAML; the closed
grammar is the safety invariant.

### Minimal worked example — Add `vendor/family.yaml`

```yaml
schema_version: 1
vendor: stm
family: stm32f4
display_name: "STMicroelectronics STM32F4 (Cortex-M4 with RDP)"
description: |
  STM32F4 family with Read-Out Protection (RDP) security model.
  RDP level 0 = unprotected, RDP level 1 = JTAG/SWD limited, RDP
  level 2 = irreversible JTAG lock.
domains:
  - name: cortex_m4_core
    arch: arm-cortex-m
    endianness: little
    instruction_word_bits: 16    # Thumb-2 mixed 16/32; matcher reads either
    data_word_bits: 32
    address_bus_bits: 32
    packing: one_byte_per_address
    address_regions:
      - name: flash_main
        start: 0x08000000
        size: 0x100000   # 1 MB STM32F407
        access: read-execute
        semantic: [flash_code, flash_data]
      - name: rdp_option_byte
        start: 0x1FFFC000
        size: 4
        access: read-only
        semantic: [security_password]
        policy:
          - operator: required_value_at_offset
            value_hex: "AA"        # RDP level 0 byte
            offset: 0
            word_size_bits: 8
            cwe_ids: [1273, 1191]
            severity: high
            finding_source: c28x_unsecure_csm   # reused; rename per Rule #25 when stm32_unsecure_rdp lands
            description: "RDP level 0 (0xAA) = unprotected; production should be level 1 (0xBB) or 2 (0xCC)"
    detection_signals:
      - kind: silicon_id_byte_match
        weight: 0.4
        address: 0xE0042000   # DBGMCU_IDCODE register
        bytes_hex: "13413040"
        description: "STM32F40x family device-ID"
      - kind: string_present
        weight: 0.2
        patterns: ["STMicroelectronics", "STM32F4", "Cube"]
      - kind: elf_magic
        weight: 1.0
        bytes_hex: "7F454C46"
    ghidra_import_params:
      processor: "ARM:LE:32:Cortex"
      loader: BinaryLoader
      base_addr: 0x08000000
```

Drop the file at `data/chip_families/stm/stm32f4.yaml`. Next walker
invocation picks it up:

```bash
# Verify it loaded
docker compose exec backend wairz-mcp list_chip_families --vendor stm

# Operator pushes a chip hint for a specific firmware
curl -X POST -H "X-API-Key: $WAIRZ_KEY" -H 'Content-Type: application/json' \
  -d '{"chip_family_hint": "stm/stm32f4"}' \
  "https://wairz.example/api/v1/projects/$P/firmware/$F/bare-metal-hint"

# Trigger walker
docker compose exec backend wairz-mcp audit_bare_metal_firmware --firmware_id $F

# Cross-firmware supply-chain audit (Rule #44):
docker compose exec backend wairz-mcp lookup_bare_metal_findings_across_firmwares \
  --finding_source c28x_unsecure_csm --scope global
```

### What you DO NOT need to do

- Touch any Python — the walker is architecture-agnostic, dispatch is closed-grammar
- Rebuild the docker image — `MtimeCachedYamlLoader` picks up the YAML at next access
- Update the alembic migration — the schema is at the application layer, no DB shape changes
- Register a new MCP tool — `list_chip_families` already enumerates the catalog

### What you DO need to do

- Match the Pydantic schema (Pydantic rejects unknown keys + invalid Literal values; the WARN log shows what's wrong via `chip_catalog.last_warning`)
- Pick reasonable `detection_signals` — without strong signals + no operator descriptor, the walker emits `bare_metal_chip_unknown_with_hints` informational findings
- Test against a representative blob (the existing F28066 + SPC58 tests are templates)

### Pointers

- Schema: `backend/app/schemas/chip_family.py`
- Reference YAMLs: `data/chip_families/ti/tms320f28066.yaml`, `data/chip_families/nxp/spc58.yaml`
- Walker: `backend/app/services/bare_metal_walker.py`
- HTTP endpoint: `backend/app/routers/bare_metal.py` (Rule #51 `TIER_A_LIGHT_ACK`)
- MCP tools: `backend/app/ai/tools/bare_metal.py`
- Rule: `CLAUDE.md` Rule #52 — schema-driven discipline for operator extensions
- External-ingestor protocol: see [`external-descriptor-ingest.md`](external-descriptor-ingest.md)
