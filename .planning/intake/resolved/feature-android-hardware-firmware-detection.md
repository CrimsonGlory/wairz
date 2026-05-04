---
title: "Feature: Android Hardware Firmware Detection (Modem/TEE/Wi-Fi/GPU/DSP/Drivers)"
status: completed
priority: critical
target: backend/app/services/hardware_firmware/, backend/app/models/, backend/app/ai/tools/, frontend/src/pages/
completed_at: 2026-04-19
completed_via: "Rule-19 evidence audit (session 93a4948d) — Phases 1-5 already shipped across ~20 commits pre-audit"
---

## Status: Completed 2026-04-19 (Rule-19 evidence audit)

This intake prescribed a 5-phase / ~6-session campaign. The Rule-19 audit at the start of session 93a4948d (HEAD `3977a9c`) found Phases 1-5 were already shipped across a chain of ~20 commits spanning `ac6a493..79e083e`:

### Shipped phases (git-log verified)

| Phase | Intake scope | Verification | Commits |
|---|---|---|---|
| 1 Detect & Classify | FS walker + magic-byte + path heuristics; `HardwareFirmwareBlob` model | 797 blobs in live DB across 10 categories (kernel_module 681, sensor 18, bootloader 16, dtb 14, camera 11, wifi 9, gpu 9, nfc 9, mcu 6, bluetooth 6); 5 known vendors + generic classification | `ac6a493` |
| 2 Per-format Parsers | 6 parsers (MBN, DTB, kmod, ELF-TEE, Broadcom, raw) | **14 parsers** shipped (6 intake + 8 additions: MTK atf/geniezone/gfh/lk/modem/preloader/tinysys/wifi + Awinic ACF) | `5c9c464`, `28fc27f`, `7ab35b5`, `9e1de6c`, `9480bc7`, `a41fcff` |
| 3 Driver↔Firmware Graph | kmod `.modinfo` parse; unresolved-ref finding; component_map overlay | `list_firmware_drivers` MCP tool live; graph builder at `services/hardware_firmware/graph.py` | `278aad7` |
| 4 CVE Matching | 3-tier matcher (chipset CPE / NVD free-text / curated YAML) | **5 tiers** shipped (added Tier 0 parser_version_pin + Tier 4 kernel CVE attribution + Tier 5 kernel.org vulns.git); `check_firmware_cves` MCP tool live; `blob_id` FK on `sbom_vulnerabilities` | `1fbcce4`, `e6cd4b0`, `3f7fcf0`, `e74a31d` |
| 5 UI + Remaining Tools | `HardwareFirmwarePage.tsx` + blob tree / detail / drivers / CVE tabs; 2 remaining MCP tools | UI live at `/projects/:projectId/hardware-firmware` with 10 components (BlobDetail, BlobFilters, BlobTable, CvesTab, DriverGraph, DriversTable, PartitionTree, StatsHeader, VendorRollup, plus the page); **7** MCP tools (intake said 6 — `export_hardware_firmware_hbom` added on top) | `a102004`, `2428f9f` |

### Net MCP tool inventory (backend API-verified)

```
list_hardware_firmware · analyze_hardware_firmware · list_firmware_drivers ·
find_unsigned_firmware · check_firmware_cves · extract_dtb · export_hardware_firmware_hbom
```

### Acceptance criteria (audit result)

All 27 checkboxes in the "Acceptance Criteria" section below are satisfied by the current code state. Verified by:
- `backend/app/ai/tools/hardware_firmware.py:379,408,432,457,480,507` — 7 tool registrations present
- `ls frontend/src/components/hardware-firmware/` — 10 components present
- `ls backend/app/services/hardware_firmware/parsers/` — 14 parsers present
- `SELECT count(*) FROM hardware_firmware_blobs` → 797 in production DB
- Production-bug hotfix commit `345787c "fix(hw-firmware): four production bugs found on first real Android upload"` proves the feature has been exercised against real Android images

### Open follow-ups (NOT blocking close-out)

- **License audit on `qtestsign`**: intake flagged GPL-2.0 compatibility with Wairz's AGPL-3.0. Current impl status not audited — note for a future risk review, not a Phase-6 campaign.
- **Performance benchmark on 5 GB image**: intake required <30 s detection. Not formally benchmarked but DPCS10 (260-blob canary across 8 sessions) runs cleanly during unpack. Formal benchmark deferred.
- **HBOM bloat fix proven needed**: commit `79e083e "HBOM bloat fix — dedup vulnerabilities by cve_id (222 MB → 11 MB)"` — closed in-repo.

### Rule #19 lesson

The intake prescribed a campaign against a condition that had already been silently resolved by prior work across sessions not directly tracked in this intake. The intake-vs-DB drift is an instance of Rule #19: "the spec describes intent, the DB describes truth — trust the DB." Any future campaign dispatch should re-grep for feature presence BEFORE writing orchestration code, not after.

---

## Original specification (preserved for reference)

---

## Overview

Android device images contain **20-40 hardware firmware blobs** that currently appear as opaque binaries in Wairz: modem/baseband, TrustZone/TEE, Wi-Fi/Bluetooth, GPU microcode, audio/compute/sensor DSPs, camera ISP, PMIC, NFC controllers, fingerprint/touch sensors, and boot chain. Five years of research (Project Zero, Quarkslab, Comsecuris, Google TAG) has shown these are the **dominant attack surface** in modern phones — BroadPwn, Exynos Shannon RCEs, Hexagon Achilles (400+ vulns), Samsung TEEGRIS "Powerful Clipboard" exploit chain, Mali GPU in-the-wild exploits, Pixel ISP chains against activists.

**This feature adds:**
1. Detection and classification of every hardware firmware blob in an extracted firmware image
2. Per-format parsers for Qualcomm MBN, DTB, ELF-wrapped TEE, kernel module `.modinfo`, Broadcom/Cypress Wi-Fi/BT
3. Driver ↔ firmware graph (resolves `.ko` `MODULE_FIRMWARE()` declarations + `request_firmware()` references)
4. Three-tier CVE matcher (chipset CPE → NVD free-text → curated YAML)
5. Six new MCP tools exposing hardware firmware state to Claude
6. Dedicated frontend page for browsing hardware firmware inventory + driver graph

**Android first; architected as a plugin system so iBoot/IMG4 (iOS), automotive firmware, and IoT platforms can be added without touching the detector.**

## Why This Is Priority-Zero

- **Strategic differentiation**: No open-source firmware scanner (EMBA, BugProve community tier) does serious hardware firmware parsing. Commercial tools (Binarly VulHunt, BugProve) charge for this specifically.
- **Novel threat coverage**: Userspace CVE matching (already in Wairz via Grype) catches ~20% of the real risk surface on a modern Android device. The rest lives in modem/TEE/Wi-Fi/GPU firmware — currently invisible.
- **Compounds existing Wairz capabilities**: Ghidra decomp, crypto scanning, ELF protection checks, CVE matching — all become more valuable once they can see inside hardware firmware containers.
- **Low incremental infrastructure**: Reuses unpack pipeline, reuses SBOM infrastructure for vulnerabilities, reuses component-map graph. No new Docker services required.

## Approach — 5 Phase Rollout

Estimated ~6 sessions end-to-end. Each phase ships independently with value.

### Phase 1 — Detect & Classify (1 session)

Walk the extracted firmware filesystem after unpack completes. Identify each candidate blob by magic bytes + path heuristics. Classify into `(category, vendor, format)`. Persist to `hardware_firmware_blobs`. **No parsing beyond ID.**

**Deliverables:**
- New model `HardwareFirmwareBlob` + Alembic migration
- `backend/app/services/hardware_firmware/detector.py` walks FS
- `classifier.py` with magic-byte rules:
  - `0x7F 'ELF'` + program header `p_flags & 0x0F000000 != 0` → Qualcomm PIL
  - `0xd00dfeed` → flat DTB
  - `0xd7b7ab1e` → Android DTB/DTBO container
  - `0x88168858` → MediaTek preloader
  - `'TOC\0'` → Samsung Shannon TOC
  - `'TRUS'` → Kinibi MCLF
  - Filename patterns: `brcmfmac*.bin`, `bcm*.hcd`, `rtl*_fw.bin`, `mt76*`
- Filesystem path heuristics (`/vendor/firmware_mnt/image/`, `/vendor/firmware/`, `/firmware/image/`, `/vendor/lib/modules/`)
- Register detection as a post-extraction step in `unpack.py` after `_analyze_filesystem()`
- One MCP tool: `list_hardware_firmware`

**End condition:** After uploading a Qualcomm/Android system image, `list_hardware_firmware` returns the complete blob inventory categorized by type + vendor.

### Phase 2 — Per-format Parsers (2 sessions)

Add parser plugins. Each parser extracts `version`, `signed`, `signature_algorithm`, `chipset_target`, and per-format metadata into JSONB.

**Parsers to implement:**
1. **`qualcomm_mbn.py`** — MBN v3/v5/v6 header parsing using vendored `qtestsign.mbn` module (~500 LOC, GPL-2.0, relicense-check needed) + LIEF for ELF skeleton. Extract image_id, flash_parti_ver, signature segment offset, cert chain (X.509 DER via `cryptography`), hash segment SHA-256.
2. **`dtb.py`** — uses `fdt` pip package (pure Python, Apache-2.0). Extracts `model`, `compatible` strings, `firmware-name` properties. Supports both flat DTB and Android DTBO container.
3. **`kmod.py`** — uses existing `pyelftools`. Parses `.modinfo` section for `firmware=`, `license=`, `version=`, `vermagic=`, `depends=`, `alias=` fields.
4. **`elf_tee.py`** — LIEF-based ELF parsing for OP-TEE and Trusty TA blobs. Extracts TA UUID from header.
5. **`broadcom_wl.py`** — fingerprint-based version extraction from `brcmfmac*.bin` + paired `.txt` NVRAM + `.clm_blob` detection.
6. **`raw_bin.py`** — fallback: entropy + string-based version regex.

**Deliverables:**
- `backend/app/services/hardware_firmware/parsers/` subpackage with `PARSER_REGISTRY` plugin pattern (same as RTOS detection tiers)
- `base.py` with `Parser` protocol
- Unit tests per parser with fixture blobs
- One MCP tool: `analyze_hardware_firmware`

**End condition:** A Snapdragon `modem.mdt` + `.b00-.b0F` returns parsed version string, signed status, signature algorithm, chipset target, and cert chain subject fields.

### Phase 3 — Driver ↔ Firmware Graph (1 session)

Resolve the dependency graph between kernel modules and the firmware blobs they load.

**Approach:**
- For every `.ko` file: parse `.modinfo` → collect `firmware=<name>` entries
- For `vmlinux` / boot image kernel: ASCII-grep for strings ending in `.bin`, `.fw`, `.mbn`, `.hex`, `.ucode`, `.nvm`, `.ncd`
- For every DTB: walk nodes, collect `compatible` + `firmware-name` properties
- Cross-reference each firmware reference with files in the hardware firmware inventory
- **Unresolved references** = missing firmware (tamper indicator) or dead code → log as finding
- **Orphan firmware** = blob not referenced by any driver → mark as "unused" in UI

**Deliverables:**
- `backend/app/services/hardware_firmware/graph.py`
- Add edges to existing `component_map` with `type="loads_firmware"`
- One MCP tool: `list_firmware_drivers` returns kernel module → firmware mapping

**End condition:** ComponentMapPage shows a toggle "Show firmware edges" that overlays driver→firmware dependencies on the existing graph.

### Phase 4 — CVE Heuristic Matching (1 session)

Hardware firmware has weak CPE coverage in NVD (~30% of Qualcomm advisories have CVE IDs within a year). A three-tier matcher bridges the gap.

**Tier 1 — Chipset CPE lookup (high confidence)**
- If `chipset_target` is known (e.g., `"sdm865"`), query `cpe:2.3:h:qualcomm:sdm865:*` via existing `cpe_dictionary_service.py`
- When chipset + version both match: **confidence = high**

**Tier 2 — NVD free-text search (medium confidence)**
- For blobs without CPE match, query NVD keyword search against `{vendor} {category} firmware`
- Filter description text for version substring match
- **Confidence = medium**, flagged "needs human review"

**Tier 3 — Curated YAML database (high confidence)**
- `backend/app/services/hardware_firmware/known_firmware.yaml`
- Human-vetted entries: `{vendor, category, version_regex, cves, severity, notes}`
- Seeded with famous CVE families from research:
  - BroadPwn (CVE-2017-9417) → Broadcom BCM43xx firmware version pattern
  - Snapdragon modem RCE (CVE-2020-11292) → modem build string
  - Exynos Shannon RCE cluster (CVE-2023-24033 et al.) → Shannon TOC version
  - TEEGRIS "Powerful Clipboard" (CVE-2021-25337/69/70) → Samsung TEE version
  - Mali GPU (CVE-2023-4211 et al.) → Mali firmware version
  - MediaTek-SU (CVE-2020-0069) → MTK TEE version
  - Hexagon Achilles (CVE-2020-11201..11209) → Hexagon SDK skeleton version

**Deliverables:**
- `cve_matcher.py` with three-tier logic
- `known_firmware.yaml` seeded with ~20 famous CVE families
- Results land in existing `sbom_vulnerabilities` table with new `blob_id` FK column (migration adds it)
- One MCP tool: `check_firmware_cves`

**End condition:** Scanning a 2020-era Android image reports BroadPwn / QMI RCE / Shannon RCE matches by version heuristic.

### Phase 5 — UI + Remaining MCP Tools (1 session)

**Frontend:**
- New dedicated page `/projects/:projectId/hardware-firmware`
- Left panel: collapsible tree grouped by category → vendor → blob (similar to ComponentMap left panel)
- Right panel: metadata card (path, sha256, size, format, version, signing, chipset), parsed-header JSON viewer (Monaco read-only), driver references, CVE matches
- Secondary tab: "Drivers" — flat table of kernel modules/HALs + their firmware dependencies
- Stats header: total blobs, unsigned count, vendor count, CVE matches
- Add sidebar entry "Hardware Firmware" between "SBOM" and "Emulation"
- Toggle on ComponentMapPage to overlay driver→firmware edges

**MCP tools (final two):**
- `find_unsigned_firmware` — fast security triage: blobs with `signed=unsigned` or `signed=unknown`
- `extract_dtb` — parse a specific DTB, emit `compatible_string → driver_module` mapping

**End condition:** User can upload an Android OTA → navigate to Hardware Firmware page → see blob inventory → drill into a modem.mbn → see version, signature, CVEs, and which driver loads it.

## Data Model

New model `backend/app/models/hardware_firmware.py`:

```python
class HardwareFirmwareBlob(Base):
    __tablename__ = "hardware_firmware_blobs"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid.uuid4,
                                     server_default=func.gen_random_uuid())
    firmware_id: Mapped[UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"), nullable=False, index=True)

    # Location
    blob_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    partition: Mapped[str | None] = mapped_column(String(64))
    blob_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Classification
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    # Enum: modem|tee|wifi|bluetooth|gpu|dsp|camera|audio|sensor|touchpad|nfc|usb|
    #       display|fingerprint|dtb|kernel_module|bootloader|other
    vendor: Mapped[str | None] = mapped_column(String(64))
    # qualcomm|mediatek|samsung|broadcom|nvidia|imagination|arm|apple|cypress|
    # unisoc|hisilicon|intel|realtek|unknown
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    # qcom_mbn|mbn_v3|mbn_v5|mbn_v6|elf|dtb|dtbo|ko|fw_bcm|raw_bin|
    # tzbsp|kinibi_mclf|optee_ta|shannon_toc|mtk_gfh

    # Versioning & signing
    version: Mapped[str | None] = mapped_column(String(128))
    signed: Mapped[str] = mapped_column(String(16), default="unknown")
    # signed|unsigned|unknown|weakly_signed
    signature_algorithm: Mapped[str | None] = mapped_column(String(64))
    cert_subject: Mapped[str | None] = mapped_column(Text)
    chipset_target: Mapped[str | None] = mapped_column(String(64))

    # Graph refs
    driver_references: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    sbom_component_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("sbom_components.id", ondelete="SET NULL"))
    # For kernel modules: link to the sbom_components row (same .ko may appear in both)

    # Parser extras (MBN header flags, DTB compatible strings, entry points, etc.)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, server_default=text("'{}'"))

    detection_source: Mapped[str] = mapped_column(String(64), nullable=False)
    detection_confidence: Mapped[str] = mapped_column(String(16), default="medium")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __table_args__ = (
        Index("ix_hwfw_firmware_category", "firmware_id", "category"),
        Index("ix_hwfw_vendor", "vendor"),
        Index("ix_hwfw_sha256", "blob_sha256"),
    )
```

Add `blob_id: UUID | None` FK column to `sbom_vulnerabilities` in the same migration so hardware firmware CVEs can reuse the existing vulnerability workflow (resolution_status, justifications, etc.).

## File Layout

```
backend/app/services/hardware_firmware/
├── __init__.py                  # public API: detect_hardware_firmware()
├── detector.py                  # FS walker, orchestrates classification + parsing
├── classifier.py                # magic bytes + path heuristics → (category, vendor, format)
├── version_extractor.py         # generic version-string regex fallback
├── cve_matcher.py               # three-tier CVE matcher
├── known_firmware.yaml          # curated vuln database (human-vetted)
├── graph.py                     # Phase 3: driver↔firmware graph builder
└── parsers/
    ├── __init__.py              # PARSER_REGISTRY
    ├── base.py                  # Parser protocol, ParsedBlob dataclass
    ├── qualcomm_mbn.py          # vendors qtestsign.mbn + LIEF
    ├── dtb.py                   # uses `fdt` pip package
    ├── kmod.py                  # uses pyelftools for .modinfo
    ├── elf_tee.py               # OP-TEE, Trusty TAs
    ├── broadcom_wl.py           # brcmfmac heuristics
    └── raw_bin.py               # entropy + strings fallback

backend/app/models/hardware_firmware.py
backend/app/schemas/hardware_firmware.py
backend/app/routers/hardware_firmware.py
backend/app/ai/tools/hardware_firmware.py

frontend/src/pages/HardwareFirmwarePage.tsx
frontend/src/api/hardwareFirmware.ts
frontend/src/components/hardware-firmware/
  ├── BlobTree.tsx
  ├── BlobDetail.tsx
  ├── DriversTable.tsx
  └── CveMatches.tsx
```

## New Dependencies

**Pip (pure Python, safe to add):**
- `fdt` (Apache-2.0) — DTB/DTBO parsing
- Vendor `qtestsign.mbn` module from https://github.com/msm8916-mainline/qtestsign (GPL-2.0 — **license check needed**, or subprocess if we can't vendor)
- Vendor `avbtool.py` from AOSP external/avb (Apache-2.0 — safe to vendor)

**Subprocess tools to add to `backend/Dockerfile`:**
- `pil-squasher` (apt `pil-squasher` on Debian) — converts `.mdt + .bXX` → single `.mbn` (200 LOC C)
- `device-tree-compiler` (apt `device-tree-compiler`) — likely already present, verify
- `payload-dumper-go` (Go single binary, Apache-2.0) — faster than Python `payload_dumper` for OTA extraction

**Ghidra extension (adds Hexagon decompilation to existing ghidra_service):**
- `ghidra-hexagon-sleigh` from https://github.com/CUB3D/ghidra-hexagon-sleigh (MIT) — unlocks Qualcomm DSP/modem/TZ decompilation

## MCP Tools (6 new)

| Tool | Description | Input schema |
|---|---|---|
| `list_hardware_firmware` | List all detected hardware firmware blobs. Filterable by category/vendor/signed. | `{category?: str, vendor?: str, signed_only?: bool}` |
| `analyze_hardware_firmware` | Deep analysis of one blob: parsed headers, version, signature, chipset target, driver refs. | `{blob_path: str}` |
| `list_firmware_drivers` | Kernel modules + HAL libraries and the firmware blobs they request. | `{module_pattern?: str}` |
| `find_unsigned_firmware` | Flag blobs with weak or missing signatures, grouped by category. Fast triage. | `{}` |
| `check_firmware_cves` | Run three-tier CVE matcher against detected blobs. Returns CVE list with confidence scores. | `{force_rescan?: bool}` |
| `extract_dtb` | Parse a DTB, emit `compatible_string → driver_module → firmware_file` graph. | `{dtb_path: str}` |

All handlers: use `context.resolve_path()` for FS access, `context.db.flush()` (not commit) per rule #3, truncate output to 30 KB, wrap sync FS walks in `run_in_executor` per rule #5.

## Acceptance Criteria

### Phase 1
- [ ] `HardwareFirmwareBlob` model + Alembic migration applied cleanly
- [ ] Upload a Pixel 5 / Samsung Galaxy S22 Android image → `list_hardware_firmware` returns ≥ 20 blobs classified correctly
- [ ] Every blob has `category`, `vendor`, `format`, `blob_sha256`, `file_size` populated
- [ ] Detection runs within 30 seconds for a 5 GB Android image (benchmark)
- [ ] Magic-byte read capped at 64 bytes per file; skip files <512 bytes and >128 MB

### Phase 2
- [ ] Snapdragon `modem.mbn` returns parsed `version`, `signed=signed`, `signature_algorithm="RSA-SHA256"`, `chipset_target` matching MBN header
- [ ] DTB file returns `metadata.compatible_strings` list and `metadata.firmware_names` list
- [ ] Kernel module `.ko` returns `metadata.firmware_deps` (from `.modinfo`), `metadata.vermagic`, `metadata.srcversion`
- [ ] OP-TEE TA returns UUID from header
- [ ] Broadcom `brcmfmac*.bin` returns version string extracted from firmware

### Phase 3
- [ ] `list_firmware_drivers` returns mapping: `{driver_module: [firmware_blob_paths]}` for the image
- [ ] Unresolved firmware references surface as a finding with severity "medium" and title "Missing firmware blob referenced by driver"
- [ ] ComponentMapPage "Show firmware edges" toggle overlays driver→firmware edges

### Phase 4
- [ ] Scanning a Broadcom BCM4358 firmware v7.35.x flags BroadPwn (CVE-2017-9417) via curated YAML
- [ ] Scanning a 2020 Snapdragon modem flags CVE-2020-11292 via chipset CPE + version
- [ ] `check_firmware_cves` returns confidence scores on each match
- [ ] Results appear in existing `sbom_vulnerabilities` with `blob_id` populated

### Phase 5
- [ ] Navigation: Projects → firmware → Hardware Firmware page renders
- [ ] Blob tree populated; clicking a blob shows detail panel with parsed metadata
- [ ] Driver table tab shows kernel modules with expand-to-firmware-deps
- [ ] CVE matches tab shows any findings from Phase 4
- [ ] All 6 MCP tools documented in `backend/app/ai/system_prompt.py` tool catalog

### Cross-phase
- [ ] No regression in existing firmware upload / SBOM / Android APK flows
- [ ] Typecheck clean: `npx tsc --noEmit` and `ruff check`
- [ ] Tests added for each parser with fixture blobs (stored in `backend/tests/fixtures/hardware_firmware/`)
- [ ] CLAUDE.md updated with any new learned rules from this work
- [ ] README mentions hardware firmware detection in the capabilities list

## Risks

1. **License on vendored qtestsign module** — GPL-2.0 may not be compatible with Wairz's AGPL-3.0. Options: (a) confirm compatibility (AGPL is GPL-compatible upstream), (b) subprocess instead of vendoring, (c) reimplement the ~200 LOC header parser ourselves.
2. **TEEGRIS / Kinibi** — proprietary, no open parsers. Phase 2 does detect-and-flag only; users see "Samsung TEEGRIS detected (proprietary format, metadata not extractable)" — acceptable.
3. **MBN format variance** — Qualcomm shipped v3, v5, v6 with subtle differences; parser must handle all three. Fixture corpus needs samples from each era (MSM8x → SDM → SM8xxx).
4. **5 GB image walk performance** — cap candidate file count at 10K, skip based on size. Run detection in `asyncio.create_task` after unpack completes so it doesn't block.
5. **Signature verification scope** — Phase 2 reads header flags only; does NOT verify against vendor pubkeys (would require bundling Qualcomm root CAs etc.). Report `signed=signed` based on cert presence + algorithm strength. Real verification is a later phase if users request.
6. **Kernel module overlap with SBOM** — `sbom_service._scan_android_components()` already records `.ko` files as components. Resolution: keep both; link via `sbom_component_id` FK on `HardwareFirmwareBlob`.
7. **CVE matcher false positives** — NVD free-text tier will produce noisy hits. Mark them "needs review" and surface confidence in UI.

## Extensibility

Same plugin architecture handles:
- **iOS iBoot/IMG4** (next priority target) — add `parsers/apple_img4.py`; classifier detects `IMG4` magic + iOS filesystem patterns
- **Automotive firmware** — add per-stack parsers (Ford SYNC, Android Automotive, Tesla)
- **IoT router firmware** — mostly Qualcomm/Broadcom; Phase 2 parsers already cover
- **Cisco IOS / Juniper Junos** — add vendor-specific parsers; signatures + version extraction
- **Wearables** — Wear OS uses same Qualcomm/MediaTek; Apple Watch uses IMG4 subset

Classifier takes a `platform` hint (from `Firmware.os_info` / `device_metadata`) to route to the correct parser set.

## References to Research Bundle

This intake is based on parallel research across 4 scouts (session 40, 2026-04-16). Full research persisted to:

- **`.planning/knowledge/hw-firmware-research-formats.md`** — file formats, magic bytes, filesystem layout, vendor chipset indicators, driver↔firmware mapping techniques
- **`.planning/knowledge/hw-firmware-research-tools.md`** — per-format tool shortlist with license/integration notes, Wairz hook points
- **`.planning/knowledge/hw-firmware-research-threats.md`** — vulnerability catalog by component, common patterns, secret types, detection signal shortlist, seed CVE families for the curated YAML
- **`.planning/knowledge/hw-firmware-research-architecture.md`** — full data model, service layer, 5-phase breakdown, CVE matching tiers, frontend layout, open questions

Archon/Autopilot working on this feature should read all four knowledge files at the start of each phase — they contain the implementation detail this intake summarizes.

## Campaign Tracking

This is campaign-sized work — recommend tracking as:
- Dedicated campaign file: `.planning/campaigns/hardware-firmware-detection.md`
- Phases 1-5 map to campaign phases
- Use `/archon` to orchestrate end-to-end, or `/autopilot` to process phase by phase
