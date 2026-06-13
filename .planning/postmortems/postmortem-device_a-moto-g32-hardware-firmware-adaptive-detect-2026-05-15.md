# Postmortem: DS1 Moto-G32 hardware-firmware adaptive detection (sequel)

> Date: 2026-05-15
> Campaign: ad-hoc systematic-debugging session (no campaign file — driven from user prompt `/citadel:systematic-debugging projects/8413d661-... only pops for 3 CVEs on Bluetooth, also missed the Qualcomm radio on the G32`)
> Predecessor: postmortem-ds1-moto-g32-zero-blobs-2026-05-14 (the 0→331 blobs recovery)
> Duration: ~3.5 hours (commit `bcdfb8c` → commit `bacb660`)
> Outcome: completed; one prong (super.img recovery) queued as follow-up.

## Summary

Yesterday's sweep recovered 0→331 blobs for DS1 Moto-G32 and 0→286 blobs for Moto-G30 via the detection-roots fallback + NUL sanitization + Broadcom Bluetooth patterns. User returned with two follow-up complaints: **(a)** "completely missed the Qualcomm radio on the G32" — UI showed only 24 qcom/modem entries despite the device being a Bengal SM6225 Snapdragon platform with a ~470 MB radio.img full of modem firmware; **(b)** "only pops for 3 CVEs on Bluetooth" — Tier 3 matcher fired exclusively the BleedingTooth cluster (CVE-2020-12351/12352/24490) against the 18 Broadcom Bluetooth blobs, ZERO Qualcomm CVEs across 312 Qualcomm blobs. User directive: "don't hard code strict formats... we need to be more adaptable/versatile/flexible/resilient across entire code base and architecture... we won't be the only ones ingesting files into the tool."

Two coordinated fixes shipped per Rule #25 per-piece commits. End-to-end leverage measured on the rebuilt backend+worker images:

| Metric | After 2026-05-14 | After 2026-05-15 | Change |
|---|---|---|---|
| G32 (eed5db82) blob count | 331 | **610** | +84% |
| G32 distinct CVEs | 3 | **31** | +10× |
| G32 sb_vuln rows | 54 | **4,352** | +80× |
| G30 (f84544a9) blob count | 286 | **515** | +80% |
| G30 distinct CVEs | 0 (status=idle) | **31** | ∞ |
| G30 sb_vuln rows | 0 | **3,672** | ∞ |
| qcom/modem (combined) | 24 | **892** | +37× |
| qcom/audio (combined) | 11 | 93 | +8× |
| qcom/dsp (combined) | 9 | 41 | +5× |
| qcom/wifi (combined) | 0 | 32 | ∞ |
| qcom/bootloader (combined) | 0 | 24 | ∞ |

CVE coverage now spans: Snapdragon modem RCE 2024-2025 (CVE-2025-27034 PLMN overflow, CVE-2025-21483 RTP heap overflow, CVE-2024-43047 DSP UAF, CVE-2025-21477 CCCH DoS), Adreno GPU zero-days (CVE-2025-21479/21480/27038 — Google TAG June 2025), FastConnect WLAN+BT (CVE-2025-47401/47403/CVE-2024-20040), Spectra ISP camera (CVE-2025-47405/47387), vdec OOB cluster (CVE-2024-20011/9/7), Hexagon Achilles (CVE-2020-11201..11209), BleedingTooth (CVE-2020-12351/12352/24490), modem DoS (CVE-2024-43048, CVE-2025-47408), Qualcomm EDL (CVE-2017-18159), plus ADVISORY-QC-ADSP and ADVISORY-QC-WLAN advisory-shape entries.

## What Broke

### 1. Hardcoded prefix if-chain in `_category_from_qcom_name` sank 517/611 (85%) qualcomm blobs into `category=other`

- **What happened:** `classifier.py:170 _category_from_qcom_name(name)` is a 17-line if-chain checking filename STEM prefixes (`modem*`, `tz*`, `xbl*`, `adsp`, etc.). Files in `radio.img_extract/.../carrier_config/` with names like `att_usa_volte.mbn`, `airtel_ind_volte.mbn`, `acg_usa_ims.mbn` (carrier-specific IMS/VoLTE modem configuration), `bdwlan.b0X` (Qualcomm WLAN combo split chunks), and EFS/RFNV item files all fall through to `return "other"`. The qcom-PIL extension matcher (`_QCOM_EXT = re.compile(r"\.(mbn|mdt|b0[0-9a-f])$")`) catches them as Qualcomm by vendor but the category resolver buckets them generically. Result: 517 of 611 qualcomm blobs were `category=other` despite living in a CELLULAR MODEM PARTITION.
- **Caught by:** Nothing automated — user noticed UI showed almost no qcom/modem entries. Root cause traced via systematic-debugging Phase 1-3 (DB partition-origin × category breakdown showed `in_radio.img qualcomm other = 517`, vs. `in_radio.img qualcomm modem = 24`).
- **Cost:** ~30 min trace + ~45 min YAML schema + classifier implementation.
- **Fix:** Commit `94df63c` — added `path_contexts:` section to `firmware_patterns.yaml` (11 initial entries) + `match_path_context()` to `patterns_loader.py` + `_apply_path_context()` in `classifier.py`. Path-context is a REFINEMENT step: when `_classify_inner` returns `category="other"`, a YAML-driven path rule can rescue it into a specific category; when it returns `None`, the path rule can build a Classification from scratch (rescue mode). Contract: path-context CANNOT demote a non-"other" filename match — filename evidence beats path evidence when both are available.
- **Infrastructure created:** 13 new tests in `test_hardware_firmware_classifier_patterns.py` (path_contexts YAML load, RFNV/BTFM/dspso/WLAN/carrier-config matches, priority ordering, no-demote contract regression guard, refine-vs-rescue distinction).

### 2. CVE matcher `chipset_regex` strict-mode produced zero Qualcomm matches across 612 blobs

- **What happened:** `cve_matcher.py:227 _match_curated`'s chipset_regex gate (`if chipset_re and not blob_chipset: continue`) rejected every Qualcomm blob — `chipset_target` is populated on **1 of 611** qualcomm blobs in the corpus (only one SM6115 entry). The four pre-existing Qualcomm YAML entries all used either strict chipset_regex (rejected) or strict version_regex like `"(?i).*(2019|2020-0[1-8]).*"` (rejected — `blob.version` is universally NULL on Qualcomm firmware; modem.b0X chunks don't surface build banners). Result: 0 Qualcomm CVE matches, 3 Broadcom Bluetooth CVEs total (BleedingTooth, no version constraint → fired on every broadcom/bluetooth blob).
- **Caught by:** DB query `SELECT chipset_target, COUNT(*) FROM hardware_firmware_blobs ... GROUP BY 1` during Phase 2 hypothesis verification — measured chipset_target population at ~0% across all qualcomm category buckets.
- **Cost:** ~20 min audit + ~30 min matcher refactor + ~45 min YAML expansion authoring.
- **Fix:** Commit `bacb660` — three coordinated changes. **(a) Soft chipset_regex:** when `chipset_re` is declared on a family but `blob.chipset_target` is NULL, the match still fires with confidence downgraded from "high" to "medium" (signals missing positive chipset evidence). Populated-but-non-matching chipset_target still rejects. **(b) Optional `category_regex`:** one family can span related categories (e.g. Hexagon Achilles `category_regex: "^(audio|dsp)$"` covers both aDSP and cDSP). Takes precedence over `category` when present. **(c) 12 new advisory-shape Qualcomm entries** covering Snapdragon modem 2024-2025, Hexagon FastRPC, Adreno zero-days, FastConnect WLAN+BT, Spectra ISP, vdec cluster, SLPI, QSEE, WLAN advisory, ADSP advisory — all with broad chipset_regex (`^(sm|sdm|qcm|qm|wcn|qca)(...).*`) covering Bengal SM6225 + SM4350 + the full Snapdragon family. The three over-constrained existing Qualcomm entries (Snapdragon modem RCE, Hexagon Achilles, QSEE Widevine) had their strict version_regex dropped + chipset_regex broadened. **(d) Defensive truncation** for advisory `cve_id` synthesis — column is `VARCHAR(20)` (Rule #15); long names like "Qualcomm SLPI framework advisory" would have INSERT-failed. Matcher clips to 20 chars and supports an explicit `advisory_id:` YAML key for collision-safe short tags (used: `ADVISORY-KAMAKIRI`, `ADVISORY-MTK-PM`, `ADVISORY-QC-QSEE`, `ADVISORY-QC-SLPI`, `ADVISORY-QC-WLAN`, `ADVISORY-QC-ADSP`).
- **Infrastructure created:** 7 new unit tests in `test_hardware_firmware_cve_matcher.py` (soft chipset null-target, strict chipset miss, populated-target high-confidence, category_regex spans audio+dsp, category_regex precedence over exact category, real-YAML qualcomm/modem advisory hit, real-YAML qualcomm/audio Achilles hit via category_regex). Two pre-existing tests updated to reflect new soft-chipset semantics (BroadPwn now fires on NULL chipset with medium confidence; advisory family-shape now accepts category_regex instead of category).

### 3. Worker image had stale `detector.py` missing yesterday's NUL sanitizers (commit fc08450)

- **What happened:** When my re-detection canary ran against the post-Fix-1+Fix-2 docker-cp'd state, the worker container's INSERT failed with `CharacterNotInRepertoireError: 0x00`. Probe revealed the worker's `/app/app/services/hardware_firmware/detector.py` had 0 occurrences of `_sanitize_text` / `_sanitize_jsonb` — the image hadn't been rebuilt since BEFORE yesterday's commit `fc08450` landed (which added the sanitizers specifically to handle Qualcomm ELF segment NUL bytes in `version` / `qc_image_version_string` metadata).
- **Caught by:** The bulk INSERT itself — failed loudly at commit time. Pre-cp'd image was running stale code.
- **Cost:** ~10 min trace. The fix was just `docker cp detector.py` + restart, then the eventual `docker compose build --pull backend worker migrator` Rule #8 rebuild.
- **Fix:** No code change needed — the right code already existed on host. Issue was image staleness. Resolved via Rule #20 fast-iteration `docker cp` then the durable Rule #8 rebuild after the per-piece commits landed.
- **Infrastructure created:** None new — confirms yesterday's `_sanitize_text`/`_sanitize_jsonb` discipline is correctly applied by detector.py at the bulk-insert boundary. The image-staleness was the issue, not the sanitizer code.

## What Safety Systems Caught

| System | What It Caught | Times | Impact Prevented |
|--------|---------------|-------|-----------------|
| Postmortem corpus (yesterday's `postmortem-ds1-moto-g32-zero-blobs-2026-05-14`) | Both projects' identity + the full sweep history were one Read away — Phase 1 took ~30 sec to understand the predecessor work | 1 | Would have spent an hour re-tracing the same ground; instead pivoted directly to the new symptom |
| `device_metadata.detection_audit` JSONB | Confirmed 56 roots + 0.989 orphan_ratio = healthy detection, narrowing the bug surface to "classifier/matcher categorization", not "extraction" | 2 (DS1 + G30) | Without the audit, would have re-investigated unblob extraction completeness |
| DB partition-origin × category SQL | `WHERE category='other' AND vendor='qualcomm' GROUP BY 1` surfaced the 517-blob mismatch in one query — precise root cause without code-tracing | 1 | Would have spent an hour reading classifier.py + tracing call paths to deduce the same finding |
| Pre-existing CVE matcher unit tests | 2 tests asserted OLD strict-chipset semantics; both surfaced as expected failures the moment I shipped the new soft semantics — forced me to update them with explicit "Updated 2026-05-15" comment explaining the new contract | 2 | Silent behavior drift across versions if the tests had been deleted instead of updated |
| Bulk INSERT NUL rejection | Caught the stale worker image before any blob row landed corrupt | 1 | Detected staleness vs. silent partial-failure |
| 3 parallel research scouts (Scout A path-context design, Scout B CVE coverage audit, Scout C super.img recovery) | Each found a different prong of the bug taxonomy; Scout B specifically called out that strict version_regex would still fail with my plan, redirecting me to soft-mode design | 3 | Single-thread investigation would have shipped Fix 2 with chipset_regex still required, producing zero qualcomm matches because of the chipset_target=0/611 finding I made independently |

## Scope Analysis

- **Planned (user prompt):** "deep research thinking and troubleshooting to enhance this feature... don't hard code strict formats... be more adaptable/versatile/flexible/resilient... only pops for 3 CVEs on Bluetooth... missed the Qualcomm radio on the G32".
- **Built:**
  - 2 Rule #25 commits across 4 files (firmware_patterns.yaml + patterns_loader.py + classifier.py + cve_matcher.py + known_firmware.yaml + 2 test files).
  - 11 path_contexts YAML entries (data-driven, vendor-agnostic; extensible without touching Python).
  - 12 new + 3 reshaped Qualcomm advisory entries in known_firmware.yaml.
  - Matcher refactor: soft chipset_regex, optional category_regex, defensive cve_id truncation, advisory_id support.
  - 20 net-new tests (13 classifier + 7 matcher).
  - End-to-end re-detection + re-cve-match of both target firmwares; firmware row aggregates updated to reflect new totals for UI display.
- **Drift:** ONE prong queued, not built. Scout C identified that `super.img_sparsechunk.0..10_extract/` directories totaling ~5 GB of content sit unwalked because unblob doesn't recombine Android sparse-image chunks into a single ext4 image. `simg2img` is already in the worker Dockerfile (line 148); helpers `_concatenate_sparsechunks` + `_scan_super_partitions` already exist in `unpack_android.py` — they're just not being invoked on the post-unblob output. Fix C is a ~100 LOC post-unblob recovery pass + a Dockerfile addition for `abootimg` for `vendor_boot.img` extraction. Estimated 1-2 hour session; deferred to follow-up because it requires re-uploading firmware to verify (the existing extracted trees on disk don't have the recombined output and re-running unblob is slow). Queued as Task #8 in this session's task list.

## Patterns

1. **Data-driven YAML extension trumps hardcoded if-chain refactors for adaptability.** Replacing `_category_from_qcom_name`'s 17-line prefix if-chain with a YAML-driven path_contexts section means future operators with different firmware shapes (Yocto, OpenWrt, other Android vendors, future Qualcomm chipset families, MediaTek radio partitions) extend coverage by editing one YAML file. No Python change. No rebuild — well, except for the Rule #20 module-level singleton state issue if the file is hot-loaded. The pattern generalizes beyond Qualcomm.

2. **Soft + Strict matcher modes give "absent evidence" different semantics from "negative evidence".** The pre-existing chipset_regex gate treated NULL chipset_target as "rejected" — wrong, because NULL means "we couldn't extract this signal", not "this blob doesn't have this chipset". Soft mode treats NULL as "match with confidence downgrade" and reserves rejection for "populated AND mismatched". This is a directly transferable pattern for any matcher that combines positive (filename match) + corroborating (chipset/version) signals.

3. **DB-grounded hypothesis verification beats grep-grounded.** Phase 2 spent ~10 minutes on three SQL queries (`SELECT vendor, category, COUNT(*)`, `SELECT chipset_target, COUNT(*)`, `SELECT partition-origin × category breakdown`) and produced surgical root-cause statements. The same conclusions via grep-tracing classifier.py + cve_matcher.py would have taken hours and missed the 1/611 chipset_target finding entirely.

4. **3 parallel research scouts dispatched in single message → ~3 min wall clock for design proposals across all bug prongs.** Each scout was given a specific deliverable shape (filename taxonomy table, YAML schema, integration point, risk analysis). Synthesis at return time was straightforward because the scouts didn't overlap and each produced design-grade output. Repeat pattern: Scout A path-context + Scout B CVE coverage + Scout C super.img recovery → 3 actionable design proposals + no scout collision.

5. **Per-piece commit discipline made the rebuild + re-verify loop crisp.** Two commits, each independently revertable. After Commit 1 (path-context), I could have stopped and shipped just that — would have moved 517 blobs into proper categories but still produced 0 Qualcomm CVE matches because Fix 2 was the matcher half. After Commit 2 (CVE expansion), the combined effect of (a) more blobs in qcom/modem + (b) the matcher firing on qcom/modem with advisory entries produced the 80× sb_vuln row increase. Either commit alone is a clean rollback target.

## Recommendations

1. **Ship Fix C (super.img + vendor_boot recovery) in a follow-up session.** Scout C's design is solid; the helpers already exist in `unpack_android.py`. The ~5 GB of unwalked super.img content likely contains the kernel + ramdisk + system + vendor partition contents — i.e. a multiplicative blob-count gain on top of today's 84% gain. Reference design in this postmortem's Scope Analysis. Add `abootimg` to the worker Dockerfile.

2. **Add an automated detection-completeness alert** — a periodic check that COUNT(*) of firmwares where `(detection_audit.blobs_detected / files_on_disk) < 0.05` is below some threshold. Today's 610-blob G32 has files_on_disk ~3,843 → ratio 0.16 (vs. yesterday's 0.09). A sub-0.05 ratio is operator-actionable.

3. **Widen `sbom_vulnerabilities.cve_id` from VARCHAR(20) to VARCHAR(64) in a follow-up migration.** The defensive truncation + advisory_id pattern in this commit is correct, but the column constraint itself is over-tight. Most CVE IDs fit in 20 chars but advisory-shape `ADVISORY-<vendor>-<category>-<detail>` benefits from a wider field. Backfill is trivial (no row content widens).

4. **Audit the rest of `_category_from_qcom_name` (and similar vendor-specific hardcoded if-chains) for path-context retrofitting opportunities.** The pattern transfers to: `_QCOM_STEMS` set (currently 23 hardcoded stems — file-name-only), `_FW_PARTITION_HINTS`, MediaTek's `_classify_by_magic` LK-partition dispatch. Each is a candidate for a small YAML-extension that lets users add new vendor stem mappings without code.

5. **Investigate why `_MAX_CANDIDATES = 10000` truncated walks on G32.** Today's re-detection emitted `Hardware firmware detector: candidate cap reached (10000), walk truncated` for at least one root. The cap may need to be parameterized per-firmware, or split across roots, or replaced with a memory-bound check.

## Numbers

| Metric | Value |
|--------|-------|
| Bug count | 2 root causes (categorization sink + CVE coverage gap) + 1 image-staleness operational |
| Commits | 2 (Rule #25 per-piece) |
| Files changed | 6 (firmware_patterns.yaml + patterns_loader.py + classifier.py + cve_matcher.py + known_firmware.yaml + 2 test files) |
| Lines added | ~1085 |
| New tests | 20 (13 classifier + 7 matcher) |
| Updated tests | 2 (cve_matcher pre-existing tests updated for new soft semantics) |
| Path-context YAML entries shipped | 11 |
| New Qualcomm CVE YAML entries shipped | 12 |
| Reshaped CVE YAML entries (drop strict version_regex) | 3 |
| G32 blobs (before → after) | 331 → 610 (+84%) |
| G32 distinct CVEs (before → after) | 3 → 31 (+10×) |
| G32 sb_vuln rows (before → after) | 54 → 4,352 (+80×) |
| G30 distinct CVEs (before → after) | 0 → 31 (∞) |
| Combined qcom/modem blob count (before → after) | 24 → 892 (+37×) |
| Parallel research scouts dispatched | 3 (Scout A path-context, Scout B CVE coverage, Scout C super.img) |
| Scout wall-clock | ~3-4 min (parallel background; primary investigation ran concurrently) |
| Rule #25 per-piece commits | 2 |
| Rule #8 rebuild | 1 (backend + worker + migrator) |
| Rule #20 fast-iteration docker cp cycles | 4 |
| Reverts | 0 |
| Cross-stream sweeps | 0 (single-session, single-branch) |
| Queued follow-up | 1 (Fix C super.img + vendor_boot.img recovery) |

---HANDOFF---
- Postmortem: ds1-moto-g32-hardware-firmware-adaptive-detect-2026-05-15
- Document: .planning/postmortems/postmortem-ds1-moto-g32-hardware-firmware-adaptive-detect-2026-05-15.md
- Failures documented: 3 (2 root causes + 1 operational stale-image)
- Safety catches: 6 (postmortem corpus, detection_audit JSONB, DB partition-origin query, pre-existing tests, INSERT NUL rejection, parallel scouts)
- Recommendations: 5
- Queued follow-up: Fix C — super.img + vendor_boot.img + boot.img recovery (Scout C design ready in this session's transcript)
---
