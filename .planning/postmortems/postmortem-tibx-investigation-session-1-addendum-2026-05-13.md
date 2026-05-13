---
title: λ session 1 ADDENDUM — .tibx investigation + ILLUMISITE end-to-end
campaign: tibx-deep-research + memory-forensic-godmode α
date: 2026-05-13
status: session-closed
relates_to: postmortem-memory-forensic-godmode-alpha-session-1-2026-05-13.md
---

# λ session 1 ADDENDUM — .tibx investigation + ILLUMISITE re-process

User pivot mid-session: "we are really missing out on windows side by not
unpacking .../Archive(1)-0001.tibx... full plan, full execute, don't wait
for me you got this." Pattern: "do them all + deep research + Citadel"
Rule-of-Four (this session's THIRD such directive — previous two on the
λ.α pre-pass + this session's start).

## What shipped

Commit ``5c19490``:

- **Magic-byte detection** for `.tibx` (master files: ``ARCH`` at offset 8;
  observed empirically on Medtronic ILLUMISITE Archive(1).tibx). Detection
  now fires on magic OR extension — catches renamed files.
- **Master vs continuation slice classifier** in ``unpack_no_handler.py``.
  Per-slice operator guidance: master → run tibxread here; continuation
  → use the master, not standalone; ambiguous → verify with xxd.
- **``.raw`` extension** added to ``_RAW_IMAGE_EXTENSIONS`` in
  ``firmware_paths.py``. Closes Scout B's latent gap shared with
  ``unpack_vhdx``. Multi-volume extractors (tibx BYOB-SC will emit
  ``vol1/disk.raw``, ``vol2/disk.raw``) need this for each vol-dir to
  qualify as a detection root.
- **CAPABILITY_NOTES** for ACRONIS_BACKUP updated with the actionable
  Acronis-on-host workflow. Operator guidance: install Cyber Protection
  Agent for Linux (30-day trial), run ``tibxread get content`` against
  the master + recovery point, re-upload the resulting ``disk.raw``.
- **3 scout reports** committed to ``.planning/research/tibx-deep-2026-05-13/``:
  - scout-a: format deep-research. Confirmed HOLD on parser-library work.
  - scout-b: wairz integration surface. 80% wired; mechanical implementation.
  - scout-c: BYOB-SC architecture. EULA forces operator-installed binary;
    Acronis ships `tibxread` Linux-native; side-container is the right
    shape.
- **4-stream BYOB-SC implementation intake** at
  ``.planning/intake/tibx-byob-side-container-architecture-2026-05-13.md``.
- **New regression test** ``test_detects_acronis_backup_via_arch_magic``.

## ILLUMISITE end-to-end re-process

User's second directive: "after complete make sure you full process what
we have in projects/b11590b8-132a-4ee6-a793-3ec665427751".

The ILLUMISITE firmware (640cda1f) carries:

- 4×~4 GB ``.tibx`` files (15.57 GB total — the actual Windows payload;
  gated on BYOB-SC, next session).
- ``sources/boot.wim`` — 510 MiB LZX-compressed Windows PE x64 image
  (Microsoft Windows PE, dated 2019-01-21, 15133 files / 3170 dirs /
  2 GB uncompressed). NOT previously extracted.
- ``Boot/``, ``EFI/Boot/``, ``EFI/Microsoft/Boot/`` — bootloader
  infrastructure. Already in detection_roots.

Operational actions (this session, no commits — operator-level
remediation against the existing data):

1. Manually extracted ``boot.wim`` via ``wimextract <wim> 1 --dest-dir=...``
   into ``firmware/640cda1f.../extracted_boot_wim/``. Output: 1.4 GiB
   of Windows PE (Program Files + ProgramData + Users + Windows
   directories). Most importantly: ``Program Files/Acronis/BackupAndRecovery/``
   carrying ``acrocmd.exe``, ``TrueImage.exe``, ``agent.exe``,
   ``trueimage_starter.exe``, ``mms.exe``, ``arsm.exe``,
   ``register_agent.exe``, ``a43.exe``, plus the WinSxS driver tree
   with hundreds of ``.sys`` files.
2. Updated ``firmware.device_metadata.detection_roots`` to include
   BOTH the original ``Boot/`` AND the new ``extracted_boot_wim/``
   path.
3. Re-fired all 23 walkers (the 22 from κ-era plus λ.α.B memory-image
   enumerator) via
   ``backend/scripts/backfill_walker_results_2026_05_13.py
   --firmware-id 640cda1f-...`` against the combined roots.

Findings post-re-process:

| Walker | Count | Notes |
|---|---:|---|
| BCD walker | 9 entries persisted | 0 testsigning, 0 anomalies — clean Acronis-managed BCD |
| WMI walker | 1 binding persisted | Likely an Acronis EventConsumer; non-benign count = 0 |
| ESP walker | 3 EFI files | bootmgr.efi + bootmgfw.efi + memtest.efi — ALL signed_valid, NONE revoked |
| AppCompat walker | 1 SYSTEM hive | regipy couldn't parse this WinPE transactional reg variant; 0 entries persisted |
| LNK walker | 3 LNKs | Basic WinPE shortcuts |
| MFT walker | 41 images probed | 0 records (file-system images, not NTFS volumes) |
| EFS walker | 41 images | 0 encrypted files |
| USN walker | 41 images | 0 records |
| MBR/VBR walker | 41 images | 0 anomalies |
| SDB walker | 2 files | Standard Microsoft AppHelp shim DBs |
| Memory enumerator | 0 images | No memory dumps in WinPE (expected) |
| Hardware-firmware detection | **323 blobs** | 322 driver_package + 1 registry_hive |
| Findings | **2** | 1 HIGH "No firmware update mechanism", 1 INFO "CIRCL Hashlookup 96/100 known-good" |

Net: the user's "Windows side" is now actually surfaced. ~322 Windows
driver packages from the WinPE WinSxS tree are now in the wairz DB,
queryable via the existing MCP tool ``list_drivers`` /
``analyze_drivers_firmware``. The Acronis Recovery binaries are visible
in the file tree (operator can ``find_files_by_type +.exe`` to
enumerate). The BCD store is parsed (9 entries). EFI signing chains
validate clean.

## What still requires BYOB-SC (next session)

The ``.tibx`` payload itself — the actual disk image inside Archive(1).tibx
+ 3 continuations — represents the full Windows installation the
ILLUMISITE device ships with. That's NTFS, registry hives, EVTX logs,
prefetch files, scheduled tasks, USN journal — the full per-walker
target set for a deployed Windows system. Until the BYOB-SC ships
(intake ``tibx-byob-side-container-architecture-2026-05-13.md``,
4 streams), this content remains inside the proprietary Acronis
wrapper and cannot be walked.

## Patterns confirmed in the addendum work

- **Pattern: opportunistic recursive descent.** When a primary
  extractor (e.g. zip-of-iso-of-folder) doesn't auto-descend into a
  nested archive (``sources/boot.wim`` in this case), operator-level
  ``wimextract`` + manual ``detection_roots`` update + walker re-fire
  closes the gap WITHOUT new code shipping. Cost: ~10 min wall-clock.
  Value: 322 driver-package detections + 9 BCD entries that were
  previously invisible. This SHOULD become a Rule #19 evidence-first
  reflex when an operator complains about missing Windows-side content
  — check the extracted tree for unexpanded ``.wim`` / ``.iso`` /
  ``.cab`` archives FIRST.
- **Pattern: BYOB side-container precedent extension.** UART-bridge +
  device-bridge already pioneered the "operator installs binary on
  host, wairz bind-mounts it" pattern. tibx-extractor (next session)
  will be the third BYOB-pattern application. Rule-of-Three.

## Companion file index for next session

- ``.planning/research/tibx-deep-2026-05-13/scout-a-format-deep-research.md``
- ``.planning/research/tibx-deep-2026-05-13/scout-b-wairz-integration.md``
- ``.planning/research/tibx-deep-2026-05-13/scout-c-sandboxed-extraction.md``
- ``.planning/intake/tibx-byob-side-container-architecture-2026-05-13.md``
- ``.planning/intake/acronis-recovery-pe-walker-validation-2026-05-13.md``
  (TO FILE — separate intake noting the wimextract+detection_roots
  recipe used this session)

DONE — λ session 1 addendum.
