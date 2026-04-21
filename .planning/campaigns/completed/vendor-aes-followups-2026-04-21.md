---
Status: completed
Direction: Three followup fixes for the vendor-AES auto-decrypt pipeline, discovered during real-firmware smoke testing of RespArray v1.05 (.zip) after the core campaign shipped.
Created: 2026-04-21
Created_in: session b3a3b580 (same session as vendor-aes-auto-decrypt campaign)
Completed: 2026-04-21
Completed_in: session b3a3b580 (same-session followup)
Type: bugfix
Baseline HEAD: 162b76a (vendor-aes-auto-decrypt campaign close)
Final HEAD: bede8a5 (HW detection race fix)
Estimated Sessions: 1
Actual Sessions: 1
Orchestrator: inline
---

# Campaign: Vendor-AES Auto-Decrypt Followups

## Motivation

The core vendor-AES auto-decrypt campaign shipped commits 8acc16f / 180d9e1 /
decac75 / 162b76a and verified end-to-end on the `.7z` upload path (RespArray
v1.12, firmware `a7523429`). When the user re-uploaded the `.zip` variant
(RespArray v1.05, firmware `33c5fdcb` → `fb2ad33e` → `aeb50fbb`) to exercise
the same pipeline, three distinct defects surfaced in sequence:

1. **The `.zip` upload path deletes the original archive and sets
   `storage_path` to an inner file.** `/unpack` then operates on that
   single inner file in isolation, so the vendor-AES detector can't see
   the recovery rootfs (which sits in a sibling inner file of the zip).
   Detector returns no key triples. Encrypted archives stay ciphertext.
   (Intake: `zip-upload-breaks-vendor-aes-autodecrypt.md`.)

2. **Firmware tarballs ship with vendor-restrictive mode bits
   (rwxr-x--- root:root) that block the backend user from reading
   extracted content.** File-explorer API returns "no access" for files
   like `gen_creds.sh` that are legitimately on disk. (Intake:
   `extractor-should-widen-perms.md`.)

3. **`_run_hardware_firmware_detection_safe` is spawned as a fire-and-
   forget asyncio task BEFORE the caller's `db.commit()`.** HW detection
   opens its own DB session, reads `device_metadata`, merges its
   `detection_audit`, and commits. If HW detection commits after the
   caller's write but computed from a pre-commit snapshot, its
   dict-replacement assignment clobbers the caller's
   `vendor_decryption` + `detection_roots`. Observed on v1.05 (0
   detection_roots → fast HW detection → wins race); masked on v1.12
   (5 roots + 299 blobs → slow HW detection → loses race).

## Phases

| # | Description | Files | Commit |
|---|-------------|-------|--------|
| 1 | Preserve original zip. Keep `Firmware.storage_path` pointing at the zip. `/unpack` reprocesses the whole archive — matches `.7z` / `.tar` paths. | `backend/app/services/firmware_service.py` | `e2f2914` |
| 2 | `widen_read_perms(root)` helper walks extraction tree, ORs 0o044 into file modes + 0o055 into dir modes, preserves execute bits, skips symlinks. Wired into 4 extraction sites (Stage 2 post-unblob + 3 shortcut paths). | `backend/app/workers/unpack_common.py` + `unpack.py` + `firmware_service.py` + `backend/tests/test_widen_read_perms.py` | `98b5ecf` |
| 3 | Move HW detection spawn out of `unpack_firmware()` — both callers (`arq_worker.unpack_firmware_job` and `routers/firmware._run_unpack_background`) now fire the task AFTER `db.commit()`. | `backend/app/workers/unpack.py` + `arq_worker.py` + `routers/firmware.py` | `bede8a5` |

## End Conditions

| # | Condition | Evidence |
|---|-----------|----------|
| 1 | RespArray v1.05 `.zip` uploaded fresh + auto-unpacked produces `extracted_path` pointing at the real rootfs | `aeb50fbb` post-fix row: `extracted_path = …/target/rootfs_partition.tar.xz_extract` |
| 2 | `device_metadata` has all three keys: `detection_roots`, `vendor_decryption`, `detection_audit` | Verified: `{detection_audit, detection_roots, vendor_decryption}` on final smoke |
| 3 | 6 encrypted archives decrypted; 6 `_extract/` dirs created | Verified: `vendor_decryption=6` in DB, 6 dirs in file explorer |
| 4 | `gen_creds.sh` (mode 750) readable via `/files/read` API | Verified: 928 bytes returned, content preview matches shell script |
| 5 | Hardware-firmware detector walks ≥1 root and finds blobs | Verified: `detection_audit.blobs_detected = 198` on v1.05 (was 0 pre-fix) |
| 6 | All existing tests still pass | Verified: 85/85 across affected suite |

## Decision Log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-04-21 | Preserve zip file on disk rather than deleting + using inner file as storage_path | Matches the `.7z` / `.tar` upload paths. Lets `/unpack` reprocess the whole archive so the vendor-AES detector has full tree visibility. Disk-usage cost (~2x per upload) is acceptable. |
| 2026-04-21 | Widen perms via post-extraction walk (Option A) vs tarfile filter during extract (Option C) | Option A covers ALL extraction sites (unblob, binwalk, tarfile, zipfile) with one helper. Option C only covered tar extracts — partial coverage, rejected. |
| 2026-04-21 | Move HW detection spawn to AFTER commit in the two callers, rather than adding merge-with-retry semantics inside HW detection | Single-point fix: changing the fire-and-forget position is cleaner than teaching the detector to re-read on conflict. Preserves HW detection's simple commit model. |

## Postmortem / lessons learned

- **Smoke-testing on a second upload format (zip after 7z) found three distinct defects in a single session.** Each defect was invisible to unit tests — only exercised by real data. Generalised: when shipping a feature on one upload shape, always run the end-to-end smoke on the OTHER common shapes before closing.
- **User UX complaint ("there must be a bug in file explorer") pointed at real backend defects.** The file explorer itself was correct — the bugs were all upstream (missing storage_path continuity, permissions, concurrent write race). Worth asking "is the thing the user sees the thing that's wrong?" before attributing to the UI.
- **Three-commit fix chain, each commit unblocked the next bug.** `e2f2914` preserved the zip → `/unpack` could run end-to-end, which exposed the permissions issue (`gen_creds.sh` unreadable) → `98b5ecf` fixed that, which exposed the race condition (decrypt audit missing despite decrypt running) → `bede8a5` fixed that. Without proceeding one commit at a time + re-smoking between each, the race would have looked like "something still seems broken" without clarity.
