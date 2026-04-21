# Intake: Zip upload path breaks vendor-AES auto-decrypt

**Status:** queued
**Created:** 2026-04-21 (session b3a3b580)
**Discovered during:** RespArray v1.05 re-upload smoke test
**Priority:** medium — affects any vendor-AES-encrypted firmware uploaded as `.zip` (works fine for `.7z` and `.tar`)

## The defect

For `.zip` firmware uploads, `firmware_service.upload` at `firmware_service.py:486-582` (the generic-zip branch) does the following at upload time:

1. Extract the zip to `firmware_dir/zip_contents/`
2. Run `_recursive_extract_nested(zip_root, 3)` on the extracted tree (line 523)
3. Pick the largest inner file via `_extract_firmware_from_zip` (line 488)
4. Delete the original zip (line 493)
5. Set `storage_path = <largest inner file>` (line 494)

This breaks our vendor-AES auto-decrypt pipeline. When `/unpack` is called later, `unpack_firmware(storage_path)` operates on ONE inner file in isolation. Its `extraction_dir` sits at `zip_contents/target/extracted/`. The recovery-rootfs shell scripts (which hold the openssl key+iv) live at `zip_contents/target/zImage-restore.tar.xz_extracted/sbin/force_update.sh` — OUTSIDE the unpack job's search root. Our `_detect_openssl_key_triples(extraction_dir)` never sees them, so no key is found, and the 6 encrypted archives stay ciphertext.

Meanwhile unblob burns CPU trying to parse the encrypted `rootfs_partition.tar.xz` as a firmware blob, eventually timing out at 20 min.

## Evidence

**Firmware that works (`.7z` path):** `a7523429-1c9c-4740-a360-545ef5b6a85f` RespArray v1.12 — `storage_path` stays the original `.7z`, unblob sees the whole tree, auto-decrypt finds the key, 5 blobs decrypted automatically. ✅

**Firmware that fails (`.zip` path):** `fb2ad33e-6004-4151-b01e-97b7bc154aa3` RespArray v1.05 — `storage_path` is `zip_contents/target/rootfs_partition.tar.xz` (post-extract inner file), unblob sees only that file, auto-decrypt can't find key, arq job hangs at 100% CPU. ❌ (Manually unblocked in the same session via Phase-1-style SQL.)

## Fix options

### Option A — Preserve the original zip (recommended)
At `firmware_service.py:493`, DO NOT `os.remove(storage_path)`. Keep the original zip. Set `storage_path` to the zip itself, not an inner file. The `/unpack` endpoint then runs `unpack_firmware` on the whole zip, unblob sees the complete tree, vendor-AES detector sees the recovery rootfs.

- **Pro:** Makes `.zip` behave like `.7z` and `.tar` — uniform behaviour across archive formats.
- **Pro:** `/unpack` is re-runnable (no lost source).
- **Con:** Doubles disk usage until the operator deletes the zip manually (or add a cleanup after successful unpack).
- **Con:** Breaks the shortcut at line 418-484 which currently relies on `_zip_contains_rootfs`-detected ZIPs being pre-extracted.

### Option B — Pass zip_contents to the auto-decrypt detector
In `unpack.py` Stage 2, after the decrypt pass runs on `extraction_dir`, ALSO run `_detect_openssl_key_triples` on `os.path.dirname(firmware_path)` (which for zip uploads is `zip_contents/target/`). If keys are found there AND encrypted archives exist in the extraction tree OR in the surrounding zip_contents tree, decrypt them.

- **Pro:** Surgical — touches only the unpack pipeline, not the upload path.
- **Con:** Asymmetric behaviour: zip upload's unpack reaches outside its extraction_dir, other archive-format unpacks don't. Harder to reason about.
- **Con:** Still leaves the "unblob burns CPU on encrypted single file" problem until it times out.

### Option C — Both
Fix the zip path to preserve the original (A) AND teach the vendor-AES detector to look in sibling directories (B). Most robust; costs 2 commits instead of 1.

## Acceptance criteria

1. Upload `RespArray_1.05.00.17.zip` (SHA256 `e13fd41f90eda354899b8a3642093ecb3fea0caa7317ccc04eba6573e88918b2`) to a fresh project. Auto-unpack completes in <60s. `device_metadata.vendor_decryption` has ≥5 entries. File explorer shows rootfs/ + decrypted archive dirs. NO manual SQL required.
2. Upload a non-encrypted `.zip` firmware (e.g. OpenWrt `.zip`) — behaviour unchanged (regression check).
3. `backend/tests/test_firmware_service.py` still passes.
4. `backend/tests/test_vendor_aes_decrypt.py` still passes.

## Related

- Campaign: `.planning/campaigns/completed/vendor-aes-auto-decrypt-2026-04-21.md`
- Commit chain: 8acc16f / 180d9e1 / decac75
- Anti-pattern knowledge: `.planning/knowledge/vendor-aes-auto-decrypt-2026-04-21-antipatterns.md`
- CLAUDE.md Rule #27 ("N additive + 1 cut-over") applies if Option A is chosen and refactors the zip-extract shortcut.
