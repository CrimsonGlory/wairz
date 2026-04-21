# Anti-patterns: Vendor-AES Auto-Decrypt Followups

> Extracted: 2026-04-21
> Campaign: `.planning/campaigns/completed/vendor-aes-followups-2026-04-21.md`

## Failed Patterns

### 1. Fire-and-forget subtask scheduled before the main task's DB commit
- **What was done:** `unpack_firmware()` called `asyncio.create_task(_run_hardware_firmware_detection_safe(firmware_id, result.extracted_path))` as the last line before `return result`. The caller (arq_worker or routers/firmware) then did its own DB write of `vendor_decryption` + `detection_roots` and committed.
- **Failure mode:** Two concurrent DB sessions both read-modify-write `device_metadata` as a JSONB dict-replacement. Whoever commits LAST wins the entire dict. If HW detection's commit lands after reading a pre-commit snapshot, it CLOBBERS the caller's audit data with a version that was computed before the caller wrote it. On v1.05 (0 detection roots, fast HW detection) the race was always lost. On v1.12 (5 roots, 299 blobs, slow HW detection) it was always won.
- **Evidence:** Worker log shows 6 successful decrypts then "Hardware firmware detector: no detection roots" then "0 blobs" — all 0.1s apart. Post-unpack DB state: only `detection_audit` + `extraction_diagnostics`, missing `vendor_decryption` + `detection_roots`. Fixed in commit `bede8a5`.
- **How to avoid:** NEVER `asyncio.create_task` a subtask that writes the same DB row as the enclosing task, BEFORE the enclosing task commits. Either (a) move the spawn to AFTER the commit in the caller, or (b) use explicit column-level updates instead of dict-replacement to avoid the clobber. Applied: moved spawn to post-commit in both callers. Companion to CLAUDE.md Rule #7.

### 2. Divergent upload-path behaviour hides defects until a different input shape exercises it
- **What was done:** `.zip` upload path pre-extracted the archive at upload time and deleted the original. `.7z` and `.tar` paths kept the original and deferred extraction to `/unpack`. Three different shapes for "what `storage_path` points at" across three upload formats.
- **Failure mode:** Vendor-AES auto-decrypt relies on `/unpack` seeing the WHOLE upload tree so it can find the recovery rootfs alongside encrypted payloads. `.7z` worked. `.zip` broke silently — detector's search root was scoped to an inner file, couldn't reach the recovery rootfs, returned no keys. No error, just encrypted archives left as ciphertext.
- **Evidence:** RespArray v1.12 (.7z): 5 archives decrypted, detection_roots populated. RespArray v1.05 (.zip): 0 archives decrypted until manual Phase-1 SQL workaround, then /unpack burned 20min on CPU-spin. Fixed in `e2f2914`.
- **How to avoid:** When a feature ships, identify all branches of the upload/input matrix (formats, sizes, shapes) and smoke-test at least TWO of them before closing the campaign. Format-specific differences in pre-processing (delete-original vs preserve, pre-extract vs defer) are a common source of hidden divergence. Before declaring a cross-format feature done, audit for behavioural parity across branches.

### 3. Preserving upstream mode bits from firmware tarballs
- **What was done:** `tarfile.extractall` (and similar) preserves the original mode bits of each member when extracting. For vendor firmware tars shipped with files owned by `root:root` with mode `rwxr-x---` (e.g. `gen_creds.sh`), the extracted file inherits that mode.
- **Failure mode:** The Wairz backend process runs as a non-root user inside the container. When the file-explorer API calls `open()` on a mode-750 file owned by root, the kernel returns EPERM. The UI renders "I don't have access to this resource" despite the file being present on disk.
- **Evidence:** User reported `gen_creds.sh` access denial. `ls -la` showed `-rwxr-x---` owner root. Fixed in `98b5ecf` with post-extraction widen walk.
- **How to avoid:** For firmware RE tooling specifically, the original device's access-control model has no meaning — the operator needs read access to everything. Widen perms AFTER extraction, once, as a post-pass. Don't trust the tarball's mode bits to match your analysis-time access needs.

### 4. Destructive `rm -rf` before confirming what `storage_path` actually points at
- **What was done:** Attempted to clear the v1.05 firmware state for a re-unpack by running `rm -rf /data/firmware/projects/.../extracted /data/firmware/projects/.../zip_contents`. Assumed `storage_path` was the original archive (as it is for .7z and .tar uploads), but it was actually pointing at `zip_contents/` (the extracted zip tree) for the old .zip path.
- **Failure mode:** The rm destroyed `zip_contents/`, which WAS the storage_path for this firmware. `/unpack` returned 410 Gone ("Firmware file not found on disk"). The original .zip was already deleted by the old upload flow. Required the user to re-upload.
- **Evidence:** Session transcript shows the rm + the 410 response + the user re-uploading. No telemetry trace yet (intake: add audit log for `rm -rf` on firmware dirs).
- **How to avoid:** Before any `rm` on a firmware data directory, FIRST query `SELECT storage_path FROM firmware WHERE id=...` and confirm it's a file, not a parent of the target dir. Better: use the `/firmware/{id}` DELETE endpoint for cleanup instead of raw filesystem operations — the API owns the cleanup semantics correctly.

### 5. Unit tests pass but real data exposes concurrency bugs not covered by fixtures
- **What was done:** Shipped the vendor-AES auto-decrypt feature with 85/85 tests green. Tests covered: magic-byte detection, shell-script key extraction, decrypt gate, symlink safety, empty-key-list no-op. None of them exercised: real-upload→arq worker→fire-and-forget HW detection→concurrent DB writes.
- **Failure mode:** The race condition between arq worker's commit and HW detection's commit was invisible to unit tests. Only manifested on v1.05 real upload (where HW detection finishes quickly and wins the race). Test coverage was 0% for this code path because the tests don't spin up a second DB session and time their commits.
- **Evidence:** Tests all green at ship time; race bug surfaced on real v1.05 upload; fix landed in `bede8a5` without a corresponding unit test (integration-timing tests are hard to write reliably).
- **How to avoid:** When a feature involves (a) background tasks spawned from the main flow, (b) shared mutable state (DB rows, files, caches), accept that unit tests will not catch the race. Ship with an explicit plan to smoke on a second user artefact before closing. Consider adding a targeted "concurrent writer to same JSONB column" test using two async sessions — harder, but possible.

### 6. Intake files become stale once the fix lands inline
- **What was done:** Created `.planning/intake/zip-upload-breaks-vendor-aes-autodecrypt.md` and `.planning/intake/extractor-should-widen-perms.md` to document the discovered bugs. Then fixed them the same session via commits `e2f2914` and `98b5ecf`.
- **Failure mode:** The intake files still sit in `.planning/intake/` as if they're open work. A future session glancing at intake counts would see "2 items pending" when actually zero are pending.
- **Evidence:** `.planning/intake/` contents.
- **How to avoid:** After an intake item is fixed inline, move it to `.planning/intake/resolved/{slug}-{YYYY-MM-DD}.md` OR rename with a `.done` suffix OR link it from the closing commit's message. This session didn't do this — follow-up candidate: script a housekeeping pass that cross-references intake filenames against recent commit messages and relocates the matched files.
