# Patterns: Vendor-AES Auto-Decrypt

> Extracted: 2026-04-21
> Campaign: `.planning/campaigns/completed/vendor-aes-auto-decrypt-2026-04-21.md`
> Postmortem: not found
> Sources: campaign file, commits 8acc16f / 180d9e1 / 162b76a, Phase 1 SQL evidence, 4 matching audit entries

## Successful Patterns

### 1. Two-phase shipping: immediate fix (data) + durable feature (code) in one session
- **Description:** When a user-blocking bug needs both an immediate unblock AND a code-level fix to prevent recurrence, ship them as two distinct artifacts in the same session. Phase 1 was a one-shot SQL + `docker compose exec` script that decrypted the 10 blobs, extracted them, repointed `extracted_path`, and set `device_metadata.vendor_decryption` for the 2 affected firmwares (user unblocked in minutes). Phase 2 was the actual backend feature (detector + decryptor + tests + pipeline wiring) that prevents the problem on every future upload.
- **Evidence:** Phase 1 at session turn immediately after user said "both"; Phase 2 at commits 8acc16f / 180d9e1 / 162b76a. No rework between phases — Phase 2 implementation ratified the approach Phase 1 demonstrated manually.
- **Applies when:** A defect has leaked into live data AND the underlying code still has the bug. Doing only Phase 1 leaves the next upload broken. Doing only Phase 2 leaves the user waiting for the fix to deploy and then re-uploading. Both in parallel = user unblocked + code fixed.

### 2. Read existing infrastructure before designing new
- **Description:** Before writing `_detect_openssl_key_triples`, grepped for existing vendor-container awareness in `unpack_common.py` and found `_VENDOR_CONTAINER_MAGICS` at line 264 — a prior author had already catalogued the EDAN magic `a3dfbbbf4e947c6649859f5e45d273ed` and the `diagnose_failed_archives` helper that surfaced unextracted vendor containers to `device_metadata`. The existing infrastructure just didn't know how to DECRYPT; new code slotted in without fighting or duplicating.
- **Evidence:** `unpack_common.py:264-290` + `diagnose_failed_archives` at `unpack_common.py:301` — both predate this campaign. Session found them via `grep -n '_VENDOR_CONTAINER_MAGICS\|diagnose_failed_archives\|_extract_single_archive'`.
- **Applies when:** Adding detection logic for a known class of firmware defect. Grep the codebase for the magic bytes, vendor names, or key terminology FIRST. Prior art is often closer than expected — even when the prior author's diagnosis was incomplete.

### 3. Bit-exact test fixtures via real openssl subprocess
- **Description:** Test fixtures build the encrypted tar.xz by calling `subprocess.run(["openssl", "aes-128-cbc", "-e", ...])` with real openssl binary, mirroring the production decrypt path which also shells out to openssl. Alternative (use Python `cryptography` library in the test) would introduce a divergence risk — if openssl and `cryptography` pad differently under edge conditions, production could work while tests pass (or vice versa).
- **Evidence:** `_write_encrypted_tarxz` helper in `test_vendor_aes_decrypt.py` uses `subprocess.run(["openssl", ...])`. 16/16 tests pass against the production code path.
- **Applies when:** Any crypto test fixture that mirrors production subprocess behaviour. Prefer the same binary that production uses over a library equivalent.

### 4. Magic-gate on decrypted output prevents false positives
- **Description:** After decryption attempt, require the output's first bytes to match the expected magic for the target file's extension (`\xfd7zXZ\x00` for .tar.xz, `PK\x03\x04` for .zip, etc.). A wrong key produces garbage that cannot coincidentally match the strict magic. No other sanity check needed beyond this gate — it's structural and cheap.
- **Evidence:** `_file_head_matches_magic` + magic dict `_ARCHIVE_MAGIC`. Regression test `test_wrong_key_does_not_pass_magic_gate` proves that a decoy `deadbeef` key is filtered out.
- **Applies when:** Any "try a candidate secret" flow where the downstream consumer has a deterministic magic signature. Filesystem images, archives, executables, certificates — all have magics. Checkpoint against them.

### 5. Silent no-op when trigger pattern absent
- **Description:** Detector returns `[]` when no shell-script keys are findable; decryptor short-circuits on empty triples. Eaton Network M3, DPCS10, GL-RM10 firmwares all produce zero detector output post-deploy — verified live via `_detect_openssl_key_triples(...)` on their extracted paths. Zero behaviour change for non-matching firmware.
- **Evidence:** Post-deploy check on live data: `Eaton extracted: []`, `DPCS10 extracted: []`. Regression test `test_no_key_no_decrypt`.
- **Applies when:** Adding a new pattern-scanning pass to a generic pipeline. Design so the pass is a pure no-op when the pattern isn't found — don't touch files, don't write DB rows, don't inflate logs. Rule #19 companion: evidence-first means "don't do anything until you have the evidence."

### 6. Audit trail enables reproducibility without re-reading sources
- **Description:** `device_metadata.vendor_decryption` records algorithm, key_hex, iv_hex, archive path, AND `key_source` (file:line) for every decrypted blob. Operator can reproduce the decryption from the DB row alone — no need to re-walk the extraction tree or re-grep for the openssl command.
- **Evidence:** Post-deploy RespArray row shows 5 entries each with all 5 audit fields; `key_source` reads `.../sbin/force_update.sh:404` precisely.
- **Applies when:** Any automated detection/transformation that an operator might need to audit or reproduce. Store the INPUTS (what we found), not just the OUTPUT (what we did). Rule #16 companion.

### 7. Two-writer parity: both in-process AND arq worker update the DB
- **Description:** `UnpackResult.vendor_decryption` field is written to DB by both `routers/firmware.py:_run_unpack_background` (when arq is unavailable) AND `workers/arq_worker.py:unpack_firmware_job` (when arq pool is up). Missing either writer would silently lose the audit trail on that code path.
- **Evidence:** Commit 180d9e1 explicitly updates BOTH files. Found via `grep -n 'firmware.binary_info\|firmware.extracted_path' backend/app/workers/arq_worker.py` to confirm the mirror path existed.
- **Applies when:** Adding a field to `UnpackResult` (or any other cross-path result object). Grep for every reader before writing — `grep -rn 'result\.<field>\|firmware\.<field>' backend/app/` — and update each. Especially critical when two paths exist by design for graceful degradation (arq fallback, synchronous fallback).

### 8. Dataclass extension over separate tracking table
- **Description:** `UnpackResult.vendor_decryption: list[dict] | None` added as a simple dataclass field, piggybacking the existing result-to-DB plumbing. Alternative (separate `vendor_decryption_events` table) would have required a migration, a new model, a new router, and two more writers. Since the data is 1:1 with firmware and audit-only (not queried), a JSONB column in the existing table is the right granularity.
- **Evidence:** `UnpackResult` at `unpack_common.py:394-409` gains one line; the persistence path in `firmware.py` / `arq_worker.py` gains 4 lines each.
- **Applies when:** Audit data for a single parent entity, written once, read rarely. JSONB column on existing model beats a new table whenever the data is 1:1 and not independently queried.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Run detector ONLY from unpack.py Stage 2, not Stage 1 | Stage 1 hits format-specific fast paths; Stage 2 is the generic "we've extracted what we can" finish line with the fully-walked tree including recovery rootfs. | Worked — auto-decrypt fired correctly after recursive-extract-nested; no Stage 1 interactions. |
| Shell-script regex, not AST parser | openssl CLI invocations have deterministic argument order and are single-line. Regex is cheap and precise. | Worked on RespArray + target-ld. Would extend if a second vendor uses a different shape (multi-line assignment, envvar indirection). |
| Trigger on ANY archive whose magic mismatches its extension | The `a3dfbbbf...` "header" is NOT a vendor magic — it's the ciphertext of the XZ header under this specific key. There's no "encrypted archive magic" to key off of. "Doesn't match expected magic" is the correct trigger. | Worked. No false triggers on plaintext archives (verified in regression test). |
| Skip silently if no shell scripts hold hardcoded keys | Trying to brute-force decrypt every misnamed archive is not a feature — it's a DoS. Key must be findable in-tree, or we skip. | Worked. Eaton + DPCS10 produced `[]` detector output; zero spurious work. |
| Accept the 2-vs-6 detection_roots gap as not-a-blocker | Phase 1 manually added 6 roots including every `_extract/` dir. Phase 2's `_compute_roots_sync` only adds dirs matching name hints — not vendor-decrypted archive-extract dirs. Primary root still points at the real rootfs. | Shipped as-is. Follow-up candidate: extend `_compute_roots_sync` to include decrypted-archive-extract dirs when a sibling was vendor-decrypted. |
