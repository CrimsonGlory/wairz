---
Status: completed
Direction: Teach the unpack pipeline to recognise vendor-encrypted archives whose decryption key is hardcoded in a recovery rootfs shell script, and auto-decrypt them during unpack so the real payload surfaces in the file explorer without operator intervention.
Created: 2026-04-21
Created_in: session b3a3b580 (immediate follow-up to tar-shortcut recursion fix + RespArray/target-ld manual decrypt)
Completed: 2026-04-21
Completed_in: session b3a3b580 (same-session ship)
Type: build
Baseline HEAD: c00ec94 (merged tar-shortcut recursion fix)
Final HEAD: 180d9e1 (Stage-2 wiring)
Estimated Sessions: 1
Actual Sessions: 1
Orchestrator: inline (single stream, single session)
End-condition audit:
  1. [PASS] backend/tests/test_vendor_aes_decrypt.py — 16/16 tests pass
  2. [PASS] Re-unpack of a7523429 produced target/rootfs_partition.tar.xz_extract, extracted_path lands there, arch=arm le
  3. [PASS] device_metadata.vendor_decryption records 5 entries with key_hex=43c8e032... matching Phase 1
  4. [PASS] grep 'openssl aes' backend/app/workers/ → 2 matches in unpack_common.py (detector + regex)
  5. [PASS] Eaton + DPCS10 regression — _detect_openssl_key_triples returns [] on both; zero behaviour change
---

# Campaign: Vendor-AES auto-decrypt detector

## Motivation — RespArray / target-ld Phase 1

Session b3a3b580 discovered that RespArray v1.12 and target-ld v1.12 firmware
packages contain five `.tar.xz` files (`rootfs_partition`, `boot_partition`,
`nxapp`, `nxcore`, `scripts`) that fail XZ magic check. File name lies; the
content is AES-128-CBC ciphertext. The decryption key + IV are **hardcoded
as plaintext** in `/sbin/force_update.sh` + `/sbin/normal_update.sh` inside
the recovery rootfs (`zImage-restore.tar.xz`), reachable via this regex:

```
openssl aes-128-cbc -d -in <path> -out <path> -K <32-hex> -iv <32-hex>
```

Same key+IV across both products, likely across the entire vendor ecosystem.
Phase 1 manually decrypted + extracted; Phase 2 (this campaign) teaches the
backend to do it automatically for future uploads and re-uploads.

This is a structurally general pattern, not RespArray-specific: a vendor
ships a recovery rootfs alongside encrypted payload archives; the recovery
rootfs must be able to decrypt the payloads to install them, so it MUST
contain the key in some recoverable form. Shell-script openssl invocations
are the most common shape.

## Phases

| # | Description | Files | Est. Commits |
|---|-------------|-------|--------------|
| 1 | `_detect_openssl_key_from_scripts(extraction_dir)` — walk extraction tree for shell files, parse `openssl aes-*-cbc -d ... -K <hex> -iv <hex>` invocations, return all distinct (algo, key, iv) triples found. | `backend/app/workers/unpack_common.py` + tests | 1 |
| 2 | `_decrypt_vendor_encrypted_archives(extraction_dir, key_triples)` — walk for archives whose first bytes do NOT match their extension's magic; try each (algo,key,iv) triple; if the decrypted output starts with a valid archive magic, write to sibling `<name>_extract/` via tar/zip/xz. Return list of newly-extracted dirs. | `backend/app/workers/unpack_common.py` + tests | 1 |
| 3 | Hook into `unpack.py` Stage 2 — after unblob/binwalk run, call the detector+decryptor. If new dirs surface, update `_recursive_extract_nested` pass to include them. Record the found (algo,key,iv) in `device_metadata['vendor_decryption']` for audit. | `backend/app/workers/unpack.py` | 1 |
| 4 | End-to-end regression test — synthetic fixture tar containing an AES-encrypted inner tar plus a shell script with the openssl command. Assert auto-decrypt runs, inner tar surfaces, detection_roots populated. | `backend/tests/test_vendor_aes_decrypt.py` | 1 |
| 5 | Close loop — re-run unpack on RespArray v1.12 + target-ld v1.12 with the new code; assert it now decrypts without manual SQL intervention (matches Phase 1 state). Remove the manual `vendor_decryption` rows from Phase 1 if the new pipeline writes them automatically; keep if the new pipeline writes something different. | (data-only) | 0 (verification only) |

## End Conditions

| # | Condition | Type |
|---|-----------|------|
| 1 | `backend/tests/test_vendor_aes_decrypt.py` passes — synthetic fixture end-to-end | command_passes |
| 2 | Re-unpack of firmware `a7523429-1c9c-4740-a360-545ef5b6a85f` produces `target/rootfs_partition.tar.xz_extract/` with ≥10,000 files, without any manual script | command_passes |
| 3 | `device_metadata->'vendor_decryption'->>'key_hex'` matches the known key after re-unpack | command_passes |
| 4 | `grep -rn 'openssl aes' backend/app/workers/` returns ≥1 match (the detector) | source_check |
| 5 | Re-running unpack on a firmware with NO encrypted blobs (Eaton, DPCS10, GL-RM10) produces identical output to pre-fix — the detector must be a no-op when no keys are found | command_passes |

## Risks

1. **False positive**: a plaintext archive happens to decrypt with the hardcoded key into something that looks like another archive. Mitigation: require the decrypted output to start with the expected magic for its extension (e.g. `.tar.xz` → `\xfd7zXZ`), not just "some archive magic." The magic-match gate is strict.
2. **Multiple keys in one rootfs**: some vendors rotate keys across product lines but ship one recovery that handles many. Detector returns a LIST of triples; decryptor tries each in turn. First hit wins.
3. **Key in a compiled binary**: the RespArray case has the key in a shell script, but future vendors may compile it into `nx_recovery` or similar. Out of scope for this campaign — document as a known limitation; scripts cover the RespArray-shape pattern. Binary key extraction would need a separate campaign (strings analysis + heuristics).
4. **Non-CBC modes**: ECB, CTR, GCM. Shell script regex must NOT match these as if they were CBC. Use explicit `-aes-*-cbc` match, not just `aes`.
5. **Recovery that uses a derived key** (e.g. `KEY=$(sha256sum /dev/mmcblk1p1)` runtime-derived): detector would skip because no literal hex key in the script. This is correct — we cannot decrypt such cases without the running device.
6. **Python subprocess vs. openssl library**: use `subprocess.run(['openssl', 'aes-128-cbc', '-d', ...])` not the cryptography library for bit-exact compatibility with shell-script invocations. The container already has `openssl`.

## Decision Log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-04-21 | Run detector ONLY from unpack.py Stage 2 (post unblob/binwalk), not Stage 1 | Stage 1 hits a format-specific fast path; Stage 2 is the generic "we've extracted what we can" finish line. Hooking at Stage 2 sees the fully-walked tree, including the recovery rootfs. |
| 2026-04-21 | Shell-script detection via regex, not AST | The openssl invocation is a single line with deterministic argument order in the observed case. Regex is cheap and precise; a shell AST parser is over-engineering. Expand if a second vendor uses a different shell shape. |
| 2026-04-21 | Trigger decrypt on ANY archive whose magic mismatches its extension, not just known-encrypted markers | The 16-byte header we saw on RespArray is the first 16 bytes of `\xfd7zXZ\x00\x00\x04...` encrypted under this specific key — it's a ciphertext, not a vendor magic. There is no "encrypted archive magic" to key off of. "Doesn't match expected magic" is the right trigger. |
| 2026-04-21 | Skip if no shell scripts with hardcoded keys found | Trying to brute-force decrypt every misnamed archive is not a feature — it's a DoS. Key must be findable in-tree, or skip silently. |

## Pickup

This file is the authoritative plan. Phase commits flow:
1. Detector helper (parse + return triples) + unit test
2. Decryptor helper (apply triples + magic-check output) + unit test
3. Integration in unpack.py + integration test
4. Re-unpack RespArray + target-ld, diff against Phase 1 state

Rule #8 rebuild runs ONCE at the end of the campaign, not per commit.
Rule #17 canary not applicable (backend-only).
Rule #25 per-commit discipline held.
Rule #27 "N additive + 1 cut-over" not applicable — this is new code, not a refactor.
