# Anti-patterns: Vendor-AES Auto-Decrypt

> Extracted: 2026-04-21
> Campaign: `.planning/campaigns/completed/vendor-aes-auto-decrypt-2026-04-21.md`
> Postmortem: not found

## Failed Patterns

### 1. Trusting a prior author's "decryption hypothesis" comment as fact
- **What was done:** `unpack_common.py:272` had a prior-art note reading "decryption key must be recovered from nxapp/nxcore via Ghidra." When designing the detector, initial inclination was to respect that prior wisdom and look inside the compiled binaries.
- **Failure mode:** The note was an UNVERIFIED hypothesis. The key was actually in plaintext shell scripts at `sbin/force_update.sh:404` and `sbin/normal_update.sh`. Following the note would have led to days of Ghidra reverse engineering when the key was 30 seconds of `grep openssl` away.
- **Evidence:** The note sits in `_VENDOR_CONTAINER_MAGICS` from a prior session; the actual key was found by `grep -r openssl` on the recovery rootfs. Both facts are now in the codebase simultaneously.
- **How to avoid:** When annotating a defect with a hypothesis about remediation, mark it `UNVERIFIED:` or `HYPOTHESIS:` until someone has actually tested it end-to-end. Rule #19 applies to prior-session notes too — the evidence describes truth; hypotheses describe speculation. A subsequent campaign should refute or confirm the hypothesis, updating the comment either way.

### 2. Overcomplicated subprocess arg assembly
- **What was done:** Initial decryptor code had `"openssl", triple.algo.split("-")[0] + "-" + triple.algo.split("-")[1] + "-" + triple.algo.split("-")[2]` — which just reconstructs `triple.algo` from its own pieces.
- **Failure mode:** Pure redundancy; `triple.algo` is already `"aes-128-cbc"`. Would have worked but obscures intent. Caught on self-review before commit; replaced with `triple.algo` directly.
- **Evidence:** Pre-commit edit applied to the initial draft of `_decrypt_vendor_encrypted_archives` at `unpack_common.py`.
- **How to avoid:** After writing a transformation expression, ask "what does this actually output? Is it the input unchanged?" If yes, delete the transformation. One-liner check: `print(f"{algo!r} == {rebuilt!r}")`.

### 3. Fragile shell-subprocess test fixtures
- **What was done:** First draft of `_write_encrypted_tarxz` used `xz -z -k -f` followed by `mv` to rename the sibling. Resulted in `mv: '/tmp/.../__plain.tar.xz' and '/tmp/.../__plain.tar.xz' are the same file` because the rename source and dest had resolved to the same path after `xz -k`.
- **Failure mode:** Test broke in CI-style conditions; the fix involved rewriting the helper to avoid subprocess chains. Replaced with in-memory `lzma.compress(tar_buf.getvalue(), format=lzma.FORMAT_XZ)` + `openssl` subprocess only for the encrypt step (which needs bit-exact parity with production).
- **Evidence:** First test run: `subprocess.CalledProcessError: Command '[..mv..] returned non-zero exit status 1`. Second run after rewrite: 16/16 passed.
- **How to avoid:** When a stdlib module covers the task (`lzma`, `tarfile`, `zipfile`, `io.BytesIO`), prefer pure Python over shell subprocess chains. Only shell out when the production code shells out (for bit-exact parity) or when no stdlib equivalent exists. Fragile shell fixtures are a recurring bisect hazard.

### 4. Off-by-one in hand-counted line-number assertion
- **What was done:** Test asserted `t.source.endswith(":7")` — the openssl call was on line 6 of the 7-line shell script, not line 7.
- **Failure mode:** Test failed with `'force_update.sh:6'.endswith(':7')` False. Fixed by changing to `:6`.
- **Evidence:** Test output at first run; fix committed before the second run.
- **How to avoid:** Line-number assertions in tests are fine but write the fixture script with an explicit marker (a comment `# LINE 6` right above the target) so the count is grep-visible. Alternatively assert on `:digit` rather than a specific number, if the exact line doesn't matter to the semantic.

### 5. Phase 2 produces fewer detection_roots than Phase 1 manual
- **What was done:** Phase 1 manually set `device_metadata.detection_roots` to a list of 6 paths (primary rootfs + every `_extract/` sibling). Phase 2's automated pipeline runs `_compute_roots_sync` which only picks up dirs matching name hints (`rootfs`, `partitions`, `partition_*`, `*-root`, etc.). Vendor-decrypted `_extract/` dirs don't match any hint and are skipped.
- **Failure mode:** Phase 2 shows 2 roots for the same firmware where Phase 1 showed 6. Primary root still points at the real rootfs, so the user-facing behaviour is correct, but the UI's "detection roots" count is inconsistent between manual and automated paths.
- **Evidence:** Post-deploy `jsonb_array_length(device_metadata->'detection_roots')` returns 2 after Phase 2 unpack, vs 6 after Phase 1 manual intervention.
- **How to avoid:** When an automated helper (here `_compute_roots_sync`) differs from manual operator behaviour, either (a) extend the helper to match the manual behaviour OR (b) accept the gap and document it. This campaign chose (b) because the primary root is correct and the gap is cosmetic, but if the gap matters, the fix is: in `_compute_roots_sync`, also include `_extract/` directories whose parent has vendor-decrypted siblings (look up `device_metadata.vendor_decryption` for the trigger).

### 6. No postmortem written despite substantive finding
- **What was done:** The campaign surfaced a significant security issue (hardcoded symmetric key across RespArray + target-ld + likely every EDAN-family product) but no postmortem was written. The finding lives only in the campaign file's motivation section and this anti-patterns doc.
- **Failure mode:** A postmortem would force structured reflection on "what was the impact, what's the disclosure path, what's the blast radius, what other vendors might have the same pattern." Without it, the finding risks being buried in tooling and never surfacing to a vendor-disclosure process.
- **Evidence:** `.planning/postmortems/` search for vendor-aes returns nothing.
- **How to avoid:** When a campaign's motivation includes a security finding (hardcoded crypto, credential leak, unsafe IPC), ALWAYS write a postmortem with a dedicated "Security Disclosure Path" section naming vendor, product line, disclosure timeline, and CVE candidacy. The knowledge files capture the engineering patterns; the postmortem captures the security posture. Both should exist.
