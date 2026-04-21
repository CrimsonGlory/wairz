# Patterns: Vendor-AES Auto-Decrypt Followups

> Extracted: 2026-04-21
> Campaign: `.planning/campaigns/completed/vendor-aes-followups-2026-04-21.md`
> Postmortem: not found (section embedded in campaign file)
> Sources: campaign file, commits e2f2914 / 98b5ecf / bede8a5, 2 intake files, 4 smoke-test verification runs

## Successful Patterns

### 1. Iterative smoke-fix cycle: each fix exposes the next bug in the chain
- **Description:** A feature shipped on one upload format (`.7z`, working end-to-end) looked complete. When the user re-uploaded the same vendor's firmware as `.zip`, three distinct defects surfaced in sequence. Each fix was committed + rebuilt + re-smoked BEFORE starting the next:
  1. `e2f2914` — preserved the zip so `/unpack` could run → revealed permissions bug.
  2. `98b5ecf` — widened read perms → revealed race condition.
  3. `bede8a5` — moved HW detection spawn past commit → all three audit fields stuck.
- **Evidence:** Commit chain with rebuild + /unpack smoke after each; final DB shows all three metadata keys + 198 blobs detected; post-fix /learn on RespArray v1.05.
- **Applies when:** Shipping a pipeline-level feature that has multiple input formats. After the first smoke passes, run the SAME end-to-end smoke on the next-most-different format (zip if you tested 7z, APK if you tested bin, Android scatter if you tested OpenWrt). Don't close the campaign until at least 2 distinct input shapes are verified.

### 2. Magic-gate on decrypted output: wrong-key decryption can't coincidentally pass
- **Description:** `_decrypt_vendor_encrypted_archives` requires the decrypted stdout to start with the EXACT archive magic (`\xfd7zXZ\x00` for `.tar.xz`, `PK\x03\x04` for `.zip`, etc.) before calling it a success. Wrong-key decryption produces high-entropy garbage that can't match a strict 5-6 byte magic.
- **Evidence:** Explicit test `test_wrong_key_does_not_pass_magic_gate` plus zero false positives on the six different firmware shapes in the project's inventory (only EDAN-encrypted archives triggered decrypt).
- **Applies when:** Any "try a candidate secret, check if it worked" flow. The checkpoint needs to be STRUCTURAL (magic bytes, signature verify, schema validation) not STATISTICAL (entropy, length). Statistical checks can accidentally let garbage through.

### 3. Widen read perms as a single post-extraction walk, hooked into multiple sites
- **Description:** Vendor tarballs ship files with restrictive modes (rwxr-x--- root:root). Rather than filtering mode bits inside each extractor's loop (tarfile filter, zipfile loop, unblob hook — four different APIs), a single helper `widen_read_perms(root)` walks the tree once after extraction and ORs the widen-mask into every entry. Hooked into 4 post-extract sites. One helper, four call sites, consistent behaviour.
- **Evidence:** `widen_read_perms` + 4 call sites in `unpack.py` + `firmware_service.py`. 794 entries widened on v1.05, 851 on v1.12. `gen_creds.sh` (mode 750) reads cleanly through the API post-fix.
- **Applies when:** A concern that cuts across multiple extractor implementations (tarfile + zipfile + unblob + binwalk). Writing one post-pass is cheaper + more consistent than modifying each extractor's internals.

### 4. Preserve the original upload artefact; match behaviour across archive formats
- **Description:** The `.7z` and `.tar` upload paths store the original archive and set `storage_path` to it. The `.zip` path used to delete the original + point `storage_path` at an inner file — a SILENT divergence that broke our vendor-AES pipeline. Fix aligned `.zip` with the other paths: preserve the original, keep the inner extraction for diagnostic purposes, `storage_path` points at the zip itself.
- **Evidence:** `firmware_service.py:e2f2914` diff. Post-fix smoke: `aeb50fbb` row has `storage_path=…/RespArray_1.05.00.17.zip` (the preserved zip, 155 MB on disk).
- **Applies when:** Discovering that one input-format branch diverges from sibling branches on an invariant that downstream code relies on. Question: "Why is this branch different? Can it match the others?" Most of the time, uniformity is correctness.

### 5. docker cp + restart for pure-function iteration, rebuild for class-shape changes
- **Description:** Rule #20 applied four times in this followup campaign — iteration on `unpack_common.py` helper additions used `docker cp` + `docker compose restart backend`. Each cycle was ~30s. The full `docker compose up -d --build backend worker` rebuild ran ONCE per commit, at the end. The exception: when `UnpackResult` dataclass gained new fields (`decryption_output_dirs`), the arq worker's cached class pointer made `docker cp` insufficient — restart alone picked up the new schema because the process reboot re-imported the module.
- **Evidence:** Multiple `docker cp … && docker compose restart backend` invocations during commit chain. Each feature commit followed by a full `up -d --build`.
- **Applies when:** Single-file changes with no image-layer dependencies. If the diff adds a method or helper function, `docker cp` + restart works. If the diff adds a dataclass field used by a cached singleton, the restart is required (not just cp). Class-shape changes to SQLAlchemy models mandate a full rebuild (alembic migration + codegen).

### 6. Retroactive campaign file for inline-fixed bugs that logically group
- **Description:** Three fix commits shipped in one session without a formal campaign file — they started as two `.planning/intake/` items + one user-surfaced bug, and were fixed inline. At session-end, wrote a retroactive campaign file at `.planning/campaigns/completed/vendor-aes-followups-2026-04-21.md` so `/learn` had a single target AND future sessions can grep for the group (not hunt across 3 separate commits + 2 intake files).
- **Evidence:** This campaign file + these knowledge files.
- **Applies when:** A cluster of ≥3 commits that share a common discovery context (e.g. "smoke testing feature X found these N defects") but were shipped inline. Write the campaign file AFTER the fact, mark `Completed_in: session-that-shipped`. Not worth it for a single-commit fix.

### 7. Trust a real user upload over a synthetic test fixture
- **Description:** The `.7z` smoke passed on v1.12 with no drama. The defects surfaced when the user uploaded the same vendor's `.zip` firmware. Synthetic test fixtures (`test_tar_of_image_integration.py`, `test_vendor_aes_decrypt.py`) were all green — they didn't exercise the full upload→extract→unpack→detect→chmod chain on a real zip. The three defects required real zip upload flow + real vendor restrictive-mode files + real async HW detection timing to manifest.
- **Evidence:** 85/85 tests pass both BEFORE and AFTER the fixes. Tests didn't fail; real data did.
- **Applies when:** Feature verification. Tests prove the unit behaves; user smoke proves the system behaves. Both are necessary; neither alone is sufficient. When a feature has multiple input shapes, aim to smoke-test at least two before closing.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Preserve original zip; match .7z/.tar behaviour | Uniformity across upload paths; lets /unpack reprocess the whole archive; disk-usage cost acceptable | v1.05 auto-decrypted on first /unpack, zero manual SQL |
| Widen perms via post-extraction walk (Option A) | One helper, one walk, covers all extractor backends (tar, zip, unblob, binwalk). Option C (tarfile filter) only covered tar — partial | 794 entries widened on v1.05; gen_creds.sh readable; 7 unit tests pass |
| Move HW detection spawn to AFTER commit | Single-point fix vs teaching HW detector to re-read on conflict. Preserves simple commit model | Race resolved; 198 blobs detected on v1.05 post-fix (0 before) |
| Retroactive campaign file for the followup cluster | `/learn` needs a target; future sessions benefit from grouping; inline commits alone are hard to rediscover | Single campaign file covers three commits + two intake files + four smoke-test runs |

## Workflow observations

- **Each race condition in this project has the same shape: concurrent JSONB dict replacement.** CLAUDE.md Rule #7 covers "don't gather() coroutines sharing a session" — add a companion guideline: "don't dict-replace a JSONB column from two concurrent sessions; merge explicitly OR order commits."
- **Intake files are a lightweight bridge between discovery and fix.** Both zip-upload and widen-perms started as `.planning/intake/*.md` before I had time/scope to write the campaign. Good for capturing discovery without blocking execution. Both got fixed inline + their intake files went stale; ideal would be to MARK them resolved (e.g. rename to `-resolved.md` or move under `.planning/intake/resolved/`) rather than leaving them looking still-queued.
- **Pytest repeatedly vanishes from the runtime container after `docker compose restart backend`.** Pytest is pip-installed ephemerally (not in the Dockerfile). Every restart requires `docker compose exec backend /app/.venv/bin/pip install pytest pytest-asyncio`. Bakes ~30s into every test run. Follow-up candidate: add pytest to Dockerfile.ci + reuse that image for dev test runs.
