# Anti-patterns: DS1 Moto-G32 zero-blobs systematic-debugging session

> Extracted: 2026-05-14
> Campaign: ad-hoc systematic-debugging session
> Postmortem: .planning/postmortems/postmortem-ds1-moto-g32-zero-blobs-2026-05-14.md

## Anti-patterns observed

### 1. Climb-only traversal can't reach segments the climb doesn't recognize

- **What happened:** `_find_unblob_extraction_top` used `if cur_name.endswith("_extract") or parent_name.endswith("_extract"): climb`. For Moto radio.img, the path goes through 4 consecutive non-_extract dirs (`efs_item_files/nv/item_files/rfnv`). The climb's local-2-name check returns False on the FIRST pair and gives up — never sees that 5 levels up there's a perfectly good `_extract` ancestor.
- **Why it happened:** The original c68b3b6 fix (Issue #20a) was designed for the case where extracted_path was INSIDE an `_extract` chain. It didn't anticipate paths that drilled BEYOND the chain into vendor-specific subtrees (RFNV, EFS, OS configs).
- **How to avoid:** When designing tree-traversal heuristics, ask: "Could the input path land OUTSIDE my local-pattern recognition window? What's the fallback if my local pattern doesn't match?" For path-based traversal, a STRUCTURAL fallback that operates on the path STRING (not the directory tree) is the durable answer. Cost: ~15 lines of Python. Benefit: covers the long-tail of extraction shapes the climb can't.

### 2. Pre-existing latent bugs surface AFTER a precondition fix

- **What happened:** The NUL-byte issue in PE/ELF metadata had existed since the detector was written — it just never surfaced because no firmware had previously surfaced ELF blobs through the detector's bulk INSERT. The detection-roots fix shipped FIRST, surfaced 313 candidates including 12 ELF sub-extracts from `bootloader.img_extract/`, then INSERT failed.
- **Why it happened:** Detection-pipeline coverage gaps: no firmware in the prior wairz test corpus drove ELF-shape metadata through the persistence layer. The NUL-byte risk was always there; it just wasn't EXERCISED.
- **How to avoid:** Two layers of defense:
  (a) **Sanitize at the boundary, not at the source.** Every TEXT/VARCHAR/JSONB-bound string should go through a sanitizer at the bulk-INSERT site, regardless of whether the source is "trusted". Parser libraries are not trusted — they DO return binary-shaped strings.
  (b) **Coverage gates that exercise the full pipeline.** A Rule #35b live canary that creates a synthetic ELF blob with NUL-shape metadata, runs `detect_hardware_firmware`, and asserts the INSERT succeeds — would have caught this BEFORE the c0c107e fix exposed it.

### 3. Forensic correctness can't be code-reviewed

- **What happened:** The classifier shipped 313 blobs and tagged 18 of them as "other/qcom_mbn/qualcomm". Code review would say "the classifier ran, made a decision, persisted the row — works as designed". Only a domain expert (DFIR analyst) would notice that "0 bluetooth blobs on a Moto-G32 (which definitively has a Broadcom BCM4361 BT chip)" is FORENSICALLY impossible regardless of the code's correctness.
- **Why it happened:** Classifier patterns are domain knowledge. The YAML fallback rules generate plausible outputs (vendor/category assignment) for every blob, even when the assignment is wrong. There's no "I don't know" output — only "best guess via fallthrough".
- **How to avoid:** For every new pattern/classifier rule, ask "what's the negative coverage?" — i.e., what SHOULD this pattern have flagged but didn't? And run a domain-aware sanity check on the output distribution: "Does a Snapdragon device have 0 Broadcom Bluetooth? Does a Linux rootfs have 0 ELF binaries?". A forensic-domain reviewer in the Citadel-agent rotation catches this; an LLM-only code review misses it.

### 4. Realpath gap on a path-based heuristic is a silent sandbox break

- **What happened:** The path-string fallback validated `os.path.isdir(outer)` — which follows symlinks. A `_extract`-suffixed symlink could resolve to a path outside the firmware sandbox, and the fallback would return that as a detection root. Bounded by `followlinks=False` in the walker but still violates Rule #1.
- **Why it happened:** `os.path.isdir` is the default validation pattern; symlink-aware variants require explicit `os.path.realpath` + ancestry check. The convenience of `isdir` masks the sandbox violation.
- **How to avoid:** Every helper that returns a filesystem path consumed by a security-sensitive downstream (sandbox resolution, blob walker, etc.) must compute `realpath(returned_path)` AND verify it's an ancestor of `realpath(input)`. The check is 3 lines; the bug it prevents is structural.

### 5. Existing-broken-corpus discovery happened late

- **What happened:** The DS1 firmware reported as broken. Phase A3 (corpus audit) THEN discovered 4 other firmwares with the same shape — which had been silently broken for up to 4 weeks (since 2026-04-18). The operator never noticed because they didn't actively query each firmware's blob count.
- **Why it happened:** No proactive monitoring on the `detection_audit.blobs_detected` / `orphan_ratio` shape. The audit JSONB exists; nothing watches it.
- **How to avoid:** Wire a periodic cron (or dashboard alert) that surfaces firmwares with `orphan_ratio >= 0.95 AND blobs_detected = 0`. Cost: 1 cron + 1 query. Benefit: same-day discovery instead of weeks-of-silence.

### 6. Stderr from LIEF / pyelftools cluttered the verification output

- **What happened:** During verify-the-fix testing, LIEF emitted ~10,000 lines of warnings ("The current binary doesn't have a section header", "Segment #N has a physical size larger than the current stream size", etc.) to stderr for each malformed Moto bootloader ELF segment. The Python script exited code 1 due to stderr noise, masking the actual SQL error.
- **Why it happened:** LIEF can't tell informational warnings from fatal errors. Both go to stderr. wairz's parser wrappers don't filter.
- **How to avoid:** When verifying a fix via direct Python invocation, capture stderr to a file + grep for the SPECIFIC error pattern ("invalid byte sequence", "asyncpg", "sqlalchemy") rather than reading raw stderr. For long-running parser pipelines, consider wrapping LIEF/pyelftools/pefile in a quiet-by-default decorator that only surfaces errors at WARNING+ level.

## Decisions worth re-examining if pattern repeats

- **`cleaned or None` empty-collapse:** Currently collapses empty-after-sanitize strings to None. Arch-reviewer F#3 (LOW) noted this might drop semantic-empty signals. Defer until a downstream consumer reports a regression.

- **LAST-marker selection for nested `extracted/extracted/`:** Documented but no production firmware has actually exercised this shape. Arch-reviewer F#1 (MED) noted FIRST-marker might be preferable for re-extraction shapes. Pin a regression test (done — commit e2e300e) and revisit if a real nested-extraction firmware surfaces.

- **278 "other/qcom_mbn/qualcomm" entries:** Forensic A2 finding flagged these as defensible-but-opaque. Future refinement: add `_category_from_qcom_name()` rules for cmnlib/keymaster/qupfw/tzbsp → "tee" and xbl/abl → "bootloader". Defer until a customer-specific TZ audit drives the work.

- **No auto-detection-rerun on backend restart:** Corpus A3 finding. Adds 1-N seconds per firmware on cold start. Defer until corpus growth makes manual `--only-broken` runs noisy.
