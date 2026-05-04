---
title: "Security: Harden Android OTA and ZIP Extraction Paths"
status: completed
priority: critical
target: backend/app/workers/unpack_android.py, backend/app/workers/unpack_common.py, backend/app/services/firmware_service.py
completed_at: 2026-04-19
completed_in: session 69f004fe phase 1
shipped_commits:
  - ab09e1c  # feat(security): safe_extract_zip — zipslip + bomb + symlink defences for all ZIP extraction paths
closed_by: wave3-stream-gamma (Rule-19 status-bump)
---

## Problem

The main firmware upload path at `backend/app/services/firmware_service.py:148-161, 231-253` has careful defenses:
- Per-entry realpath containment check
- Zip-bomb gates (entry count, declared size, compression ratio)
- Symlink-rejecting tar filter

But **two other extraction paths bypass all of these**:

1. **`backend/app/workers/unpack_android.py:378, 400`** — calls `zf.extract(name, extraction_dir)` directly on Android OTA files. `zf.namelist()` is iterated with zero pre-validation (`:373`). Android OTAs are pure attacker data.

2. **`backend/app/workers/unpack_common.py:411-415`** — another raw extract call site that reaches into the zipfile API without the bomb gates.

3. **`firmware_service.py:_extract_archive` zip branch (`:224-254`)** runs `zf.extractall()` after per-entry containment checks pass. Symlink entries with Unix-symlink attr (`info.external_attr >> 16 & 0o170000 == 0o120000`) are not rejected. Python's default `extractall` behavior on zip-symlinks has varied; a malicious OTA can plant symlinks pointing anywhere.

## Root Cause

The extraction primitives in `firmware_service.py` (`_firmware_tar_filter`, realpath-containment-per-entry, bomb gates) are not reused by Android/OTA paths. Each path reimplemented only the parts its author remembered.

## Approach

**Step 1 — Extract a shared `safe_extract` module.**

Create `backend/app/workers/safe_extract.py`:

```python
def safe_extract_zip(zf: ZipFile, output_dir: str, *, 
                    max_files: int, max_total_bytes: int, max_ratio: float,
                    allow_symlinks: bool = False) -> None:
    """Extract ZIP with containment, bomb, and symlink gates."""
    # Pre-flight: count, total declared size, ratio
    # Per-entry: realpath containment check
    # Per-entry: reject Unix-symlink bit unless allow_symlinks
    # Stream writes with running size check (abort if written > declared + epsilon)
    ...

def safe_extract_tar(tf: TarFile, output_dir: str, *, 
                    max_files: int, max_total_bytes: int) -> None:
    """Use existing _firmware_tar_filter logic."""
    ...
```

**Step 2 — Migrate all call sites.**

Replace raw extractions:
- `unpack_android.py:378, 400` → `safe_extract_zip(zf, output_dir, allow_symlinks=False, ...)`
- `unpack_common.py:411-415` → same
- `firmware_service.py:224-254` → `safe_extract_zip(zf, output_dir, allow_symlinks=False, ...)` (removes the inline bomb gate and extractall)

**Step 3 — Add per-entry actual-size enforcement.**

The declared `info.file_size` is attacker-controlled. Zip bombs can declare 1KB and actually decompress to GB. Stream the write and abort if `bytes_written > info.file_size + 1024` (allow for small alignment slop).

**Step 4 — Integration tests.**

Add `backend/tests/test_safe_extract.py`:
- Evil ZIP with path traversal (`../../etc/passwd`) — must reject
- Evil ZIP with zip bomb (small declared, huge decompressed) — must abort mid-stream
- Evil ZIP with Unix-symlink bit — must reject unless `allow_symlinks=True`
- Normal OpenWrt ZIP — must extract successfully

## Files

- `backend/app/workers/safe_extract.py` (new)
- `backend/app/workers/unpack_android.py`
- `backend/app/workers/unpack_common.py`
- `backend/app/services/firmware_service.py`
- `backend/tests/test_safe_extract.py` (new)

## Acceptance Criteria

- [ ] All call sites listed above use `safe_extract_zip`; zero direct `zf.extract` or `zf.extractall` calls in `backend/app/workers/` or `backend/app/services/firmware_service.py`
- [ ] `grep -rn 'zf\.extract\|zf\.extractall' backend/app/workers backend/app/services/firmware_service.py` returns only references inside `safe_extract.py` itself
- [ ] All 4 adversarial test cases in `test_safe_extract.py` fail safely (reject or abort)
- [ ] Normal firmware uploads still work (regression test: DD-WRT image, OpenWrt tarball)

## Risks

- Some legitimate firmware (Android OTAs especially) may contain symlinks that are currently handled correctly — start with `allow_symlinks=False` but add per-caller override if regressions surface
- The existing `_firmware_tar_filter` in `firmware_service.py:199-216` should be moved into `safe_extract` module too — but avoid scope creep for this intake; mention in a follow-up

## References

- Security review H1, H2
- CLAUDE.md learned rule about ZIP slip defenses (in knowledge base)
