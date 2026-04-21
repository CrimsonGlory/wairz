# Intake: Firmware extractor preserves restrictive mode bits, blocking file-explorer reads

**Status:** queued
**Created:** 2026-04-21 (session b3a3b580)
**Discovered during:** RespArray v1.05 file-explorer access to `gen_creds.sh`
**Priority:** low-medium — affects occasional files in most firmware, not blocking common-case use

## The defect

When `tarfile`/`zipfile`/unblob extracts firmware content, the original mode bits are preserved (e.g. `rwxr-x---` root:root for `gen_creds.sh` in nxapp). The Wairz backend runs as the `wairz` user inside the container. When the file-explorer API calls `open()` on a mode-750 file owned by root, the kernel returns EPERM and the UI shows "I don't have access to this resource."

This is a UX defect specific to firmware RE tooling — the original device's access model (only root reads creds) has no meaning in an analysis context. We want to read everything.

## Concrete affected files from the RespArray v1.05 upload

- `.../nxapp-0.2.2-Linux.tar.xz_extract/nxapp-0.2.2-Linux/bin/gen_creds.sh` — mode `rwxr-x---`
- `rootfs_partition.tar.xz_extract/etc/*` — many mode `drwx------` directories (seen earlier in this session when `[ -e ... ]` tests falsely returned "not exist")
- Anything the vendor chose to lock down in the rootfs

## Fix options

### Option A — `chmod -R a+r` after each extraction (recommended)
After unblob/binwalk/tar extract finishes, walk the extraction tree and OR the mode with `0o044` (group + other read) for files, `0o055` (group + other read + execute) for directories. Preserves execute bits. Files stay readable to the backend without changing ownership.

```python
def _widen_read_perms(root: str) -> None:
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        for name in files + dirs:
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
                if stat.S_ISLNK(st.st_mode):
                    continue
                is_dir = stat.S_ISDIR(st.st_mode)
                new_mode = st.st_mode | (0o055 if is_dir else 0o044)
                if new_mode != st.st_mode:
                    os.chmod(p, new_mode)
            except OSError:
                pass
```

Call from unpack.py Stage 2 completion path, and from firmware_service.py zip/tar shortcut paths.

### Option B — Run the backend as root (bad)
Violates least-privilege principle, enables path-traversal to do more damage if a bug appears. Skip.

### Option C — Tarfile extractor filter widens mode as it writes (alternative to A)
In `_firmware_tar_filter` (firmware_service.py:199), OR the mode with `0o044` before returning the member. Cheaper (no second walk) but only applies to tar extractions — doesn't cover unblob/binwalk output. Partial coverage, not preferred.

## Acceptance criteria

1. After re-unpacking RespArray v1.05 through the pipeline, `curl /files/read?path=nxapp-0.2.2-Linux.tar.xz_extract/nxapp-0.2.2-Linux/bin/gen_creds.sh` returns the file content (not a permissions error).
2. No regression on firmware that already extracts readable content (most of them).
3. Extracted executable scripts/binaries retain their execute bits.

## Related

- Surfaced by `/nxapp-0.2.2-Linux.tar.xz_extract/.../gen_creds.sh` access attempt in session b3a3b580.
- Discovery: the script itself references `/etc/nx/nxapp/default/creds/EDAN_Root_CA.key` — worth a follow-on investigation into whether the private key is extractable from a provisioned device (out of scope for this intake).
