# Scout B — wairz integration surface for `.tibx` (Acronis Archive3)

Read-only research; no wairz tree files modified.

---

## TL;DR

**The wairz scaffolding for `.tibx` is already 80% wired.** Detection, capability mapping, no-handler stub, strategy registry entry, tests, frontend banner copy — all exist and route `.tibx` → `DetectedFormat.ACRONIS_BACKUP` → `unpack_no_handler` today. The implementation work is:

1. Create `backend/app/workers/unpack_tibx.py` mirroring `unpack_vhdx.py` (same shape, same trusted-binary-subprocess pattern).
2. Flip ONE LINE in `extraction_strategies.STRATEGIES` from `unpack_no_handler` → `unpack_tibx`.
3. Flip ONE LINE in `format_detection.EXTRACTION_CAPABILITY` from `NONE` → `FULL`/`PARTIAL`.
4. Add `_RAW_IMAGE_EXTENSIONS` entry for `.raw` in `firmware_paths.py` (latent gap shared with vhdx).
5. Add `backend/tests/test_unpack_tibx.py` mirroring `test_unpack_vhdx.py`.
6. Update Dockerfile + intake test: `test_unpack_no_handler_acronis_backup` will start failing once the strategy flips — it must be migrated (likely to a new sentinel format) or deleted.

**No DB migration needed.** `firmware.detected_format` is free-form `VARCHAR(48)` (`backend/app/models/firmware.py:82`) with no CHECK constraint — adding a new `DetectedFormat` enum value is a Python-only change. `ACRONIS_BACKUP` is already in the enum.

**No walker addition needed.** Existing NTFS-touching walkers (registry hive, EVTX, prefetch, AppCompat, BCD, DPAPI, MFT, USN, SRUM, scheduled tasks) already pick up any NTFS volume reachable from `get_detection_roots(firmware)` — the `disk.raw` (or recovered NTFS dir) becomes their input transparently, exactly as for `unpack_vhdx`.

---

## 1. Strategy dispatch — already exists

File: `backend/app/workers/extraction_strategies.py`.

Single source-of-truth dict `STRATEGIES: dict[DetectedFormat, Strategy]` at line 63. Contract for a strategy callable documented at lines 9-16:

```python
async def strategy(
    firmware_path: str,
    output_base_dir: str,
    progress_callback: ProgressCallback | None = None,
    firmware_id: uuid.UUID | None = None,
) -> UnpackResult
```

Current `.tibx` routing (line 83): `DetectedFormat.ACRONIS_BACKUP: unpack_no_handler`. Replacement is one-line.

Dispatch consumer: `backend/app/services/extraction_pipeline.py:36-69` (`resolve_strategy`). Reads `firmware.detected_format` → enum → `get_strategy(fmt)` → falls back to `_DEFAULT` (the monolith `unpack_firmware`) if missing. The router for upload calls `run_unpack` at line 72-91. Both arq path (`app.workers.arq_worker.unpack_firmware_job`) and in-process fallback (`routers/firmware._run_unpack_background`) route through here — single integration point.

---

## 2. `unpack_vhdx.py` end-to-end shape (template)

File: `backend/app/workers/unpack_vhdx.py` (305 LOC).

Entry point signature line 75-80 matches the Strategy contract exactly. The 7-step body is:

1. **Async `_report` callback wrapper** (lines 100-105) — wraps `progress_callback` exceptions so a broken callback never breaks extraction.
2. **`extraction_dir` derivation + reset** (lines 107-111) — `os.path.join(output_base_dir, "extracted")` is the conventional output dir for ALL workers; `_reset_extraction_dir_sync` (lines 68-72) rmtree+makedirs via `run_in_executor` (Rule #5 minimum-hop). Same helper inlined in every per-format unpacker; the consolidated `reset_extraction_dir_sync` in `unpack_common.py` from D.34 lives at `unpack_common.py:17`.
3. **Magic-byte probe** (lines 113-135) — `loop.run_in_executor(None, _read_head)` reads `_VHDX_MAGIC_PROBE_BYTES`; rejects with `result.error = "Not a VHDX..."` on mismatch. **For tibx this is the head-pattern check Scout A's research produced** (Acronis Archive3 has identifiable internal markers even though the on-disk header is undocumented per Acronis KB 63498 — the existing extension-fallback at `format_detection.py:344` covers the wrapper-extension case).
4. **Trusted-binary probe via `asyncio.create_subprocess_exec`** (lines 137-185) — `qemu-img info --output=json`. Pattern: try-block around `create_subprocess_exec` for the `FileNotFoundError`-on-missing-tool case (lines 147-155 emit a Phase α.6 install hint pointing at the Dockerfile delta). Then `asyncio.wait_for(proc.communicate(), timeout=...)` for the timeout case (lines 158-172).
5. **Disk-space check** (lines 192-211) — `loop.run_in_executor` for `os.path.getsize` + `shutil.disk_usage`. Heuristic: raw conversion can expand 5× a compressed VHDX; for tibx this should be the documented Acronis compression ratio Scout A surfaces.
6. **Main extraction subprocess** (lines 213-272) — `qemu-img convert -f vhdx -O raw <in> <out>` to `extraction_dir/disk.raw`. Same try/wait_for pattern; `_QEMU_IMG_CONVERT_TIMEOUT_SECONDS = 600` per Rule #29 (matches Ghidra tier 360_000ms → 600s × 1.2).
7. **Post-conversion analysis + result population** (lines 273-303) — `check_extraction_limits(extraction_dir, fw_size)` from `unpack_common.py:577`. Sets `result.success`, `result.extracted_path = extraction_dir`, `result.extraction_dir = extraction_dir`, `result.unpack_log` with operator guidance pointing at the NTFS MCP tools.

`UnpackResult` dataclass at `unpack_common.py:447-466`. Fields the worker must set: `success`, `extracted_path`, `extraction_dir`, `unpack_log`, `error` (on failure). Optional: `architecture`, `endianness`, `os_info`, `binary_info`, `vendor_decryption`, `decryption_output_dirs` — all `None` for tibx since the existing NTFS walkers handle these post-extraction.

---

## 3. Existing `.tibx` detection — wired

`backend/app/services/format_detection.py:339-345`:

```python
# ── 8. Acronis backup — extension-based fallback ─────────────────
name = p.name.lower()
if name.endswith((".tibx", ".tib")):
    return DetectedFormat.ACRONIS_BACKUP
```

Reason for extension-only: docstring lines 22-25 explicitly cites Acronis KB 63498 (no public magic-byte signature for `.tibx` — replaced `.tib` without a public spec). If Scout A surfaces real-world magic markers, augment with an offset-N probe BEFORE the extension fallback (head buffer is 512 KB, lines 51-52). Otherwise the existing extension match is the correct shape and stays.

Enum value at `format_detection.py:66`: `ACRONIS_BACKUP = "acronis_backup"`. `EXTRACTION_CAPABILITY` mapping at line 123: `ExtractionCapability.NONE` — flip to `FULL` or `PARTIAL` based on Scout A's findings on what fraction of Archive3 dialects the extractor handles.

`CAPABILITY_NOTES` entry at lines 144-148 — currently the "use Acronis True Image" workaround text. Update with operator guidance on what the new handler does + any known limitations once Scout A reports.

---

## 4. unblob handler API — not directly usable

unblob is NOT installed in the dev venv (`pip3 install --no-cache-dir --break-system-packages unblob` at `backend/Dockerfile:98`); it ships only in the worker container image. wairz uses unblob via subprocess (`run_unblob_extraction` in `unpack_common.py`), not as an in-process Python plugin host. No code path imports `unblob` as a Python module.

unblob DOES have a handler plugin API (per its upstream `unblob.handlers` package), but wairz doesn't use it — wairz's pattern is per-format dedicated workers that shell out to trusted binaries (`msiextract`, `qemu-img`, `cabextract`, `wimlib-imagex`, `7z`, `ifsdump`). Following this pattern for `.tibx` is the correct integration shape — no unblob plugin needed.

If Scout A's chosen extractor is a Python library rather than a CLI binary, the worker can `import` it lazily inside the `unpack_tibx` function body per Rule #30 (function-body imports for optional / slow deps). Mock-patch target then becomes `app.workers.unpack_tibx.<symbol>` for unit tests — Rule #30 applies if the symbol is rebound there, else patch the source module.

---

## 5. Detection roots — one latent gap to fix

File: `backend/app/services/firmware_paths.py`.

`get_detection_roots(firmware)` at lines 446-485 calls `_compute_roots_sync(extracted_path)` (lines 267+) which walks the extraction container looking for subdirs that "qualify" via `_scan_container_for_roots` (line 155). A directory qualifies if it has a raw-image file by extension (`_dir_has_raw_image` at line 107) — list at `_RAW_IMAGE_EXTENSIONS` line 69-72:

```python
_RAW_IMAGE_EXTENSIONS: frozenset[str] = frozenset({
    ".img", ".bin", ".elf", ".mbn", ".hcd", ".tar", ".zip",
    ".lz4", ".ota", ".sin", ".pac",
})
```

**`.raw` is NOT in this list.** This is a latent gap shared with `unpack_vhdx` — VHDX writes to `extraction_dir/disk.raw`, and the only reason it currently works is that the `extracted_path = extraction_dir` assignment at `unpack_vhdx.py:300` makes the extraction_dir ITSELF the detection root (and at lines 305-307 of firmware_paths `_dir_has_raw_image(container)` is consulted ONLY for the top-level container, which has the raw image as a direct child). For the tibx case where extraction may produce a DIRECTORY of NTFS-walked files OR a `disk.raw`, the same shape applies — set `result.extracted_path = extraction_dir` and the existing logic catches it.

**Recommendation: add `.raw` to `_RAW_IMAGE_EXTENSIONS`** for defense-in-depth (covers any future case where the raw image is in a SUBDIR of extraction_dir, e.g. a multi-volume tibx producing `extraction_dir/vol1/disk.raw` + `extraction_dir/vol2/disk.raw`). One-line change at line 69-72.

No special-case registration needed for tibx — it's the same "raw image file in a directory" shape as VHDX, so once `.raw` is in `_RAW_IMAGE_EXTENSIONS` the detection-roots resolver auto-discovers it.

---

## 6. Test harness pattern

Reference: `backend/tests/test_unpack_vhdx.py` (238 LOC, 7 tests).

Test shape:

- `_make_proc_stub(returncode, stdout=b"", stderr=b"")` (lines 18-29) — synchronous helper returning a fake process object with `communicate()` async method and `kill()` method.
- `_make_two_phase_subprocess(info_proc, convert_factory)` (lines 32-41) — sequences a first-call `info` subprocess then a second-call `convert`. Mirror this for tibx if the extractor needs a probe step before the main extract.
- Each test patches `app.workers.unpack_vhdx.asyncio.create_subprocess_exec` with `AsyncMock(side_effect=...)` to inject the stub process.
- Magic-byte rejection test (lines 44-56), missing-binary test (lines 59-76), info-step failure test (lines 79-99), convert-step failure (lines 102-129), timeout test (lines 132-167), happy path (lines 170-206), progress-callback test (lines 209-237).
- Happy-path test (lines 170-206) writes a `disk.raw` stub inside the mock convert function via `_populate(*_a, **_kw)` (lines 181-186) — mirror for tibx output.

For Rule #36 no-execute test, see `backend/tests/test_unpack_msi.py:329-372` (`test_unpack_msi_never_executes_custom_actions`) — captures every subprocess `args`, asserts `args[0]` is the trusted extractor binary, and scans tokens for forbidden names. For tibx the forbidden-token list is whatever interactive Acronis tools exist (`acronis-cli` exec mode if present; Scout A documents whether the chosen extractor has an "execute restored binary" sub-command). If the chosen extractor is parse-only Python and never spawns a subprocess, this test is N/A — but the pattern still applies as defense-in-depth if any subprocess fires.

For Rule #35b live canary, see `backend/tests/test_unpack_msi.py:382-` (`_TINY_MSI_FIXTURE` + auto-skip when the CLI is not on PATH). Mirror: if Scout A surfaces a public tibx test fixture or a generator command, ship a tiny fixture under `backend/tests/fixtures/acronis/tiny.tibx` and a fixture-based test that auto-skips when the real extractor is not in the worker container.

---

## 7. DB migration — NOT needed

`backend/app/models/firmware.py:82`:

```python
detected_format: Mapped[str | None] = mapped_column(String(48), nullable=True)
```

`backend/alembic/versions/d2e3f4a5b6c7_add_upload_stage_to_firmware.py:101-108` declares the column with no CHECK constraint (vs. `upload_stage` which has `ck_firmware_upload_stage` at lines 109-114). `DetectedFormat` is a Python-only `str` Enum — adding values is zero-migration. `ACRONIS_BACKUP` already exists at `format_detection.py:66`; no schema change for tibx.

If Scout A surfaces variant Acronis formats that justify separate enum values (e.g. `ACRONIS_TIB_LEGACY` vs `ACRONIS_TIBX_ARCHIVE3`), add the Python enum members — still zero migration. The `48`-char column width covers any reasonable enum value.

---

## Punch list — files to add/modify

| File | Action | Notes |
|---|---|---|
| `backend/app/workers/unpack_tibx.py` | **CREATE** | Mirror `unpack_vhdx.py` shape. Module-level: timeout constants, magic-byte probe constants (if any from Scout A). Single `async def unpack_tibx(...)` entry point with 7-step body. Use `reset_extraction_dir_sync` from `unpack_common.py:17` for the rmtree+makedirs. Set `result.extracted_path = extraction_dir`, `result.extraction_dir = extraction_dir` on success. |
| `backend/app/workers/extraction_strategies.py:39` | **EDIT** | Add `from app.workers.unpack_tibx import unpack_tibx`. |
| `backend/app/workers/extraction_strategies.py:83` | **EDIT** | Change `DetectedFormat.ACRONIS_BACKUP: unpack_no_handler` → `DetectedFormat.ACRONIS_BACKUP: unpack_tibx`. |
| `backend/app/services/format_detection.py:123` | **EDIT** | Change `DetectedFormat.ACRONIS_BACKUP: ExtractionCapability.NONE` → `FULL` or `PARTIAL` per Scout A's coverage assessment. |
| `backend/app/services/format_detection.py:144-148` | **EDIT** | Update `CAPABILITY_NOTES[DetectedFormat.ACRONIS_BACKUP]` text — describe what the new handler extracts + any known limitations. Or remove the entry if capability becomes FULL (per the WIM/ISO/CAB precedent at lines 153-170 comments). |
| `backend/app/services/firmware_paths.py:69-72` | **EDIT** | Add `".raw"` to `_RAW_IMAGE_EXTENSIONS`. Defensive — also benefits VHDX. |
| `backend/Dockerfile` | **EDIT** | Add the chosen tibx extractor install (apt package or `pip3 install` line). Place near the existing `qemu-img`/`cabextract`/`msitools` block (~lines 85-100). Per Rule #8 the rebuild needs `backend worker migrator` triplet. |
| `backend/tests/test_unpack_tibx.py` | **CREATE** | Mirror `test_unpack_vhdx.py`. Tests: magic/extension rejection, missing-binary, extractor-step failure, timeout, happy path emitting `disk.raw` (or NTFS dir), progress-callback. Add Rule #36 no-execute test if the extractor spawns subprocesses. Add Rule #35b live canary with fixture if Scout A surfaces one. |
| `backend/tests/test_extraction_pipeline.py:288-330` | **EDIT** | `test_unpack_no_handler_acronis_backup` + `test_unpack_no_handler_invokes_progress_callback` (line 308) will START FAILING once the strategy flips. Migrate the canary to a different `ExtractionCapability.NONE` format if one exists, OR delete these two tests (the no-handler unit test at `test_extraction_pipeline.py:288` is the canonical coverage for `unpack_no_handler` itself — moving the canary to a unit test in a future `test_unpack_no_handler.py` may be cleaner). Either way, this must land in the same commit per Rule #21 mirror-discipline. |
| `backend/tests/test_format_detection.py:205-211` | **KEEP** | `test_detects_acronis_backup_via_extension` should still pass — detection logic is unchanged. |
| `backend/tests/test_firmware_router.py:533-555` | **EDIT** | `test_capability_banner_for_acronis_backup` asserts `capability='none'` + the workaround note. Update to assert the new capability + note (or assert no banner if capability becomes FULL). |
| `CLAUDE.md` Learned Rules section | **OPTIONAL** | If the tibx integration surfaces a NEW pattern (e.g. forensic-archive parse-only contract beyond Rule #36, or a new trusted-binary discipline), add a Rule-of-One entry. Otherwise no rule update needed — the integration follows existing patterns. |

---

## Architectural notes for the implementation agent

- **No new walker family needed.** Once `unpack_tibx` sets `result.extracted_path = extraction_dir` and produces `disk.raw` (or recovered NTFS files), the post-extraction hook in `backend/app/workers/unpack.py:74-154` (`_run_hardware_firmware_detection_safe`) iterates `WALKER_AUTO_TRIGGERS` from `walker_registry.py`. The Windows-NTFS walkers (registry, EVTX, prefetch, AppCompat, BCD, DPAPI, MFT, USN, SRUM, scheduled tasks, LNK, WMI) all resolve their targets via `get_detection_roots(firmware)` per Rule #16 — so a successfully-mounted NTFS volume inside the extraction is transparently picked up. This is the same pattern that makes VHDX work today.
- **Rule #36 no-execute applies.** The extracted backup contents may include Windows Custom Action equivalents, installer scripts, or auto-run hooks. The unpacker MUST be parse-only. If Scout A's chosen extractor has any "execute restored binary" or "run pre-restore hook" mode, the worker MUST NOT invoke it — only parse-mode flags. Test with the Rule #36 pattern from `test_unpack_msi.py:329-372`.
- **Rule #29 timeout discipline.** The chosen subprocess (if any) MUST declare an explicit `asyncio.wait_for(..., timeout=N)`. Pick the tier matching extractor complexity: 600s (Ghidra tier) for a full restore, 300s for partial, 30s for header probes. Frontend axios timeout inherits the 600s ceiling via existing `SECURITY_SCAN_TIMEOUT`.
- **Rule #16 detection-roots.** The post-extraction caller in `unpack.py:74` already invokes `_run_hardware_firmware_detection_safe` which calls `detect_hardware_firmware(firmware_id, db, walk_roots=None)` — the `None` triggers a fresh `get_detection_roots` resolution. tibx fits transparently.
- **Output-path contract.** Mirror VHDX exactly: `extraction_dir/disk.raw` for single-volume; `extraction_dir/vol1/disk.raw`, `extraction_dir/vol2/disk.raw` etc. for multi-volume. Multi-volume requires `.raw` in `_RAW_IMAGE_EXTENSIONS` (item 5 above) so each vol-dir qualifies as a detection root.
- **Frontend banner.** `routers/firmware.py` already surfaces `EXTRACTION_CAPABILITY[fmt]` + `CAPABILITY_NOTES[fmt]` on the upload-status response (see `test_firmware_router.py:533`). No frontend changes — the banner updates automatically when the capability + note are flipped.

---

## Key file paths (absolute)

- `/home/dustin/code/wairz/backend/app/workers/unpack_vhdx.py` — template to mirror (305 LOC).
- `/home/dustin/code/wairz/backend/app/workers/extraction_strategies.py:63-84` — STRATEGIES dict to edit.
- `/home/dustin/code/wairz/backend/app/workers/unpack_no_handler.py` — current routing target for ACRONIS_BACKUP.
- `/home/dustin/code/wairz/backend/app/workers/unpack_common.py:447-466` — `UnpackResult` dataclass shape.
- `/home/dustin/code/wairz/backend/app/services/format_detection.py:339-345` — extension-based tibx detection.
- `/home/dustin/code/wairz/backend/app/services/format_detection.py:113-137` — EXTRACTION_CAPABILITY mapping.
- `/home/dustin/code/wairz/backend/app/services/format_detection.py:143-189` — CAPABILITY_NOTES copy.
- `/home/dustin/code/wairz/backend/app/services/extraction_pipeline.py:72-91` — `run_unpack` dispatcher.
- `/home/dustin/code/wairz/backend/app/services/firmware_paths.py:69-72` — `_RAW_IMAGE_EXTENSIONS` to extend with `.raw`.
- `/home/dustin/code/wairz/backend/app/workers/unpack.py:74-154` — post-extraction walker auto-trigger hook (fires automatically; no edits needed).
- `/home/dustin/code/wairz/backend/app/workers/walker_registry.py` — walker auto-trigger registry (no edits needed; existing NTFS walkers cover tibx output).
- `/home/dustin/code/wairz/backend/tests/test_unpack_vhdx.py` — test template (238 LOC, 7 tests).
- `/home/dustin/code/wairz/backend/tests/test_unpack_msi.py:329-372` — Rule #36 no-execute test pattern.
- `/home/dustin/code/wairz/backend/tests/test_extraction_pipeline.py:288-330` — no-handler tests that will need migration once strategy flips.
- `/home/dustin/code/wairz/backend/app/models/firmware.py:82` — `detected_format` column (no migration needed).
- `/home/dustin/code/wairz/backend/Dockerfile:85-100` — where the new tibx extractor install line goes.
