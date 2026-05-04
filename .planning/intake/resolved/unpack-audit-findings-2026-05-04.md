---
title: "unpack_audit_service: promote unpack-time discoveries to Findings"
status: resolved
priority: high
target: backend/app/services/unpack_audit_service.py + backend/alembic/versions/ + backend/app/workers/arq_worker.py + backend/app/routers/firmware.py + frontend/src/types/index.ts + frontend/src/constants/statusConfig.ts + frontend/src/components/findings/FindingsList.tsx
closed_by: "session 2026-05-04 — full DAG (C1 migration / C2 service+tests / C3 wiring / C4 frontend) shipped + 2 follow-up bug fixes"
shipped_commits: [877f83e, 8471ab8, 7dc21fe, 672b020, 057ea67, a852659]
---

## Resolution — 2026-05-04

All four DAG commits shipped in order, plus two post-ship fixes that the live RespArray canary surfaced.

| DAG step | Status | Commit |
|---|---|---|
| C1 — migration: add `unpack_audit` to `ck_findings_source` CHECK | shipped | `877f83e` |
| C2 — `services/unpack_audit_service.py` + `tests/test_unpack_audit_service.py` | shipped | `8471ab8` |
| C3 — wiring in `arq_worker.py` + `routers/firmware.py` (+ confidence-drop fix in `FindingService.create()`, Rule #35b live-canary discovery) | shipped | `7dc21fe` |
| C4 — frontend: `FindingSource` union + `FINDING_SOURCE_CONFIG` + filter chip | shipped | `672b020` |
| Follow-up — normalise legacy `vendor_decryption` dict shape (Rule #35c JSONB shape drift) | shipped | `057ea67` |
| Follow-up — recompute `partial_extraction` post-decrypt + link findings | shipped | `a852659` |

Surfaced two new Learned Rules along the way: Rule #35b (mock unit tests pass while real ORM rows persist `confidence=None`) and Rule #35c (JSONB without `schema_version` discriminator — boundary normaliser pattern). Both folded into CLAUDE.md commit `cd49d36`.

Spawned two follow-up intakes:
- `findings-confidence-ui-display-2026-05-04.md` — render `Finding.confidence` in UI (now load-bearing post-`7dc21fe`)
- `findings-source-tag-drift-ci-2026-05-04.md` — DB CHECK ↔ frontend union CI gate (the `?? FINDING_SOURCE_CONFIG.manual` fallback masks drift; this intake adds a discoverability gate)

## Description

The unpack pipeline (`backend/app/workers/unpack.py:756-816` + `unpack_common.py:_detect_openssl_key_triples` + `_decrypt_vendor_encrypted_archives`) recovers vendor-AES keys (e.g. EDAN MPM RespArray's hardcoded `aes-128-cbc` key `43c8e032ff65f5cc762d1dc15580d425` / iv `50719d498aa89db2d3fccac9ff310c79` from `force_update.sh:755`) and writes the audit to `firmware.device_metadata["vendor_decryption"]`. **No `Finding` row is emitted** — the highest-confidence finding class the system can produce (cryptographic magic-gate verification proves correctness mathematically) is invisible to `list_findings`, `comparison_service`, the FDA SBOM export, and the frontend FindingsPage.

Implement Option C from the architectural analysis: a dedicated `services/unpack_audit_service.py` that mirrors the existing `_run_hardware_firmware_detection_safe` post-commit-task pattern. Promotes structured `device_metadata` artifacts to `Finding` rows with `source="unpack_audit"`. DELETE-then-REPOPULATE per `(firmware_id, source)` for clean rescan idempotency.

Three findings emitted per RespArray-shaped firmware (deduped by `(algo, key_hex, iv_hex)` triple, NOT per-archive):

| ID | CWE | Severity | Confidence |
|---|---|---|---|
| F1 — Hardcoded AES key in update script | CWE-798, CWE-321 | High | High (cryptographic magic-gate proof) |
| F2 — Static IV reuse with CBC across N ciphertexts | CWE-323, CWE-329 | Medium | High |
| F3 — Cleartext key in shipped recovery initramfs | CWE-312, CWE-256 | Medium | High |

Plus zero-or-more **info** findings when `len(extraction_diagnostics.encrypted_archives) > len(vendor_decryption)` (vendor-encrypted archive whose key was not recovered).

## Cross-step DAG

```
C1 (Migration) ──► drop+recreate ck_findings_source CHECK with 'unpack_audit'
                   MUST land FIRST or any subsequent INSERT raises IntegrityError
                                          │
C2 (Service)   ◄──┘  services/unpack_audit_service.py + tests/test_unpack_audit_service.py
                     Pure-Python no callers; safe to land independent of wiring
                                          │
C3 (Wiring)    ◄──┘  arq_worker.py:142 + routers/firmware.py:289 (asyncio.create_task)
                     REQUIRES C1+C2; triggers Rule #8 rebuild + Rule #11 smoke + Rule #17 canary
                                          │
C4 (Frontend)  ◄──┘  types/index.ts + statusConfig.ts + FindingsList.tsx
                     Independent of backend (graceful fallback); Rule #24 typecheck + Rule #26 rebuild
```

## Acceptance Criteria

### Commit 1 — Migration

- [ ] New file `backend/alembic/versions/<new_id>_add_unpack_audit_source.py` with `down_revision = "e6f7a8b9c0d1"` (current head)
- [ ] `upgrade()` drops `ck_findings_source`, recreates with `'unpack_audit'` appended to the existing 16-value list (mirror constants from `54c8864fbe0c_add_enum_check_constraints.py:41`)
- [ ] `downgrade()` is symmetric — drop, recreate without `unpack_audit`
- [ ] **Rule #17 canary**: pre-migration `INSERT INTO findings (..., source='unpack_audit')` raises `IntegrityError`; post-migration succeeds. Canary mandatory before trusting the migration; otherwise the constraint update is silently a no-op.
- [ ] Apply via Rule #20 fast iteration: `docker cp` the file in, run `alembic upgrade head` via container exec — no rebuild required for migrations alone

### Commit 2 — Service + tests

- [ ] New file `backend/app/services/unpack_audit_service.py` exporting:
  - `UNPACK_AUDIT_SOURCE = "unpack_audit"` module constant
  - `async def run(firmware_id: uuid.UUID) -> int` returning count of findings created
  - `async def _run_safe(firmware_id: uuid.UUID) -> None` fire-and-forget wrapper, swallows exceptions with `logger.warning(..., exc_info=True)`
  - Internal extractors `_extract_aes_key_findings`, `_extract_partial_extraction_findings`, `_extract_signed_archive_finding` each returning `list[FindingCreate]`
- [ ] Architectural template: `backend/app/workers/unpack.py:73-119` (`_run_hardware_firmware_detection_safe`)
- [ ] Owns its own `AsyncSession` via `async_session_factory` (Rule #7 — never share session across coroutine boundaries)
- [ ] DELETE `WHERE firmware_id=X AND source='unpack_audit'` then INSERT — idempotent per Rule #33 design
- [ ] Skip Rule #32 violation: NO `await db.refresh(...)` after `await db.commit()`
- [ ] Triple dedup: `vendor_decryption` typically has N entries (one per decrypted archive) all citing the same `(algo, key_hex, iv_hex)`; emit ONE F1 + ONE F2 + ONE F3, not N×3
- [ ] Width-canary discipline (Rule #31): undecrypted-archive logic computes `encrypted_count - decrypted_count`, NOT just `encrypted_archives` non-empty (otherwise every successfully-decrypted RespArray emits a false "key not recovered" finding because `extraction_diagnostics` is upload-time and never updated post-decrypt)
- [ ] New file `backend/tests/test_unpack_audit_service.py` mirroring `test_vendor_aes_decrypt.py` shape:
  - `test_emits_three_findings_for_clean_decrypt`
  - `test_partial_decrypt_emits_undecrypted_info`
  - `test_no_vendor_decryption_emits_zero`
  - `test_idempotent_rerun_replaces_findings`
  - `test_dedup_collapses_repeated_triples`
  - `test_check_constraint_rejects_pre_migration` (Rule #17 canary)
  - `test_silent_skip_on_missing_firmware`

### Commit 3 — Wiring

- [ ] Edit `backend/app/workers/arq_worker.py:142` — after the existing `await db.commit()`, before the `_run_hardware_firmware_detection_safe` spawn, add:
  ```python
  if result.success:
      from app.services.unpack_audit_service import _run_safe as _run_unpack_audit_safe
      asyncio.create_task(_run_unpack_audit_safe(firmware.id))
  ```
- [ ] Edit `backend/app/routers/firmware.py:289` — same shape in the in-process `_run_unpack_background` callback
- [ ] New file `backend/tests/test_unpack_audit_integration.py` exercising the full path: synthetic Firmware row → `_run_safe` → query Finding rows; verify all required fields populate (firmware_id, project_id, source, cwe_ids, severity, confidence, evidence, file_path, line_number)
- [ ] **Rule #8 + Rule #11 verification gates**: `docker compose up -d --build backend worker` ONCE after this commit; then `docker compose exec -T backend python -c "from app.services.unpack_audit_service import run; print('ok')"`
- [ ] **Rule #17 live canary**: invoke `run(uuid.UUID('6f8f9cc2-e05f-45b3-9a02-8af47f7c9b96'))` against the existing RespArray firmware row → expect 3 findings created (F1 + F2 + F3)

### Commit 4 — Frontend

- [ ] Edit `frontend/src/types/index.ts:184` — add `'unpack_audit'` to `FindingSource` union
- [ ] Edit `frontend/src/constants/statusConfig.ts:67` — add `unpack_audit: { icon: Lock, label: 'Unpack Audit', className: 'border-cyan-500/50 text-cyan-600 dark:text-cyan-400' }` (Lock icon = "discovered crypto material at extraction"; cyan unused per existing entries)
- [ ] Edit `frontend/src/components/findings/FindingsList.tsx:122` — add `'unpack_audit'` to the hardcoded chip array
- [ ] **Rule #24 verification**: canary `frontend/src/__canary.ts` with deliberate type error, expect `npx tsc -b --force` failure; remove canary; expect pass
- [ ] **Rule #26 rebuild**: `docker compose up -d --build frontend` (NOT `restart`)

### Backfill (one-shot, after C3 ships)

- [ ] Run snippet against existing firmware rows with populated `vendor_decryption`:
  ```python
  async with async_session_factory() as db:
      rows = (await db.execute(select(Firmware.id).where(
          Firmware.device_metadata["vendor_decryption"].isnot(None)
      ))).scalars().all()
  for fw_id in rows:
      await unpack_audit_service.run(fw_id)
  ```
- [ ] Per Rule #19 (evidence-first): currently 1 row qualifies (RespArray fw `6f8f9cc2-e05f-45b3-9a02-8af47f7c9b96`) → expect 3 findings emitted. Do NOT write a "general backfill utility"; document the snippet in the C3 commit message.

## Cross-step risks (analysed during planning)

1. **Pre-existing source-tag drift OUT OF SCOPE.** DB CHECK has 8 values (`attack_surface, hardware_firmware_graph, cwe_checker, uefi_scan, clamav_scan, vt_scan, fuzzing_scan, fuzzing`) NOT in frontend `FindingSource` union; frontend has `ai_discovered, known_good_scan` NOT in DB CHECK. Existing `?? FINDING_SOURCE_CONFIG.manual` fallback at `FindingDetail.tsx:93` masks the drift. Adding `unpack_audit` to BOTH sides keeps the new tag drift-free; do not attempt to reconcile pre-existing drift in this campaign.

2. **`extraction_diagnostics` is upload-time only.** Written by `firmware_service.py:641-667` BEFORE unpack runs; never rewritten post-decrypt. On a fully-decrypted RespArray, `encrypted_archives` still lists 6 entries even though all 6 succeeded. Service MUST compute `encrypted_count - decrypted_count` as the undecrypted indicator, NOT non-emptiness. Failure to apply this discipline emits a false "key not recovered" finding for every successful EDAN-class firmware. Captured in test `test_emits_three_findings_for_clean_decrypt`.

3. **Source-tag exclusivity.** The service's DELETE-then-REPOPULATE will clobber any other writer of `source='unpack_audit'`. Mitigation: comment in service file documenting exclusive ownership; consider future harness rule `auto-unpack-audit-source-exclusive` flagging non-service writes.

## Open questions (deferred)

- Should unpack_audit also auto-fire CVE matching on the now-decrypted nxapp/nxcore binaries? — out of scope; future intake
- Should F1 carry `component_id` linking to an SBOM "EDAN update bundle" component? — SBOM has no such shape today; ship without
- Should AES key be redacted in evidence? — key is on disk in plaintext anyway; redaction is theatrical; ship full key, add `--redact-keys` to `export_service` if compliance demands later
- Source tag `unpack_audit` vs `vendor_keys`? — `unpack_audit` chosen to cover any unpack-time finding (signed archives, partial extraction, future discoveries), not only vendor keys

## Recovered evidence (live data for testing)

- **EDAN container magic** (16 bytes, offset 0): `a3 df bb bf 4e 94 7c 66 49 85 9f 5e 45 d2 73 ed`
- **AES key triple** (matches `_OPENSSL_AES_CBC_RE` at `unpack_common.py:811`):
  - algorithm: `aes-128-cbc`
  - key: `43c8e032ff65f5cc762d1dc15580d425`
  - iv: `50719d498aa89db2d3fccac9ff310c79`
  - source: `RespArray_1.05.00.17.zip_extract/target/zImage-restore.tar.xz_extract/.../usr/sbin/force_update.sh:755`
- **Audit trail in DB**: `firmware.device_metadata["vendor_decryption"]` for fw `6f8f9cc2-e05f-45b3-9a02-8af47f7c9b96` already contains 6 entries (one per decrypted archive: rootfs_partition / boot_partition / scripts / libqt / nxapp-0.2.2-Linux / nxcore-0.2.2-Linux), all citing the same triple. After C3 lands, backfill emits 3 findings for this row.
- **Walkthrough**: full pipeline deep-dive at `~/edan-mpm-resparray-unpack-walkthrough.md` (19.5 KB)

## References

- Architectural template: `backend/app/workers/unpack.py:73-119` (`_run_hardware_firmware_detection_safe`)
- Source-of-truth post-commit spawn: `backend/app/workers/arq_worker.py:151-156`
- Existing CHECK constraint migration: `backend/alembic/versions/54c8864fbe0c_add_enum_check_constraints.py:41-89`
- Test fixture pattern: `backend/tests/test_vendor_aes_decrypt.py:45-80` (`_write_update_script`, `_write_encrypted_tarxz`)
- Background-task shape (Rule #33): `backend/app/services/firmware_paths.py` (`populate_detection_roots`)
- Closest finding-creation cousin: `backend/app/services/assessment_service.py:260-272` (`_create_finding` via `FindingCreate` + `FindingService.create`)
