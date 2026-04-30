---
title: "Frontend: Sweep Bare e.message Error Display Sites to extractErrorMessage"
status: proposed
priority: medium
target: frontend/src/components/, frontend/src/pages/, frontend/src/stores/
discovered_in: session bdaf9d20 (2026-04-26) — firmware upload 409 surfacing as "Request failed with status code 409" in UI instead of FastAPI detail
related_to: frontend-api-client-hardening.md (completed 2026-04-21) — established the axios+detail-aware error contract
---

## Problem

11 frontend `try/catch` sites render error messages via the bare pattern:

```typescript
err instanceof Error ? err.message : 'Fallback message'
```

For axios errors, `err.message` is *"Request failed with status code N"* — the framework default — which clobbers the FastAPI `detail` text the backend deliberately raises. Users see a generic "Request failed with status code 409" or "Scan failed" instead of the actionable message ("This firmware is already in the project (id=…)" or "APK not found at /path/to/app.apk").

`frontend/src/utils/error.ts` already exports `extractErrorMessage(err, fallback)` which checks `err.response.data.detail` first (FastAPI shape) before falling back to `err.message`. The function is in use at several call sites already (e.g., `projectStore.ts:5`); the remaining 11 sites pre-date the helper or were missed during the `frontend-api-client-hardening` sweep.

## Origin

Session bdaf9d20 (2026-04-26) shipped a backend `409` for duplicate firmware upload (commit `<TBD-backend-409>` `firmware_service.py`) plus a single frontend conversion at `FirmwareUpload.tsx:52` (commit `<TBD-frontend-firmware-upload>`). The user's surface symptom on retry — *"Request failed with status code 409"* in the upload card — exposed the pattern across the codebase.

## Scope (11 sites, by severity)

| # | File:Line | User Action | Endpoint | 4xx Cases the Backend Raises | Severity |
|---|---|---|---|---|---|
| 1 | `components/apk-scan/ApkScanTab.tsx:281` | Click "Run Manifest" scan | `POST /projects/{id}/firmware/{fwid}/apk-scan/manifest` | 400 firmware not extracted · 404 APK/firmware not found | **HIGH** |
| 2 | `components/apk-scan/ApkScanTab.tsx:304` | Click "Run Bytecode" scan | `POST /projects/{id}/firmware/{fwid}/apk-scan/bytecode` | 400 firmware not extracted · 404 APK not found | **HIGH** |
| 3 | `components/apk-scan/ApkScanTab.tsx:329` | Click "Run SAST" scan | `POST /projects/{id}/firmware/{fwid}/apk-scan/sast` | 400 firmware not extracted · 404 APK not found | **HIGH** |
| 4 | `components/projects/DocumentsCard.tsx:73` | Upload document | `POST /projects/{id}/documents` | 400 file validation · 404 project not found | MEDIUM |
| 5 | `components/emulation/NetworkTrafficPanel.tsx:74` | Trigger network analysis | `GET /projects/{id}/emulation/system/{sid}/network-analysis` | 400 invalid state · 404 session/pcap not found | MEDIUM |
| 6 | `components/emulation/NetworkTrafficPanel.tsx:80` | Capture traffic | `POST /projects/{id}/emulation/system/{sid}/capture` | 400 invalid params · 404 session not found | MEDIUM |
| 7 | `components/emulation/NetworkTrafficPanel.tsx:94` | Re-analyze existing PCAP | `GET /projects/{id}/emulation/system/{sid}/network-analysis` | Same as #5 | MEDIUM |
| 8 | `pages/ProjectDetailPage.tsx:193` | Upload rootfs to existing firmware | `POST /projects/{id}/firmware/{fwid}/upload-rootfs` | 404 firmware not found · 409 already has extracted FS · 400 validation | MEDIUM |
| 9 | `pages/SecurityToolsPage.tsx:165` | Run security tool | `POST /projects/{id}/tools/run` | 403 tool not whitelisted · 404 firmware not found | MEDIUM |
| 10 | `components/apk-scan/ApkScanTab.tsx:228` | Refresh APK discovery | `GET /projects/{id}/files/search?pattern=*.apk` | 404 path not found · 403 permission denied | MEDIUM |
| 11 | `stores/explorerStore.ts:158` | Click directory tree to load folder | `GET /projects/{id}/files?path=...` | 404 path not found · 403 forbidden | LOW |

**Already fixed in this session:** `components/projects/FirmwareUpload.tsx:52` (firmware upload). Use as the reference shape for the rest.

## Approach

Mechanical replacement at each site. Per CLAUDE.md Rule #22 (multi-file find/replace): grep all sites first → typecheck every 1–2 edits → run acceptance grep at end.

### Reference shape (from FirmwareUpload.tsx fix)

```typescript
// Before
} catch (e) {
  setErrorMsg(e instanceof Error ? e.message : 'Upload failed')
}

// After
import { extractErrorMessage } from '@/utils/error'
// ...
} catch (e) {
  setErrorMsg(extractErrorMessage(e, 'Upload failed'))
}
```

Per Rule #25, ship one commit per file (8 unique files: ApkScanTab handles 4 sites in one commit; NetworkTrafficPanel handles 3 in one commit; the other 6 are 1-per-file). Final commit count: ~6.

### Files

- `components/apk-scan/ApkScanTab.tsx` (sites 1, 2, 3, 10 — 4 catches in one file)
- `components/projects/DocumentsCard.tsx` (site 4)
- `components/emulation/NetworkTrafficPanel.tsx` (sites 5, 6, 7 — 3 catches in one file)
- `pages/ProjectDetailPage.tsx` (site 8)
- `pages/SecurityToolsPage.tsx` (site 9)
- `stores/explorerStore.ts` (site 11)

### Order suggestion (by severity + isolation)

1. **HIGH** ApkScanTab (4 catches) — biggest user-visible win; one file.
2. **MEDIUM** ProjectDetailPage rootfs upload — has its own 409 ("already has extracted FS") for which detail clarity matters.
3. **MEDIUM** NetworkTrafficPanel (3 catches) — emulation users hit these.
4. **MEDIUM** SecurityToolsPage, DocumentsCard — lower frequency.
5. **LOW** explorerStore — directory-load errors are often quietly retried; least urgent.

### Lint guard (optional, post-sweep)

Add an ESLint rule (or a lightweight `grep` post-build check) banning `instanceof Error\s*\?.*\.message` at *display sites* — e.g., a `// eslint-disable-next-line wairz/use-extract-error-message` comment is required to opt out. Prevents regression. Defer if eslint config burden is high; the acceptance grep below is the minimum viable enforcement.

## Acceptance Criteria

- [ ] **Width-canary baseline (Rule #31):** the narrow grep `grep -rEn "instanceof Error \\? .{1,40}\\.message" frontend/src/` AND the broad grep `grep -rEn "(\\b[a-z]+) instanceof Error \\?\\s*\\1\\.message" frontend/src/` both return the same site count. Establish baseline before edits, target zero residuals after edits.
- [ ] All sites listed in the table above use `extractErrorMessage(e, '<context-specific fallback>')`.
- [ ] `grep -rn "extractErrorMessage" frontend/src/components/ frontend/src/pages/ frontend/src/stores/` has 11+ hits (1 per migrated site, plus pre-existing usages).
- [ ] `cd frontend && npx tsc -b --force` is green; Rule #17 canary done once per session.
- [ ] Manual smoke at one site per severity bucket: trigger a 4xx and confirm the FastAPI `detail` is rendered (not "Request failed with status code N"). HIGH bucket: try APK scan against firmware that isn't extracted yet → expect "Firmware not yet extracted" or similar. MEDIUM bucket: try uploading a rootfs to a firmware that already has one → expect 409 with detail. LOW bucket: try loading a non-existent directory path → expect 404 with detail.
- [ ] `docker compose up -d --build frontend` ran (Rule #26 — restart won't pick up the new bundle).

## Risks

- **Pure UX change, no protocol change.** No backend impact. No DB migration. Bisect-clean per Rule #25 if shipped one-file-per-commit.
- **Easy to miss new sites added between intake and execution.** Re-run the width-canary grep at execution time — Rule #28 says intake counts drift +14-22% over time; be prepared for the 11 to grow.
- **Fallback messages must remain context-specific.** Don't replace `'Manifest scan failed'` with a generic `'An error occurred'`. The fallback only fires when the response shape is unrecognised; preserve the user-meaningful default.

## References

- Reference fix: `frontend/src/components/projects/FirmwareUpload.tsx` (this session's commit `<TBD>`)
- Helper definition: `frontend/src/utils/error.ts:1` `extractErrorMessage(err, fallback = "An error occurred"): string`
- CLAUDE.md Rule #22 (multi-file find/replace discipline)
- CLAUDE.md Rule #25 (per-sub-task commits — ship 6 commits, one per file)
- CLAUDE.md Rule #26 (frontend image rebuild after `frontend/src/` changes)
- CLAUDE.md Rule #31 (broader-grep width canary on scope counts)
- Original auth-aware error pattern: `frontend-api-client-hardening.md` (completed 2026-04-21) established the axios contract this sweep extends.
