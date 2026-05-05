---
title: "Frontend Rule #34b sweep — 3 browser-issued URL helpers missing appendApiKey()"
status: pending
priority: critical
target: frontend/src/api/hardwareFirmware.ts + frontend/src/api/emulation.ts
---

## Description

Three URL helpers return URLs that are consumed by the BROWSER (not axios) and bypass the `X-API-Key` header interceptor. All three return 401 under default API-key auth. This is the same shape as the 2026-04-30 fix (session b266f17e) on `getDocumentDownloadUrl` / `getFileDownloadUrl` — these three helpers were missed in that sweep.

**Evidence (3 sites):**
1. `frontend/src/api/hardwareFirmware.ts:231` — `buildBlobDownloadUrl` returns a URL consumed by `<a href download>` in `BlobDetail.tsx:96`. Hardware firmware blob downloads → 401.
2. `frontend/src/api/emulation.ts:294` (`getPcapDownloadUrl`) → consumed by `NetworkTrafficPanel.tsx:199` `<a href download>`. PCAP exports → 401.
3. `frontend/src/api/emulation.ts:201` (`buildSystemEmulationTerminalURL`) → consumed by terminal WebSocket. System-emulation terminal → connection rejected.

**Cross-stream confirmation:** Stream B (F-B-01), Stream E (F-E-01/F-E-02), Stream F (F-F-01/F-F-02/F-F-23). All three streams independently identified the same set.

**Rule #34b** — generalised rule: any URL passed into `<a href download>`, `<img src>`, `window.open()`, or `window.location.href = …` must wrap with `appendApiKey()`. The `X-API-Key` header path applies to fetch/axios only.

## Acceptance Criteria

- [ ] All 3 helpers return URLs wrapped with `appendApiKey()` from `frontend/src/api/client.ts` (already exported). One-line change per helper.
- [ ] Mechanical detection grep returns ZERO additional sites: `grep -RIn "href=\{[^}]*[Dd]ownload\|window\.open\|window\.location\.href\s*=" frontend/src/ | grep -v "appendApiKey"`.
- [ ] Pytest mock OR Playwright smoke: load `BlobDetail` for a real hardware-firmware blob, click download, assert 200 + Content-Disposition.
- [ ] Frontend rebuild per Rule #26: `docker compose up -d --build frontend`.

## Out of Scope

- Migrating from query-param auth to short-lived signed URL tokens (architecturally cleaner but out of band for this fix; query-param leak into uvicorn access logs is the same tradeoff already accepted for WebSocket terminal/emulation paths and is documented in `frontend/src/api/client.ts:25`).

## Cross-step

Single commit `fix(frontend): wrap 3 browser-issued URL helpers in appendApiKey (Rule #34b)`. Frontend rebuild gate.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery files: `.planning/discoveries/audit-stream-{b,e,f}-2026-05-04.md`.
