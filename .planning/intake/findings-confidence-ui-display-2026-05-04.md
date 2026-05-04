---
title: "Findings UI: surface Finding.confidence in FindingsList + FindingDetail"
status: pending
priority: medium
target: frontend/src/components/findings/FindingsList.tsx + frontend/src/components/findings/FindingDetail.tsx + frontend/src/constants/statusConfig.ts (new CONFIDENCE_CONFIG)
---

## Description

`Finding.confidence` (Confidence enum: `low | medium | high`) is persisted in the DB (`findings.confidence`), returned by the API (verified 2026-05-04 against firmware `6f8f9cc2-…` — all 4 unpack_audit findings have `confidence=high`), and present in the TypeScript type at `frontend/src/types/index.ts:199` (`confidence: Confidence | null`). It is NOT rendered anywhere in the UI.

Operators viewing unpack_audit findings see severity (high/medium/medium/info) and source (Unpack Audit chip) but cannot distinguish a `confidence=high` cryptographic-magic-gate-verified finding from a `confidence=low` heuristic guess. This was the entire point of commit `7dc21fe`'s `FindingService.create()` confidence-drop fix — the field is now load-bearing.

Discovered during the unpack-audit-findings UI verification sub-session (2026-05-04, this session). Companion to the unpack-audit-findings intake (already shipped commits `877f83e..057ea67`).

## Acceptance Criteria

- [ ] New `CONFIDENCE_CONFIG: Record<Confidence, {label: string; className: string}>` in `frontend/src/constants/statusConfig.ts` — exhaustive per Rule #9, with `?? fallback` at lookup sites for `null` confidence.
- [ ] `FindingDetail.tsx` header row shows a confidence badge between severity badge and source badge: `Badge variant="outline"` styled by `CONFIDENCE_CONFIG[finding.confidence ?? 'medium']`. Hidden when `finding.confidence == null`.
- [ ] `FindingsList.tsx` row line 1 shows confidence as a small text suffix after status badge — only rendered when non-null. Examples (visual): `[Hardcoded AES key]  [Open]  [Unpack Audit]  conf=high`.
- [ ] No backend changes. Pure frontend.
- [ ] Rule #24 typecheck canary; Rule #26 frontend rebuild (`docker compose up -d --build frontend`).
- [ ] Smoke: load `/projects/00815038-cb0f-4642-b2bf-2f176fd807f7/findings?firmware_id=6f8f9cc2-…` and confirm 4 unpack_audit rows show `conf=high` in the list.

## Out of Scope

- Filter chip for confidence (not requested; can be a follow-up if operators ask).
- Backend changes — `confidence` is already in the API response.
- Changes to other scanners that don't yet emit confidence (graceful fallback covers them).

## Cross-step

Single-commit sub-task per Rule #25 (one frontend layer, one logical change). Single commit `feat(findings-ui): show confidence badge in FindingDetail + list`. Rebuild once at end.
