---
title: "APK Scan Deep Linking — Fix Required"
status: completed
priority: medium
created: 2026-04-15
completed: 2026-04-19
completed_in: wave3-stream-gamma verify-only (Rule-19 close-out)
---

# APK Scan Deep Linking — Fix Required

**Priority:** Medium
**Status:** completed
**Created:** 2026-04-15
**Completed:** 2026-04-19
**Completed In:** wave3-stream-gamma verify-only (Rule-19 close-out)

> **Status note 2026-04-21 (Rule-19 audit):** Added YAML frontmatter so the intake
> scanner (`^status:` regex) picks up the already-shipped state. Content was closed
> out in session 198243b8 (commit `e1f94c3`). No code change this session.

## Verification (wave3-stream-gamma)

Confirmed wired end-to-end:
- `frontend/src/components/findings/FindingDetail.tsx:73-75` — emits `tab=apk-scan&apk=<path>&finding=<rule>&line=<n>` URL from Findings page.
- `frontend/src/pages/SecurityScanPage.tsx:40-42` — reads URL params and passes `initialApk`, `initialFinding` into `<ApkScanTab>`.
- `frontend/src/components/apk-scan/ApkScanTab.tsx:101-106, 219-220, 386-393` — `initialApkHandled` ref guards one-shot `setSelectedApk(initialApk)` + `loadCachedResults(initialApk)` via `setTimeout(0)` so React has committed the state before the cache fetch.
- `frontend/src/components/apk-scan/SecurityScanResults.tsx:377-398` — `deepLinkHandled` ref guards one-shot finding match (by `title` OR `ruleId`), auto-expands the finding's group + the finding itself, then `scrollIntoView({ behavior: 'smooth', block: 'center' })`.

All 4 "What Deep Linking Should Do" bullets met. No code change this session.

## Current State

When clicking an APK finding's file path in the Findings page, it navigates to
`/security?tab=apk-scan&apk=<path>`. The APK Scan tab opens and results load
from cache, but several things don't work:

1. **APK selector shows wrong APK** — The display card shows the first APK
   (BuildManifest.apk) instead of the deep-linked one, even though results
   load for the correct APK.

2. **Finding not expanded** — The user expects to see the specific finding
   they clicked on, expanded with details visible. Currently all findings
   are collapsed.

3. **No scroll to finding** — Even if expanded, it doesn't scroll to the
   specific finding that was clicked.

4. **Stale persisted data** — Findings persisted before fixes still have
   temp paths in evidence (`/tmp/mobsfscan_xxx/sources/...`). Need force
   rescan or migration to clean up.

## What Deep Linking Should Do

1. Parse URL params: `tab=apk-scan&apk=<path>&finding=<rule_id>&line=<n>`
2. Switch to APK Scan tab
3. Set selectedApk to the APK from params (ensure selector visual matches)
4. Load cached results for that APK
5. Find the matching finding by rule_id
6. Expand that finding's group and the finding itself
7. Scroll to it

## Root Cause

The current implementation was built incrementally (8+ patches) instead of
designed holistically. The APK selector, results loading, and finding
expansion all happen in separate effects with race conditions between them.

## Suggested Approach

- Pass all deep-link params as props to ApkScanTab
- Handle them in a single coordinated effect after discovery completes
- Use refs to track "initial load complete" state
- Set selectedApk, load results, expand finding, and scroll in sequence
