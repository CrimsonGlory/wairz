---
title: "MCP find_apk + vulhunt._find_binaries ignore get_detection_roots() — APKs in scatter-zip siblings invisible (Rule #16)"
status: pending
priority: high
target: backend/app/ai/tools/{android,vulhunt}.py
---

## Description

Rule #16 mandates that filesystem walks of a Firmware extraction MUST use `get_detection_roots(firmware)` from `backend/app/services/firmware_paths.py`, not `firmware.extracted_path` alone. The latter only returns ONE rootfs the unpacker chose; scatter-zip uploads, multi-archive medical firmware, and nested unblob output produce sibling directories that `extracted_path` misses entirely.

**Two MCP tool handlers violate the rule:**
1. `backend/app/ai/tools/android.py::find_apk` — uses `firmware.extracted_path` directly. APKs in scatter-zip siblings (Android multi-partition uploads) are invisible to the Android scan tools.
2. `backend/app/ai/tools/vulhunt.py::_find_binaries` — same shape. Binary triage / CVE matching misses files outside the primary rootfs.

**Evidence:** Stream D (F-D-05).

**Original incident:** the DPCS10 Android bug (md1dsp.img invisible) and the RespArray ZIP (0 blobs before fix, 11+ after) — same root cause as Rule #16 but on the unpack-time detection side. The MCP tools ship the next-layer-up version of the same bug.

## Acceptance Criteria

- [ ] Both handlers replace `firmware.extracted_path` with `get_detection_roots(firmware)` and iterate over all returned roots.
- [ ] Tests: against a fixture firmware with 2+ detection roots (scatter-zip layout), assert `find_apk` returns APKs from BOTH roots and `_find_binaries` finds binaries in BOTH roots.
- [ ] Width-canary (Rule #31): `grep -rn 'firmware\.extracted_path' backend/app/ai/tools/ backend/app/services/` and audit each remaining hit. Per-binary flows (emulation/fuzzing/sandbox) may legitimately use `extracted_path` since they need a single binary path; filesystem walks must use the helper. Document each kept-as-is hit with an inline comment.
- [ ] Backend rebuild per Rule #8.

## Out of Scope

- Generalising `get_detection_roots()` to ALL filesystem-walking helpers across services (likely some additional sites to grep — but the audit specifically called out these 2 MCP tools as the high-impact ones).

## Cross-step

Single commit `fix(mcp): use get_detection_roots() in find_apk + vulhunt (Rule #16)`. Per Rule #25 split if the test addition is significant.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-d-mcp-2026-05-04.md` finding F-D-05.
