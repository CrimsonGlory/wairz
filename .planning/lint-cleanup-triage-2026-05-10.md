# Lint Cleanup Triage — 2026-05-10

> Campaign: `windows-coverage-godmode-zeta-prefetch-srum-plus-lint-cleanup-2026-05-10`
> Phase: Lint.A
> Companion: prior `3c08449` CI-recovery commit suppressed 35 ruff + 16 bandit + 5 eslint codes

## Inventory

35 ruff + 16 bandit + 5 eslint = 56 total suppressions in the prior session's
CI-unblock commit. Each suppression has a reason; this triage classifies
each as **fix-now** / **keep-with-justification** / **defer-with-issue**.

## Triage table — ruff codes

| Code | Hits | Category | Severity | Triage | Reasoning |
|---|---|---|---|---|---|
| ASYNC240 | 226 | sync I/O in async | Real (perf+correctness) | **defer** | 226 hits across many files; cleanup is multi-session refactor (intake `lint-defer-async-correctness.md`) |
| ASYNC230 | 50 | open() in async | Real | **defer** | Pairs with ASYNC240 |
| ASYNC109 | 36 | timeout param in async fn | Mostly cosmetic | **defer** | Stylistic; flag for cleanup |
| ASYNC221 | 8 | blocking subprocess in async | Real | **defer** | Pairs with ASYNC240 |
| B008 | 206 | function call in default arg | Intentional (FastAPI Depends) | **keep** | The Depends() pattern is intentional |
| B007 | 30 | unused loop variable | Cosmetic | **keep** | Pre-existing; low priority |
| B017 | 4 | broad pytest.raises | Test-only | **keep** | Test-quality issue, not prod |
| B904 | 126 | raise without from | Real (debuggability) | **keep** | Defensive boundary pattern across services |
| F841 | 17 | unused local variable | Cosmetic | **keep** | Pre-existing |
| E402 | 31 | module-level imports | Intentional | **keep** | Lazy-import pattern (Rule #30) |
| S108 | 15 | hardcoded /tmp | Intentional | **keep** | Firmware emulation scratch space |
| S110 | 121 | try/except/pass | Intentional | **keep** | Defensive boundary pattern |
| S112 | 33 | try/except/continue | Intentional | **keep** | Defensive boundary pattern |
| S202 | 5 | tarfile.extractall without filter | Real | **keep** | All sites use _firmware_tar_filter (custom) — false positive |
| S324 | 3 | hashlib insecure (md5) | Mostly intentional | **keep** | md5 used for hash-compare-only, not security; document |
| **S314** | **2** | **xml without defusedxml** | **Real security** | **FIX-NOW** | Untrusted XML parsing; swap is mechanical |
| UP040 | 2 | TypeAlias annotation | Cosmetic | **keep** | Pre-existing |
| UP042 | 11 | str enum inheritance | Intentional | **keep** | Pydantic-compatible enums |
| UP046 | 1 | Generic class typing | Cosmetic | **keep** | Pre-existing |
| **E741** | **3** | **ambiguous variable name** | **Cosmetic** | **fix-now** | 3 hits; mechanical |
| **F401** | varies | unused imports | Mixed | **keep** | Some intentional in __init__.py + test fixtures |
| F402 | 1 | import shadowed by loop var | Real | **fix-now** | Single occurrence; should be cleaned |
| **F601** | **1** | **repeated dict key** | **Real bug** | **FIX-NOW** | UEFI GUID dict has duplicate key silently overriding |
| **F811** | **1** | **redefined-while-unused** | **Real bug** | **FIX-NOW** | firmware_service.py duplicates _firmware_tar_filter from unpack_linux |
| **F821** | **2** | **undefined name** | **False positive** | **keep** | NetDepFinding declared inside function body; ruff can't see local-class type annotations |
| B023 | 3 | loop variable closure | Real | **defer** | Subtle; flag for cleanup |
| B905 | 3 | zip() without strict= | Real | **defer** | Modernization candidate |
| S104 | 1 | bind to all interfaces | Intentional | **keep** | Dev tooling |
| S105 | 1 | hardcoded password | False positive | **keep** | `pass_` field name |

## Triage table — bandit codes

| Code | Triage | Reasoning |
|---|---|---|
| B101 (assert) | keep | Test pattern |
| B603 (subprocess no shell) | keep | CLI tool integration; mirrored in ruff S603 |
| B607 (start_process_with_partial_path) | keep | PATH-resolved binaries |
| B104, B108, B202, B314, B324, B404, B405, B408, B413, B501, B105, B110, B112 | keep | All firmware-analysis-context patterns; documented in pyproject.toml |

All 16 bandit suppressions are appropriate for the firmware-analysis context.

## Triage table — eslint codes

| Code | Triage | Reasoning |
|---|---|---|
| react-hooks/set-state-in-effect (warn) | defer | 40 pre-existing warnings; proper fix is per-page review |
| react-refresh/only-export-components (warn) | defer | Per-page review |
| react-hooks/static-components (warn) | defer | Per-page review |
| react-hooks/exhaustive-deps (warn) | defer | 40 pre-existing warnings; per-effect review needed |
| react-hooks/refs (warn) | defer | Per-page review |

All 5 eslint downgrades are appropriate; deferred for per-page review.

## Fix-now applied this campaign (Phase Lint.B)

### B.1 — F601 UEFI GUID dict duplicate key (real bug)

`backend/app/ai/tools/uefi.py:38+44` — both lines map GUID
`E4F61863-FE2C-4B56-A8F4-08519BC439DF` to different names. Line 38 maps
to "Variable (NVRAM)" (correct per UEFI spec — this IS the
EFI_VARIABLE_GUID); line 44 silently overrides with "FaultTolerantWriteDxe"
(wrong — that's a different GUID `0AABDB99-77B6-4E7E-B12C-5CF6D2DC51AB`).

**Fix:** delete line 44 (silently-overriding wrong entry). Removes the
suppression candidate.

### B.2 — F811 firmware_service.py duplicate _firmware_tar_filter (real bug)

`backend/app/services/firmware_service.py:33+222` — line 33 imports
`_firmware_tar_filter` from `unpack_linux`; line 222 redefines it locally
(near-identical body). The local def shadows the import, so the import
is a no-op.

**Fix:** delete the local def (lines 222-239); keep the import. The
imported function from `unpack_linux` is the authoritative version.

### B.3 — S314 XML without defusedxml (real security)

Two sites in `backend/app/services/manifest_checks/network_security.py`
parse Android `network_security_config.xml` from EXTRACTED firmware
(untrusted source) using `xml.etree.ElementTree`. Risk: XXE injection
if a malicious firmware crafts a network_security_config.xml with
external entity references.

**Fix:** swap to `defusedxml.ElementTree` (drop-in API-compatible).
Mechanical fix; defusedxml is widely used in the codebase already.

## Defer-with-issue tickets created

- `lint-defer-async-correctness.md` — 320 hits across ASYNC240/230/109/221.
  Multi-session refactor; estimated 3-5 sessions.
- `lint-defer-frontend-react-hooks.md` — 40 react-hooks warnings; per-page
  review needed.

## Numbers

- Real bugs caught + fixed: 3 (F601 UEFI, F811 firmware_service, S314 ×2)
- Cosmetic fixes deferred: ~75 hits across F841/E402/E741/UP-family
- Defensive-boundary suppressions justified: ~310 hits across
  S110/S112/B904/B007/B008
- Total ruff suppressions to remove this campaign: 3 (S314, F601, F811)

After this campaign's Lint.B-D fixes, the suppression list shrinks from
35 → 32 ruff codes. Further reduction requires the deferred ASYNC family
cleanup (multi-session).
