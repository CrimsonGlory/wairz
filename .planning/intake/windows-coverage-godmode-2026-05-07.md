---
intake_id: windows-coverage-godmode-2026-05-07
title: Windows ecosystem god-mode coverage — multi-phase campaign
status: approved-for-execution
opened: 2026-05-07
campaign_branches:
  - feat/windows-phase-alpha-2026-05-07  # archive extraction (in progress)
  - feat/windows-phase-beta-2026-05-08    # authenticode + RICH + DBX + ARM-arch
  - feat/windows-phase-gamma-2026-05-09   # registry + drivers + persistence
  - feat/windows-phase-delta-2026-05-10   # .NET + update-diff + storage
research_artifacts:
  recon: in-conversation Phase 0 Explore agent output
  personas:
    - persona-A-formats-cartographer
    - persona-B-oss-tooling-survey
    - persona-C-re-workflow-architect
    - persona-D-wairz-platform-integrator
    - persona-E-adversary-completionist
---

# Wairz Windows-Ecosystem God-Mode Coverage — Campaign PRD

## Goal

Wairz reaches god-mode coverage of the Windows binary/archive/image/system-image format universe. Anything a security RE-er or update analyst would expect of a serious Windows-RE platform: CAB / MSI / MSIX / MSU / Authenticode / registry / driver / .NET / VHDX / NTFS / BCD / ESEDB / PSF deltas / ARM64EC-X / CBS-CSI-MUM / DBX revocation / R2R-stomping / dual-signed PE / Catalog signing chain / Driver signing tier (WHQL vs attestation vs cross-signed) / single-file .NET bundles / capa-on-IL.

## Pre-existing baseline (do not re-build)

WIM (`unpack_wim.py`, wimlib-imagex, 1hr Rule #33 timeout), Windows Installer ISO (`unpack_windows_installer_iso.py`, recursive WIM extraction, 3-tier ranking), ESD (transparent via wimlib), ISO 9660 (`unpack_iso9660.py`, 7z), PE introspection (LIEF + pefile + radare2 + Ghidra + Qiling). 21 MCP tool categories / 172 tools. JSONB normalizers per Rule #35c discipline. 202+polling per Rule #29/#33.

## Out of scope (explicit non-goals for this campaign)

- Memory dump triage / Volatility integration (separate future campaign)
- Live-system forensic formats: EVTX / EVT / ETL / Prefetch / hibernate.sys decompression
- BitLocker FVEK extraction (key recovery)
- EFS DDF/DRF cert-key matching
- Surface / Xbox / IoT-Core encrypted firmware (vendor-key-gated; detection only)
- Shim engine `.sdb` parsing
- NTFS write-mount or read-write FUSE
- dnSpy GUI integration
- Fully-AOT'd .NET (truly opaque without symbols)

## Decision log (D1–D9, all defaulted to recommended unless redirected by user)

- **D1 PSF support gated `ARG INCLUDE_PSF=1`:** YES (license-unclear PSFExtractor isolated to side-container)
- **D2 dotnet-runtime in worker gated `ARG INCLUDE_DOTNET=1`:** YES (+200 MB worker only)
- **D3 Hub-first UX (`WindowsHubPage` default landing):** YES (with sibling routes for direct-link)
- **D4 Findings sources extend enum (no new pe_finding subtable):** YES (CHECK + Pydantic Literal gate)
- **D5 Memory dump / Volatility scope:** NO (separate campaign)
- **D6 Forensic-on-running-system formats (EVTX/ETL/PF):** NO (Phase ε)
- **D7 CLAUDE.md Rule #36 (no-execute discipline) + Rule #37 (offline-trust-anchor discipline):** YES (added end of Phase β)
- **D8 Rule #23 worktree-per-phase discipline:** YES (single-stream branch per phase)
- **D9 Auto-chain phases via citadel:daemon:** YES (overnight execution authorized)

## 4-Phase rollout

### Phase α — archive extraction (THIS BRANCH: feat/windows-phase-alpha-2026-05-07)

**Acceptance:** Wairz extracts any Windows archive into the firmware tree end-to-end. CAB / MSI / MSIX / MSU / PSF / VHDX / DriverPackage all detected, routed, unpacked. Sub-tasks (~10 commits per Rule #25):

1. Migration: `firmware.device_metadata['windows_artifacts']` schema-versioned normalizer + tests
2. Worker: `unpack_cab.py` + test + tiny.cab fixture
3. Worker: `unpack_msi.py` + test + tiny.msi fixture
4. Worker: `unpack_msix.py` + test + tiny.msix fixture
5. Worker: `unpack_psf.py` + test + tiny.psf fixture (+ `ARG INCLUDE_PSF=1` Dockerfile gate)
6. Worker: `unpack_msu.py` (composes 2+5) + test
7. Worker: `unpack_driver_package.py` + test
8. Worker: `unpack_vhdx.py` + test (with NTFS reparse-walk hardening per E#29)
9. Detection: 7 new `DetectedFormat` + capability + STRATEGIES + `classify_firmware()`
10. MCP: `windows_archive.py` (8 tools) + `__init__.py` wire-in
11. Frontend: `WindowsHubPage.tsx` + `WindowsArchivePage.tsx`
12. Cut-over: Rule #8 backend+worker rebuild + Rule #11 import smoke + Rule #35b live canary on real Win11 23H2 ISO + KB MSU

### Phase β — Authenticode + ARM-arch (feat/windows-phase-beta-2026-05-08)

**Acceptance:** Every PE in any uploaded firmware has its Authenticode chain validated against bundled offline MS roots + DBX cross-reference + ARM64EC/X dual-view detection.

1. Migration: `windows_pe_signatures` table (per-blob FK, indexed on signer thumbprint for DBX cross-ref)
2. Migration: `firmware.authenticode_chain_*` 5-column 202+poll status set per Rule #33 contract
3. Background runner `_run_authenticode_chain_background` (asyncio.create_task — pure-Python, in-process)
4. MCP: `windows_pe_signature.py` (6 tools incl. `verify_authenticode`, `decode_rich_header`, `scan_dbx_revocation`, `detect_pe_arch_view`)
5. Bundle MS roots + dbx into worker image + quarterly cron `scripts/refresh-ms-roots.sh`
6. Frontend: `PeHardeningPage.tsx` + `AuthenticodeDetailPage.tsx`
7. Findings extension: source = `windows_authenticode`, `windows_dbx_revoked`
8. CLAUDE.md Rule #36 (no-execute) + Rule #37 (offline-trust-anchor)
9. Cut-over

### Phase γ — registry + drivers + persistence (feat/windows-phase-gamma-2026-05-09)

**Acceptance:** Registry hives auto-walked on unpack; driver matrix populated with class GUID + PnP IDs + signing tier + capability badges.

1. Migration: `windows_registry_extracts` + `windows_drivers` tables
2. Migration: `firmware.registry_hive_walk_*` 5-column status set
3. Worker: registry hive auto-walk on unpack (regipy)
4. Worker: driver INF/CAT auto-extract on unpack
5. MCP: `windows_registry.py` (7 tools) + `windows_driver.py` (6 tools)
6. Frontend: `RegistryHivePage` + `RegistryDiffPage` + `DriverMatrixPage` + `DriverDetailPage`
7. Findings extension: `windows_registry_persistence`, `windows_inf`, `windows_driver_imports`
8. WHQL/attestation-signed/cross-signed driver tier classification (Persona E #13)
9. Cut-over

### Phase δ — .NET + update-diff + storage (feat/windows-phase-delta-2026-05-10)

**Acceptance:** .NET single-file bundles extracted + decompiled; KB-vs-KB update diff computes per-DLL changeset; VHDX/BCD/ESEDB inspectable.

1. Migration: `windows_update_packages` table
2. Migrations: `dotnet_decompile_*`, `windows_update_diff_*` 5-column status sets
3. Worker: arq job `decompile_dotnet_bundle_job` + Dockerfile delta `dotnet-runtime-8.0` + `ilspycmd` (gated `ARG INCLUDE_DOTNET=1`)
4. Background runner: `_run_windows_update_diff_background` (asyncio.create_task — DB-persisted incremental work)
5. R2R-stomping detection (Persona E #5 — single highest-impact differentiator)
6. MCP: `windows_update.py` (5 tools) + `windows_storage.py` (5 tools) + `windows_dotnet.py` (6 tools)
7. Frontend: `UpdateDiffPage` + `DotNetBrowserPage`
8. Findings extension: `windows_il_capa`, `windows_r2r_stomp`
9. Cut-over

## Quality rule deltas (durable)

- New harness `qualityRules.custom`:
  - `auto-windows-pe-without-authenticode-chain-stamp` (Phase β)
  - `auto-windows-dotnet-runtime-not-in-backend-image` (Phase δ)
  - `auto-msi-custom-action-execute-forbidden` (Phase α)
- Existing `auto-review-no-raw-join-in-sandbox` filePattern extended to `app/workers/unpack_*.py`
- New mex patterns:
  - `.mex/patterns/add-windows-format-handler.md`
  - `.mex/patterns/add-202-polling-windows-op.md`
- New CLAUDE.md rules (added at end of Phase β):
  - Rule #36 — No-execute discipline for installer custom actions
  - Rule #37 — Offline-trust-anchor discipline for cert roots / DBX

## Tooling stack — apt + pip deltas

```
apt-get install -y \
  msitools libregf-utils libesedb-utils libpff-utils \
  libfsntfs-utils libvhdi-utils libfwsi-utils libscca-utils \
  hivex libhivex0 libhivex-bin uefitool-cli qemu-utils 7zip llvm \
  python3-libregf python3-libesedb python3-libpff \
  python3-libfsntfs python3-libvhdi python3-libfwsi python3-libscca

pyproject.toml:
  regipy>=4.0,<5
  python-evtx>=0.8.1
  signify>=0.7
  asn1crypto>=1.5
  flare-capa>=9.4
  dnfile>=0.18
  dncil>=1.0
  LnkParse3>=1.5
  uefi-firmware>=1.12

Gated (ARG INCLUDE_DOTNET=1, worker only):
  dotnet-runtime-8.0
  ilspycmd (via dotnet tool install)

Gated (ARG INCLUDE_PSF=1, side-container):
  psfextract (Secant1006 — license-unclear, isolated)
```

## Test fixture sourcing

`backend/tests/fixtures/windows/` — small ≤200 KB synthesised samples:
- `tiny.cab` — 4-file CAB built with `cabextract` reference
- `tiny.msi` — minimal Wix-compiled MSI with one custom-action stub
- `tiny.msix` — minimal AppxManifest + 1 PE
- `tiny.msu` — CAB-of-CAB
- `tiny.psf` — synthesised via psfextract reference
- `tiny.vhdx` — `qemu-img create -f vhdx test.vhdx 1M; mkfs.ntfs -F`
- `tiny.sys` + `tiny.inf` + `tiny.cat` — driver-package smoke

## Live canaries (Rule #35b, per phase)

- Phase α: real Win11 23H2 ISO + KB cumulative MSU + signed driver CAB
- Phase β: dual-signed PE (SHA-1 + SHA-256) + signed driver `.cat` + DBX-revoked PE certificate
- Phase γ: SOFTWARE.hive from real install + registry diff between two firmwares
- Phase δ: .NET 8 single-file bundle + R2R PE + KB-vs-KB diff

## References

- Persona briefs (in conversation transcript)
- CLAUDE.md Rules #1, #6, #8, #11, #16, #19, #20, #21, #22, #23, #25, #27, #29, #33, #34, #35
- `.mex/patterns/INDEX.md` precedent recipes
- `.claude/harness.json` quality rules

## Status

- ✅ Phase 0 (recon) complete
- ✅ Phase 1 (5-persona research fleet) complete
- ✅ Phase 2 (synthesis) complete
- ✅ Phase 3 (user review) approved 2026-05-07
- ✅ Phase α (archive extraction) — **12 commits shipped** on `feat/windows-phase-alpha-2026-05-07`; α.6 cut-over rebuild verified; 235 mock tests + 2/3 live canaries pass post-rebuild
- 🟡 Phase β (Authenticode + RICH + DBX + ARM64EC/X) — IN PROGRESS
- ⬜ Phase γ / δ — pending phase-β completion
- ⬜ Phase ε (forensic formats) — deferred to separate campaign

### Phase α shipped commits (chronological)

| # | SHA | Subject | Tests |
|---|---|---|---|
| α.1 | d174a62 | JSONB normalizer for `device_metadata['windows_artifacts']` (sub-key + Rule #35c) | 12 normalizer tests |
| α.2.1 | e21545a | `unpack_cab` worker (cabextract foundation) | 6 + 1 skipped (gcab) |
| α.2.2 | 508feca | `unpack_msi` worker (msitools msiextract) | 8 + 1 skipped (msitools) |
| α.2.3 | 320f4ea | `unpack_msix` worker (7z + AppxManifest gate) | 10 (incl. live canary) |
| α.2.4 | 8086c32 | `unpack_msu` worker (CAB-of-CABs + PSF detect) | 8 + 1 skipped (gcab) |
| α.2.5 | c7d2854 | `unpack_psf` stub (magic + gating) | 7 |
| α.2.6 | 8516fa2 | `unpack_driver_package` worker (CAB + INF/SYS/CAT subtype) | 7 |
| α.2.7 | b9d124d | `unpack_vhdx` worker (qemu-img → raw NTFS) | 7 |
| α.3 | 49e5b6b | Detection seam — 7 enum + EXTRACTION_CAPABILITY + STRATEGIES | 28 detection tests |
| α.4 | 5632600 | MCP `windows_archive` category — 6 tools (172 → 178) | 20 tool tests |
| α.5 | 27e9ada | Frontend `WindowsHubPage` skeleton + route | typecheck clean |
| α.6 | eaf94d2 | Dockerfile delta (msitools / gcab / qemu-utils) + cut-over verified | 235 tests + 2 live canaries activate (CAB + MSU-of-CAB) |

**Test counts:** 235 tests pass (vs 213 pre-α.6); 2 live canaries activated post-rebuild (cab + msu via gcab); 1 skipped (msi canary needs `tiny.msi` fixture — Phase β refinement). Total tool registry: 178 tools (was 172). Rule #11 import smoke: ALL GREEN against rebuilt image.

**Architectural patterns established:**
- Worker shape: two-phase subprocess (validate-probe → extract), defensive FileNotFoundError + TimeoutError + non-zero-exit handling, `run_in_executor` for blocking I/O, success-with-no-rootfs fallback.
- Tool-category shape: `register_<category>_tools(registry)` + handlers using `context.resolve_path()` per Rule #1, 30 KB output cap per Rule #29.
- Rule #25 per-sub-task commits: 11 commits, each independently revertable.
- Rule #21 mirror discipline: every `DetectedFormat` entry mirrored in `EXTRACTION_CAPABILITY` AND `STRATEGIES`.
- Rule #35c JSONB normalizer + stamp + schema_version.
- Custom-action discipline (Rule #36 candidate): MSI custom actions extracted as data only, never executed. Tested via forbidden-token scan in `unpack_msi`'s test.
- Offline trust anchor (Rule #37 candidate): no cert chain fetching at scan time; bundle MS roots + DBX at image build (Phase β work).
