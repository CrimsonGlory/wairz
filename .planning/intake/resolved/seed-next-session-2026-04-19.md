---
title: "Next-session seed — post-DPCS10-overhaul continuation (deep-researched)"
status: option-a-completed
resolved_at: 2026-04-18
resolved_in: session 59045370 autopilot
resolution: |
  Option A fully processed. Commits on clean-history:
    10872d6 — A.1 bind backend + frontend to 127.0.0.1
    906cfe2 — A.1 follow-up: Postgres + FirmAE passwords via env vars
    e3053b6 — A.2 widen analysis_cache.operation VARCHAR(100→512)
    b9797da — A.3 null-tier CVE backfill (verified no-op, doc-only)
  DPCS10 canary intact: 260 blobs / 27 hw-firmware CVE / 439 kernel CVE.
  Options B (security sweep) and C (hardware firmware expansion) remain
  for a future session.
priority: high
format: ouroboros-seed-v1
author: session-53c9c5ff-handoff
created: 2026-04-18T22:06:00Z
enriched: 2026-04-18T22:45:00Z  # 3-scout research fleet
target_session: next
---

# Next-session seed (deep-researched)

> Read order for the incoming Citadel session:
>   1. `.planning/knowledge/handoff-2026-04-18-session-end.md` (context)
>   2. This file (proposed scope + scout findings)
>   3. User decides scope → `/do` or `/archon` or `/autopilot`

## ⚠ CRITICAL FINDING SURFACED BY SCOUT B

**The backend has an exploitable security gap right now.**

- `backend/app/middleware/auth.py` uses `BaseHTTPMiddleware` which only
  covers HTTP scope — WebSocket endpoints bypass it entirely.
- `routers/terminal.py:87` (`@router.websocket("/ws")`) spawns an Alpine
  shell container without any auth check.
- `routers/terminal.py:307` (`websocket_tcp_proxy`) forwards arbitrary
  bytes to emulation containers without auth.
- `config.py:77` default is `api_key: str = ""` — empty string disables
  auth entirely, so most deployments have NO auth.
- Combined with `0.0.0.0:8000` binding in `docker-compose.yml:55`:
  **any host on the LAN can open `/ws` and get shell access** to an
  Alpine container, then through the Docker socket (mounted at
  `/var/run/docker.sock:77`) pivot to the full container host.

**Recommended near-term mitigation (do regardless of option):**
Change backend port binding to `127.0.0.1:8000` (Option A's Item 1).
This is ~3 lines in `docker-compose.yml` and removes LAN exposure
immediately. Not a fix for auth — but a tight enough container until
the real fix lands.

---

## Motivation

Session 2026-04-18 shipped DPCS10 extraction fix + HW Firmware page
overhaul. Four threads surfaced and 24 pending intake items remain.

## Three scope options — SCOUT-DEEPENED

### Option A — **Short (1.5-2 h) · Quick-wins bundle** — **recommended**

Scout-A-validated items:

**A.1 Safe bindings** (~8-12 LOC, 15 min, LOW risk)
- `docker-compose.yml:55` — `"0.0.0.0:8000:8000"` →
  `"${BACKEND_HOST_BIND:-127.0.0.1}:${BACKEND_HOST_PORT:-8000}:8000"`
- `docker-compose.yml:253` — frontend port: same pattern
- `docker-compose.yml:59` — hardcoded `wairz:wairz@postgres` →
  `${POSTGRES_PASSWORD}`
- `docker-compose.yml:194` — hardcoded `POSTGRES_PASSWORD=firmae` in
  system-emulation → env var
- `docker-compose.dev.yml:33` — uvicorn `--host 0.0.0.0` → env var
- `.env.example` — document `POSTGRES_PASSWORD` + `BACKEND_HOST_BIND`
- **Intake**: `.planning/intake/infra-secrets-and-auth-defaults.md`
- **Blocker**: none. vulhunt (line 210) binds to `0.0.0.0:8080`
  internally only — no change needed.

**A.2 Widen `analysis_cache.operation` VARCHAR** (~30-35 LOC, 20 min, LOW)
- Model at `backend/app/models/analysis_cache.py:26` already declares
  `String(512)`; migration `01ac34151ca4_add_analysis_cache_table.py:28`
  still has `length=100` — DB is stale vs model.
- Callers that already hit >100 chars: `ghidra_service.py:645`
  (`decompile:{function_name}` — Java mangled names),
  `jadx_service.py`, `analysis.py:276`, `mcp_server.py:165`
  (`code_cleanup:{function_name}`).
- Work: `alembic revision -m widen_analysis_cache_operation_to_512` +
  new test file. Metadata-only ALTER TABLE in Postgres, no data
  movement, no lock storm.

**A.3 Legacy null-tier CVE backfill** (~40-60 LOC, 40 min, MEDIUM risk)
- Scout finding: `match_firmware_cves()` at
  `cve_matcher.py:531-610` is insert-only with
  `(blob_id, cve_id)` dedup — re-running **skips** existing
  null-tier rows. A separate UPDATE pass is needed.
- Work: new `backfill_null_tier_cves(firmware_id, db)` that queries
  `sbom_vulnerabilities WHERE match_tier IS NULL` and re-runs the
  tier-matching logic per row (curated YAML → kernel subsystem → etc.).
- **Risk**: Tier 5 (kernel_subsystem) pulls from kernel_vulns_index,
  which might be cold at original match time — re-tiering could
  produce different results. Recommend: test on staging DB first; run
  on one firmware, diff the aggregate, then roll out.

**A.4 Pending-rule drift check** (0 LOC, 5 min, NONE) —
Scout found no orphaned "pending manual addition" rules. Cron idea
still good for future sessions; no action needed now.

**Subtotal**: 3 real items + 1 no-op = **~1.5 h end-to-end**

Orchestrator: `citadel:autopilot` per-item, in order A.1 → A.2 → A.3.

---

### Option B — **Medium-to-Large (3-4 days) · Security sweep**

Scout B quantified this as a real campaign, not a bundle:

**B.1 Auth hardening** — 60-120 LOC, 1.5 days, **CRITICAL risk**
- Replace `BaseHTTPMiddleware` with a pure-ASGI middleware covering
  both `http` AND `websocket` scopes.
- `config.py:77`: `api_key: str = ""` → `api_key: str | None = None` +
  new `allow_no_auth: bool = False`. Fail startup if neither is set.
- Add `slowapi` rate limiter integrated with existing Redis.
- WebSocket close-code 4401 on auth failure — audit `frontend/src/api/
  client.ts` to confirm it handles correctly.
- **Critical because**: closes the current LAN-shell exposure.

**B.2 Fuzzing shell injection** — 20-40 LOC, 1.5 days, **CRITICAL**
- TWO injection sites (not one): `fuzzing_service.py:532-535`
  (start_campaign) + `:827-844` (triage_crash). Both do
  `sh -c 'f"...{user_input}..."'` — `shlex.quote()` is single-level
  but the outer single-quote wrap defeats it.
- Plus secondary site at `emulation_service.py:1383` missing
  `shlex.quote` around `session.binary_path`.
- Fix pattern: write command to file via `put_archive` (tar stream in
  memory), then `exec_run(["sh", "run.sh"])`. Add cleanup on campaign
  stop to avoid stale-script accumulation.
- Add CI check: `grep -rn 'sh", "-c",\s*f"' backend/app/services/`
  must return 0.

**B.3 Android/ZIP extraction hardening** — 200 LOC, 1 day, HIGH risk
- Gap: `unpack_android.py:503, 525` + `unpack_common.py:265` skip the
  per-entry realpath + bomb checks that `firmware_service.py` has.
- Plus symlink-attr (`info.external_attr >> 16 & 0o170000 == 0o120000`)
  never checked anywhere — a malicious OTA can plant symlinks escaping
  the sandbox.
- Work: new `workers/safe_extract.py` with
  `safe_extract_zip(zf, out_dir, allow_symlinks=False, ...)` +
  `safe_extract_tar(...)`. Consolidate 3 call sites + existing inline
  defenses in `firmware_service.py:224-254`.
- 4 adversarial tests: traversal, bomb, symlink, normal-firmware.

**Subtotal**: 280-360 LOC, 3-4 days, serial execution recommended.

Orchestrator: `citadel:archon` — multi-day campaign with
post-deploy validation between items.

---

### Option C — **Large (1-2 sessions) · Hardware firmware expansion (Phase 1)**

Scout C found this is NARROWER than the intake implies:

- **Qualcomm MBN parser already exists** (~150 LOC covers modem/DSP).
- **Existing parsers: 16 total** (~3,300 LOC). New work = ~500 LOC =
  15% expansion, not the rebuild the intake suggested.

**C.1 Qualcomm Adreno + WCNSS** — 200 LOC, leverage 12-15 new blobs/image
- Adreno GPU: `a[0-9]{3,4}_(zap|sqe|gmu).*\.(elf|fw|bin)` — ELF-wrapped.
- WCNSS Wi-Fi: `WCNSS_qcom_*.bin` — opaque binary with version strings.
- CVE sources: Qualcomm Security Bulletin, Project Zero, Qualcomm QVL.

**C.2 Samsung Shannon modem** — 120 LOC, leverage 2-3 critical CVEs
- `modem.bin` or `cbd` with TOC magic `0x00434f54` — 12-entry TOC.
- Matches intake's "Project Zero, Comsecuris" threat model.
- CVE source: Samsung SMR.

**C.3 Enhance Broadcom/Cypress Wi-Fi** — 80 LOC
- Existing heuristic parser exists; add `.txt` NVRAM version
  extraction + HCI prefix detection for BT blobs.
- CVE families: 3 known (incl. BleedingTooth).

**C.4 Scope-reduce: advisory-only ARM Mali, PowerVR, Imagination** —
defer to Phase 2+. Low leverage (0-2 CVEs).

**Subtotal**: ~400 LOC Phase 1, 1 session if focused, 2 if thorough.

Orchestrator: `citadel:archon` — reuses the 5-phase shape from
`feature-extraction-integrity` (research → patterns → parsers →
tests → live verify).

---

## Recommendation

**Hybrid approach**:
1. **FIRST** (regardless of option): ship Option **A.1** (safe
   bindings) as a standalone commit. 15 min, closes the exploitable
   WebSocket-shell gap at the network layer.
2. Then pick between rest-of-A (quick wins), B (full security sweep),
   or C (feature expansion) based on appetite.

If picking B, do **B.1 (auth)** first — it's the real fix for what
A.1 mitigates at the network layer.

If picking C, the win is **C.1 + C.2** (Qualcomm Adreno + Samsung
Shannon) — ~320 LOC unlocks 14-18 new blobs per typical Android
image. C.3 Broadcom enhancement is a nice-to-have follow-on.

## Verifiable end-conditions

**A (all 3 items):**
- `docker-compose config | grep "0.0.0.0:"` returns only intentional
  internal bindings (no backend / frontend)
- `docker compose exec backend /app/.venv/bin/python -c "from
  app.models.analysis_cache import AnalysisCache; print(
  AnalysisCache.__table__.c.operation.type.length)"` reports 512
- `docker compose exec postgres psql -U wairz -d wairz -c "SELECT
  COUNT(*) FROM sbom_vulnerabilities WHERE match_tier IS NULL OR
  match_tier='';"` reports 0 for any firmware that's been backfilled

**B:**
- `curl -s http://host:8000/api/v1/projects` without API key → 401
- WebSocket `ws://host:8000/ws` without key → close code 4401
- `grep -rn 'sh", "-c",\s*f"' backend/app/services/` → 0 matches
- Malicious-filename regression test in
  `test_fuzzing_sanitization.py` passes
- Zip-bomb + path-traversal + symlink-escape regression tests in
  `test_safe_extract.py` all reject

**C:**
- Qualcomm MBN + Adreno + WCNSS detected on a known Qualcomm firmware
  (need one in test corpus; RespArray has some Qualcomm blobs)
- Samsung Shannon parser extracts TOC entries + version string from a
  real modem.bin
- `distinct format` count in `hardware_firmware_blobs` grows by ≥3
  post-deploy on the live DB

## Seed metadata — Ouroboros

```yaml
interview:
  source: session-handoff-2026-04-18 + 3-scout research fleet
  scouts:
    - option-a-quick-wins (46s, 19 tool uses)
    - option-b-security-sweep (62s, 21 tool uses)
    - option-c-firmware-expansion (53s, 24 tool uses)
  clarifying_questions:
    - Do A.1 (bindings) immediately as security mitigation? y/n
    - Which larger option after A.1: rest-of-A / B / C / defer?
    - If B: do all three in one campaign or split?
    - If C: stop at C.2 (Qualcomm + Samsung) or push to C.3 (+Broadcom)?

orchestrator_hint:
  a1_standalone: direct commit (15 min, no orchestrator needed)
  rest_of_a:    citadel:autopilot per-item
  option_b:     citadel:archon (multi-day campaign)
  option_c:     citadel:archon (5-phase shape from extraction-integrity)

verification_gate:
  always:
    - Full affected-suite pytest via /app/.venv/bin/python -m pytest
    - tsc -b clean (canaried with known-bad input per CLAUDE.md rule 17)
    - docker compose up -d --build backend worker  (rule 8)
    - Live verification on DPCS10 firmware 0ed279d8 still shows 260 blobs
  option_specific:
    b: post-deploy verify WebSocket auth + rate-limit 429 before next item
    c: post-deploy verify no regression on DPCS10 MTK blob count
```

## Risk + rollback

- All 3 options are additive, not destructive.
- Baseline rollback: `f8777b1` (session 2026-04-18 start) or this
  session's uncommitted state can be stashed.
- DPCS10 state (260 blobs, 26 hw-firmware CVEs) is the canary — any
  option must leave it intact.

## For the next session's first action

```text
1. Read .planning/knowledge/handoff-2026-04-18-session-end.md
2. Read this file
3. Ask user:
     (a) "Ship A.1 bindings mitigation right away? [y/n]"
     (b) "Then: rest of A (quick wins), B (security), or C (firmware)?"
4. Route:
     a-only → direct commit + /autopilot A.2-A.4
     B → /archon security-hardening (auth first, fuzzing next, zip last)
     C → /archon hw-firmware-expansion (C.1 + C.2, optionally C.3)
5. Pre-flight: canary tsc, /app/.venv/bin/python for tests
```
