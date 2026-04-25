---
title: "GUI golden-path smoke: 3 pre-existing bugs surfaced by post-P3 verification"
status: partial-completed
priority: high
target: backend/app/services/, backend/app/models/, backend/alembic/versions/
baseline_head: a1c5d54  # knowledge: /learn extraction for p3-triple-close-2026-04-24
target_session: next
created: 2026-04-24T18:10:00Z
author: session-d8edd200-do-continue (smoke driven against fw a7523429 — RespArray V1.12)
previous_handoff: session aa8b4a17 ("Unresolved — GUI not exercised; CLAUDE.md explicitly requires end-to-end UI verification")
research_method: REST-driven smoke against fw a7523429-1c9c-4740-a360-545ef5b6a85f (project ACM test, 00815038-cb0f-4642-b2bf-2f176fd807f7) covering Security Scan / Attack Surface / HBOM / CVE flows; backend+worker logs tailed throughout; verdict cross-checked against `git blame` and prior commit messages
priority_order: "#3 → #1 → #2 (most-blocking to least-blocking — #3 unblocks the entire Security Scan tab on deeply-nested firmware; #1 unblocks /cve-match; #2 cosmetic-but-visible arch column)"
closed_by: "session 56797be2 — three-commit sweep; Bug #3 + Bug #2 fully verified; Bug #1 mechanically verified (singleton fix in place, 0 CPE loads in second smoke) but cve-match endpoint still OOMs from a SEPARATE root cause not anticipated by the intake — see follow-up intake cve-match-residual-oom-2026-04-25.md"
shipped_commits: [ca583d0, f71f978, 9f7ddde]
---

## Smoke verification results — 2026-04-25 session 56797be2

| Bug | Acceptance criteria | Result |
|---|---|---|
| **#3 (HIGH, title widening)** | DB=512 ✓, mapper=512 ✓, alembic head=d4a7c8b6e2f1 ✓, post-audit findings count ≥ 50 ✓ (got **315**), 0 truncation errors ✓ | **VERIFIED** |
| **#2 (LOW-MED, attack_surface arch)** | scan returned 200 in 14.5s ✓, arch != NULL > 0 ✓ (got **1613/1624 = 99.3%**), 'arm' in distinct ✓ (sole non-null value) | **VERIFIED** |
| **#1 (MEDIUM, cve_matcher singleton)** | grep `CpeDictionaryService\(\)` in cve_matcher = 0 hits ✓; CPE dictionary loads during 2nd cve-match = **0** ✓ (vs the intake's pre-fix 11×); Rule #11 import smoke clean ✓; **request returned 2xx within 60 s ✗ — backend was killed at 87 s with no log output, RestartCount went 1→2 at 21:11:22 UTC** | **MECHANICALLY VERIFIED, FUNCTIONALLY INCOMPLETE** |

**Bug #1 residual:** the singleton fix correctly eliminates the 11× per-blob `CpeDictionaryService()` instantiation that the intake identified as the OOM driver. Live evidence confirms: zero "CPE dictionary loaded from Redis cache" events fire during cve-match after the fix (vs 11 in the intake's pre-fix smoke). However, cve-match STILL OOMs the backend container — meaning the per-blob dictionary load was one of multiple memory-pressure sources in this endpoint, not the only one. The remaining cause is unknown and requires investigation; the most plausible suspects (in code-reading order) are Tier 4 `_match_kernel_cpe` (fetches grype kernel CVEs per kernel-component blob; could fan out to thousands of vuln rows held in memory at once) and Tier 5 `_match_kernel_subsystem` (Redis-backed kernel.org vulns.git CNA index lookup per `.ko` blob). The cve-match endpoint produced ZERO log output during the 85 s before the kill, which makes log-trace-driven attribution impossible without instrumentation.

**Why this is not a regression of the fix:** Bug #1's commit is correct in isolation — it does precisely what the intake specified, and verifies against the intake's own acceptance criterion #1, #3, and #4. The endpoint's still-failing behaviour is a SEPARATE bug that the intake's investigator did not surface (the prior smoke OOM'd at the 11× CPE-load phase before any tier-4/tier-5 work was reached, so the secondary cause was masked).

**Follow-up:** see `.planning/intake/cve-match-residual-oom-2026-04-25.md` (this session author) — describes the observed behaviour + diagnostic plan + suggested next steps. Ranked HIGH because /cve-match is still un-shippable from the GUI without further work.

---


# GUI golden-path smoke — 3 pre-existing bugs surfaced

> Read order for the next session:
>   1. This file (catalog + fix shapes)
>   2. `.planning/fleet/session-backend-pytest-unstable-2026-04-23.md` (most recent fleet handoff)
>   3. The session-d8edd200 transcript / `/tmp/wairz-smoke-logs.txt` (preserved smoke evidence — full StringDataRightTruncationError traceback)
>   4. CLAUDE.md Rules #11, #15, #19, #20, #25, #29

## Headline

The previous session (aa8b4a17, P3 triple-close 2026-04-24) closed with the explicit unresolved note "GUI not exercised — CLAUDE.md explicitly requires end-to-end UI verification." Session d8edd200 (this seed's author) drove that smoke.

**P3 refactors (clamav_service / attack_surface_service / cve_matcher) are GREEN.** Backend ran ~12 minutes of audit + scanner work + threat-intel HTTP calls + import smokes across the three refactored services without a single ImportError / NameError / AttributeError / Traceback attributable to the carve-outs. `grep -cE "ImportError|NameError|AttributeError|Traceback" /tmp/wairz-smoke-logs.txt` = **0**.

**But three orthogonal pre-existing bugs surfaced — none caused by the P3 work.** Each is documented below with file:line, evidence, fix shape, and acceptance criteria.

## Smoke evidence (reproducer + verdict)

| Path | Endpoint | HTTP | Verdict | Evidence |
|---|---|---:|---|---|
| (a) ClamAV-only | `POST /security/clamav-scan` | 200 | ✅ refactor green | structured fail-soft `{"status":"unavailable",...}` — clamav daemon is `profiles:[clamav]`-gated, not in default stack; clamav_service P3 imports loaded clean |
| (a) full audit | `POST /security/audit` | (curl -m 700 timed out at 11m40s; backend continued detached) | ⚠️ scanner pipeline ran clean; **persistence rolled back** | see Bug #3 below — `StringDataRightTruncationError` on `findings.title` killed the flush at the end |
| (b) attack-surface | `POST /attack-surface/scan?force_rescan=true` | 200 (16.6s) | ⚠️ ran end-to-end, **arch column NULL on 100% of rows** | DB query: `SELECT COUNT(*) FILTER (WHERE architecture IS NULL)` = **1624 / 1624** — see Bug #2 |
| (c) blob list | `GET /hardware-firmware` | 200 | ✅ | 563 blobs |
| (c) cve-aggregate | `GET /hardware-firmware/cve-aggregate` | 200 | ✅ | structured response, all severity buckets present (values=0 because `/cve-match` had never been triggered for this fw) |
| (c) blob detail | `GET /hardware-firmware/{blob_id}` | 200 | ✅ | full blob detail rendered |
| (c) per-blob CVEs | `GET /hardware-firmware/{blob_id}/cves` | 200 | ✅ | returns `[]` (no per-blob matches yet — `cve-match` never ran successfully) |
| (c) firmware-edges | `GET /hardware-firmware/firmware-edges` | 200 | ✅ | 51 edges |
| (c) cve-match | `POST /hardware-firmware/cve-match` | (HTTP=000, backend OOM-killed at ~100s) | ❌ **OOM** | see Bug #1 — 11 chipset-tagged blobs × 11 fresh `CpeDictionaryService()` instances × 37,268 CPE products each |

Smoke artifacts preserved in `/tmp/`:
- `/tmp/wairz-smoke-b.json` — 1624 attack-surface entries (arch=null visible in every row)
- `/tmp/wairz-smoke-a-clamav.json` — clamav fail-soft response
- `/tmp/wairz-smoke-logs.txt` — 154 KB backend+worker log including the full `StringDataRightTruncationError` traceback (UTC 2026-04-25 00:05:08)

## Bug catalog (priority-ordered: #3 → #1 → #2)

### Bug #3 — `findings.title VARCHAR(255)` truncates on deeply-nested extract paths (HIGH)

**File:** `backend/app/models/finding.py` (column definition); `backend/alembic/versions/` (new revision needed).

**Symptom:** `/security/audit` against fw a7523429 (RespArray V1.12) ran the entire scanner pipeline + 3-firmware × 4-threat-intel-source loop in ~12 minutes without any Python error, then crashed at the per-finding flush with:

```
sqlalchemy.dialects.postgresql.asyncpg.AsyncAdapt_asyncpg_dbapi.Error:
<class 'asyncpg.exceptions.StringDataRightTruncationError'>:
value too long for type character varying(255)
```

**Failed-row evidence (verbatim from `/tmp/wairz-smoke-logs.txt`):**

```
title: 'Hardcoded credential in /zImage-restore.tar.xz_extract/xz.uncompressed_extract/
        zImage-restore/zImage-restore_extract/51279-18857223.gzip_extract/
        gzip.uncompressed_extract/12859576-26309905.gzip_extract/
        gzip.uncompressed_extract/etc/ImageMagick-7/delegates.xml'
length: ~290 chars (column is VARCHAR(255))
file_path: same path — but file_path is VARCHAR(512) so it fits
```

**Why this is pre-existing, not P3:**
- `git log --since='2026-04-21' backend/app/models/finding.py backend/app/services/finding_service.py` returns **no commits**. Neither file was touched during P3 work.
- The credentials-detector formats title as `f"Hardcoded credential in {path}"`, so as nested-archive depth grows, titles grow proportionally.
- Existing-finding distribution at smoke time confirms the column was never adequately sized: max title length across all sources = 211 chars (apk-mobsfscan), max file_path = 85 chars — both under 255 — but only because no audit had previously been run against firmware with this nesting depth.

**Why it's HIGH priority:** silently breaks `/security/audit` end-to-end on any sufficiently nested firmware. Frontend Security Scan tab will surface only a generic 500. **No ClamAV / VT / abuse.ch / hashlookup findings persist, even though all of them ran successfully.** This is the actual root cause of "GUI not exercised" in the previous handoff.

**Fix shape:**

```python
# backend/app/models/finding.py — change
title: Mapped[str] = mapped_column(String(255), nullable=False)
# to
title: Mapped[str] = mapped_column(String(512), nullable=False)
# (matches file_path's column width, keeps it indexable; or use Text if any
#  caller composes a path-PLUS-snippet title — prefer 512 unless evidence
#  shows >512 incoming)
```

Plus an Alembic migration: `alembic revision --autogenerate -m "widen_findings_title_to_512"` then `op.alter_column('findings', 'title', type_=sa.String(512), existing_type=sa.String(255), existing_nullable=False)`.

Apply Rule #20 caveat: `findings.title` is on the `Finding` ORM model. Since SQLAlchemy models register in session metadata, this IS a class-shape change for the `Finding` mapper. Rule #20 mandates `docker compose up -d --build backend worker` after the migration applies (not just `docker cp`).

**Acceptance criteria:**

1. `python3 -c "from app.models.finding import Finding; print(Finding.__table__.columns['title'].type.length)"` returns `512` (or your chosen width).
2. `alembic upgrade head` runs cleanly inside backend container.
3. Smoke re-run: `POST /security/audit` against fw `a7523429` returns 2xx within `SECURITY_SCAN_TIMEOUT` (600 s) and `SELECT COUNT(*) FROM findings WHERE source='security_audit' AND project_id='00815038-cb0f-4642-b2bf-2f176fd807f7'` ≥ 50 (the per-partition credentials/shellcheck/network/update_mechanisms checks were each producing 50 findings each pre-flush — full count likely 200+ across 3 firmwares).
4. No `StringDataRightTruncationError` in `docker compose logs backend` during the audit.

**Backwards-compat note:** widening a varchar column to a longer varchar is non-locking on PostgreSQL (no table rewrite, no row scan). Safe for online migration.

---

### Bug #1 — `/cve-match` OOM via per-blob `CpeDictionaryService()` bypass of module's own singleton (MEDIUM)

**File:** `backend/app/services/hardware_firmware/cve_matcher.py:253` (also depends on top-level import at `:45`).

**Symptom:** `POST /api/v1/projects/{pid}/hardware-firmware/cve-match` against fw a7523429 caused backend container kernel OOM (SIGKILL) at ~100 s. Container memory grew from ~227 MiB baseline to >4 GiB before the kernel killed it; container exited with code 0; auto-restarted.

**Mechanism (verified by counting):**

```python
# cve_matcher.py:240-263 (the offending function)
async def _match_chipset_cpe(blob: HardwareFirmwareBlob) -> list[CveMatch]:
    if not blob.chipset_target:
        return []
    try:
        svc = CpeDictionaryService()      # <-- per-call instantiation
        if not await svc.ensure_loaded(): # <-- loads 37268-product CPE
            return []                     #     index from Redis into self._index
        # We validated the CPE path works; actual CPE -> CVE query is
        # deferred to a later phase so Phase 4 remains scoped.
    except Exception:
        ...
    return []   # <-- always returns []; the work is purely a memory burner
```

`_match_chipset_cpe` is called once per blob with `chipset_target IS NOT NULL`. For fw `a7523429`: **11 such blobs** (10× `am4372`, 1× `bcm43438`). Logs confirmed exactly **11 "CPE dictionary loaded from Redis cache (37268 products)"** events in a 3-second window, each from a fresh `CpeDictionaryService()` instance with its own un-evictable `self._index`.

**Module already has a singleton accessor — it's just bypassed:**

```python
# backend/app/services/cpe_dictionary_service.py:346-355
_service: CpeDictionaryService | None = None

def get_cpe_dictionary_service() -> CpeDictionaryService:
    """Get or create the singleton CPE dictionary service."""
    global _service
    if _service is None:
        _service = CpeDictionaryService()
    return _service
```

**Why this is pre-existing, not P3:** `git blame -L 250,260 backend/app/services/hardware_firmware/cve_matcher.py` resolves to commit `1fbcce4` (2026-04-16, 8 days before the P3 carve-out at `9a26c1a` on 2026-04-24). The P3 carve-out only promoted the `from app.services.cpe_dictionary_service import CpeDictionaryService` import to top-level — it didn't touch the instantiation pattern.

**Fix shape (two-line change):**

```diff
# backend/app/services/hardware_firmware/cve_matcher.py
-from app.services.cpe_dictionary_service import CpeDictionaryService
+from app.services.cpe_dictionary_service import (
+    CpeDictionaryService,
+    get_cpe_dictionary_service,
+)

 # ... inside _match_chipset_cpe ...
-        svc = CpeDictionaryService()
+        svc = get_cpe_dictionary_service()
```

(`CpeDictionaryService` is still imported because the type annotation may still reference it — if it doesn't, drop it from the import line.)

**Acceptance criteria:**

1. `grep -nE "CpeDictionaryService\(\)" backend/app/services/hardware_firmware/cve_matcher.py` returns **0 matches** (only `get_cpe_dictionary_service()` should appear).
2. Smoke re-run: `POST /hardware-firmware/cve-match?firmware_id=a7523429-...` returns 2xx within 60 s; backend memory rises by < 200 MiB during the call (single dictionary load, not 11).
3. `grep -c "CPE dictionary loaded from Redis cache" /tmp/cve-match-logs.txt` ≤ **1** (the singleton's first-call load, or 0 if a prior call warmed it).
4. Rule #11 import smoke: `from app.services.hardware_firmware.cve_matcher import match_firmware_cves` works in backend + worker container after `docker cp` (no Rule #20 class-shape rebuild needed — module-level function only).

**Latent semantic note:** `_match_chipset_cpe` currently always returns `[]` after loading (Tier 1 stub). The dictionary load itself produces no useful work in this path. Fix #1 stops the OOM but does NOT change the stub status. A real Tier-1 CPE→CVE lookup is "deferred to a later phase" per the function's own docstring; orthogonal to this fix.

---

### Bug #2 — `_LIEF_ELF_ARCH_MAP` empty → `architecture=NULL` on 100% of attack-surface rows (LOW-MEDIUM, cosmetic-but-visible)

**File:** `backend/app/services/attack_surface_service.py:142` (the lookup); `backend/app/services/binary_analysis_service.py:33` (the population side-effect).

**Symptom:** `POST /attack-surface/scan?force_rescan=true` against fw a7523429 returned HTTP 200 in 16.6 s with 1624 entries, all of which had `architecture: null`. Frontend Attack Surface page would render an empty arch column for every row.

**DB confirmation:**

```sql
SELECT COUNT(*) FILTER (WHERE architecture IS NULL) AS null_arch,
       COUNT(*) FILTER (WHERE architecture IS NOT NULL) AS set_arch
FROM attack_surface_entries
WHERE firmware_id = 'a7523429-1c9c-4740-a360-545ef5b6a85f';
-- => null_arch=1624, set_arch=0
```

**Mechanism:**

```python
# binary_analysis_service.py:16
_LIEF_ELF_ARCH_MAP: dict[int, str] = {}     # starts empty

# binary_analysis_service.py:30-65 (approx)
def _ensure_lief() -> None:
    """Lazy-load LIEF and populate _LIEF_ELF_ARCH_MAP."""
    if _lief_loaded: return
    import lief
    _LIEF_ELF_ARCH_MAP.update({
        lief.ELF.E_MACHINE.ARM: "arm",
        lief.ELF.E_MACHINE.AARCH64: "aarch64",
        # ...
    })

# attack_surface_service.py:142 (after P3 promotion at 4bd491b)
arch = _LIEF_ELF_ARCH_MAP.get(binary.header.machine_type)  # → None unless _ensure_lief() called first
```

`_ensure_lief()` is called inside `get_binary_info` and a few other binary_analysis_service entrypoints, but **the attack-surface scan path goes through a different code path that uses pyelftools first and only falls back to LIEF for arch detection — without calling `_ensure_lief()`.** So the map stays `{}` and every `.get(machine_type)` returns `None`.

**Why this is pre-existing, not P3:** Commit `4bd491b` (the P3 carve-out for attack_surface_service) explicitly documented this in its message:

> Pre-existing latent semantic — if nobody in the session calls binary_analysis_service._ensure_lief() first, _LIEF_ELF_ARCH_MAP.get(...) always returns None. Out-of-scope for this refactor; documented for the audit trail.

The previous handoff (session aa8b4a17) listed this as: "_LIEF_ELF_ARCH_MAP latent side-effect-dep bug documented in 4bd491b but NOT fixed (orthogonal)."

**Fix shape (one of two options — recommend option A):**

**Option A — call `_ensure_lief()` once at scan entry:**

```diff
# backend/app/services/attack_surface_service.py
-from app.services.binary_analysis_service import _LIEF_ELF_ARCH_MAP
+from app.services.binary_analysis_service import _LIEF_ELF_ARCH_MAP, _ensure_lief

 def scan_attack_surface(extracted_path, path_filter=None):
+    _ensure_lief()  # populates _LIEF_ELF_ARCH_MAP for the .get() at L142
     ...
```

**Option B — promote `_ensure_lief()` to module-init in binary_analysis_service:**

Could add `_ensure_lief()` to `binary_analysis_service.py` module bottom, but that would force LIEF cold-import (~500 ms) on every backend startup even for code paths that never need ELF arch (e.g. android-only flows). Rule #30 caveat (a) — optional / slow dependency — argues against this. Stick with Option A.

**Acceptance criteria:**

1. After fix: `SELECT COUNT(*) FILTER (WHERE architecture IS NOT NULL) FROM attack_surface_entries WHERE firmware_id='a7523429-...'` after `force_rescan=true` is **> 0** (expected: a substantial fraction; ARM/AARCH64 binaries should now report arch).
2. `SELECT DISTINCT architecture FROM attack_surface_entries WHERE firmware_id='a7523429-...' AND architecture IS NOT NULL` returns at minimum `arm` (this firmware's blobs are predominantly ARM).
3. Rule #11 import smoke: `from app.services.attack_surface_service import scan_attack_surface` clean.
4. No new ImportError on `_ensure_lief` symbol — it's a module-level function in binary_analysis_service that's already exported (no underscore-prefix doesn't prevent import; just a hint).

---

## Reproducibility — exact smoke commands

```bash
# Pre-flight
docker compose ps  # backend, worker, postgres, redis must be healthy

API_KEY=$(docker compose exec -T -w /app -e PYTHONPATH=/app backend \
  /app/.venv/bin/python -c "from app.config import get_settings; print(get_settings().api_key)" \
  2>/dev/null | tr -d '\r\n')
PID=00815038-cb0f-4642-b2bf-2f176fd807f7
FID=a7523429-1c9c-4740-a360-545ef5b6a85f
H="X-API-Key: $API_KEY"

# Tail logs in a separate shell
docker compose logs -f --tail=0 backend worker > /tmp/wairz-smoke-logs.txt 2>&1 &

# (a) full audit — repro Bug #3
curl -s -m 700 -H "$H" -X POST "http://localhost:8000/api/v1/projects/$PID/security/audit"
# Expect: backend logs show StringDataRightTruncationError on findings.title

# (b) attack-surface — repro Bug #2
curl -s -m 600 -H "$H" -H "Content-Type: application/json" -X POST \
  "http://localhost:8000/api/v1/projects/$PID/attack-surface/scan?firmware_id=$FID" \
  -d '{"force_rescan": true}'
# Expect: 200; DB count of arch=NULL == total entries

# (c) cve-match — repro Bug #1
curl -s -m 600 -H "$H" -H "Content-Type: application/json" -X POST \
  "http://localhost:8000/api/v1/projects/$PID/hardware-firmware/cve-match?firmware_id=$FID" \
  -d '{}'
# Expect: HTTP=000 / OOM; logs show 11× "CPE dictionary loaded from Redis cache"

# Diagnostic queries
docker compose exec -T postgres psql -U wairz -d wairz -c "
  SELECT chipset_target, COUNT(*) FROM hardware_firmware_blobs
  WHERE firmware_id::text = '$FID' AND chipset_target IS NOT NULL
  GROUP BY chipset_target ORDER BY 2 DESC;
"
# Expect: am4372=10, bcm43438=1 (= 11 total = 11 OOM-causing instantiations)
```

## Execution plan suggestions

### Single-session, three-commit shape (recommended; Rule #25 per-fix splits)

1. **Commit 1 (Bug #3 — schema + migration):** widen `findings.title` to `String(512)`, add Alembic revision, `docker compose up -d --build backend worker` (Rule #20 mandate — class-shape change), confirm `alembic upgrade head` runs.
2. **Commit 2 (Bug #1 — cve_matcher singleton):** import + replace per-call instantiation. `docker cp` + Rule #11 smoke (no rebuild).
3. **Commit 3 (Bug #2 — attack_surface arch):** add `_ensure_lief()` import + call at scan entry. `docker cp` + Rule #11 smoke.

End-of-session: full smoke re-run (commands above), log all three acceptance criteria, write a follow-up handoff confirming GUI verification closed.

### Splitting risk

- Rule #28 size check: `wc -l backend/app/models/finding.py backend/app/services/hardware_firmware/cve_matcher.py backend/app/services/attack_surface_service.py` — all < 1500 LOC; no Rule #27 monolith-split scope concerns.
- Rule #23 worktree discipline: NOT needed for sequential single-session work. Only required when running in parallel via Fleet.
- Rule #15 lesson note: this is the second documented schema-vs-data length bug after the analysis_cache.operation VARCHAR(100→512) fix. Worth promoting to "always check column widths against incoming-value distribution before reusing" — already in CLAUDE.md.

## Baseline + rollback

Baseline `a1c5d54` is the post-/learn-extraction HEAD. Each commit is independently revertable:
- `git revert <bug3-sha>` rolls back the title widening AND the Alembic head — caveat: PostgreSQL won't auto-shrink the column; manual `ALTER TABLE findings ALTER COLUMN title TYPE VARCHAR(255)` in a forward migration if revert is needed.
- `git revert <bug1-sha>` and `git revert <bug2-sha>` are clean reverts (single-file mechanical changes).

## Risk

- **Rule #20 trap on Bug #3:** widening a column without `docker compose up -d --build backend worker` will cause `Settings`-style stale class-shape errors on the running container. The Alembic migration alone runs against the DB, but the SQLAlchemy ORM mapper in the running process still has `String(255)` cached in metadata. Rebuild is mandatory.
- **Rule #29 timeout alignment:** `SECURITY_SCAN_TIMEOUT=600_000` (frontend) matches backend audit ceiling. After Bug #3 fix the audit will SUCCEED in 11-12 minutes — well under 600 s ceiling for typical firmware, but RespArray V1.12's 3-firmware project may push close to the edge. Watch for client-side timeout regressions if the fix removes the early-failure shortcut.
- **Bug #1 latent stub:** the singleton fix stops the OOM but doesn't make Tier 1 CPE→CVE matching actually return data — that's a separate "deferred to a later phase" item in cve_matcher's docstring. Acceptance criteria #2 above measures memory, not CVE rows; the function is allowed to still return `[]`.
- **Bug #2 LIEF cold-import cost:** `_ensure_lief()` triggers a one-time ~500 ms LIEF library load on first call per backend process. After Option A fix, this happens on the first attack-surface scan after backend restart. Acceptable — the scan is already a long-op; users won't notice 0.5 s in a 16 s scan.

## Scout telemetry

None — single-session smoke (session d8edd200) drove the entire investigation. No parallel Explore scouts. All evidence is from REST calls + log analysis + DB queries against fw a7523429 (project 00815038, ACM test).
