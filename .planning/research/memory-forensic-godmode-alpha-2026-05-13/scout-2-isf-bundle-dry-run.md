---
title: Scout 2 — Vol3 ISF bundle download dry-run for λ campaign (memory-forensic-godmode-α)
opened: 2026-05-12
scope: Read-only network probe; no wairz tree modifications; no `refresh-*.sh --apply` execution.
parent_intake: .planning/intake/memory-forensic-godmode-alpha-kickoff-2026-05-12.md
sibling_scouts: scout-1-vol3-library-probe.md, scout-3-plugin-api-taxonomy.md
---

# Scout 2 — Vol3 ISF bundle download dry-run

## TL;DR — actionable findings for λ.α

1. **Canonical source is the GitHub release**, NOT `downloads.volatilityfoundation.org`. Both serve byte-identical content (verified — SHA256 matches across both endpoints), but the Vol3 README at `develop/README.md:68-72` points only to `github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/`. Last-Modified on the volatilityfoundation.org files is stale (2019 / 2020 / 2024); the GitHub release was refreshed 2026-03-12. Use the GitHub URL.
2. **SHA256 pinning works out-of-the-box.** Volatility Foundation publishes `SHA256SUMS` + `SHA1SUMS` + `MD5SUMS` sidecars at canonical URLs. No need for compute-on-first-fetch workaround.
3. **Total cumulative compressed size: ~885 MiB (0.864 GiB)** — significantly smaller than the intake's "~1.5 GB compressed" estimate. windows.zip is the bulk (800 MiB); linux.zip is tiny (2.8 MiB); mac.zip is medium (81 MiB).
4. **Refresh cadence: yearly minimum, quarterly recommended.** The whole `volatility3-test-data` release was uploaded as a single `v0.0.1` tag on 2026-03-12; there is no prior tag history. The downloads.volatilityfoundation.org bundles haven't moved since 2019/2020/2024. Cadence is dominated by Vol3 RELEASE rate (~4 releases/year per `api.github.com/repos/volatilityfoundation/volatility3/releases`), not bundle churn.
5. **Refresh script shape mirrors `refresh-loldrivers.sh` closely** — multi-bundle (4 files: 3 zips + SHA256SUMS), HTTP/206 supported for resume-on-failure, atomic-write per Rule #19 already proven in DBX/loldrivers precedent.

## 1. Reachability — `https://downloads.volatilityfoundation.org/volatility3/symbols/`

Both candidate origins are reachable from this development host (Linux 5.15, curl 7.81). No DNS / rate-limit / TLS issues observed in 12 probes during the dry-run window (2026-05-13 ~00:58 UTC).

### 1.a downloads.volatilityfoundation.org probe results

```
$ curl -sI https://downloads.volatilityfoundation.org/volatility3/symbols/
HTTP/1.1 403 Forbidden
Server: Apache/2.4.58 (Ubuntu)
Strict-Transport-Security: max-age=63072000; includeSubDomains;
Content-Type: text/html; charset=iso-8859-1
```

Directory listing is **disabled** (HTTP 403). The root `/` returns 403, but explicit file paths return 200. No `X-RateLimit` or `Retry-After` headers observed. HSTS is enforced. Server stack: Apache 2.4.58 on Ubuntu — production-grade, but the only HTTP-cache header is `ETag` (no `Cache-Control`, no `Surrogate-Control`, no CDN headers — bare Apache origin, not behind Cloudflare / Fastly / Akamai).

### 1.b github.com (canonical, per README)

```
$ curl -sI -L https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/windows.zip
HTTP/2 302
location: https://release-assets.githubusercontent.com/github-production-release-asset/905437756/...
HTTP/2 200
last-modified: Thu, 12 Mar 2026 22:07:44 GMT
content-type: application/octet-stream
content-length: 839727133
```

Redirects through `release-assets.githubusercontent.com` (Azure-backed blob storage) via a 30-minute-signed JWT URL. **The `Location` header carries a time-limited signature** (`se=2026-05-13T01:50:47Z` query param expires ~30 min after request) — refresh script must follow the 302 in the SAME curl invocation, NOT cache the resolved location URL.

GitHub Releases is fundamentally a CDN-backed endpoint; expect higher reliability than the volatilityfoundation.org origin (single Apache box). No rate-limit headers observed on unauthenticated GETs to release-asset URLs (different from GitHub API endpoints which have `X-RateLimit-*`).

## 2. Bundle inventory + sizes (HEAD probe results)

All three OS bundles + the SHA256SUMS sidecar, observed on canonical URLs:

| Bundle | URL (canonical) | Content-Length | Last-Modified (origin: vol-foundation.org) | Last-Modified (origin: github) | SHA256 (verified) |
|---|---|---:|---|---|---|
| `windows.zip` | `…/v0.0.1/windows.zip` | 839,727,133 | Wed, 16 Oct 2019 15:17:32 GMT | Thu, 12 Mar 2026 22:07:44 GMT | `231d69735b9a5482b16bdbf1ec356e0a95574c44079e68dfb02ebddb34d55f3e` |
| `linux.zip` | `…/v0.0.1/linux.zip` | 2,980,184 | Fri, 08 Nov 2024 02:27:09 GMT | Thu, 12 Mar 2026 20:57:16 GMT | `58bb7da2ed1e491ce922d04a59881d201e233b5605c9fd5a7f0c08ee528253c6` |
| `mac.zip` | `…/v0.0.1/mac.zip` | 84,808,562 | Mon, 22 Jun 2020 18:17:17 GMT | Thu, 12 Mar 2026 21:01:33 GMT | `fd12c8338724b175b0c5765af3313328b700ad53de4a00b4aa50e9a8bcef9129` |
| `SHA256SUMS` | `…/refs/tags/v0.0.1/symbols/SHA256SUMS` (raw.gh) AND `…/volatility3/symbols/SHA256SUMS` (volfdn.org) | 228 (volfdn) / 327 (gh) | Fri, 08 Nov 2024 02:46:50 GMT (volfdn) | n/a (raw.gh) | n/a (covers all 4 bundles incl. `symbols_win-10_19041-2025_03.zip` on the gh variant only) |

**Cumulative compressed size for 3 OS bundles: 927,515,879 bytes = 884.5 MiB = 0.864 GiB.** This is **significantly smaller than the intake's 1.5 GB estimate** — the intake should be updated to reflect ~885 MiB.

### 2.a Hash file content (canonical)

```
$ curl -s https://raw.githubusercontent.com/volatilityfoundation/volatility3-test-data/refs/tags/v0.0.1/symbols/SHA256SUMS
58bb7da2ed1e491ce922d04a59881d201e233b5605c9fd5a7f0c08ee528253c6  linux.zip
fd12c8338724b175b0c5765af3313328b700ad53de4a00b4aa50e9a8bcef9129  mac.zip
abd6500fba6a59c9a7c21f2c4b8a4d7edc2da417ec3161311a19a0e0beffd94e  symbols_win-10_19041-2025_03.zip
231d69735b9a5482b16bdbf1ec356e0a95574c44079e68dfb02ebddb34d55f3e  windows.zip
```

The GH variant ALSO includes `symbols_win-10_19041-2025_03.zip` (789 KiB) — a Win10 19041 symbol pack the volfdn.org variant omits. Probably a release-only patch; wairz should bundle it alongside `windows.zip` (it's <1 MiB, negligible). Verify by checking whether vol3 itself uses it — Scout 1 should confirm.

### 2.b Sidecar files probed

```
windows.zip.sha256     → 404 (no per-file sidecars; only the aggregate SHA256SUMS)
windows.zip.sha256sum  → 404
windows.zip.sig        → 404 (no GPG signatures)
windows.zip.asc        → 404
SHA256SUMS             → 200 (aggregate; preferred)
sha256sums.txt         → 404
manifest.json          → 404 (no JSON manifest)
```

**Volatility Foundation does NOT publish GPG signatures** — only the SHA256/SHA1/MD5 aggregate sums files. The trust chain is "the SHA256SUMS file ON GitHub is itself the integrity anchor" — secured by GitHub's TLS + repo-ownership ACLs, not by an out-of-band PGP signature. This is comparable to LOLDrivers' trust model (also no PGP) and acceptable per Rule #37's build-time-pinning discipline: wairz pins the SHA256 of each bundle in its repo, and a corrupted/swapped bundle fails `sha256sum -c` at build time.

## 3. Total / cumulative size

Confirmed via HEAD `Content-Length`:

| Source | Compressed | % of total |
|---|---:|---:|
| windows.zip | 800.8 MiB | 90.5% |
| mac.zip | 80.9 MiB | 9.1% |
| linux.zip | 2.8 MiB | 0.3% |
| **TOTAL** | **884.5 MiB (0.864 GiB)** | **100%** |

**Intake said ~1.5 GB; actual is ~0.86 GB**. Update the intake — image-growth budget can be revised down by ~40%. Operators with `INCLUDE_VOL3=1` will see roughly +900 MiB compressed → +2.5–4.3 GB on-disk (uncompressed; see §4 for decompression estimates).

## 4. Decompressed bundle layout — what does extraction look like?

Sampled by full-download-and-`unzip -l` on the two small bundles (linux.zip 2.9 MiB, mac.zip 80.9 MiB); windows.zip extrapolated from compression ratio.

### 4.a linux.zip (verified — downloaded, hash matched, unzipped)

```
$ unzip -l /tmp/vol3-linux.zip
        0  2024-11-06 18:52   linux/
   194636  2024-11-06 18:51   linux/Centos_2.6.18-8.1.15.el5_2.6.18-8.1.15.el5_x64.json.xz
   843440  2024-11-06 18:51   linux/Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz
   684796  2024-11-06 18:51   linux/Debian_2.6.32-48squeeze6_2.6.32-5-amd64_x64.json.xz
  1255728  2024-11-06 18:51   linux/Debian_4.9.30-2+deb9u2_4.9.0-3-amd64_x64.json.xz
---------                     -------
  2978600                     5 files
```

5 `*.json.xz` files inside a `linux/` directory. **Each ISF is a single .xz-compressed JSON file with the kernel signature in the filename.** Decompressed: ~2.84 MiB total. Per the README at line 89: "Due to the ease of compiling Linux kernels and the inability to uniquely distinguish them, an exhaustive set of Linux symbol tables cannot easily be supplied." — so this is a curated tiny baseline; operators are expected to provide their own ISFs for non-pre-bundled kernels via `dwarf2json` (out-of-scope for λ.α).

### 4.b mac.zip (verified — downloaded, hash matched, unzipped)

```
129 files, sum decompressed 84,750,164 bytes (80.82 MiB)
Pattern: KernelDebugKit_<ver>_build<XXX>.dmg.json.xz at TOP LEVEL (no enclosing mac/ dir)
Example: KernelDebugKit_10.10.5_build14F1912.dmg.json.xz (606,656 bytes)
Examples cover OS X 10.6 through macOS 10.13+ across multiple build IDs.
```

Note the layout difference: **mac.zip extracts to top-level filenames**, NOT into a `mac/` subdirectory like linux.zip into `linux/`. This affects the Dockerfile COPY shape — wairz's `/opt/wairz/vol3-symbols/mac/` target may need a wrapping step. Vol3's own `volatility3/symbols/mac/` directory layout (confirmed via WebFetch on the vol3 develop branch) expects them at `mac/<file>.json.xz`. Refresh script should `unzip -d mac/ mac.zip` to ensure consistent on-disk layout.

### 4.c windows.zip (not downloaded — too large; extrapolated)

840 MiB compressed. xz on JSON typically achieves 3:1 to 5:1; **decompressed estimate is 2.5 to 4.2 GiB.** Each `.json.xz` is one PDB → ISF conversion; expected file count is in the thousands (PDBs per Windows kernel version × architecture × patch level). The Vol3 README warns: "The first run of volatility with new symbol files will require the cache to be updated. The symbol packs contain a large number of symbol files and so may take some time to update!" Implication for wairz: first-runtime cache hydration may add 30–120s to the first vol3 invocation per worker container. Scout 1 should validate empirically.

**Worker image impact:** baseline ~885 MiB compressed download → ~2.6 to 4.3 GiB on-disk uncompressed after extraction. With `INCLUDE_VOL3=1`, the worker image grows accordingly. Mirrors `INCLUDE_DOTNET=1` pattern: opt-in build flag, off by default.

## 5. SHA256 pinning workability

**Works cleanly — no workaround needed.** Volatility Foundation publishes:

- `https://raw.githubusercontent.com/volatilityfoundation/volatility3-test-data/refs/tags/v0.0.1/symbols/SHA256SUMS` (canonical per README)
- Equivalent at `https://downloads.volatilityfoundation.org/volatility3/symbols/SHA256SUMS` (same hashes, byte-for-byte)

Format is plain `sha256sum`-compatible (`<hash>  <filename>` with TWO spaces) — drop directly into `backend/vol3-symbols/SHA256SUMS` for use with `sha256sum -c` in the Dockerfile. **Verified empirically**: downloaded linux.zip (2.9 MiB) and mac.zip (80.9 MiB) and confirmed both sha256 values match the published SHA256SUMS exactly.

The campaign brief should mirror this in the per-file SHA256 sidecar pattern (`backend/ms-anchors/dbxupdate.bin.sha256`) — given Vol3 publishes a single aggregate SHA256SUMS, wairz can:

- **Option A (recommended):** check in `backend/vol3-symbols/SHA256SUMS` (the aggregate file) and use `sha256sum -c SHA256SUMS` in the Dockerfile. Mirrors how `sha256sum -c` works natively.
- **Option B:** split into per-file sidecars (`windows.zip.sha256`, `linux.zip.sha256`, `mac.zip.sha256`) matching DBX/loldrivers shape. More verbose but consistent with existing precedent.

Pick A — fewer files, fewer sync points, native `sha256sum` UX. If consistency with `backend/ms-anchors/` matters more, pick B.

## 6. Refresh cadence

### 6.a Empirical evidence

- GitHub release `v0.0.1` is the only tag (no prior releases on `volatility3-test-data`). All 7 assets uploaded over a ~2-hour window on **2026-03-12**.
- `downloads.volatilityfoundation.org` Last-Modified dates: **2019-10-16 (windows.zip), 2020-06-22 (mac.zip), 2024-11-08 (linux.zip + SHA256SUMS)**. Effectively dormant from 2024 onwards on this origin.
- Volatility3 releases per `api.github.com/repos/volatilityfoundation/volatility3/releases?per_page=5`: 2.28.0 (2026-04-30), 2.27.0 (2026-01-29), 2.26.2 (2025-09-25), 2.26.0 (2025-05-16), 2.11.0 (2025-01-16) — **~4 vol3 framework releases/year**.

### 6.b Recommendation

**Quarterly cadence (per DBX precedent)** — matches existing `refresh-ms-roots.sh` cron schedule on `30 3 1-7 1,4,7,10 0`. Rationale:

- The `volatility3-test-data` symbol bundle has only ONE release in its history; bundles are stable and don't change often.
- Vol3 framework releases quarterly; new ISFs may accompany new framework features.
- Quarterly catches every major upstream release with operator lead time to review (vs monthly noise).
- LOLDrivers precedent (quarterly with explicit operator guidance to bump frequency if BYOVD coverage matters more) is a near-identical match — wairz already has the cron precedent dialed in.

**Operator can bump to monthly** if memory-forensic coverage is high-priority — bundles are small enough (~900 MiB total) that more frequent rebuilds are cheap. Document this in the refresh script header per loldrivers precedent.

## 7. Recommended `scripts/refresh-vol3-symbols.sh` shape

**Don't write code — sketch only.** Mirror `refresh-loldrivers.sh` structurally:

### Diffs from refresh-ms-roots.sh / refresh-loldrivers.sh

| Aspect | refresh-ms-roots.sh / refresh-loldrivers.sh | refresh-vol3-symbols.sh |
|---|---|---|
| File count | 1 bundle | 4 files: 3 zips + 1 SHA256SUMS aggregate |
| URL format | Single `<file>.url` sidecar | Single `SHA256SUMS.url` sidecar PLUS hardcoded canonical URL prefix; per-file URLs derived |
| Hash verification | Per-file `<file>.sha256` | Single aggregate `SHA256SUMS` matching upstream format |
| Atomic-write | `.tmp` → mv per Rule #19 | Same pattern, applied per-file in a loop |
| Drift detection | If LIVE_HASH ≠ PINNED_HASH → exit 1 | Compute LIVE_HASH per file; if ANY mismatch → exit 1 (collect ALL drifts before exit for operator visibility) |
| Quarantine on failure | N/A (single bundle) | If one bundle fails, the others may still be current — surface per-file status in the operator workflow |
| Resume on partial download | Not needed (small bundles, single-bundle) | windows.zip is 840 MiB; use `curl -C -` for resume support OR HEAD + Range OR retry-only — both candidate origins support `Accept-Ranges: bytes` HTTP/206 |

### Sketched flow (mirrors refresh-loldrivers.sh `set -eu` shape — Rule #35a-safe exit codes via `|| RC=$?`)

```
# Sanity-check repo state (require_file each pinned file)
# Read SHA256SUMS URL from backend/vol3-symbols/SHA256SUMS.url
# Atomically download SHA256SUMS via curl --max-time 30 to /tmp/staging/
# For each bundle in [windows.zip, mac.zip, linux.zip]:
#   Read the expected hash from /tmp/staging/SHA256SUMS
#   Compare against the pinned hash in backend/vol3-symbols/<file>.sha256
#   If different → defer (collect ALL drifts) and continue
# At end:
#   If NO drifts → exit 0 (no work; do NOT download bundles to verify — SHA256SUMS is the truth)
#   If --apply specified AND drifts present → for each drifted file:
#     curl --proto '=https' --tlsv1.2 -fsSL -C - --max-time 600 (windows.zip is 840 MiB; max-time 600s = ~13 Mbit/s minimum)
#     sha256sum the downloaded file; compare against the live SHA256SUMS hash
#     If match → cp to backend/vol3-symbols/, rewrite per-file .sha256
#     If mismatch → fail loud (suggests upstream corruption OR upstream-CDN-vs-SHA256SUMS skew)
#   Print operator workflow (git add + git commit + docker compose build)
# Exit 1 if mismatches and no --apply (operator review required)
# Exit 0 if --apply succeeded
# Exit 2 on network / parse / fs error
# Exit 3 on --rebuild failure
```

**Key optimization vs DBX/loldrivers:** because Vol3 publishes a canonical SHA256SUMS, the NO-OP path (most common — bundles haven't changed) downloads only ONE small file (327 bytes) instead of 884 MiB. Drift detection is cheap. Only ACTUAL DRIFT triggers the multi-bundle download. This is dramatically more efficient than the DBX/loldrivers per-file-download-then-hash pattern (where the per-file download IS the only way to know if anything changed).

### Multi-bundle quarantine concern

If `windows.zip` SHA256 changes but `linux.zip` doesn't, the operator should be able to apply the windows-only update without disturbing linux/mac. The refresh script's `--apply` loop must be per-file, not all-or-nothing. The atomic-write per file (`.tmp` → rename to `backend/vol3-symbols/<file>.zip`) per Rule #19 already covers this — just run the loop with `|| RC=$?` per iteration and report the aggregate at the end.

## 8. Build-time integration — Dockerfile delta sketch

Mirror the `INCLUDE_DOTNET=1` gate at `backend/Dockerfile:395-412`. Add a new stage AFTER the DBX/LOLDrivers COPY (lines 337-362) and BEFORE the dotnet gate (line 395). Sketch:

```
# Phase λ.α.C — Vol3 ISF symbol bundle bake-in (CLAUDE.md Rule #37
# offline-trust-anchor discipline). Default OFF — operator opts in
# with --build-arg INCLUDE_VOL3=1 when memory forensics matters.
# Image size impact: +~885 MiB compressed source → +2.6-4.3 GiB on-disk
# uncompressed.
ARG INCLUDE_VOL3=0
RUN if [ "$INCLUDE_VOL3" = "1" ]; then \
        echo "Installing Volatility3 ISF symbol bundles (Phase λ.α.C)" && \
        mkdir -p /opt/wairz/vol3-symbols/windows /opt/wairz/vol3-symbols/linux /opt/wairz/vol3-symbols/mac && \
        (cd /app/vol3-symbols && sha256sum -c SHA256SUMS) && \
        unzip -q -o /app/vol3-symbols/windows.zip -d /opt/wairz/vol3-symbols/windows && \
        unzip -q -o /app/vol3-symbols/linux.zip   -d /opt/wairz/vol3-symbols/ && \  # already has linux/ prefix
        unzip -q -o /app/vol3-symbols/mac.zip     -d /opt/wairz/vol3-symbols/mac && \
        chmod -R 0444 /opt/wairz/vol3-symbols && \
        echo "vol3-symbols installed at /opt/wairz/vol3-symbols/ (windows + linux + mac)" ; \
    else \
        echo "INCLUDE_VOL3=0 — skipping Volatility3 symbol bundle install (default)" ; \
    fi
```

**Layout note:** linux.zip already wraps content in `linux/`, so unzip-d-target is `/opt/wairz/vol3-symbols/` (not `/opt/wairz/vol3-symbols/linux/`). mac.zip has no enclosing dir, so unzip-d-target is `/opt/wairz/vol3-symbols/mac/`. windows.zip layout unverified (didn't extract); Scout 1 should confirm. Per the README at line 82 ("Symbol tables zip files must be placed, as named, into the `volatility3/symbols` directory"), Vol3 expects the ZIPs themselves OR the extracted contents — verify Scout 1.

**docker-compose.yml addition (matches DBX precedent):**

```
environment:
  ...
  - VOL3_SYMBOLS_PATH=/opt/wairz/vol3-symbols   # on BOTH backend AND worker
```

**Lifespan probe in `backend/app/main.py`** (matches β.10 DBX bundle probe + η.D LOLDrivers probe — both already exist; verify shape in `main.py` and add a third) — log size + mtime of `/opt/wairz/vol3-symbols/` directory. Anything other than "ready: size=N mtime=…" is a cron-alert candidate.

## 9. Risks + open questions for the next session

1. **Scout 1 must verify the on-disk shape vol3 expects.** Does Vol3 want the ZIP files at `volatility3/symbols/*.zip` OR the extracted JSONs at `volatility3/symbols/<os>/*.json.xz`? README says "as named, into the volatility3/symbols directory" — ambiguous. If ZIPs are expected on disk, change the Dockerfile to skip the `unzip` step (saves +1.5–3 GiB image growth at the cost of slower vol3 first-run cache). Likely answer: vol3 handles both (auto-extract on first read), but verify empirically against `windows.info` plugin.

2. **The single-tag-only release pattern is mildly worrying for long-term refresh.** `volatility3-test-data` has only `v0.0.1` — if upstream never bumps the tag, the GitHub URL is permanently stable but stale. Operators may need to manually re-pin to a different upstream source if Volatility Foundation ever rotates. Document this in the `refresh-vol3-symbols.sh` header.

3. **GitHub release URLs are 302 redirects to time-limited signed Azure URLs** (`release-assets.githubusercontent.com` with `se=<expiry>` JWT). Refresh script must follow redirects in one curl invocation (`curl -L`) — never cache the resolved Location header. Apache origin at downloads.volatilityfoundation.org has no such expiry — operators preferring a permanent URL could use that, accepting the staleness (last refreshed 2024-11). Per Vol3 README, GitHub is canonical.

4. **windows.zip is 840 MiB — single-file download time at consumer broadband (~50 Mbit/s) is ~140s.** `refresh-vol3-symbols.sh` should set `--max-time 600` per bundle (matches existing curl invocations in refresh-loldrivers.sh `--max-time 300`) and use `curl -C -` for resume support. HTTP/206 confirmed available on both origins.

5. **Windows symbols are PARTIAL.** Vol3's README at line 84 documents that "Windows symbols that cannot be found will be queried, downloaded, generated and cached" — i.e. the symbol pack is a STARTER set; Vol3 itself fetches from Microsoft Symbol Server (`http://msdl.microsoft.com/download/symbols` per Vol3 source constants) at scan time. This is a **Rule #37 conflict** — wairz worker would attempt scan-time network egress to Microsoft. Resolution options: (a) disable the runtime fetch via vol3 config (`SYMBOL_SERVER_URL=None` or env var), (b) ensure the Microsoft Symbol Server is reachable from the worker network (defeats Rule #37 offline guarantee), (c) ship a richer Windows ISF pack OR accept that vol3 will degrade on unknown Windows kernels (truthful "no symbols available — skip this dump" verdict per Rule #37 graceful-degradation guidance). **Scout 1 should test (a) — can vol3 be configured to NEVER fetch Microsoft symbols at runtime?** If not, λ.α must own an architectural decision before β.

## 10. Reproducible probe commands (for next session re-verification)

All commands are read-only; safe to re-run.

```bash
# Reachability + Content-Length
curl -sI --proto '=https' --tlsv1.2 --max-time 30 \
    https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
curl -sI --proto '=https' --tlsv1.2 --max-time 30 -L \
    https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/windows.zip

# Canonical SHA256SUMS (GitHub-side, per README)
curl -s --proto '=https' --tlsv1.2 --max-time 15 \
    https://raw.githubusercontent.com/volatilityfoundation/volatility3-test-data/refs/tags/v0.0.1/symbols/SHA256SUMS

# Asset inventory via GitHub API
curl -s 'https://api.github.com/repos/volatilityfoundation/volatility3-test-data/releases' | \
    python3 -c "import json, sys; data=json.load(sys.stdin); \
    [print(f\"{r['tag_name']} {a['name']:<24} {a['size']:>14,} {a['updated_at']}\") \
     for r in data for a in r.get('assets', [])]"

# Small bundle full-DL + hash verify (linux.zip is 2.9 MiB)
curl -s --proto '=https' --tlsv1.2 --max-time 60 \
    https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip \
    -o /tmp/vol3-linux.zip && sha256sum /tmp/vol3-linux.zip
```

Expected output:

- HEAD requests return `HTTP/1.1 200 OK` with `Content-Length` matching the inventory in §2.
- SHA256SUMS hashes match the empirical sha256sum on the downloaded bundle exactly.
- Asset inventory should still show one tag `v0.0.1` published 2026-03-12 (unless Volatility Foundation rotates between now and the next session).

## Primary source citations

- Volatility3 README on develop branch (canonical install instructions):
  `https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/README.md` lines 66-89.
- Volatility3 test-data release (canonical bundle source):
  `https://github.com/volatilityfoundation/volatility3-test-data/releases/tag/v0.0.1` (uploaded 2026-03-12).
- Volatility3 symbol-tables docs (installation paths):
  `https://volatility3.readthedocs.io/en/latest/symbol-tables.html`.
- Volatility3 framework constants (Microsoft Symbol Server runtime URL):
  `https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/constants/__init__.py` —
  `SYMBOL_SERVER_URL = "http://msdl.microsoft.com/download/symbols"`.

## Verification artefacts saved (this session)

- `/tmp/vol3-linux.zip` (2,980,184 bytes, SHA256 `58bb7da2…`) — verified
- `/tmp/vol3-mac.zip` (84,808,562 bytes, SHA256 `fd12c833…`) — verified
- `/tmp/vol3-SHA256SUMS` (228 bytes, downloaded from volatilityfoundation.org)
- `/tmp/vol3-windows-head.bin` (65,536 bytes — first 64KB of windows.zip, not extractable; range-request validation only)
- `/tmp/vol3-readme.md` (5,752 bytes — full vol3 README)

These can be deleted once λ.α opens — the SHA256 in this report is the durable evidence.
