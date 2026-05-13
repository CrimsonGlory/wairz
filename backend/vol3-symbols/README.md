# Vol3 ISF symbol bundles — wairz λ.α.C bake-at-build directory

This directory holds Volatility 3 ISF (Intermediate Symbol File) symbol
bundles, baked into the wairz worker / backend image at build time per
CLAUDE.md Rule #37 (offline-trust-anchor discipline). The runtime Vol3
invocation in `app.services.vol3_runner` (λ.α.D) passes `--offline` to
the `vol` binary so NO scan-time network fetch happens — the bundle
must be present in-image at build time.

## What lives here

```
backend/vol3-symbols/
├── README.md               ← this file (always present, tracked in git)
├── SHA256SUMS              ← upstream-published hash aggregate (pinned)
├── SHA256SUMS.url          ← canonical URL the SHA256SUMS came from
├── windows.zip             ← ~840 MiB compressed, populated by refresh script (NOT in git)
├── linux.zip               ← ~2.9 MiB compressed (NOT in git)
└── mac.zip                 ← ~81 MiB compressed (NOT in git)
```

The three `.zip` archives are **NOT** committed to git (see top-level
`.gitignore`). They are downloaded + verified by
`scripts/refresh-vol3-symbols.sh` on the BUILD HOST before
`docker compose build --build-arg INCLUDE_VOL3=1`.

`SHA256SUMS` itself **IS** committed — it carries the pinned hashes the
build verifies against. Hash drift between commit and host bundles is
the integrity check that catches both upstream rotations + accidental
host contamination.

## Canonical upstream source

GitHub release:
`https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/`

Files served:
- `windows.zip`
- `linux.zip`
- `mac.zip`
- `SHA256SUMS`

The Volatility Foundation publishes a `SHA256SUMS` aggregate in the
canonical `sha256sum`-compatible format (`<hash>  <filename>` with TWO
spaces) — drop it directly into this directory and `sha256sum -c
SHA256SUMS` works natively. No GPG signature, but the SHA256SUMS-on-GitHub
trust anchor is parity with the LOLDrivers + Microsoft Authenticode
patterns wairz already uses for `backend/ms-anchors/`.

The `downloads.volatilityfoundation.org/volatility3/symbols/` Apache
mirror serves byte-identical content but is stale (last refreshed
2024-11 per λ Scout 2's 2026-05-13 audit). **Use the GitHub URL.**

## Refresh cadence

Quarterly, matching the DBX + LOLDrivers refresh schedule. Run:

```
scripts/refresh-vol3-symbols.sh --probe-only   # check upstream for drift
scripts/refresh-vol3-symbols.sh --apply        # download + verify + write
docker compose build --build-arg INCLUDE_VOL3=1 worker backend migrator
```

`--probe-only` exits non-zero on drift so a host-side cron can alert.

The `volatility3-test-data` GitHub release has only ONE tag (`v0.0.1`)
as of 2026-05-13 — bundles are stable. If upstream rotates the tag
URL, the refresh script needs a one-line `--apply --tag <new>` flag.

## Build-time integration

`backend/Dockerfile` carries an `ARG INCLUDE_VOL3=0` gate. With
`INCLUDE_VOL3=1`:

1. `volatility3==2.28.0[full]` pip-installs into `/app/.venv/`.
2. If `SHA256SUMS` is present in this directory, `sha256sum -c` verifies
   each `.zip` against the pinned hash.
3. Each `.zip` is `unzip`'d into `/opt/wairz/vol3-symbols/` with the
   layout Vol3 expects:
   - `windows.zip` → `/opt/wairz/vol3-symbols/windows/<file>.json.xz`
   - `linux.zip` already wraps in `linux/`; unzip target is the parent
   - `mac.zip` has no wrapping dir; unzip target is `mac/`
4. The runtime path `/opt/wairz/vol3-symbols/` is owned by `wairz:wairz`,
   readable by all (chmod 0444 on files), and surfaced to the runtime
   via the `VOL3_SYMBOLS_PATH` env var in `docker-compose.yml`.

If `SHA256SUMS` is absent (i.e. bundles haven't been fetched yet), the
build logs a clear warning and proceeds — the pip install completes,
the symbols directory exists but is empty, and λ.α.D's vol3_runner
will return graceful "no symbols available; rebuild with refreshed
bundles" errors per Rule #37 truthful-degradation guidance.

## Image-size budget

Bundles are NOT committed to git but consume image-layer space at build:

| Bundle | Compressed | Extracted (approx) |
|--------|-----------:|-------------------:|
| `windows.zip` | 840 MiB | ~3 GiB |
| `linux.zip` | 2.9 MiB | ~10 MiB |
| `mac.zip` | 81 MiB | ~270 MiB |
| **Total** | **~924 MiB** | **~3.3 GiB** |

The slim wairz worker baseline is ~6.4 GiB; INCLUDE_VOL3=1 grows it
to ~10 GiB. INCLUDE_VOL3=0 (default) leaves it unchanged.

## Per-CLAUDE.md cross-references

- Rule #36 (no-execute) — Vol3 parses images AS DATA; never invokes
  binaries inside an image.
- Rule #37 (offline-trust-anchor) — symbol bundles baked at build,
  pinned via SHA256SUMS, refreshed quarterly via the companion script.
- Rule #25 (per-piece commits) — refresh-vol3-symbols.sh ships as
  its own commit; bundle updates ship as one commit each (per-file
  per Scout 2's recommendation).
