# Offline trust anchors (Phase β.10 + Phase η.D)

Build-time assets bundled into the wairz worker image so DBX revocation
matching and LOLDrivers BYOVD fingerprinting both run **fully offline**
at scan time. Per CLAUDE.md Rule #37 (offline-trust-anchor discipline):
NO network fetch when the worker handles a firmware; ALL trust anchors
land here at image-build time and are COPY'd into `/opt/wairz/`.

## Files

| File | Purpose |
|------|---------|
| `dbxupdate.bin` | Microsoft UEFI Secure Boot revocation list (x86_64). The canonical authenticated-variable bundle Microsoft publishes through https://github.com/microsoft/secureboot_objects (UEFI Forum redirected operators here in 2024). Contains the EFI_VARIABLE_AUTHENTICATION_2 wrapper + EFI_SIGNATURE_LIST array. Consumed by `app.services.dbx_service.match_dbx_revocation` after the wrapper is auto-stripped on load. |
| `dbxupdate.bin.sha256` | `sha256sum`-format pin: `<hash>  dbxupdate.bin`. Verified at Docker build time and by `scripts/refresh-ms-roots.sh`. A drift between the live Microsoft bundle and this pin signals a new revocation list; the cron exits non-zero and the operator must review + update the pin. |
| `dbxupdate.bin.url` | Canonical source URL — single line. Read by `scripts/refresh-ms-roots.sh` so the script doesn't hardcode the URL. |
| `loldrivers.json` | LOLDrivers data set (Phase η.D BYOVD fingerprinting). 29.8 MB JSON containing 622 driver records / 2132 KnownVulnerableSamples. Each record carries SHA1 / SHA256 / MD5 / Imphash / Authentihash hashes for a known-vulnerable or known-malicious Windows kernel driver. Consumed by `app.services.loldrivers_lookup_service.lookup_driver_byovd`. Category enum: `"vulnerable driver"` (510) + `"malicious"` (112). |
| `loldrivers.json.sha256` | `sha256sum`-format pin: `<hash>  loldrivers.json`. Verified at Docker build time and by `scripts/refresh-loldrivers.sh`. Drift signals upstream regeneration; the cron exits non-zero and the operator must review + update the pin. |
| `loldrivers.json.url` | Canonical source URL — single line. Read by `scripts/refresh-loldrivers.sh`. |
| `loldrivers.LICENSE` | Apache-2.0 (full copy from `magicsword-io/LOLDrivers`). Redistribution permitted as part of derivative/composite works (incl. a Docker image) provided LICENSE + attribution NOTICE are preserved alongside. |
| `loldrivers.NOTICE` | Attribution: "LOLDrivers data set provided by magicsword-io/LOLDrivers under Apache-2.0." Required alongside `loldrivers.LICENSE` per Apache-2.0 §4. |

## Microsoft Authenticode roots (PKCS#7 chain validation)

These do **not** ship as a separate file in this directory. The
`signify` Python package (β.1, `pyproject.toml`) ships its own
`TRUSTED_CERTIFICATE_STORE` containing every Microsoft Authenticode
root signify recognises; β.4 (`d12f64e`) wired
`authenticode_service.verify_pe_file` to use that store. The Dockerfile
creates `/opt/wairz/ms-roots/` as a marker directory so operators can
drop additional PEM-format roots there for future signify-extension
work. β.10 baseline ships an empty marker; γ/δ work may extend.

## Refresh schedule

- Microsoft DBX (β.10): quarterly via `scripts/refresh-ms-roots.sh`.
  Microsoft publishes new DBXUpdate.bin revisions a few times per year.
- LOLDrivers (η.D): quarterly via `scripts/refresh-loldrivers.sh`.
  Upstream regenerates on every commit to `magicsword-io/LOLDrivers`
  (~5 commits/week, but most are metadata-only). Monthly would be more
  faithful to the upstream cadence; quarterly is the documented baseline
  with explicit operator guidance to bump frequency if BYOVD coverage
  matters more for a given deployment.

Both scripts exit non-zero on SHA256 drift so the cron alert fires.

## Bootstrap procedure (operator instructions for new wairz checkouts)

These files are checked into the repo. A fresh `git clone` already has
them — no bootstrap is required. The Dockerfile `COPY` + `sha256sum -c`
verifies on every build.

If a SHA256 pin is invalidated (Microsoft published a new DBX bundle, OR
LOLDrivers upstream regenerated), follow the operator workflow printed
by the matching refresh script.
