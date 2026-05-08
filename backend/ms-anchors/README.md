# Microsoft trust anchors (Phase β.10)

Build-time assets bundled into the wairz worker image so DBX revocation
matching runs **fully offline** at scan time. Per CLAUDE.md Rule #37
candidate (offline-trust-anchor discipline): NO network fetch when the
worker handles a firmware; ALL trust anchors land here at image-build
time and are COPY'd into `/opt/wairz/`.

## Files

| File | Purpose |
|------|---------|
| `dbxupdate.bin` | Microsoft UEFI Secure Boot revocation list (x86_64). The canonical authenticated-variable bundle Microsoft publishes through https://github.com/microsoft/secureboot_objects (UEFI Forum redirected operators here in 2024). Contains the EFI_VARIABLE_AUTHENTICATION_2 wrapper + EFI_SIGNATURE_LIST array. Consumed by `app.services.dbx_service.match_dbx_revocation` after the wrapper is auto-stripped on load. |
| `dbxupdate.bin.sha256` | `sha256sum`-format pin: `<hash>  dbxupdate.bin`. Verified at Docker build time and by `scripts/refresh-ms-roots.sh`. A drift between the live Microsoft bundle and this pin signals a new revocation list; the cron exits non-zero and the operator must review + update the pin. |
| `dbxupdate.bin.url` | Canonical source URL — single line. Read by `scripts/refresh-ms-roots.sh` so the script doesn't hardcode the URL. |

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

Quarterly, via `scripts/refresh-ms-roots.sh` (see that script's
docstring for cron-line guidance and operator workflow). The script
exits non-zero on SHA256 drift so the cron alert fires.

## Bootstrap procedure (operator instructions for new wairz checkouts)

These files are checked into the repo. A fresh `git clone` already has
them — no bootstrap is required. The Dockerfile `COPY` + `sha256sum -c`
verifies on every build.

If the SHA256 pin is invalidated (Microsoft published a new bundle),
follow the operator workflow printed by `scripts/refresh-ms-roots.sh`.
