# Patterns: Windows-Coverage God-Mode β.10 + β.13 (2026-05-08)

> Extracted: 2026-05-08
> Campaign: `.planning/intake/windows-coverage-godmode-2026-05-07.md`
> Postmortem: `.planning/postmortems/postmortem-windows-coverage-godmode-beta10-beta13-2026-05-08.md`
> Branch: `feat/windows-coverage-godmode-2026-05-07`
> Commits in scope: `856b640` (β.10 bundle MS DBX + EFI auth-var wrapper strip), `f80d606` (β.13 promote Rule #36 + Rule #37 to canonical CLAUDE.md + .mex mirror)
> Status: 2 sub-tasks completed; campaign as a whole IN PROGRESS (β.11 frontend, β.12 findings extension, β.14 cut-over remain)

This is an incremental extraction layered on top of:
- `windows-coverage-godmode-2026-05-07-{patterns,antipatterns}.md` (α + β.1-β.4)
- `windows-coverage-godmode-beta5-beta6-2026-05-08-{patterns,antipatterns}.md` (β.5-β.6 delta)
- `windows-coverage-godmode-beta7-2026-05-08-{patterns,antipatterns}.md` (β.7 delta + α.3 cleanup)
- `windows-coverage-godmode-beta8-beta9-2026-05-08-{patterns,antipatterns}.md` (β.8-β.9 delta)

Patterns already captured there are not re-stated; this file captures
only the β.10/β.13-delta learnings.

## Successful Patterns

### 1. Rule #19 evidence-first applied to binary-format verification

- **Description:** Before writing parser-extension code for a third-party
  binary asset (here: Microsoft's `DBXUpdate.bin`), do a one-second
  `xxd <file> | head` + Python struct-decode probe of the freshly-
  downloaded asset. The probe surfaces the actual on-disk format,
  which may differ from what synthetic test fixtures or upstream
  documentation suggest. β.7's parser was built against synthetic bare
  EFI_SIGNATURE_LIST fixtures; the real Microsoft bundle has an outer
  3337-byte EFI_VARIABLE_AUTHENTICATION_2 wrapper that β.7 had no
  awareness of. The 1-minute evidence-first probe surfaced the
  wrapper before β.10's Dockerfile delta + rebuild cycle had committed
  to the bundle's working shape.
- **Evidence:** β.10 commit `856b640`. Postmortem section "What Broke
  #1": `xxd dbxupdate.bin | head` decoded bytes 0..15 as EFI_TIME
  (year=2010 = Microsoft signing-cert validity-start), bytes 16..23
  as WIN_CERTIFICATE (dwLength=3321, wType=0x0EF1 = WIN_CERT_TYPE_EFI_GUID).
  Combined with `EFI_CERT_X509_GUID first offset = 0` search returning
  empty + `EFI_CERT_SHA256_GUID first offset = 3337` returning
  `wrapper_size_diff = 0`, the format was unambiguous.
- **Applies when:** Bundling any third-party binary asset that needs
  to be parsed by an existing in-tree parser. The discipline:
  (1) download the live asset; (2) parse it locally with the existing
  parser; (3) inspect entries-extracted; (4) if entries == 0 OR shape
  doesn't match expectations, run `xxd | head` + struct-decode of the
  first 64-128 bytes BEFORE writing Dockerfile-delta code. Cost:
  ~1 minute. Avoids: a 5-10 min rebuild + smoke + diagnostic loop on
  production data + ~30+ min post-ship debugging when an operator
  notices the silently-degraded behaviour. Companion to Rule #19 (the
  evidence-first generalisation: spec describes intent, the data
  describes truth) and Rule #6 (CLI-flag verification — same shape:
  never assume the surface; measure with real data). Three independent
  applications of Rule #19 to different problem shapes (DB conditions,
  source-tree iteration columns, third-party binary formats); the
  pattern's generalisation is durable.

### 2. Atomic-write pattern with `.tmp` + rename + trap-on-EXIT cleanup

- **Description:** `scripts/refresh-ms-roots.sh` downloads to
  `/tmp/refresh-ms-roots.XXXXXX/dbxupdate.bin.tmp` (mktemp-suffixed),
  computes SHA256, atomic-renames `.tmp → .bin` ONLY when the
  hash-verify passes. `trap 'rm -rf "$STAGING_DIR"' EXIT` ensures
  partial downloads / failed verifications / panic exits all clean up
  the staging directory without leaking. The atomic-rename within the
  same filesystem is the durable guarantee — no consumer ever sees a
  half-written file at the canonical path.
- **Evidence:** β.10 commit `856b640`,
  `scripts/refresh-ms-roots.sh:91-103`. Tested via `--quiet` smoke
  (exit 0, no stderr); default-path smoke shows MATCH cleanly.
- **Applies when:** Any host-side script that fetches a remote artifact
  + verifies it + writes it to a known location. The 4-bullet contract:
  (a) download to a `.tmp` suffix in a mktemp staging dir;
  (b) verify integrity (SHA256, signature, parseability) BEFORE the
  rename; (c) atomic-rename within the same filesystem on verify-pass;
  (d) trap-on-EXIT cleanup of the staging dir. Companion to Rule #19
  (atomic-write discipline) — generalises from "alembic migration via
  docker cp" to "host-side cron download". The wider pattern is
  "consumer never sees an intermediate state".

### 3. Build-time SHA256 pin via sidecar text file

- **Description:** `backend/ms-anchors/dbxupdate.bin.sha256` is a
  `sha256sum`-format file (`<hash>  <filename>` on one line). Read by
  the Dockerfile's `RUN cd /app/ms-anchors && sha256sum -c
  dbxupdate.bin.sha256` step — build fails LOUDLY on hash mismatch
  (corrupted commit OR Microsoft publishing a new revision both
  surface at build time). The pin lives in a sidecar (not Dockerfile
  ARG) so the refresh script can read + write it without dockerfile
  edits, and `git diff backend/ms-anchors/dbxupdate.bin.sha256`
  surfaces a single-line change for review.
- **Evidence:** β.10 commit `856b640`,
  `backend/Dockerfile:319-336`,
  `backend/ms-anchors/dbxupdate.bin.sha256` (single line:
  `74df077175dca7ff8bcd27ce8285656e38097803f803e2d124467273699e4b17  dbxupdate.bin`).
  `scripts/refresh-ms-roots.sh` reads via `awk '{print $1}'` for
  comparison + (in --apply mode) re-runs `sha256sum dbxupdate.bin >
  dbxupdate.bin.sha256` to update.
- **Applies when:** Any build-time-pinned binary asset (trust anchor,
  precompiled binary, model file, kernel image). Sidecar format
  (`<hash>  <filename>`) is preferred over Dockerfile ARG because:
  (a) it's git-tracked + diff-friendly; (b) sha256sum -c is a
  one-liner integrity check; (c) refresh tooling can read + write
  the same format; (d) clearly separates "what's pinned" from "how
  it's bundled". Companion to Rule #25 (per-sub-task commits — a
  pin update is its own commit shape) and Rule #37 (offline-trust-
  anchor — sidecar is the canonical pin shape).

### 4. Conservative shape-detecting wrapper-strip helper

- **Description:** `_strip_authenticated_variable_wrapper(buf)` returns
  `buf` unchanged on ANY heuristic-failure path. Bare-format synthetic
  fixtures (β.7 shape) pass through unmolested; only real Microsoft-
  canonical bundles trigger the strip. The year-range check
  (`year ∈ [1900, 2100]`) is the durable disambiguator: bare fixtures
  start with EFI_CERT_X509_GUID (`a1 59` → year=0xA159=41305 — outside
  window) or EFI_CERT_SHA256_GUID (`26 16` → year=0x1626=5670 — outside
  window). Even if `wType` happened to look like 0x0EF1 by coincidence,
  the year-check rules out false-positive strip on synthetic input.
- **Evidence:** β.10 commit `856b640`,
  `backend/app/services/dbx_service.py:_strip_authenticated_variable_wrapper`.
  Test `test_strip_wrapper_returns_buf_unchanged_for_bare_signature_list`
  + `test_strip_wrapper_strips_microsoft_canonical_shape` enforce both
  directions.
- **Applies when:** Adding a format-detection helper that must
  distinguish two coexisting on-disk shapes (canonical wrapped vs.
  bare; or v1 vs v2 of an evolving format). The conservative-on-failure
  discipline: when ANY heuristic check fails, return the input
  unchanged + let the downstream parser handle malformed input via
  its existing graceful-degradation path. Avoid the "aggressive strip
  + rely on parser to handle the result" failure mode where
  legitimate-but-unusual inputs get mangled by an over-eager helper.
  Pattern Three of Three: at the third format-helper in this campaign
  (β.5 RICH-header, β.6 ARM64EC/X arch detect, β.10 EFI auth-var
  wrapper), the conservative-on-failure shape is durable.

### 5. Worked-example-first rule promotion (Rule #36 + #37)

- **Description:** Rule #36 promoted to canonical CLAUDE.md AFTER 4
  worked examples (α.2 unpack_msi `508feca`, α.2.4 unpack_msu
  `8086c32`, α.2.6 unpack_driver_package `8516fa2`, α.2.7 unpack_vhdx
  `b9d124d`). Rule #37 promoted AFTER 2 worked examples (β.4 signify-
  bundles-MS-roots `d12f64e`, β.10 dbx bundle `856b640`). Both rules
  reference their worked examples explicitly — operators reading the
  rule in CLAUDE.md can `git show <hash>` the worked code. Avoiding
  the inverse failure mode (write rule, then implement once) where the
  rule's mechanical guidance is speculative and may not match what
  the codebase actually wants to do.
- **Evidence:** β.13 commit `f80d606`, `CLAUDE.md` lines 368-410
  (Rule #36) + 388-410 (Rule #37). Both rules' "Worked examples"
  sections list the commit hashes; both have "Promoted from … at the
  end of Phase β.10, codifying what the campaign already practiced."
- **Applies when:** Promoting a learned discipline to a permanent
  rule. Two-of-three rules: minimum 2 worked examples (Rule #37);
  preferred 3+ worked examples (Rule #36 has 4). Sub-clauses of an
  existing rule (e.g. Rule #35a's pipe-trap + set-e-trap as siblings)
  can be added with single-incident evidence since they generalise an
  established rule. Companion to Rule #21 (mirror discipline — the
  rule promotion includes the .mex/context/conventions.md Verify
  Checklist update IN THE SAME COMMIT) and Rule #25 (per-sub-task
  commits — rule promotion is its own sub-task).

### 6. Backend lifespan startup probe with WARNING-on-missing graceful degrade

- **Description:** `main.py` lifespan logs `DBX bundle ready: path=…
  size=… mtime=…` when `/opt/wairz/dbxupdate.bin` is present + readable;
  logs a WARNING (not an exit) when missing. wairz keeps booting and
  serving requests; only DBX-revocation matching silently degrades to
  `dbx_revoked=False` for every PE. Operators grep
  `docker compose logs backend | grep "DBX bundle"` to confirm the
  bundle survived the build / cron-refresh schedule held.
- **Evidence:** β.10 commit `856b640`, `backend/app/main.py:143-176`
  (lifespan probe block). Verified post-rebuild: log line surfaced
  cleanly with size=24053 + mtime=2026-05-08T16:56:35.570603+00:00.
- **Applies when:** Any build-time-bundled asset that's a hardening
  signal (not a critical-path dependency). The discipline:
  (a) lifespan probe runs on every backend boot;
  (b) presence + size + mtime logged so operators have a reproducible
  signal;
  (c) WARNING (not exit) on missing — partial-functionality is
  preferred over hard-fail when the missing asset is degradation-
  acceptable;
  (d) consuming service handles missing gracefully (returns truthful
  "no info" verdict, NOT fabricated answer). Companion to Rule #37
  (offline-trust-anchor's "graceful WARNING-degrade" sub-clause is
  the worked example for this pattern) and Rule #19 (evidence-first
  — the probe IS the evidence-first probe at runtime).

### 7. Test fixture pair: bare + wrapped, both committed, both regenerable

- **Description:** `backend/tests/fixtures/windows/tiny.dbxupdate.bin`
  (1024 B bare β.7 shape) + `backend/tests/fixtures/windows/tiny.dbxupdate.wrapped.bin`
  (1128 B wrapped β.10 shape) cover BOTH code paths in
  `_load_bundle → _strip_authenticated_variable_wrapper → _parse_bundle_bytes`.
  `_build_tiny_dbxupdate.py` regeneration script lives next to the
  fixtures; future contributors can re-run after dbx_service changes
  (e.g. adding a new EFI signature-list type). Underscore prefix marks
  the script as a utility, not a pytest target.
- **Evidence:** β.10 commit `856b640`,
  `backend/tests/fixtures/windows/{__init__.py, _build_tiny_dbxupdate.py,
  tiny.dbxupdate.bin, tiny.dbxupdate.wrapped.bin}`. Tests
  `test_committed_tiny_fixture_bare_parses_cleanly` +
  `test_committed_tiny_fixture_wrapped_parses_cleanly` exercise the
  file-on-disk path with deterministic structural assertions
  (entries ≥ 3, expected serials present) — NOT byte-equality (RSA
  keys are fresh per regeneration).
- **Applies when:** A parser handles two coexisting on-disk shapes
  (or a format with multiple variants). Ship one committed fixture
  per shape + a single generator script that produces all of them.
  The generator's deterministic content (apart from the cryptographic
  primitives that legitimately vary per-run) is the contract — tests
  assert structural properties, not bytes. Companion to Rule #4
  (verdict-mirror — same single-source-of-truth reasoning, but for
  test fixtures + generator script).

### 8. Pinned URL sidecar (`<file>.url`)

- **Description:** `backend/ms-anchors/dbxupdate.bin.url` is a single-
  line text file containing the canonical source URL. Refresh script
  reads via `head -n1`. URL is never hardcoded in the script or
  Dockerfile; an operator can update via a single-line edit if
  Microsoft moves the path (e.g. github.com/microsoft/secureboot_objects
  reorganises the directory structure).
- **Evidence:** β.10 commit `856b640`,
  `backend/ms-anchors/dbxupdate.bin.url` (single line:
  `https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/DBX/amd64/DBXUpdate.bin`).
  `scripts/refresh-ms-roots.sh:90-91` reads via `head -n1`.
- **Applies when:** Any pinned-asset directory (`backend/ms-anchors/`,
  `backend/vendor-anchors/`, `backend/ct-anchors/`, etc.). Ship three
  sidecars per anchor: `<file>` (the binary), `<file>.sha256` (the
  pin), `<file>.url` (the canonical source). Plus a directory-level
  `README.md` documenting the refresh process. Refresh tooling reads
  all three; operators can rotate any one independently. Companion to
  Rule #37 (offline-trust-anchor — the sidecar layout IS the
  worked-example for the rule).

## Key Decisions

| # | Decision | Rationale | Outcome |
|---|----------|-----------|---------|
| 1 | Bundle x86_64 only in β.10; defer ARM64/AArch64/IA-32 | Microsoft secureboot_objects has 4 arch directories but β.10's single-bundle satisfies the 80%+ majority case (most signed PEs in firmware corpus are x86_64); expanding to multi-arch would add Dockerfile complexity (per-arch COPY + service-side arch detection) for no immediate gain | β.10 ships clean; future γ/δ work can add arch-suffixed bundle paths if firmware corpus shifts toward ARM64 |
| 2 | Wrapper-strip in dbx_service (β.7 extension), NOT pre-strip in Dockerfile | The bundled file at /opt/wairz/dbxupdate.bin remains the canonical Microsoft format (operators familiar with dbxtool / efivar / mokutil can inspect it directly); the parser handles both bare + wrapped formats; wrapper retains Microsoft's PKCS#7 signature for future signature-verify extensions | β.10 ships clean; the bundled file is interoperable with external tooling; future PKCS#7 verify can be plumbed without re-bundling |
| 3 | SHA256 pin in sidecar text file (.sha256), NOT in Dockerfile ARG | Dockerfile ARGs require build-arg flags or dockerfile edits to update; sidecar files are git-tracked + sha256sum-compatible; refresh script reads + writes the same sidecar; clearly separates "what's pinned" from "how it's bundled" | Refresh workflow is operator-friendly; --apply flag rewrites the sidecar in place; `git diff backend/ms-anchors/<file>.sha256` surfaces a single-line change for review |
| 4 | `--quiet`, `--apply`, `--rebuild` flags on refresh script | Single script supports both default check-only path (cron alert on drift) and operator-driven rebuild path (one command does the whole refresh+rebuild); reduces the number of scripts needed for the workflow | Script is end-to-end usable for the quarterly cron AND the manual refresh case; the `--help` output documents the workflow inline |
| 5 | Backend startup probe is WARNING-on-missing, not EXIT-on-missing | dbx is a hardening signal, not a critical-path dependency; missing bundle should NOT prevent wairz from booting (operators may temporarily run without it during refresh-cron-failure recovery); WARNING log line is the durable signal | Backend stays resilient; the log line gives operators an actionable signal without blocking startup |
| 6 | Generator script `_build_tiny_dbxupdate.py` lives next to the fixtures, NOT in tests/ | Generator + output stay co-located; future regenerations are obvious; `_` prefix marks it as a utility (not a pytest target) | Fixtures are reproducible; generator script's relationship to its outputs is unambiguous |
| 7 | Promote Rule #36 + Rule #37 in a SINGLE β.13 commit, NOT one per rule | Both are end-of-Phase-β codifications; they share the same evidence-first → worked-example → rule shape; both reference each other in companion-rule cross-refs; splitting into two commits would obscure the "Phase β closure" semantics | β.13 ships clean; the two rules' worked examples reinforce each other; reviewers can see both promotions in one diff |
| 8 | `_strip_authenticated_variable_wrapper` is conservative (returns buf unchanged on heuristic failure) | Bare-format synthetic fixtures must keep working; the parser already handles malformed inputs gracefully; conservative-on-failure keeps the strip helper from BREAKING anything | All 33 dbx tests pass on host; bundled-image canary activates inside worker post-rebuild; `_parse_bundle_bytes`'s existing malformed-list recovery is the downstream safety net |
| 9 | `/opt/wairz/ms-roots/` ships as empty marker dir | Signify's TRUSTED_CERTIFICATE_STORE is the functional source of MS Authenticode roots (β.4 d12f64e); β.10's job is dbx side; ms-roots/ is a future-proof slot for additional PEM roots; an empty dir is a clear "intent declared, content TBD" marker | β.10 ships without speculative PEM bundling; γ/δ can populate as needed |
| 10 | Refresh script defaults to check-only (non-zero on drift); `--apply` is opt-in | Cron schedule alerts on drift WITHOUT auto-modifying the pinned bundle (security discipline: operator must consciously update); explicit `--apply` is for operator-driven refreshes; explicit `--rebuild` is for end-to-end refresh+rebuild | Cron alerts fire when Microsoft publishes new dbx; operator reviews + applies + rebuilds in one command (`--apply --rebuild`); auto-update path requires deliberate flag |

## Cross-references back into existing knowledge

- **Pattern #1 (Rule #19 evidence-first generalised to format verification)** is the third application of Rule #19 to a different problem shape (DB conditions / source-tree iteration columns / third-party binary formats). The pattern's generalisation is durable — Rule #19 is "the data describes truth; the spec/intake describes intent". Apply at any pre-coding question whose answer is in the source tree, in production data, OR in a freshly-downloaded third-party binary.
- **Pattern #2 (atomic-write `.tmp` + rename + trap-on-EXIT)** generalises the existing "alembic via docker cp" atomic-write to host-side cron downloads. Same shape; different surface. Promote to a `.mex/patterns/atomic-write.md` recipe alongside the trust-anchor recipe (β.10 postmortem rec #1).
- **Pattern #5 (worked-example-first rule promotion)** is the durable shape for converting learned discipline to permanent rule. Two-of-three rule: minimum 2 worked examples (Rule #37); preferred 3+ (Rule #36 has 4). β.5/β.6 postmortem rec #1 ("promote Pattern #2 to `.mex/patterns/add-pe-verdict-field.md`") is now reinforced — the rule-of-N for promotion is durable across this campaign.
- **Pattern #6 (graceful-degrade WARNING-on-missing)** is the worked example for Rule #37's graceful-degrade sub-clause. The Rule #37 text says "service reads ONLY from the in-image path with graceful WARNING-degrade if missing"; β.10's main.py probe is the canonical implementation.
- **Pattern #7 (test fixture pair: bare + wrapped + generator)** generalises β.7's in-memory builder approach to committed binary fixtures. Same shape; different lifecycle (in-memory regenerates per-test; committed regenerates per-design-change).
- **Rule #25 per-sub-task commits** held under back-to-back execution again — β.10 + β.13 shipped as 2 separate commits, just as β.8 + β.9 the previous session. Pattern is now Rule-of-Six across this campaign (β.5/β.6/β.7/β.8/β.9/β.10/β.13 each its own commit).
