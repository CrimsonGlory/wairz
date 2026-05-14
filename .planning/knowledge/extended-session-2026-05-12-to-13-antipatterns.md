# Anti-patterns: extended session 2026-05-12 → 2026-05-13

> Extracted: 2026-05-13
> Postmortem: `postmortem-extended-session-2026-05-12-to-13.md`

## Failed Patterns

### 1. Building BYOB-SC architecture before probing tibxread standalone

- **What was done:** Shipped 4-commit BYOB-SC architecture
  (`767d0d6` + `69b381a` + `23cb720`) for `.tibx` extraction
  assuming operator-installed `tibxread` would work.
- **Failure mode:** Post-ship probe revealed `tibxread` crashes at
  startup (`Archive3_GetDefaultPcsProcess BUG`) even with full Acronis
  Docker Hub image running `--privileged` + all 5 services up. The
  binary requires Acronis-Agent-registered runtime state set up
  during install + cloud-dependent activation.
- **Evidence:** `postmortem-tibx-byob-extraction-attempt-2026-05-13.md`
- **How to avoid:** **Probe vendor binaries in isolation BEFORE
  designing side-container plumbing.** Specifically: extract the
  binary + its libraries from a vendor Docker Hub image, run with
  proper LD_LIBRARY_PATH, attempt the lightest command (--help). A
  clean exit on `--help` is the prerequisite for "BYOB works without
  operator install"; without it the architecture is moot. **Added to
  the Path-2 BYOB-SC viability checklist.**

### 2. Naïve BCD layout for QEMU-PE-boot probe

- **What was done:** Built a partition-less FAT32 disk image, mcopy'd
  the customer's Recovery PE files including the BCD, added a
  `startup.nsh` chain. Expected the BCD to work.
- **Failure mode:** Windows Boot Manager rejected the BCD with
  `0xc000000e`. The BCD's device-GUID references point at the
  ORIGINAL prepared-media volume; our naïve FAT had a different
  volume serial.
- **Evidence:** `probe-1-qemu-boot-results.md` + `probe-2-bcd-patch-results.md`
- **How to avoid:** Microsoft's `MakeWinPEMedia` writes the BCD with
  matching volume-GUID/serial at media-prep time. Replicating that
  on Linux is non-trivial — hivex/byte-level BCD patching is
  insufficient (cross-referenced GUIDs + suspected integrity
  hashes). Either (a) use Microsoft tooling on Windows or (b) build
  a proper UEFI hybrid ISO via xorriso `-eltorito-alt-boot -e
  efisys.bin`. Both have real engineering cost; budget accordingly.

### 3. SQLAlchemy identity-map silently caching pre-walk row

- **What was done:** Backfill script ran walkers (each in own
  `async_session_factory` session) then re-SELECTed the firmware
  row from the OUTER session to count result columns.
- **Failure mode:** Identity map returned the cached pre-walk
  instance; reported `results 0 → 0` even though DB had 21 stamps.
- **Evidence:** `2321ebe` commit message
- **How to avoid:** **`db.expire(firmware)` BEFORE the re-SELECT.**
  Rule #32 explicit EXCEPTION case where `db.refresh()` IS
  load-bearing (different session updated the row). Documented in
  the backfill script + Rule #32 body.

### 4. Git revert missed deleting an added file

- **What was done:** `9428b5f` reverted three tibx commits including
  `23cb720` which had ADDED `backend/tests/test_unpack_tibx.py`. The
  revert handled `767d0d6` + `69b381a` correctly but missed the test
  file's add.
- **Failure mode:** Working tree had an orphan test referencing a
  deleted worker; would have broken `pytest --collect-only` next
  session.
- **Evidence:** `08ec2b7` cleanup commit
- **How to avoid:** After `git revert <a..b>`, run `git diff
  <revert-target>..HEAD --stat` to verify ALL expected deletions
  fired. A test file added in commit X that wasn't deleted by the
  revert of X means the revert was incomplete.

### 5. Stale GitHub auth token surfaced silently

- **What was done:** `git push origin main` failed with 403 +
  `gh auth status` claimed "Logged in" simultaneously.
- **Failure mode:** Fine-grained PAT had `Metadata: Read` only;
  no `Contents: Write` — silent partial-permission state.
- **Evidence:** session-end push attempt
- **How to avoid:** When a `gh auth status` says "Logged in" but
  push fails 403, immediately verify token SCOPE not just
  authentication. Fine-grained PATs are per-permission; classic
  PATs are per-scope (`repo` includes write). The `gh api -X PUT
  /repos/<org>/<repo>/git/refs/heads/main` 403 test is the
  cheapest verification.

### 6. gh CLI version 2.4.0 missing `gh auth token` subcommand

- **What was done:** Shelled out `gh auth token` to inspect token
  scopes; gh 2.4.0 doesn't have that subcommand.
- **Failure mode:** `gh auth token` returned the gh help text
  ("unknown command 'token'") which got embedded as a "token" in
  curl Authorization header.
- **Evidence:** session-end auth-debug
- **How to avoid:** Use the canonical `gh auth git-credential get`
  shell-fed protocol to retrieve credentials. Or check `gh --version`
  before shelling out new subcommands.

### 7. Acronis Docker Hub image extraction-only path is structurally
incomplete

- **What was done:** Pulled `mercurylabssagl/acronis_backup_agent:15.0.31637`,
  extracted `/usr/lib/Acronis/` (897 MiB), expected `tibxread` to be
  runnable standalone.
- **Failure mode:** Vendor binary depends on registered runtime state
  set up during the agent's install + activation flow. Service
  startup alone is insufficient.
- **Evidence:** `postmortem-tibx-byob-extraction-attempt-2026-05-13.md`
- **How to avoid:** When extracting a vendor binary from a Docker Hub
  image, verify it CAN RUN STANDALONE in isolation BEFORE designing a
  BYOB side-container around it. Some vendor binaries are clients to
  install-time-registered supervisors; service-startup-in-container
  is not enough. Codified as Path-2 BYOB-SC viability checklist
  prerequisite.

## Quality rule candidates (none promoted)

The patterns above are SHAPE-discipline / mechanical-reflex patterns;
regex auto-enforcement would have too many false positives. The closest
candidate is a hook that flags `gh auth token` invocations in shell
scripts (Anti-pattern #6) — but that's a one-off until gh upgrades.
