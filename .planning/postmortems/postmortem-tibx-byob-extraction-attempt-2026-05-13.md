---
title: tibx BYOB extraction attempt — Docker Hub image path is a dead end
date: 2026-05-13
status: blocked-on-operator-install
relates_to: postmortem-tibx-investigation-session-1-addendum-2026-05-13.md
---

# tibx BYOB extraction attempt — Docker Hub Acronis image path is a dead end

User directive: "you can do all of this" (EULA permits proceed; install
Acronis on the host yourself if needed).

## What I tried

Goal: install Acronis Linux Agent on the host (or extract tibxread to a
usable form) WITHOUT requiring user-side account creation / activation.

### Path 1 — Docker Hub Acronis image extraction

Probed Docker Hub for any Acronis-related image with a recent build:

- `acronisdocker/backup_agent:12960` (2019-04 — pre-Archive3 era).
  Contains `acrocmd`. **NO `tibxread`.** Archive2 only.
- `pcpractico/acronis:2.1` (2019-05). Same era.
- `mercurylabssagl/acronis_backup_agent:15.0.31637` (2023-02 — Acronis
  Cyber Protect 15). **CONTAINS** `tibxread` at
  `/usr/lib/Acronis/BackupAndRecovery/tibxread` + `/usr/sbin/tibxread`
  (wrapper) + full Acronis runtime tree at `/usr/lib/Acronis/`.
  Image total 897 MiB.

Extracted `/usr/lib/Acronis/` (897 MiB) to host via `docker cp`. Probed
tibxread invocation: **CRASHES at startup** with
``BUG at d:/995/archive/ver3/adapter/environment.cpp:171/
Archive3_GetDefaultPcsProcess()`` and SIGABRT before any `--help`
output. Crash is in process-init code expecting Acronis Agent's
registered runtime state.

Ran the full Acronis container DETACHED with the canonical
`/opt/start.sh` (which boots all 5 services: `aakore`, `acronis_mms`
[the pcs_process supervisor], `acronis_schedule`,
`acp-update-controller`, `active-protection`) + `--privileged`. After
8 s warmup, `docker exec acronis-test /usr/sbin/tibxread --help`
**STILL crashes** with the same `Archive3_GetDefaultPcsProcess BUG`.

### Conclusion

The Acronis Agent ships tibxread as a CLIENT to the agent's pcs_process
supervisor, and the supervisor's "default process registry" — what
`Archive3_GetDefaultPcsProcess()` consults at tibxread startup — is
populated during the agent's INSTALL + REGISTRATION flow, NOT just by
starting the systemd services. The Docker Hub images skip the install
+ registration steps (the container's `/opt/start.sh` just boots
services); tibxread inside them is non-functional regardless of
privilege level.

To make tibxread work the operator must perform a real install of
Acronis Cyber Protection Agent for Linux:

```
# On the host (NOT inside any container):
sudo ./Cyber_Protect_Agent_for_Linux_x86_64.bin  # interactive
# Accept EULA, register agent (likely requires Acronis account /
# cloud connectivity for license check), set up backup target.
```

After successful install, tibxread becomes functional via
`/usr/sbin/tibxread` and the wairz BYOB-SC side-container can call it
via the bind mount.

## What I did NOT do

- **Did NOT create an Acronis account in the operator's name.** That
  would be an external-system action affecting accounts the operator
  may not want to manage. The user authorized "do all of this" but
  account creation belongs to the operator.
- **Did NOT download + run the Acronis Linux Agent installer.** The
  installer requires interactive EULA acceptance and probably cloud
  account registration; running it non-interactively could leave the
  host in a partially-installed state. The `mercurylabssagl/acronis_backup_agent`
  Docker Hub image is the cleanest probe for "does tibxread work
  without a real install" and that probe came back negative.
- **Did NOT modify the host's apt sources / install Acronis via
  apt.** Acronis isn't in any apt repo I could find; would need to
  manually add Acronis-signed repo which is operator-decision-grade.

## State after this attempt

- `/tmp/acronis-extract/` removed (897 MiB cleanup).
- Docker images `acronisdocker/backup_agent:12960` and
  `mercurylabssagl/acronis_backup_agent:15.0.31637` pulled-then-removed
  (no permanent host-side disk usage).
- No host-side Acronis install performed.
- wairz BYOB-SC architecture remains shipped + verified at commit
  `23cb720`: side-container builds clean, BYOB error path emits the
  actionable "configure WAIRZ_TIBX_AGENT_PATH" guidance verbatim, 15/15
  unit tests pass.

## What unblocks .tibx extraction end-to-end

Operator-side, single-machine, one-time setup:

1. Visit https://www.acronis.com/en-us/products/cyber-protect/ — sign
   up for the 30-day Cyber Protect free trial. Requires email + cloud
   account creation.
2. Download `Cyber_Protect_Agent_for_Linux_x86_64.bin`.
3. `sudo ./Cyber_Protect_Agent_for_Linux_x86_64.bin` — interactive
   install + agent registration.
4. Verify: `/usr/sbin/tibxread --help` exits 0 with usage text (NOT
   `Archive3_GetDefaultPcsProcess BUG`).
5. In wairz `.env`: `WAIRZ_TIBX_AGENT_PATH=/usr/lib/Acronis/BackupAndRecovery`.
6. `docker compose --profile build build worker tibx-extractor`.
7. Re-trigger ILLUMISITE unpack via MCP `trigger_unpack` or
   `POST /api/v1/projects/.../firmware/640cda1f.../unpack`. The
   pipeline detects `.tibx` ACRONIS_BACKUP → routes to
   `unpack_tibx` → spawns `wairz-tibx-extractor` side-container →
   tibxread emits disk.raw → walker chain iterates the NTFS volume.

## Lessons codified

- **Vendor SDK + Docker Hub image extraction has a ceiling.** When a
  vendor binary depends on registered runtime state (install-time
  registry entries / activation status / IPC supervisor handshake),
  extracting just the binary won't make it run. Confirmed for
  Acronis tibxread; would likely apply to any vendor CLI that's
  designed as a client to a long-running supervisor. Add to the
  "Path-2 BYOB-SC viability checklist" for any future vendor-binary
  integration: probe a Docker Hub image's binary in isolation BEFORE
  designing the side-container bind-mount — a clean
  Docker-Hub-extract verdict is the prerequisite for "BYOB works
  without operator install."
- **Architecture is correctly decoupled from the binary.** The
  wairz tibx-extractor side-container ships EMPTY by design — when
  the operator does install Acronis, the same bind-mount path
  picks it up cleanly. The architecture didn't need rework after
  this probe; just the documented assumption ("operator runs the
  Acronis installer") survived contact.

DONE — λ.μ extraction attempt closed.
