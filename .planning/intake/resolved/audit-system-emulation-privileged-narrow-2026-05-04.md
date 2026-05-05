---
title: "system-emulation container privilege over-provisioned — replace privileged: true with cap-add"
status: pending
priority: high
target: docker-compose.yml + emulation/Dockerfile
---

## Description

`docker-compose.yml` declares `privileged: true` on the system-emulation service, despite the `emulation/Dockerfile` containing a comment listing the narrower capability set that would suffice: `NET_ADMIN + SYS_ADMIN + MKNOD + /dev/net/tun`.

`privileged: true` grants ALL capabilities + access to all host devices + relaxes seccomp/apparmor. For a container that runs untrusted firmware code under QEMU, this is the highest-impact reduction the audit identified. The Dockerfile comment proves the narrow set has already been thought through — it just hasn't been wired into compose.

**Evidence:** Stream H (F-H-03).

## Acceptance Criteria

- [ ] Replace `privileged: true` in `docker-compose.yml` system-emulation service with:
  ```yaml
  cap_add:
    - NET_ADMIN
    - SYS_ADMIN
    - MKNOD
  devices:
    - /dev/net/tun:/dev/net/tun
  ```
- [ ] Smoke: a known-good firmware system-mode emulation start succeeds end-to-end (the `firmae` startup sequence depends on `/dev/net/tun` and `mknod` for tap creation).
- [ ] If a missing capability surfaces, add it ONE AT A TIME and document why in the compose comment. Do NOT revert to `privileged: true` to "see if it works".
- [ ] Update CLAUDE.md / `.mex/context/architecture.md` "Containers" section to document the cap-add set.

## Out of Scope

- User-mode emulation container (already runs unprivileged).
- Replacing seccomp/apparmor profile (separate hardening intake).

## Cross-step

Single commit `fix(infra): narrow system-emulation cap set, drop privileged: true`. Verify against a smoke test before merge.

## Provenance

Audit campaign `audit-2026-05-04`. Discovery file: `.planning/discoveries/audit-stream-h-infra-2026-05-04.md` finding F-H-03.
