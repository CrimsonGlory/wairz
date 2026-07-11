# Wairz Enterprise — Full Manual Test

An end-to-end acceptance pass for a fresh cloud deployment: stand it up with a
custom domain + Cognito auth + remote MCP, exercise every user-facing path
(SPA login, user onboarding, firmware analysis, Claude-over-MCP, heavy Ghidra
compute, multi-user), spot-check the security posture, then tear down clean.

Work top to bottom; each step has an **Expect** line so it doubles as a pass/fail
checklist. Commands assume you run from `enterprise/terraform/` with your AWS
profile/region set (examples use `AWS_PROFILE=default`, `us-east-1`). See
`RUNBOOK.md` for the reference details behind each step.

---

## 0. Prerequisites

- [ ] AWS account + credentials; Docker (buildx), Node/npm, AWS CLI, Terraform ≥ 1.6 on the host.
- [ ] A Route53 hosted zone you own (for the custom domain + ACM validation).
- [ ] Claude Code (for the MCP path), Python 3.9+ (for the token helper).
- [ ] A small test firmware image (e.g. an OpenWrt or DVRF build — see root `CLAUDE.md` → Testing Firmware).

---

## 1. Configure + deploy

Edit `terraform.tfvars`:

```hcl
domain_name      = "wairz.example.com"   # a name in your hosted zone
route53_zone_id  = "Z0123456789ABCDEF"
auth_enabled     = true
mcp_http_enabled = true
```

Seed your login (declarative): copy `users.yaml.example` → `users.yaml`, add your email:

```yaml
- email: you@example.com
  name: Your Name
```

Deploy:

```bash
AWS_PROFILE=default terraform apply
```

- [ ] **Expect:** apply completes (~30–40 min, CloudFront is the long pole), builds + pushes the image, publishes the SPA. No errors.
- [ ] Capture outputs: `terraform output` — note `app_url`, `mcp_url`, `cognito_user_pool_id`, `cognito_app_client_id`, `cognito_hosted_ui_domain`, `cognito_seeded_users`, `dashboard_name`.
- [ ] **Expect:** `cognito_seeded_users` lists your email.

---

## 2. Infrastructure health

```bash
# DNS + cert + SPA
dig +short wairz.example.com            # → CloudFront IPs
curl -s -o /dev/null -w "%{http_code}\n" https://wairz.example.com/        # 200
# API requires auth now
curl -s -o /dev/null -w "%{http_code}\n" https://wairz.example.com/api/v1/projects   # 401
```

- [ ] **Expect:** DNS resolves to CloudFront; SPA `200`; unauthenticated API `401`.
- [ ] ECS: `aws ecs describe-services --cluster <name>-backend --services <name>-backend` → `runningCount = desiredCount`, both `backend` and `mcp` containers RUNNING.
- [ ] Target groups healthy: backend TG and `*-mcp-tg` both `healthy` (give health checks ~1 min after apply).

---

## 3. User onboarding + SPA login

- [ ] Check your inbox for the Cognito invite (from `no-reply@verificationemail.com`; **check spam** — Cognito's default sender is capped ~50/day).
  - If it doesn't arrive, set a password directly:
    ```bash
    aws cognito-idp admin-set-user-password \
      --user-pool-id <cognito_user_pool_id> --username you@example.com \
      --password '<TempPass123!>' --permanent
    ```
- [ ] Open `app_url` in a browser.
  - **Expect:** redirected to the Cognito hosted UI login.
- [ ] Log in. First time: forced to set a new password (≥12 chars, mixed case + number + symbol).
  - **Expect:** redirected back to the SPA, authenticated; the app loads.
- [ ] Reload the page.
  - **Expect:** stays logged in (no re-prompt); API calls (e.g. projects list) succeed.

---

## 4. Remote MCP — connect Claude

Point the token helper at your pool, then log in once:

```bash
export WAIRZ_MCP_COGNITO_DOMAIN=$(terraform output -raw cognito_hosted_ui_domain)
export WAIRZ_MCP_REGION=us-east-1
export WAIRZ_MCP_CLIENT_ID=$(terraform output -raw cognito_app_client_id)

python3 ../scripts/wairz_mcp_token.py login        # opens a browser
python3 ../scripts/wairz_mcp_token.py token        # prints an access token
```

- [ ] **Expect:** `login` opens the hosted UI, you authenticate, terminal prints "Logged in. Token cached…". `token` prints a JWT.

Wire Claude Code (`.mcp.json` in your project; commit-safe — no token in the file):

```jsonc
{ "mcpServers": { "wairz-cloud": {
  "type": "http",
  "url": "https://wairz.example.com/mcp",
  "headersHelper": "python3 /abs/path/enterprise/scripts/wairz_mcp_token.py headers"
}}}
```

- [ ] In Claude Code, run `/mcp` and confirm `wairz-cloud` connects (tools listed).
- [ ] Ask Claude to `list_projects`.
  - **Expect:** it returns (empty list on a fresh stack), proving the MCP path + DB reachability.

Negative check:
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://wairz.example.com/mcp \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```
- [ ] **Expect:** `401` (no token).

---

## 5. Firmware analysis (the core workflow)

- [ ] In the SPA: create a project, upload your test firmware, trigger unpack.
  - **Expect:** status polls from `unpacking` → done; the file tree + components populate.
- [ ] Browse the filesystem, open a binary, view strings — via the SPA.
  - **Expect:** content loads (served from EFS through the backend).
- [ ] In Claude (MCP): `switch_project` to that project, then `get_project_info`.
  - **Expect:** correct firmware metadata (kind/arch/endianness).
- [ ] Run a filesystem/strings tool via Claude (e.g. `find_hardcoded_credentials`).
  - **Expect:** results round-trip through `/mcp`.

---

## 6. Heavy compute — Ghidra on Batch (scale-from-zero)

- [ ] Ask Claude to `decompile_function` (or `list_functions`) on a binary — the first call triggers a Batch job.
  - **Expect:** first call takes minutes (Batch scales 0→1, imports, analyzes); watch `aws batch list-jobs --job-queue <name>-ghidra` or the AWS console.
  - **Expect:** decompiled C returns; a **second** call on the same binary is fast (persistent Ghidra project reuse + cache).
- [ ] Confirm Batch scales back to zero after the job (compute env desired vCPUs → 0) — no idle EC2 cost.

---

## 7. Multi-user / per-session isolation

- [ ] Open a second MCP session (or a second Claude instance) with the same token; `switch_project` each to a *different* project.
  - **Expect:** `get_project_info` in each session shows its own project — no cross-session bleed (per-session `ProjectState`).
- [ ] (Optional) Log into the SPA in a second browser as a second seeded user; confirm both work concurrently.

---

## 8. Security spot-checks

```bash
# Direct ALB hit (bypassing CloudFront) must be blocked
ALB=$(terraform output -raw alb_dns_name)
curl -s -o /dev/null -w "%{http_code}\n" --max-time 8 "http://$ALB/health"   # times out / 000
# Security headers present at the edge
curl -sI https://wairz.example.com/ | grep -iE "strict-transport-security|x-frame-options|x-content-type-options|referrer-policy"
```

- [ ] **Expect:** direct ALB request **times out / blocked** (CloudFront-only prefix list); the four security headers are present.
- [ ] **Expect:** `/api/*` and `/mcp` both reject missing/garbage tokens with `401`.
- [ ] (Awareness) The in-firmware **terminal** WS requires a token now, but it's still a real shell on the backend task — confirm you're comfortable with that for your threat model (see `PLAN.md §11`).

---

## 9. Observability

- [ ] AWS Console → CloudWatch → Dashboards → `<dashboard_name>`: ECS/ALB/Aurora/Redis panels populate.
- [ ] (Optional) Set `alarm_email` in tfvars and re-apply to get the SNS subscription; confirm the subscription email and that alarms are in `OK`.

---

## 10. Teardown + verify clean

```bash
AWS_PROFILE=default terraform destroy
```

- [ ] **Expect:** "Destroy complete!"; then verify nothing lingers:
  ```bash
  terraform state list | wc -l                 # 0
  aws cognito-idp list-user-pools --max-results 20 --query 'length(UserPools)'   # 0
  aws rds describe-db-clusters --query 'DBClusters[?contains(DBClusterIdentifier,`wairz`)]|length(@)'  # 0
  ```
- [ ] Clear the local token cache: `python3 ../scripts/wairz_mcp_token.py logout`.

---

## Pass criteria

All boxes checked: SPA login + onboarding, Claude-over-MCP round-trips,
firmware unpack + filesystem/strings, Ghidra-on-Batch decompile (scale 0→1→0),
per-session isolation, the auth/ALB/header security checks, and a clean
teardown. Any failure → capture the step + output and file it before re-running.
