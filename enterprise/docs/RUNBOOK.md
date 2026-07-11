# Wairz Enterprise — Operations Runbook

Operational guide for the elastic AWS deployment (`enterprise/terraform`). For
the architecture and design rationale see [`../PLAN.md`](../PLAN.md); for cost
see [`COST.md`](./COST.md).

---

## 1. Prerequisites

On the machine running Terraform:

- **Terraform** ≥ 1.5
- **Docker** with `buildx` (the apply builds + pushes the backend images)
- **Node + npm** (the apply builds the SPA)
- **AWS CLI**, authenticated to the target account (`aws sts get-caller-identity`)
- IAM permissions to create VPC/ECS/RDS/ElastiCache/EFS/Batch/CloudFront/Cognito/
  IAM/CloudWatch/SNS resources

State is **local by default** (`terraform.tfstate` in the module dir). For team
use, migrate to an S3 backend with DynamoDB locking before the first real apply.

---

## 2. Deploy

```bash
cd enterprise/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars        # region, sizing, alarm_email, etc.
terraform init
terraform apply
```

What `apply` does end-to-end (Phase 4a/4e automation):

1. Derives a content-addressed image tag from git (`scripts/image-tag.sh`):
   the 12-char commit SHA, plus a `-<hash>` suffix if the tree is dirty.
   **Commit before applying** for a clean, reproducible tag.
2. Builds two images and pushes each to its ECR repo
   (`scripts/build-and-push-backend.sh`):
   - `--target backend` → `<name>-backend` repo — slim serving image (no Ghidra).
   - `--target ghidra`  → `<name>-ghidra` repo — full image for the Batch worker.
3. Builds the SPA and publishes it (`scripts/deploy-spa.sh`): `npm run build`,
   `aws s3 sync`, CloudFront invalidation.
4. Provisions the stack and prints outputs.

Key outputs:

| Output | Use |
|---|---|
| `app_url` | CloudFront URL serving the SPA + API |
| `alb_dns_name` | Backend ALB (CloudFront's API origin) |
| `dashboard_name` | CloudWatch dashboard (Console → CloudWatch → Dashboards) |
| `alarm_topic_arn` | SNS topic alarms publish to |
| `cognito_user_pool_id` / `cognito_hosted_ui_domain` | Auth |
| `backend_ecr_repository_url` / `ghidra_ecr_repository_url` / `spa_bucket` | Out-of-band CI targets |

> **Cold start (first apply):** the image push and the ECS service are created
> concurrently, so the backend may take an extra 1–2 min to report healthy while
> it pulls the freshly-pushed image. ECS retries the pull until it lands. The
> slim backend image (4e) keeps this short. Later applies only re-push when the
> git tag changes.

### Creating users

Cognito is configured **admin-create-only** (no self sign-up). There is no
admin UI inside Wairz — accounts are managed by whoever holds AWS access. Two
ways to add people:

**Declarative (recommended) — `users.yaml`.** Copy `terraform/users.yaml.example`
to `terraform/users.yaml` and list your roster:

```yaml
- email: analyst@example.com
  name: Ana Lyst        # optional
- email: lead@example.com
```

`terraform apply` (with `auth_enabled = true`) creates each account in the
standard invite flow: Cognito generates a temporary password, emails an invite,
and the user sets their own password (min 12 chars, mixed case + number +
symbol) on first login — Terraform never holds a password. The file is
declarative: add an entry to onboard, remove one to delete that account, re-apply
to sync. `terraform output cognito_seeded_users` lists who's provisioned.
`users.yaml` is gitignored (it's your roster / PII); only the `.example` ships.

**Imperative (one-off) — CLI.** Equivalent for a single ad-hoc account:

```bash
aws cognito-idp admin-create-user \
  --user-pool-id "$(terraform output -raw cognito_user_pool_id)" \
  --username analyst@example.com \
  --user-attributes Name=email,Value=analyst@example.com Name=email_verified,Value=true
```

> **Email delivery / scale.** The pool uses Cognito's **default** email sender
> (~50 emails/day, generic from-address). For a larger rollout wire **SES** into
> the pool. If an invite never arrives, that cap or spam filtering is the usual
> cause — you can also set a temporary password inline and share it securely.
>
> **Least-privilege onboarding.** To let someone add users *without* full AWS
> access, grant an IAM policy scoped to `cognito-idp:AdminCreateUser` /
> `AdminSetUserPassword` / `AdminDisableUser` / `AdminDeleteUser` on this one
> pool ARN — they can run the CLI form above but touch nothing else. (Editing
> `users.yaml` requires Terraform/state access, so it's the operator's path.)

### Custom domain + login (optional, SSO-ready)

All optional and flag-gated — set nothing and the app serves open on the
CloudFront domain.

```hcl
domain_name     = "wairz.example.com"   # your domain
route53_zone_id = "Z0123456789ABCDEF"   # the hosted zone that owns it
auth_enabled    = true                  # require Cognito login (needs domain_name)
```

`apply` then provisions an ACM cert (DNS-validated in your zone), points the
domain at CloudFront, and turns on auth: the SPA requires sign-in (Authorization
Code + PKCE against the Cognito hosted UI) and the API requires a valid bearer
token (validated against the pool's JWKS). With auth on and no NAT, a
`cognito-idp` VPC endpoint is added so the backend can reach the JWKS privately —
without it a valid token hangs the request (CloudFront 504).

**SSO via an external IdP (JumpCloud/Okta/Azure AD/…):** Cognito is the
federation broker. Add a SAML 2.0 or OIDC identity provider to the user pool
(`aws_cognito_identity_provider`, or the console) and add its name to the auth
module's `identity_providers`. The SPA login flow is unchanged — the hosted UI
brokers to your IdP. No app or SPA code change.

### Remote MCP — drive the cloud instance with Claude (optional)

By default the MCP server is **stdio-only**: it talks straight to the database +
firmware files, so it can only run *inside* the deployment, not from a laptop.
Set `mcp_http_enabled = true` to run the **Streamable HTTP** MCP transport as a
sidecar in the backend task and route `/mcp` to it (ALB + CloudFront). Claude
then connects over HTTPS — no SSH, no VPN.

```hcl
auth_enabled     = true     # MCP is gated by the same Cognito bearer as the API
mcp_http_enabled = true
```

`terraform output mcp_url` gives the endpoint (`https://<domain>/mcp`). It is
**Cognito-gated**: every request needs a valid access token (no/invalid token →
401), the *same* token the SPA obtains. Each MCP session gets its own project
context, so multiple analysts share one instance without colliding.

**Connect Claude Code** — use the token helper so the short-lived (~1 h) Cognito
token refreshes itself. Claude Code's `headersHelper` runs a command on every
connection and uses the header JSON it prints; `enterprise/scripts/wairz_mcp_token.py`
is that command (zero deps, Python 3.9+ stdlib only).

1. Point it at your pool (from Terraform outputs) — e.g. in `~/.config/wairz/mcp.json`
   or as env vars:
   ```bash
   export WAIRZ_MCP_COGNITO_DOMAIN=$(terraform output -raw cognito_hosted_ui_domain)
   export WAIRZ_MCP_REGION=us-east-1
   export WAIRZ_MCP_CLIENT_ID=$(terraform output -raw cognito_app_client_id)
   ```
2. Log in once (browser; works through your federated SSO IdP too). Caches a
   refresh token (~30 d) under `~/.config/wairz/`:
   ```bash
   python3 enterprise/scripts/wairz_mcp_token.py login
   ```
3. Wire it into `.mcp.json` (commit-safe — no token in the file):
   ```jsonc
   {
     "mcpServers": {
       "wairz-cloud": {
         "type": "http",
         "url": "https://wairz.example.com/mcp",
         "headersHelper": "python3 ${CLAUDE_PROJECT_DIR}/enterprise/scripts/wairz_mcp_token.py headers"
       }
     }
   }
   ```
   On each connect the helper returns a fresh token from cache (silently
   refreshing via the refresh-token grant when the access token is stale); you
   only re-run `login` when the refresh token expires (~monthly). `… token`
   prints just the access token for manual/env use.

> The loopback redirect (`http://localhost:51789/callback`) must be registered
> on the Cognito client — Terraform does this via `mcp_cli_redirect_port`
> (default 51789); change the var + `--port` together if it collides.

The sidecar runs `wairz-mcp --transport http` from the same image and shares the
task's EFS + DB + OIDC env; it serves an unauthenticated `/healthz` for the ALB
check only. `essential=false`, so an MCP fault never takes down the REST API.

### Out-of-band image/SPA builds (CI)

Set `auto_deploy_images = false` and pass `image_tag = "<tag>"`. Build/push to
both ECR repos and `aws s3 sync` the SPA bucket yourself; the `*_repository_url`
and `spa_bucket` outputs give the targets. Infra-only flows then need no
Docker/Node on the Terraform host.

---

## 3. Operate

### Deploy new code

```bash
git commit -am "..."         # tag derives from the commit
terraform apply              # rebuilds + repushes images, re-syncs SPA, rolls ECS
```

ECS rolls the service to the new task definition (new image tag). Migrations run
on task start, guarded by a Postgres advisory lock (Phase 4b) so concurrent
tasks don't race.

### Scale the backend

`desired_count` (floor) and `max_count` (ceiling) on `module.backend`; the
service autoscales on CPU (`cpu_target_percent`). All state is in
Aurora/Redis/EFS, so scaling is safe.

### Heavy compute (Ghidra on Batch)

- `$0` at rest — the compute environment scales to zero.
- `batch_max_vcpus` caps total concurrent vCPUs (cost guardrail).
- `batch_max_jobs_per_firmware` (default 8) caps in-flight jobs **per firmware**
  so one analyst can't saturate the queue (Phase 4c). The backend rejects
  dispatches over the cap with `rejected - …`. Raise it for power users.

### Observability

- **Dashboard:** `terraform output dashboard_name` → CloudWatch console.
- **Alarms** publish to `alarm_topic_arn`. Set `alarm_email` to subscribe (and
  confirm the AWS confirmation email). Covered: ECS CPU + no-running-tasks, ALB
  unhealthy-hosts / 5XX / latency, Aurora CPU, Redis memory, backend error rate.
- **Logs:** backend `/wairz/<name>/backend`, Batch jobs `/wairz/<name>/batch`.
  AWS Batch publishes no native CloudWatch metrics — watch the Batch console +
  the job log group for heavy-compute health.

---

## 4. Troubleshoot

| Symptom | Likely cause / fix |
|---|---|
| `ecs-no-running-tasks` alarm / API 502 | Task crash-looping. Check `/wairz/<name>/backend` logs. Common: bad `DATABASE_URL` secret, migration failure. |
| Backend healthy but slow first decompile | Batch scale-from-zero: first job waits ~1–3 min for a Spot instance to boot + join the cluster. Subsequent jobs are warm. |
| Batch jobs stuck in `RUNNABLE` | EC2 instances can't join ECS — verify the `ecs`/`ecs-agent`/`ecs-telemetry` VPC endpoints exist (no-NAT path), or that NAT egress works. |
| Image pull slow / task PENDING on first apply | Expected cold start (see §2). Slim backend image keeps it short. |
| `rejected - firmware … already has N Batch job(s)` | Hit `batch_max_jobs_per_firmware`. Wait for jobs to finish or raise the cap. |
| `terraform destroy` → `BucketNotEmpty` | The SPA bucket has `force_destroy=true`; if it still fails, empty leftover object versions (see §5). |
| Aurora cold-resume latency | If `aurora_min_capacity = 0` (auto-pause), the first query after idle takes ~15 s to resume. Set `0.5` to stay warm. |

Inspect live state:

```bash
aws ecs describe-services --cluster <name>-backend --services <name>-backend \
  --query 'services[0].{running:runningCount,desired:desiredCount}'
aws logs tail /wairz/<name>/backend --follow
curl -s -o /dev/null -w '%{http_code}\n' "$(terraform output -raw app_url)/api/v1/projects"
```

---

## 5. Teardown

```bash
terraform destroy
```

This removes everything billable (verified: a full apply/destroy cycle leaves no
ECS/RDS/ECR/ElastiCache/EFS/endpoint resources). The SPA and ECR repos have
`force_destroy`/`force_delete`, so populated buckets/repos are emptied.

If a destroy ever fails on a non-empty versioned bucket:

```bash
aws s3api delete-objects --bucket <bucket> \
  --delete "$(aws s3api list-object-versions --bucket <bucket> \
    --query '{Objects: [].{Key:Key,VersionId:VersionId} + DeleteMarkers[].{Key:Key,VersionId:VersionId}}' \
    --output json)"
terraform destroy
```

---

## 6. Out-of-scope (local install only)

Fuzzing, emulation, and carving need `docker.sock` and are **not** in the cloud
MVP — run them in a local docker-compose Wairz. The IaC leaves clean seams to
add them later (another Batch queue / an on-demand EC2 worker); see PLAN.md §8.
