# Wairz Enterprise — Elastic AWS Deployment

This directory contains the **enterprise cloud deployment** of Wairz: an
elastic, mostly-serverless AWS architecture that runs the always-on serving
layer cheaply and bursts heavy compute (Ghidra decompilation) onto ephemeral,
scale-to-zero workers via **AWS Batch**.

It is a self-contained deployment target. Clone the repo, `cd enterprise`,
set your variables, and apply the Terraform.

> **Status:** all Terraform modules (network, storage, database, cache, batch,
> backend, frontend, auth, observability) are authored and **apply-tested on a
> live AWS account** — backend healthy behind ALB + CloudFront and Aurora, and
> the Batch scale-from-zero Ghidra path verified end-to-end (see PLAN.md §0). The
> local docker-compose deploy is unchanged (suite green). **Phase 4 is complete:**
> `terraform apply` builds + pushes both backend images and publishes the SPA;
> migrations are advisory-lock-guarded; a per-firmware Batch concurrency cap and
> CloudWatch alarms/dashboard are in place; the Fargate image is slimmed (no
> Ghidra); an optional custom domain + Cognito/OIDC login (SSO-ready — federate
> JumpCloud/Okta into the pool) is flag-gated and live-validated; and
> `docs/RUNBOOK.md` + `docs/COST.md` document operations and cost. **Phase 5
> (remote Streamable-HTTP MCP transport) is complete and live-validated**, and
> the Phase 6 cloud-MCP UX hardening is done except one low-priority item
> (persist active project across reconnect) — see PLAN.md §5–6 and
> `docs/MCP-FIELD-FINDINGS.md`. None of these is a merge blocker.

## Why this exists

The single-EC2 monolith forced an oversized instance: heavy Ghidra
decompilation runs *in the backend process* and contends with the lightweight
web serving. Most of the time Wairz just serves findings, reports, and agent
Q&A — needing almost nothing. This deployment splits the two:

- **Control plane** (always on, cheap): static SPA on S3/CloudFront, FastAPI on
  Fargate, Aurora Serverless v2 (scales toward zero), small ElastiCache, shared
  firmware storage on EFS.
- **Compute plane** (on demand, scales 0→N, Spot): Ghidra runs as an AWS Batch
  job, submitted by the backend and polled through the existing
  `ghidra_analysis_run` cache row. **$0 at rest.**

Fuzzing, emulation, and carving (the `docker.sock` features) are **out of scope
for the cloud MVP** and run in a local Wairz install. The architecture leaves
clean seams to add fuzzing (another Batch queue) and emulation (an on-demand
EC2 worker) later.

## Quickstart

```bash
git clone <repo> && cd wairz/enterprise/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars        # region, domain, sizing, secrets refs
terraform init
terraform apply
```

`terraform apply` builds **two** backend image variants — a slim serving image
(no Ghidra) for the Fargate backend and the full image for the Batch Ghidra
worker — and pushes each to its ECR repo, publishes the SPA to S3 + invalidates
CloudFront, provisions the full stack, and outputs the CloudFront URL
(`app_url`). See [`docs/RUNBOOK.md`](./docs/RUNBOOK.md) and
[`docs/COST.md`](./docs/COST.md).

**Prerequisites on the machine running Terraform:** Docker (with `buildx`),
Node/npm, and an authenticated AWS CLI. The image tag is derived from git
(commit SHA; a content hash is appended for uncommitted edits), so commit before
applying for a reproducible tag.

> **Cold-start note:** on the very first `apply`, the image push and the ECS
> service are created concurrently, so the backend may take an extra minute or
> two to report healthy while the freshly-pushed image is pulled — ECS retries
> until it lands. Later applies only re-push when the source (tag) changes.

**Building out-of-band (CI):** set `auto_deploy_images = false`, build/push to
the two ECR repos and sync the SPA bucket yourself, and pass the tag via
`image_tag`. The `backend_ecr_repository_url`, `ghidra_ecr_repository_url`, and
`spa_bucket` outputs give you the targets.

## Layout

```
enterprise/
├── README.md            # this file — operator-facing overview
├── PLAN.md              # detailed, phased build plan for agents (start here if building)
├── docs/                # architecture decision records, runbooks
├── docker/              # enterprise image overrides / entrypoints (Batch Ghidra, slim backend)
└── terraform/
    ├── *.tf             # root module: wires the modules together
    ├── terraform.tfvars.example
    └── modules/
        ├── network/     # VPC, subnets, security groups, VPC endpoints
        ├── storage/     # EFS (firmware), S3 (SPA + uploads)
        ├── database/    # Aurora Serverless v2 (PostgreSQL)
        ├── cache/       # ElastiCache (Redis — locks/coordination)
        ├── backend/     # ECR, ECS Fargate service, ALB
        ├── frontend/    # S3 + CloudFront for the SPA
        ├── batch/       # AWS Batch compute env + Ghidra job queue/definition
        ├── auth/        # Cognito (shared multi-user instance)
        └── observability/ # CloudWatch alarms + dashboard + SNS alarm topic
```

## Relationship to the main app

This deployment requires a small set of **app-code changes** on the
`wairz_enterprise` branch (dispatching Ghidra to Batch, moving the analysis
lock to Redis, EFS-friendly storage). Those changes are listed in
[`PLAN.md`](./PLAN.md) and are gated behind config so the local
`docker-compose` workflow keeps working unchanged.
