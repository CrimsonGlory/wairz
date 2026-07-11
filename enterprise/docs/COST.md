# Wairz Enterprise — Cost Estimate

Rough monthly cost of the AWS deployment, **us-east-1, on-demand list prices,
mid-2026**. Treat as ±20% planning figures, not a quote — actual cost depends on
traffic, stored firmware, and how much heavy analysis you run. Heavy compute
(Batch) is **usage-based and $0 at rest**.

## At-rest baseline (defaults)

Defaults: 1 backend task (0.5 vCPU / 1 GB), Aurora 0.5 ACU always-warm,
`cache.t4g.micro` Redis, **no NAT** (8 interface VPC endpoints across 2 AZs),
2 AZs.

| Component | Config | ~$/mo |
|---|---|---:|
| **VPC interface endpoints** | 8 services × 2 AZ × $0.01/hr | **~$117** |
| Aurora Serverless v2 | 0.5 ACU min, always warm ($0.12/ACU-hr) + storage | ~$45 |
| ALB | 1 ALB + low LCU | ~$20 |
| Fargate backend | 0.5 vCPU / 1 GB × 1 task, 24/7 | ~$18 |
| ElastiCache Redis | `cache.t4g.micro` | ~$12 |
| EFS | ~10 GB Standard + IA (grows with firmware) | ~$3 |
| CloudWatch | 8 alarms + logs (dashboard free, first 3) | ~$3 |
| S3 + CloudFront | SPA serving, light traffic | ~$1 |
| Secrets Manager | 1–2 secrets | ~$1 |
| ECR | 2 images stored (~1.5 GB compressed) | ~$0.50 |
| **Total at rest** | | **~$220/mo** |

> The early PLAN.md figure (~$35–75/mo) under-counted: the **8 interface VPC
> endpoints dominate** (~$117/mo, billed per-AZ), and always-warm Aurora is
> ~$45. The numbers above supersede it. The endpoints buy a no-internet-egress
> security posture (private subnets reach only AWS services); the levers below
> trade some of that cost back.

## Heavy compute (Batch) — usage-based, $0 at rest

Ghidra runs on Spot EC2 (`optimal`), scale-to-zero. A typical decompile/import
job is minutes on a small instance ≈ **$0.01–0.10 per job**; cached by binary
hash, so repeats are free. `batch_max_vcpus` is the hard ceiling. Budget by
expected analyses/day; even heavy use is usually < $20/mo.

## Cost levers

| Lever | Variable | Saves | Tradeoff |
|---|---|---:|---|
| **NAT instead of endpoints** | `create_nat_gateway = true` | ~$84/mo (single NAT ~$33 vs ~$117 endpoints; removes all interface endpoints) | + $0.045/GB egress; single-AZ NAT is an egress SPOF; firmware host reaches the internet |
| **Aurora auto-pause** | `aurora_min_capacity = 0` | ~$45/mo ($0 idle) | ~15 s cold-resume on first query after idle |
| **Smaller/zero baseline** | `desired_count` (already 1) | — | 1 is the floor for an always-on API |
| Spot Ghidra (default on) | `batch_use_spot = true` | — | rare interruption → job re-runs (idempotent) |

**Custom domain + auth (`auth_enabled`):** ACM certs are free and Route53 is
~$0.50/mo per zone. With auth on and no NAT, one extra `cognito-idp` interface
endpoint is added so the backend can validate tokens privately (~$7/mo, single
AZ). Negligible against the baseline.

**Illustrative configs:**

- **Defaults (security-first, always-warm):** ~$220/mo at rest.
- **Cost-optimized** (`create_nat_gateway=true` + `aurora_min_capacity=0`):
  ~$220 − $84 (endpoints→NAT) − $45 (auto-pause) ≈ **~$90/mo at rest**, with the
  ~15 s Aurora cold-resume and internet egress from the private subnets.

Plus Batch usage (~$0.01–0.10/job) and data transfer/CloudFront for real
traffic. Set `alarm_email` and a billing budget alarm to catch surprises.
