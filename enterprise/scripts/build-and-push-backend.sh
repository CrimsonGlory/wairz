#!/usr/bin/env bash
# Build the two backend image variants and push each to its ECR repo under the
# same content-addressed tag (PLAN.md §4 / Phase 4):
#   --target backend → BACKEND_REPO_URL : SLIM serving image (no Ghidra/JDK),
#                      run by the Fargate backend (Ghidra is dispatched to Batch).
#   --target ghidra  → GHIDRA_REPO_URL  : FULL image (base + Ghidra), run by the
#                      Batch worker.
# Both targets share the `base` stage, so buildx builds those layers once and
# reuses them for the second target via the local build cache.
#
# Invoked by Terraform's null_resource.backend_image (local-exec). All inputs
# arrive via environment variables:
#   REPO_ROOT         absolute path to the repo root (contains backend/, ghidra/, emulation/)
#   AWS_REGION        region of the ECR registry
#   BACKEND_REPO_URL  <acct>.dkr.ecr.<region>.amazonaws.com/<name>-backend
#   GHIDRA_REPO_URL   <acct>.dkr.ecr.<region>.amazonaws.com/<name>-ghidra
#   IMAGE_TAG         tag to push (from image-tag.sh / var.image_tag)
set -euo pipefail

: "${REPO_ROOT:?}" "${AWS_REGION:?}" "${BACKEND_REPO_URL:?}" "${GHIDRA_REPO_URL:?}" "${IMAGE_TAG:?}"

# Both repos live in the same registry; one login covers both.
registry="${BACKEND_REPO_URL%%/*}"

echo "==> Logging in to ECR registry ${registry}"
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$registry"

# Build for linux/amd64 — Fargate tasks and the Batch EC2 fleet are x86_64, even
# when Terraform runs on an arm64 host (e.g. Apple Silicon). The Dockerfile pulls
# the emulation kernels and Ghidra headless scripts in via named build contexts
# (same wiring as docker-compose's additional_contexts); reproduce them here.
build() {
  local target="$1" repo_url="$2"
  echo "==> Building ${target} image ${IMAGE_TAG} (linux/amd64) → ${repo_url}"
  docker buildx build \
    --platform linux/amd64 \
    --target "${target}" \
    --build-context kernels="${REPO_ROOT}/emulation/kernels" \
    --build-context ghidra_scripts="${REPO_ROOT}/ghidra/scripts" \
    --tag "${repo_url}:${IMAGE_TAG}" \
    --push \
    "${REPO_ROOT}/backend"
  echo "==> Pushed ${repo_url}:${IMAGE_TAG}"
}

# Slim serving image first (its layers are the shared `base`), then the full
# Ghidra image reuses that cached base.
build backend "${BACKEND_REPO_URL}"
build ghidra "${GHIDRA_REPO_URL}"
