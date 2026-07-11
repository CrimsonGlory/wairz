#!/usr/bin/env bash
# Build the SPA and publish it: sync the static bundle to the SPA S3 bucket and
# invalidate the CloudFront distribution so viewers get the new assets at once
# (PLAN.md §4 / Phase 4 #1).
#
# Invoked by Terraform's null_resource.spa (local-exec). Inputs via environment:
#   REPO_ROOT        absolute path to the repo root (contains frontend/)
#   AWS_REGION       region for the S3 sync
#   SPA_BUCKET       target S3 bucket name
#   DISTRIBUTION_ID  CloudFront distribution to invalidate
# Optional (auth):
#   AUTH_ENABLED     "true" to write a config.json that turns on SPA login
#   OIDC_AUTHORITY   OIDC issuer URL (the Cognito user pool)
#   OIDC_CLIENT_ID   Cognito app client id
#   COGNITO_DOMAIN   hosted-UI base URL (for logout)
#
# The SPA talks to the API over the relative path /api/v1 (CloudFront routes
# /api/* to the ALB origin), so there is no build-time API config to inject. The
# only runtime config is auth: the SPA reads /config.json at startup, so when
# AUTH_ENABLED=true we overwrite the default (auth-off) dist/config.json before
# syncing.
set -euo pipefail

: "${REPO_ROOT:?}" "${AWS_REGION:?}" "${SPA_BUCKET:?}" "${DISTRIBUTION_ID:?}"

cd "${REPO_ROOT}/frontend"

echo "==> Installing SPA dependencies"
if [ -f package-lock.json ]; then
  npm ci
else
  npm install
fi

echo "==> Building SPA"
npm run build  # tsc -b && vite build -> ./dist

if [ "${AUTH_ENABLED:-false}" = "true" ]; then
  echo "==> Writing dist/config.json (auth enabled)"
  cat > dist/config.json <<JSON
{ "authEnabled": true, "oidc": { "authority": "${OIDC_AUTHORITY}", "clientId": "${OIDC_CLIENT_ID}", "scope": "openid email profile", "cognitoDomain": "${COGNITO_DOMAIN}" } }
JSON
fi

echo "==> Syncing dist/ to s3://${SPA_BUCKET}"
aws s3 sync dist/ "s3://${SPA_BUCKET}/" --delete --region "$AWS_REGION"

echo "==> Invalidating CloudFront distribution ${DISTRIBUTION_ID}"
aws cloudfront create-invalidation \
  --distribution-id "$DISTRIBUTION_ID" \
  --paths '/*' >/dev/null

echo "==> SPA deployed"
