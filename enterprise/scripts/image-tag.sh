#!/usr/bin/env bash
# Terraform `external` data source helper: emits the deterministic image tag for
# the current source tree as JSON on stdout: {"tag":"<sha12>[-<dirty8>]"}.
#
# Clean tree  -> the 12-char commit SHA (reproducible, content-addressed).
# Dirty tree  -> "<sha12>-<dirty8>" where dirty8 hashes the staged+unstaged diff,
#                so iterating on uncommitted changes still rolls the tag (and thus
#                the image). Untracked files are NOT captured — commit for a fully
#                reproducible tag.
#
# The script locates the repo itself (it lives at enterprise/scripts/), so it
# needs no input, but it still drains stdin to satisfy the external-program
# protocol. Only the final JSON line may go to stdout.
set -euo pipefail

cat >/dev/null  # consume Terraform's JSON query (unused)

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(git -C "$script_dir" rev-parse --show-toplevel)"

sha="$(git -C "$repo_root" rev-parse --short=12 HEAD)"
if git -C "$repo_root" diff-index --quiet HEAD -- 2>/dev/null; then
  tag="$sha"
else
  dirty="$(git -C "$repo_root" diff HEAD | sha256sum | cut -c1-8)"
  tag="${sha}-${dirty}"
fi

printf '{"tag":"%s"}\n' "$tag"
