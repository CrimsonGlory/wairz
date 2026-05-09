#!/usr/bin/env bash
# Close the 4 UI-residue PRs whose content is already in main.
#
# Usage:
#   bash .planning/close-ui-residue-prs.sh
#
# These PRs were superseded by direct push of ε branch tip to main +
# cherry-picking of postmortem-followups + gitignore. Their head/base
# SHAs don't auto-resolve, so they remain OPEN until manually closed.
# The Citadel external-action-gate hook classifies `gh pr close` as
# HARD-tier per-action confirmation; this script provides the explicit
# operator confirmation by being run from your terminal.
#
# This gh version doesn't support `--comment` on `gh pr close` — we
# add the closing comment via `gh pr comment` first, then close.

set -euo pipefail

REPO=eastmadc/wairz

echo "Closing 4 UI-residue PRs..."
echo ""

echo "[PR #1] Adding closing comment..."
gh pr comment 1 --repo "$REPO" --body \
  "Closing — δ branch content (e3e94cc..ed3b515) is in main via direct push of ε tip (which descends from δ)."
echo "[PR #1] Closing..."
gh pr close 1 --repo "$REPO"
echo ""

echo "[PR #2] Adding closing comment..."
gh pr comment 2 --repo "$REPO" --body \
  "Closing — postmortem-followups 3 commits cherry-picked onto main (a1883e5, c53ad63, 9e16221) with CLAUDE.md merge-conflict resolution combining refined Rule #38 + new Rule #39."
echo "[PR #2] Closing..."
gh pr close 2 --repo "$REPO"
echo ""

echo "[PR #3] Adding closing comment..."
gh pr comment 3 --repo "$REPO" --body \
  "Closing — ε branch tip (post Rule #39 + ε.2.A folds, d81381d) pushed directly to main. PR was DRAFT. Subsequent ε.2.B/C + ζ.1 work also in main."
echo "[PR #3] Closing..."
gh pr close 3 --repo "$REPO"
echo ""

echo "[PR #5] Adding closing comment..."
gh pr comment 5 --repo "$REPO" --body \
  "Closing — commit 8e27106 cherry-picked onto main as 86f4028 with extension: 18 files un-tracked total (γ/δ/ε branches added more operational state files)."
echo "[PR #5] Closing..."
gh pr close 5 --repo "$REPO"
echo ""

echo "All 4 PRs closed. Verify with:"
echo "  gh pr list --repo $REPO --state open"
