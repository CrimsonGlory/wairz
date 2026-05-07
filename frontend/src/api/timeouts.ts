// Frontend axios timeout tier constants — single source of truth.
//
// Per CLAUDE.md Rule #29: every long-op endpoint MUST declare an upward
// override of the apiClient default 30_000 ms floor (client.ts:6). The
// frontend value derives from the backend authoritative ceiling via:
//   frontend_ms >= backend_seconds * 1200
// (×1000 for ms-conversion, ×1.2 for network + JSON-serialization grace).
//
// Each constant carries an inline citation to its backend source. Adding
// a new long-op endpoint: pick the tier whose value satisfies the math,
// or add a new tier here (do not redeclare in the API file).
//
// Drift consolidation shipped 2026-05-05 (audit-2026-05-04 quick-wins M-1).
// Restored 2026-05-06 — see Phase 1 follow-up commit; commit 4f75596
// claimed "the timeouts.ts module landed in a prior commit" but the file
// was never tracked in git. Values verified against the running bundle
// (`6e5` appearing 10× = SECURITY_SCAN_TIMEOUT=600_000ms baked in).

// radare2 `aaa` analysis — matches backend/app/ai/tools/binary.py:1637
// communicate(timeout=120) × 1.25 grace.
export const RADARE2_ANALYSIS_TIMEOUT = 150_000

// Ghidra headless decompilation — matches backend/app/config.py:24
// ghidra_timeout=300 × 1.2 grace.
export const GHIDRA_ANALYSIS_TIMEOUT = 360_000

// Hash lookup scans (NVD / OSV / per-binary CVE matchers).
export const HASH_SCAN_TIMEOUT = 300_000

// Device acquisition bridge (ADB partition dump, device info).
export const DEVICE_BRIDGE_TIMEOUT = 300_000

// Outermost synchronous-tier ceiling for security pipelines (mobsfscan,
// vulnerability scan, YARA, security audit, SBOM generate). Matches the
// backend mobsfscan `_PIPELINE_BUDGET_SECONDS=600` outer wall-clock cap.
//
// Caveat per Rule #29: 100s+ tiers are unsafe behind reverse proxies
// (nginx default proxy_read_timeout=60s, ALB idle=60s, Cloudflare=100s).
// wairz currently deploys same-origin so this works; deployments behind
// a proxy must EITHER tune the proxy OR convert the endpoint to the
// 202+polling pattern (Rule #33). The vuln-scan endpoint shipped a
// Rule #33 conversion in the same session this file was restored.
export const SECURITY_SCAN_TIMEOUT = 600_000
