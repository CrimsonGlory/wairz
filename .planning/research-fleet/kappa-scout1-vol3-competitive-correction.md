---
campaign_id: windows-coverage-godmode-kappa-2026-05-12
scout: 1
angle: memory forensics competitive landscape — correction of iota's MemProcFS MCP finding
opened: 2026-05-12
duration_ms: 73102
total_tokens: 72394
tool_uses: 10
---

# κ Scout 1 — Memory forensics competitive landscape

**Headline finding:** The iota campaign brief (last week) was based on a false-positive
finding from iota-scout3 citing `skywork.ai` as evidence that "MemProcFS shipped MCP."
This κ scout went direct to the official MemProcFS releases page and confirmed:
**MemProcFS does NOT have MCP / LLM / AI integration in any release through v5.17
(Feb 2026).** The wairz "first OSS memory-forensic tool with MCP" wedge is still wide
open. This is a textbook Antipattern A1 instance — secondary-source aggregator
contradicted by the canonical upstream.

---

## MemProcFS current state (verified)

**v5.17 (Feb 2026)** — Windows 11 26H1 support, registry parsing, gRPC LeechAgent,
FindEvil signatures.

**No MCP / LLM / AI integration in any release through v5.17.**

Source: https://github.com/ufrisk/MemProcFS/releases

The skywork.ai post cited by iota-scout3
(`/unlocking-system-internals-memprocfs-mcp-server/1980472180219695104`) appears to
describe a community fork OR aspirational marketing OR confused MemProcFS-as-MCP-host
context (MemProcFS is sometimes used as a data source via gRPC LeechAgent by external
LLM apps — but MemProcFS itself ships no MCP server).

## Volatility 3 current state (verified)

**v2.28.0 released 2026-04-30** (Intel layer scanning, Linux sockscan, Windows
Cryptodome). **v2.28.1 patch follow-up.**

**Cadence:** ~3-4 month cadence sustained from 2023 → 2026, with v2.26 → v2.28
functional-parity expansion and 20+ new plugins.

**Maintenance signal:** STRONG. Volatility Foundation publicly committed to "many
years" of support + 2025/2026 conference roadmap.

Source: https://github.com/volatilityfoundation/volatility3/releases

## ISF (Intermediate Symbol Format) bundle situation

Three-source ecosystem:

1. **JPCERTCC/Windows-Symbol-Tables** — canonical Windows source; 200+ Win7 → Win11/
   Server2022 symbol tables, 171 commits, semi-active updates.
   https://github.com/JPCERTCC/Windows-Symbol-Tables
2. **Abyss-W4tcher/volatility3-symbols** — Linux/macOS; 1327 packs.
   https://github.com/Abyss-W4tcher/volatility3-symbols
3. **isf-server.techanarchy.net** — queryable mirror.

**Build-time bake-in per Rule #37 is viable.** JPCERTCC repo is a plain JSON.xz
collection, SHA256-pinnable, modest size (likely <500 MB for full Windows coverage),
refresh schedule quarterly aligns with existing DBX cadence.

## Differentiation potential: 8/10

MemProcFS ships zero MCP surface, so wairz would be the FIRST and currently UNCONTESTED
MCP-exposed memory forensics platform.

The unique wedge is structural — wairz already owns the firmware-extraction + 281-tool
artifact-walker surface (registry hives, EVTX, Authenticode, prefetch, SRUM, AMCache,
EFS, journald, systemd, ETL, container), so a Vol3 integration enables
CROSS-CORRELATION queries no competitor can match:

> "Vol3 found injected DLL X in pslist → wairz hive walker confirms persistence
> registry key references X → wairz prefetch shows X executed at T1 → wairz SRUM
> shows X did network egress at T1+5min."

MemProcFS provides similar primitives in isolation; the integration story is the wedge.

## Maintenance risk: LOW

Vol3 is a Volatility Foundation project with sustained 2023-2026 release cadence,
Python package on PyPI, active contributor count, Foundation organizational backing.
Far more stable than typical research-grade forensics dependencies (signify, dbx, etc.
already in tree). ISF bundles add a quarterly refresh chore matching existing Rule #37
cadence — incremental ops cost, not new risk class.

## Recommendation: GO

**Open Vol3 as a multi-session κ' campaign** (codename "memory-forensic-godmode-α"
suggested for new series naming). The competitive landscape has an open lane (zero
MCP-exposed memory forensics today) AND wairz holds the highest-leverage adjacent
surface for cross-correlation that competitors structurally cannot replicate; the
dependency is low-risk and the ISF bundling fits existing Rule #37 discipline.

This scout's input to the κ scope decision: REJECT the iota brief's premature defer
on Vol3. The hybrid (option c) form is still right for THIS session (Vol3 deserves
dedicated research-fleet pre-pass + 8-stream 2-3-session shape per Scout 3), but the
adjacency batch this session is a warmup, not a substitute — Vol3 itself remains the
strategic high-value play.

## Sources

- [Releases · ufrisk/MemProcFS](https://github.com/ufrisk/MemProcFS/releases)
- [Releases · volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3/releases)
- [GitHub - JPCERTCC/Windows-Symbol-Tables](https://github.com/JPCERTCC/Windows-Symbol-Tables)
- [Volatility 3 2.28.1 documentation](https://volatility3.readthedocs.io/en/latest/)
- [Abyss-W4tcher/volatility3-symbols (Linux/macOS ISF)](https://github.com/Abyss-W4tcher/volatility3-symbols)
- [Volatility3 ISF Server mirror](https://isf-server.techanarchy.net/)
- [Volatility Foundation timeline](https://volatilityfoundation.org/volatility-timeline/)
