---
title: "Audit MCP tool enum schemas vs DB CHECK / Pydantic Literal allowlists"
status: completed
priority: low
target: backend/app/ai/tools/*.py vs backend/alembic/versions/*.py CHECK constraints + backend/app/schemas/*.py Literal narrowings
discovered: 2026-05-07
discovered_by: post-fleet-Wave-1 systemic followup to commit 8329933 (Stream α fix)
closed: 2026-05-07
closed_by: clean bill of health — only the α drift existed; sweep confirms no other MCP enum mismatches present.
---

## Background

Commit `8329933` (Stream α of the post-F-C-05 fleet wave) closed a single
drift: the MCP `assess_vulnerabilities` tool declared `adjusted_severity`
enum as `(critical, high, medium, low, info)` while the DB CHECK
`ck_sbom_vulns_adjusted_severity` allowed `(critical, high, medium, low,
unknown)`. The drift would have caused a 500 CheckViolationError on any
LLM-emitted `info` write.

This audit asks: are there OTHER MCP tools with the same shape of bug?
For every JSON-schema `enum` array declared in a tool's `input_schema`,
is the set a subset of whatever validation gate sits between the tool
and the DB (a Pydantic Literal at the schema layer, or a DB CHECK at
the column layer)?

## Method

Inventory: `grep -rn "\"enum\":" backend/app/ai/tools/*.py` produced 38
hits across 13 files. Each was hand-classified into one of four
categories:

1. **DB-write target.** The enum value lands in a CHECK-constrained
   column (directly via SQLAlchemy assignment, or transitively via a
   service / handler call). Must be a subset of the column's
   allowlist.
2. **Pydantic-narrowed write.** The enum value passes through a
   Pydantic schema with a `Literal[...]` narrowing before reaching the
   DB. Must be a subset of the Literal AND the Literal must already be
   a subset of the DB CHECK (verified separately by
   `tests/test_status_check_constraint_alignment.py`).
3. **Filter-only.** The enum is for read-side filtering (e.g.
   `min_severity`, `severity_filter`). Doesn't reach the DB write
   path. Out of scope.
4. **External CLI / local string.** The enum value is passed to an
   external tool (shellcheck `-S`, ifsdump flags, HTTP method) or used
   only in the handler's local control flow. Doesn't touch the DB.

For categories 1+2, cross-referenced enum values against the DB CHECK
definition fetched live via `pg_get_constraintdef`.

## Findings

**Zero α-class drifts beyond the one already fixed.** Full per-file
per-enum breakdown:

| File:line | Enum (first 5 / total) | Target | Class | Verdict |
|---|---|---|---|---|
| `reporting.py:33` | critical/high/medium/low/info | `findings.severity` (write) | DB | ✓ aligned (5 of 5) |
| `reporting.py:64` | ai_discovered/manual/sbom_scan/fuzzing/security_review | `findings.source` (write) | DB | ✓ subset of 18-value CHECK (post-`a9f4e9cdabe2` + `61b147189fcf` widenings) |
| `reporting.py:69` | high/medium/low | `findings.confidence` (write) | DB | ✓ aligned (3 of 3) |
| `reporting.py:97` | critical/high/medium/low/info | filter | filter | ✓ N/A |
| `reporting.py:102` | open/confirmed/false_positive/fixed | filter | filter | ✓ N/A |
| `reporting.py:126` | open/confirmed/false_positive/fixed | `findings.status` (write) | DB | ✓ aligned (4 of 4) |
| `reporting.py:156` | markdown/html | local | local | ✓ N/A |
| `reporting.py:202-210` | phase names | local control flow | local | ✓ N/A |
| `sbom.py:55` | application/library/operating-system | filter | filter | ✓ N/A |
| `sbom.py:128` | open/resolved/ignored/false_positive | filter | filter | ✓ N/A |
| `sbom.py:133` | critical/high/medium/low | severity filter | filter | ✓ N/A (narrows to 4 of 5; can't filter for `unknown` via this tool, by design) |
| `sbom.py:167` | cyclonedx-json/spdx-json/cyclonedx-vex-json | local | local | ✓ N/A |
| `sbom.py:224` | critical/high/medium/low/unknown | `sbom_vulnerabilities.adjusted_severity` (write) | DB | ✓ aligned **post commit 8329933** |
| `sbom.py:239` | open/resolved/ignored/false_positive | `sbom_vulnerabilities.resolution_status` (write) | DB | ✓ aligned (4 of 4) |
| `sbom.py:280` | not_affected/affected/fixed/under_investigation | `sbom_vulnerabilities.resolution_status` (write, via VEX→internal mapping) | DB | ✓ aligned — handler at `sbom.py:1064-1069` maps `not_affected→false_positive, affected→open, fixed→resolved, under_investigation→open`, all four mapped values are in the CHECK allowlist |
| `security.py:4234` | error/warning/info/style | shellcheck `-S` flag | external | ✓ N/A — external CLI, never persisted |
| `security.py:4242` | sh/bash/dash/ksh | shellcheck `--shell=` flag | external | ✓ N/A |
| `security.py:4285,4293` | low/medium/high | filter | filter | ✓ N/A |
| `security.py:4527` | pass/fail/partial/not_tested/not_applicable | `cra_requirement_results.status` (write) | DB | ✓ aligned (5 of 5) |
| `security.py:4737` | sha256_hash/ip:port/domain/url | local | local | ✓ N/A |
| `android_sast.py:59` | info/low/medium/high/critical | min_severity filter | filter | ✓ N/A |
| `android_bytecode.py:56` | info/low/medium/high/critical | min_severity filter | filter | ✓ N/A |
| `android_bytecode.py:61` | low/medium/high | min_confidence filter | filter | ✓ N/A |
| `taint_llm.py:820` | low/medium/high | min_confidence filter | filter | ✓ N/A |
| `emulation.py:86` | arm/aarch64/mips/mipsel/x86/x86_64 | architecture filter/string | filter | ✓ N/A |
| `emulation.py:128,482` | user/system | `emulation_sessions.mode` (write via Pydantic Literal) | Pydantic | ✓ Literal already constrained, CHECK is a superset |
| `emulation.py:184,519` | none/generic/tenda | `emulation_presets.stub_profile` (write via Pydantic Literal) | Pydantic | ✓ aligned |
| `emulation.py:827` | GET/POST/PUT/DELETE/HEAD/OPTIONS | local HTTP method | local | ✓ N/A |
| `binary.py:2419` | hex/string/disasm | local output format | local | ✓ N/A |
| `filesystem.py:520` | (sorted VALID_TYPES) | filter | filter | ✓ N/A |
| `uart.py:58,64` | N/E/O, 1/2 | UART config | local | ✓ N/A |
| `fuzzing.py:88,236` | stdin/file/network | local | local | ✓ N/A |

## False-positive filter rules

- **Filter-only enums.** `min_severity`, `severity_filter`, `min_confidence`, `status_filter` etc. constrain query/listing output and never reach a write path. Excluded from the audit by design.
- **External CLI enums.** `shellcheck -S`, `--shell=`, HTTP methods, file format flags. Not persisted; their alignment is the external tool's contract, not wairz's CHECK.
- **Local control-flow enums.** Phase names (`run_full_assessment`'s `skip_phases`), output formats (`markdown/html`, `hex/string/disasm`). Used only inside the handler.
- **Architecture / shell-dialect / IOC-type strings.** Local helpers; no DB persistence under any constraint.

## Closure

Clean bill of health. Tonight's α fix was the entire α-class drift surface.

## Method-replay recipe

For the next audit run when an MCP tool is added or modified:

```bash
# 1. inventory
grep -rn "\"enum\":" backend/app/ai/tools/*.py > /tmp/mcp_enums.txt

# 2. for each enum, ask:
#    a. what column does the enum value land in (if any)?
#    b. does a Pydantic Literal narrow it on the way?
#    c. is the enum a subset of (Literal ∩ DB CHECK)?
# 3. if yes -> aligned
#    if no  -> drift; either widen the CHECK, narrow the Literal, or
#             narrow the MCP enum to the intersection.
```

A future durable backstop would be a `tests/test_mcp_enum_alignment.py`
that walks the MCP tool registry, extracts each `enum` field, and
asserts each is a subset of a hand-curated `(target_column,
allowlist_source)` mapping. Cost: ~30 min to author the mapping + ~5 min
maintenance per new tool. Filed as a possible follow-up if α-class
drifts recur.

## Out of scope

- The MCP `enum` declarations are JSON-schema-level. Some tools also
  apply Python-level `Enum`/`Literal` validation in their handlers
  before the DB write — a deeper audit could trace each enum value
  through the full handler path (not just the registration site).
  Out of scope here; the registration-site enum is the canonical
  contract.
- Tools that use `Enum`-class hints in handlers without a JSON-schema
  `enum` declaration are NOT inventoried. They would be visible only by
  walking the Python AST. Out of scope.

## Provenance

Audit run by post-fleet-Wave-1 deep-research session 2026-05-07 after
commit `509b42d` shipped the autogenerate-empty CI gate. Closes the
"are there other α-class drifts" question raised implicitly by Stream α.
