---
postmortem_id: postmortem-windows-coverage-godmode-iota-D-efs-walker-2026-05-12
campaign_id: windows-coverage-godmode-iota-2026-05-12
stream_id: ι.D — Windows EFS DDF/DRF metadata walker (parse-only)
status: closed
opened: 2026-05-12
session_id: ι.D single-stream (cont. from ι.C close f5b06c6)
trust_level: trusted (direct-push to main per-piece, Pattern P5)
commits:
  - 8c748a6 feat(windows-efs): WindowsEfsEncryptedFile ORM + alembic migration (ι.D.A)
  - d810189 feat(firmware): efs_walk_* 5-column 202+poll status set (ι.D.B)
  - 5ec71a4 feat(efs): Rule #39 walker triplet for EFS DDF/DRF metadata (ι.D.C)
  - 541a00b feat(findings): Windows EFS cross-stack alignment + emit (ι.D.D)
  - f5b06c6 feat(mcp): windows_efs MCP tool category — 6 tools (ι.D.E)
mcp_count_delta: 269 → 275 (+6 — 5 per-firmware + 1 cross-firmware aggregation)
alembic_head_delta: aabbccddee06 → aabbccddee09 (3 new revisions: aabbccddee07, aabbccddee08, aabbccddee09)
finding_source_count_delta: 61 → 65 (+4 — SECOND ι Windows source-family extension)
new_oss_dep: zero — dissect.ntfs (η.A baseline) + asn1crypto (already in deps) reused
rule_chain_extensions:
  - Rule #39 inner/outer/safe runner triplet — Rule-of-Seventeen → Rule-of-Eighteen
  - Rule #25 single-slice exception #2 — Rule-of-Twenty-One → Rule-of-Twenty-Two
  - Pattern P1 single-sub-agent + precedent reuse — Rule-of-Eight → Rule-of-Nine
  - Cross-firmware aggregation at walker-stream time — Rule-of-Two → Rule-of-Three (DURABLE)
  - Rule #36 EXTENSION (no-decrypt for security-sensitive metadata walkers) — Rule-of-One (NEW)
  - Parse-only metadata walker — Rule-of-One (NEW — candidate codification)
tests_landed: ι.D.A 33 + ι.D.B 8 + ι.D.C 42 + ι.D.E 28 = 111 new tier-1 tests (all passing)
duration_clock_to_clock: 25 minutes wall (16:11Z dissect.ntfs API probe → 16:36Z final commit landing)
duration_caveat: |
  Clock-to-clock duration measured against `date -u` boundaries at session start
  (16:11Z dissect.ntfs API surface probe via inspect.getsource) and final
  commit landing (16:36Z f5b06c6 push). Excludes pre-session prompt-read time.
  Antipattern A4 reminder applied — wall claim only, no inflated self-reported
  duration.
---

# Phase ι.D — Windows EFS DDF/DRF metadata walker postmortem

## Summary

ι.D shipped the **FOURTH ι walker** and the **SECOND ι Windows-side
walker** in wairz's portfolio across 5 per-piece direct-pushed commits.
All 5 streams landed clean — zero rollbacks, zero cross-stream sweeps.
MCP tool count 269 → 275 (+6, including the third cross-firmware
aggregation tool). Alembic chained 3 new revisions. FindingSource
catalog expanded from 61 to 65 values (the SECOND ι Windows extension
after ι.C ETL). Pattern P1 sub-agent + precedent-reuse continues to
compound: the η.A NTFS plumbing (`walk_raw_ntfs_images`,
`looks_like_ntfs`, `_safe_attribute_value`) and the ι.C ETL Rule #39
triplet shape were both reused with mostly per-symbol substitutions
plus the EFS-specific blob parser as the genuine novelty.

**Strategic outcome:** ι.D closes the MS-EFSR persistence + insider-
threat surface gap identified by the Phase ι kick-off Scout 1 (API
verification on `dissect.ntfs` LOGGED_UTILITY_STREAM 0x100). The EFS
walker surfaces the canonical T1486 (Data Encrypted for Impact —
SafeBreach 2020 PoC ransomware-via-EFS) and T1564.001 (Hidden Files
and Directories — insider stealth via unauthorized SID in DDF)
adversary tradecraft. EZTools has a genuine $EFS gap; NTFSTool is
CLI-only with no LLM integration — **wairz now has a unique MCP-
callable EFS surface with cross-firmware aggregation that no other
forensic tool ships**.

**Cross-firmware aggregation differentiation reinforced — pattern now
DURABLE.** ι.D.E shipped `lookup_efs_recovery_agent_across_firmwares`
from the start (NOT deferred), making this the **THIRD application of
the cross-firmware aggregation pattern at walker-stream time**:

- ι.B.E `lookup_systemd_unit_across_firmwares` (Rule-of-One)
- ι.C.E `lookup_etl_provider_across_firmwares` (Rule-of-Two)
- ι.D.E `lookup_efs_recovery_agent_across_firmwares` (Rule-of-Three)

The EFS application is the **highest-value** of the three — recovery
agent thumbprint matching is a STRONG indicator (shared backdoor key,
un-rekeyed vendor default, supply-chain compromise). This is a
**promotion candidate for end-of-ι codification** as a top-level
CLAUDE.md rule or `.mex/patterns/cross-firmware-aggregation-at-walker-
stream.md` recipe. The pattern is now applied across 3 walkers in 3
distinct domains (Linux systemd; Windows ETW; Windows EFS) — the
shape is universal.

**NEW pattern — parse-only metadata walker (Rule-of-One precedent).**
ι.D establishes the precedent for walkers that surface metadata
WITHOUT decryption / execution / plaintext recovery, distinct from
previous walkers that surfaced full content (e.g. ETL events, MFT
attributes, registry hives). The EFS walker reads the $EFS
LOGGED_UTILITY_STREAM blob bytes as DATA for METADATA extraction
(SIDs, cert thumbprints, friendly names) and IGNORES the
RSA-encrypted FEK entirely. This is a structurally distinct shape
from "read everything, classify suspicious patterns". Future walkers
needing this discipline (DPAPI master keys, BitLocker recovery,
PGP/GPG keyring metadata, TPM-sealed blobs) would inherit this
precedent.

**Rule #36 EXTENSION pattern — no-decrypt test gate for security-
sensitive metadata walkers (Rule-of-One precedent).** ι.D.C's
`test_efs_walker_no_execute_no_decrypt_attempt` extends the standard
Rule #36 no-spawn test with a second tier of forbidden tokens:
DPAPI primitives (`CryptUnprotectData`, `CryptProtectData`),
decryption module imports (`cryptography.fernet`, `asn1crypto.cms`,
`asn1crypto.algos`), generic decrypt call patterns (`.decrypt(`,
`decrypt_fek`, `extract_fek`), and DPAPI wrapper packages
(`impacket.dpapi`, `dpapick`). The test uses `tokenize` to strip
docstrings + comments before scanning, so prose mentions of forbidden
primitives (in "we don't do this" context) don't false-positive.
This is the **second-tier safety floor** — Rule #36 catches spawn
primitives universally; Rule #36 EXTENSION catches decryption
primitives specifically for walkers handling encrypted artifacts.

## What Broke

**Net 2 incidents caught + fixed in-flight; 0 regressions to main.**

### W1 (caught in ι.D.C `parse_efs_blob` test, fixed pre-commit)

- **Mechanical:** `test_parse_efs_blob_friendly_name_extraction`
  passed `"alice@example.com\x00".encode("utf-16-le")` to the parser;
  the assertion expected `friendly_name == "alice@example.com"` but
  the parser returned `"alice@example.co"` (missing the trailing 'm').
- **Root cause:** the parser stripped trailing NUL bytes via
  `fn_bytes.rstrip(b"\x00")` — but UTF-16LE 'm' is `b'm\x00'`, and
  `rstrip` is byte-by-byte. It stripped the high byte of 'm', then
  the high byte of the actual NUL terminator, eating one too many.
- **Fix:** changed to a `while fn_bytes.endswith(b"\x00\x00"): fn_bytes
  = fn_bytes[:-2]` loop that strips only complete UTF-16LE null
  wide-chars (2-byte pairs). All 7 parse_efs_blob tests now pass.
- **Time-to-detect:** ~10 seconds (test fail with clear assertion diff).
- **Time-to-fix:** ~30 seconds (3-line replacement).

### W2 (caught in ι.D.C Rule #36 EXTENSION test, fixed pre-commit)

- **Mechanical:** `test_efs_walker_no_execute_no_decrypt_attempt` failed
  with 2 matches for `\bCryptUnprotectData\b` against the walker
  source. The walker MENTIONS `CryptUnprotectData` in its module
  docstring as something it explicitly DOES NOT invoke — but the
  naive regex didn't distinguish prose from executable code.
- **Root cause:** scanning the raw source text included docstrings
  + comments, which legitimately mention forbidden primitives in
  "we don't do this" context.
- **Fix:** added `_strip_docstrings_and_comments(source)` helper using
  the `tokenize` module to drop every `STRING` and `COMMENT` token
  before scanning. The cleaned source contains only executable code,
  so prose mentions don't trigger false positives. Belt-and-braces:
  also use the raw source for the `row.encrypted_fek =` persistence
  anti-token check (that pattern is unambiguously code).
- **Time-to-detect:** ~5 seconds (assertion error with matched tokens).
- **Time-to-fix:** ~3 minutes (write tokenize-based helper, restructure
  test into raw vs cleaned source scans).

## What Safety Systems Caught

1. **Tests** — both incidents (W1 / W2) caught by the test suite BEFORE
   the commit was authored, not after. Live canaries (Rule #35b)
   verified the value-flow contract end-to-end for the inner walker
   (mocked dissect.ntfs.NTFS feeding synthetic MFT records with
   FILE_ATTRIBUTE_ENCRYPTED + handcrafted $EFS blobs through the row
   builder).

2. **Rule #19 evidence-first probe** — confirmed the dissect.ntfs API
   surface BEFORE writing walker code. `dir(dissect.ntfs.c_ntfs)`
   confirmed `ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM=0x100` +
   `ATTRIBUTE_FLAG_ENCRYPTED=0x4000`; `inspect.getsource(AttributeMap
   / AttributeCollection / StandardInformation)` confirmed
   `record.attributes[ATTRIBUTE_TYPE_CODE.X]` returns a list-like
   `AttributeCollection` that supports indexing + `header.open() /
   .data()` for raw bytes. Took ~5 minutes; saved ~30 minutes of "wait,
   how do I read this attribute?" speculation.

3. **Rule #11 runtime import smoke** — caught at each commit boundary.
   After ι.D.A, verified ORM imports clean against the host-side venv;
   after ι.D.C, verified the Rule #39 triplet (`_do_efs_walk`,
   `run_efs_walk_background`, `auto_efs_walk_firmware_safe`) plus
   helpers all import clean; after ι.D.D, verified
   `classify_efs_findings` + `emit_efs_findings_from_walk` import
   clean; after ι.D.E, verified `create_tool_registry()` produces
   exactly 275 tools (269 + 6).

4. **Rule #36 + Rule #36 EXTENSION test gate** — `test_efs_walker_no_
   execute_no_decrypt_attempt` greps the walker source for forbidden
   spawn primitives AND forbidden decryption / DPAPI / FEK-handling
   primitives. The walker treats $EFS blob bytes as DATA for METADATA
   extraction only — never decrypts, never invokes DPAPI, never even
   imports cryptographic modules. The tokenize-based strip ensures
   prose mentions don't false-positive.

5. **Rule #24 frontend tsc canary** — fired correctly with exit 2 on
   the planted `const x: number = "nope"` test, then exit 0 for the
   real ι.D.D type-check (after the WindowsFindingSource extension +
   FINDING_SOURCE_CONFIG mirror with 4 new EFS entries).

6. **Cross-stack alignment test** — passed cleanly on first run for
   ι.D.D. The test stack-awareness established for ι.A.D + ι.B.D +
   ι.C.D accepted the 4 new windows_efs_* values automatically.

7. **CI per-piece direct-push** (Pattern P5 + Rule #41) — 5 commits
   pushed directly to main per-piece; Lint job invoked per commit
   (queued/running at postmortem-author time; not blocking for the
   author).

## Patterns Promoted

### Pattern P1 single-sub-agent + precedent reuse — Rule-of-Eight → Rule-of-Nine

ι.D is the NINTH consecutive application of Pattern P1. Each precedent
file (η.A `mft_walker.py` for NTFS plumbing; ι.C `etl_walker.py` for
the Rule #39 triplet shape; ι.C `windows_etl.py` for the MCP tools
including the cross-firmware aggregation tool; ι.C `aabbccddee04/05/
06` alembic migrations; `test_finding_source_alignment.py` test
shape) was reused with mostly per-symbol substitutions plus walker-
specific parsing logic (the EFS $EFS blob parser is the novel piece).
Promotion: **Rule-of-Nine**.

### Rule #39 inner/outer/safe runner triplet — Rule-of-Seventeen → Rule-of-Eighteen

The eighteenth consecutive Rule #39 application. The triplet shape
transferred cleanly from ι.C's ETL precedent. The MS-EFSR-specific
parsing inside the inner orchestrator (vs ι.C's dissect.etl
substitution) did not change the triplet shape at all. Promotion
confirmed.

### Rule #25 single-slice exception #2 — Rule-of-Twenty-One → Rule-of-Twenty-Two

The twenty-second consecutive cross-stack alignment single-slice
commit. ι.A.D was Rule-of-Nineteen (FIRST non-Windows); ι.B.D was
Rule-of-Twenty (SECOND non-Windows); ι.C.D was Rule-of-Twenty-One
(FIRST ι Windows). ι.D.D is Rule-of-Twenty-Two (SECOND ι Windows
extension — windows_efs_*). The alignment test stack-awareness
required zero changes to accept the 4 new windows_efs_* values
automatically. Promotion confirmed.

### Cross-firmware aggregation at walker-stream time — Rule-of-Two → Rule-of-Three (DURABLE)

**Strong-evidence promotion across 3 distinct domains.** ι.B.E shipped
`lookup_systemd_unit_across_firmwares` (Linux persistence;
Rule-of-One). ι.C.E shipped `lookup_etl_provider_across_firmwares`
(Windows ETW; Rule-of-Two). ι.D.E ships `lookup_efs_recovery_agent_
across_firmwares` (Windows EFS metadata; Rule-of-Three). **The
pattern is now DURABLE BEYOND DEBATE** — it applies cleanly across:

- Persistence artefacts (systemd unit names + ExecStart)
- Trace-log providers (ETW GUIDs)
- Cryptographic recovery metadata (EFS SIDs + cert thumbprints)

Common shape across all 3:
- Tool name pattern: `lookup_<artefact>_<across_firmwares>`
- Required parameter: the per-firmware natural-key (with optional
  refinement parameter like event_id / cert_thumbprint).
- `scope` parameter: `"project"` (default) | `"global"`
- Output schema: per-firmware match metadata + `supply_chain_signal`
  field on `match_count >= 2`
- Implementation: SQL JOIN against the per-firmware table + Firmware
  + Project, grouped by firmware, then Python-side filter for JSONB
  containment where applicable.

The EFS application is the **highest-value** of the three — recovery
agent thumbprint matching is a STRONG indicator (shared backdoor key,
un-rekeyed vendor default, supply-chain compromise). Future walker
streams MUST ship the cross-firmware aggregation tool at walker-stream
time, not as a follow-up. **Promotion candidate for end-of-ι
codification** as a new top-level CLAUDE.md rule OR a
`.mex/patterns/cross-firmware-aggregation-at-walker-stream.md`
recipe with the standard shape documented above.

### NEW: Parse-only metadata walker — Rule-of-One (CODIFICATION CANDIDATE)

ι.D establishes the precedent for walkers that surface METADATA
WITHOUT touching the sensitive payload (decryption, execution,
plaintext recovery). Distinct from previous walkers:

- ι.C ETL walker: parses event records, including DECODED payloads
  (manifest-resolved field key/value pairs).
- η.A NTFS walker: walks the MFT including ADS stream sizes (but
  not stream contents).
- ε.1.b EVTX walker: parses event records and their full Message XML.

ι.D EFS walker is structurally different — it reads the $EFS
LOGGED_UTILITY_STREAM blob bytes for METADATA extraction (SIDs, cert
thumbprints, friendly names) but IGNORES the RSA-encrypted FEK
entirely. The encrypted_fek field is never read into a variable,
never persisted, never decrypted.

Future walkers needing this discipline:
- DPAPI master keys (similar shape — surface key metadata, never
  decrypt).
- BitLocker recovery information (surface recovery agent + key
  protectors, never extract the master key).
- PGP/GPG keyring (surface key IDs + UIDs, never decrypt private keys).
- TPM-sealed blobs (surface PCR policy, never unseal).

**Codification candidate** as a new top-level CLAUDE.md rule OR a
`.mex/patterns/parse-only-metadata-walker.md` recipe. The shape:

1. Walker reads the encrypted/sensitive blob bytes ONLY for METADATA
   extraction.
2. The "decrypt" / "unseal" / "recover-plaintext" code path NEVER
   exists in the walker source.
3. Rule #36 EXTENSION test gate enforces — scans for forbidden
   decryption / DPAPI / FEK / decryption-library tokens using
   docstring-stripped source.
4. Forensic value: WHO has access (SIDs / key IDs / recovery agents),
   not WHAT they decrypt to.

### NEW: Rule #36 EXTENSION (no-decrypt for security-sensitive metadata walkers) — Rule-of-One

ι.D.C's `test_efs_walker_no_execute_no_decrypt_attempt` extends Rule
#36 (no-spawn) with a second tier of forbidden tokens for walkers
that handle encrypted artifacts. The pattern:

1. Standard Rule #36 forbidden_spawn check (subprocess / asyncio /
   os.system / runpy / eval / exec).
2. NEW forbidden_decrypt check:
   - DPAPI: `CryptUnprotectData`, `CryptProtectData`
   - Decryption libs: `from cryptography.fernet`, `cryptography.fernet.`
   - asn1crypto crypto submodules: `asn1crypto.cms.`, `asn1crypto.algos.`
   - Generic decrypt calls: `.decrypt(`, `decrypt_fek`, `extract_fek`
   - DPAPI wrappers: `impacket.dpapi`, `dpapick`
3. Persistence anti-token check on RAW source: `row.encrypted_fek =`,
   `WindowsEfsEncryptedFile(..., encrypted_fek=...)`.
4. `_strip_docstrings_and_comments(source)` helper using `tokenize`
   to drop STRING + COMMENT tokens, so prose mentions in "we don't
   do this" docstrings don't false-positive.

**Codification candidate** as a Rule #36 sub-pattern or expansion.
The standard Rule #36 already covers the spawn-primitive class
universally; this extension adds the decryption-primitive class for
the parse-only walker shape. Could be folded into Rule #36's text
as a sub-clause, or codified as a sibling Rule #36c "no-decrypt
discipline for parse-only metadata walkers".

### Scout 1 OSS-library decision (Rule #19 evidence-first)

**Choice:** zero new dependencies. Reuse `dissect.ntfs` (η.A baseline)
+ `asn1crypto` (already in tree).

**Evidence considered:**
- `dissect.ntfs` ships `ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM`
  (0x100) + `ATTRIBUTE_FLAG_ENCRYPTED` (0x4000) constants; the
  `AttributeMap` returned by `MftRecord.attributes` supports
  `attrs[ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM]` indexing returning
  a list-like `AttributeCollection` whose elements expose
  `header.open()` / `data()` for raw bytes.
- `asn1crypto` 1.5.1 already in tree (transitive dep from existing
  signing-chain code paths); ASN.1 parsing for the cert-hash-data
  blob if needed.
- The $EFS blob is **not** ASN.1 — it's a custom Microsoft-defined
  binary layout (EFS_HEADER + EFS_DATA_KEY_TABLE + EFS_RSA_KEY_HASH_
  DATA arrays). Parsed with `struct` from stdlib. asn1crypto wasn't
  needed in the end.

**Decision rationale:** zero-new-dep was the right call. The MS-EFSR
layout is small (~76-byte header + ~40-byte per-entry header +
variable-length SID/cert-hash/friendly-name data) and was perfectly
parseable with `struct.unpack_from` + bounds-checking. A vendor lib
would have added dependency surface without value.

**Tradeoff accepted:** the EFS blob parser is custom code (~110 LOC
between `parse_efs_blob`, `_parse_efs_table`, `parse_sid_binary`,
`format_thumbprint_hex`). Future Microsoft format changes (e.g.
the rumored MS-EFSR v3 with CNG-only support) would require parser
updates. Acceptable — Microsoft hasn't changed the $EFS layout since
~Vista, and the parser is heavily bounds-checked + defensive.

## Decision Log

### D1 — OSS library choice (Rule #19 evidence-first)

**Choice:** zero new deps; reuse dissect.ntfs + custom struct-based
$EFS parser.

See "Scout 1 OSS-library decision" above. The clean-room parser is
~110 LOC vs an unknown vendor lib footprint; given the MS-EFSR layout's
small surface, clean-room was the right tradeoff.

### D2 — Anomaly source-name set (4 sources, 3 anomaly bits not emitted)

**Choice:** 4 Finding sources covering the canonical EFS abuse surface:

- `windows_efs_orphaned_drf` (HIGH — T1486 ransomware-via-EFS OR
  T1564.001 insider stealth)
- `windows_efs_unusual_recovery_agent` (MEDIUM — T1564.001 supporting)
- `windows_efs_domain_admin_in_ddf` (MEDIUM — T1078.002)
- `windows_efs_large_drf` (LOW — baseline review)

**NOT emitted as Findings** (informational via JSONB anomaly_flags only):
- `cert_thumbprint_anomaly` — empty / suspiciously short thumbprint.
  This is informational; it indicates a parse oddity or a non-standard
  cert format, not actionable security signal on its own.
- `parse_error` — $EFS blob couldn't be parsed. Same — informational.

**Rationale:** the 4 emitted sources are each tied to a specific MITRE
ATT&CK technique with a clear operator action. The 2 informational
bits are visible to MCP queries via `list_efs_encrypted_files`
`anomaly_bit="cert_thumbprint_anomaly"` filter but don't churn the
Finding table with low-actionable rows.

### D3 — Anomaly classifier suppression hierarchy

**Choice:** every anomaly bit fires INDEPENDENTLY. A file with both
`orphaned_drf` (HIGH) and `domain_admin_in_ddf` (MEDIUM) gets BOTH
finding rows.

**Rationale:** unlike ι.C ETL where `non_microsoft_in_diagtrack`
subsumed `unusual_provider` (both fired on the same event, the
Diagtrack one was strictly stronger), EFS anomaly bits represent
genuinely distinct adversary signals: orphaned_drf is the
"encrypted-via-recovery-only" shape; domain_admin_in_ddf is the
"admin pre-staging vs compromise" shape. They CAN co-occur (admin
pre-staged with no DDF) but each carries independent triage value.

**Tradeoff accepted:** a file with multiple anomalies produces
multiple Finding rows. Operator triage may need to consolidate.
Acceptable — the Findings table already supports multiple sources
per artefact via the (firmware_id, file_path) natural key.

### D4 — Cross-firmware aggregation by SID OR thumbprint (AND-combinable)

**Choice:** `lookup_efs_recovery_agent_across_firmwares` accepts EITHER
sid OR cert_thumbprint OR BOTH (AND-combined). Either alone is
sufficient to query; both together is a stricter filter.

**Rationale:** an operator finding a suspicious recovery agent on one
firmware may have only the SID (from the per-file lookup) or only the
thumbprint (from a documented external source like a vendor recovery
policy). Supporting either alone covers both workflows. The
AND-combined case is for advanced operators who want to disambiguate
matches when one of the two fields has known collisions.

**Tradeoff accepted:** the implementation reads all rows in scope and
Python-side filters (since JSONB containment for arbitrary
list-of-dict matching is dialect-specific). For very large
deployments (10K+ firmwares × 100+ EFS files), this could be slow.
Acceptable for current wairz scale; can be optimized later with a
materialized `(firmware_id, sid, cert_thumbprint)` projection if
operators report slow queries.

### D5 — PARSE-ONLY discipline visible in MCP tool descriptions

**Choice:** every windows_efs tool description includes the
"PARSE-ONLY" notation in the description string. The
`trigger_efs_walk` description specifically calls out "wairz NEVER
decrypts the RSA-encrypted FEK, NEVER invokes Windows DPAPI".

**Rationale:** the LLM consumer needs to understand the security
contract of the walker. An LLM that doesn't know we don't decrypt
might suggest "and then we could decrypt the FEK to recover the
file contents" — which is exactly the violation we're guarding
against. Making the discipline visible at the tool-description
layer prevents LLM-driven misuse.

**Tradeoff accepted:** tool descriptions are longer (~50-100 chars
added per tool). Acceptable — Rule #29 truncation cap is 30 KB; we
have plenty of headroom.

## HANDOFF stub

**State at session close:** ι.D complete. All 5 commits landed on
main. Backend ready for `docker compose up -d --build backend worker
migrator` (Rule #8) to apply alembic head aabbccddee09 + load new
dissect.ntfs-based walker + register 6 new EFS MCP tools. MCP tool
count 275. FindingSource catalog 65 values.

**Next stream:** Per the Phase ι kick-off brief, ι is now COMPLETE
(ι.A journald + ι.B systemd + ι.C ETL + ι.D EFS = 4 streams, the
campaign target of 4-5 single-session streams). Recommended next:
either ι.E (one of the deferred candidates — auditd walker, EVT
pre-Vista, container runtime forensics) if capacity remains, OR move
to end-of-ι learn/postmortem-rollup. The Rule #39 triplet shape +
cross-firmware aggregation tool shape + parse-only metadata walker
shape all transfer directly from ι.D.

**Rebuilds needed:** backend + worker + migrator after `git pull`
because ι.D adds:
- A new ORM table (windows_efs_encrypted_files) — Rule #20 exception
  applies if class-shape changes; here it's additive so `docker compose
  restart backend` would suffice for backend-only smoke, but Rule #8
  three-way rebuild is the durable shape for production deployment.
- A new firmware column set (efs_walk_*) — additive.
- 3 new alembic revisions (aabbccddee07/08/09).
- 6 new MCP tools registered in create_tool_registry().

**Open follow-ups (none blocking ι.E if dispatched):**
- D1 tradeoff: custom struct-based parser may need updates if
  Microsoft releases an MS-EFSR v3 with CNG-only fields. Defer.
- D2 tradeoff: 2 informational bits (cert_thumbprint_anomaly /
  parse_error) only surface via JSONB queries. If operator workflow
  reveals demand for Finding-row emission, easy to add.
- D3 fold tradeoff: independent firing across all 4 emitted sources.
  Defer until operator workflow reveals consolidation demand.
- D4 query-performance tradeoff: Python-side filtering for JSONB
  containment in cross-firmware aggregation. If queries become slow
  at scale, add materialized projection.

**Pattern P1 Rule-of-Nine confirmed at ι.D close.** Future ι.E estimate
(per A6 brief estimate discounting): ~20-25 min agent-wall based on
ι.B's ~25 min, ι.C's ~22 min, ι.D's ~25 min — pattern is durable at
~20-30 min per Rule #39 walker stream.

**Cross-firmware aggregation Rule-of-Three confirmed at ι.D close —
PATTERN IS DURABLE.** Future Linux + Windows walkers MUST ship
`lookup_<X>_across_firmwares` from the start. CODIFICATION CANDIDATE
for end-of-ι.

**Parse-only metadata walker pattern Rule-of-One established at ι.D
close.** New pattern shape for future walkers handling encrypted /
sensitive artifacts (DPAPI, BitLocker, PGP, TPM). CODIFICATION
CANDIDATE for end-of-ι.

**Rule #36 EXTENSION (no-decrypt) Rule-of-One established at ι.D
close.** Second-tier safety floor for parse-only walkers. CODIFICATION
CANDIDATE for end-of-ι (fold into Rule #36 as a sub-clause or codify
as sibling Rule #36c).

**Rule #19 evidence-first OSS-library decision confirmed.** Zero new
deps for ι.D — dissect.ntfs (η.A baseline) + struct + bounds-checking
parser was sufficient. Continues to validate the Rule #19 discipline
of "measure the actual library API before committing to a dep choice."
