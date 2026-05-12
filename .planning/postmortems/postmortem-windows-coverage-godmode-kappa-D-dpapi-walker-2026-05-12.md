---
postmortem_id: postmortem-windows-coverage-godmode-kappa-D-dpapi-walker-2026-05-12
campaign_id: windows-coverage-godmode-kappa-2026-05-12
stream_id: κ.D — Windows DPAPI master-key PARSE-ONLY METADATA walker
status: closed
opened: 2026-05-12
session_id: κ.D single-stream (cont. from κ.C close 7469feb)
trust_level: trusted (direct-push to main per-piece, Pattern P5)
commits:
  - 2d5d8e7 feat(windows-dpapi): WindowsDpapiMasterKey ORM + alembic migration (κ.D.A)
  - 8720b28 feat(firmware): dpapi_walk_* 5-column 202+poll status set (κ.D.B)
  - bbf1a1d feat(dpapi): Rule #39 walker triplet for DPAPI master-key parse-only metadata (κ.D.C)
  - 9360709 feat(findings): Windows DPAPI cross-stack alignment + emit (κ.D.D)
  - 43ab2dd feat(mcp): windows_dpapi MCP tool category — 5 tools (κ.D.E)
mcp_count_delta: 292 → 297 (+5 — 4 per-firmware + 1 cross-firmware aggregation)
alembic_head_delta: aabbccddee12 → aabbccddee15 (3 new revisions: aabbccddee13, aabbccddee14, aabbccddee15)
finding_source_count_delta: WindowsFindingSource 41 → 44 (+3 — third κ Windows extension)
new_oss_dep: zero — stdlib-only (pure-Python struct parsing; impacket NOT used; cryptography NOT used)
rule_chain_extensions:
  - **Rule #45 PARSE-ONLY metadata walker — Rule-of-One → Rule-of-Two DURABLE BEYOND DEBATE** (campaign-defining promotion)
  - Rule #36 EXTENSION (no-decrypt test gate via tokenize) — Rule-of-One → Rule-of-Two (ι.D + κ.D both ship the gate)
  - Rule #39 inner/outer/safe runner triplet — Rule-of-Twenty-One → Rule-of-Twenty-Two
  - Rule #25 single-slice exception #2 — Rule-of-Twenty-Five → Rule-of-Twenty-Six
  - Rule #44 cross-firmware aggregation at walker-stream time — Rule-of-Seven → Rule-of-Eight (DURABLE BEYOND DEBATE)
  - Pattern P1 single-sub-agent + precedent reuse — Rule-of-Thirteen → Rule-of-Fourteen
  - Pattern P7 trust-but-verify orchestrator gate — Rule-of-Nine → Rule-of-Ten (decimal milestone)
  - **Rule #17 canary discipline EXTENSION — Rule-of-Three** (silent-CLI-exit cache + tsc --noEmit + κ.D test-gate-tokenization gap = 3 instances of "verify the verification mechanism actually works before trusting it")
tests_landed: walker tests (~38 in test_dpapi_walker.py incl. parser tests + path-recognizer tests + 3 anomaly classifier tests + Rule #36+#45 no-decrypt gate + canary that gate actually fires) + 8 jsonb normalizer tests + 3 alignment tests = ~49 new tier-1 tests (all passing)
duration_clock_to_clock: ~38 minutes wall (sub-agent self-reported; matches κ.B + κ.C cadence)
duration_caveat: |
  Antipattern A4 acknowledged — 38 min matches the κ stream cadence baseline.
  Worth noting that the test-gate-canary iteration added ~5-10 min to what would
  otherwise have been ~28-30 min if the f-string-vs-concatenation canary bug
  had been caught on first try. The iteration was VALUE-POSITIVE (caught a
  latent bug in the gate; saved κ.D from shipping broken).
---

# Phase κ.D — Windows DPAPI master-key PARSE-ONLY METADATA walker postmortem

## Summary

κ.D shipped the **fourth Windows walker in κ** and the **second Rule #45 PARSE-ONLY METADATA walker** in wairz's portfolio. 5 per-piece direct-pushed commits, all clean. MCP total 292 → 297. Alembic chained 3 new revisions (`aabbccddee13/14/15`). WindowsFindingSource catalogue expanded from 41 → 44 values. 890 LOC walker (header struct parser + body preamble probe + path-pattern detector + 3 anomaly classifiers) + 747 LOC tests. ~49 new tier-1 tests pass.

**Strategic outcome — Rule #45 PROMOTION to Rule-of-Two DURABLE BEYOND DEBATE.** Parse-only-metadata is now a durable wairz discipline:

- ι.D EFS DDF/DRF metadata (Rule-of-One — never decrypts FEK, surfaces recovery-agent SIDs and DDF-user SIDs as metadata)
- κ.D DPAPI master-key metadata (Rule-of-Two — never decrypts master keys, surfaces GUID + flags + hmac_iterations + creator_sid + size metadata)

The pattern is mechanically verifiable via a `tokenize`-based test gate that scans the walker source for forbidden decrypt-related tokens. Future security-sensitive metadata walkers (BitLocker recovery info, PGP keyring metadata, TPM blobs, certificate trust stores) inherit the discipline by default.

**Adversary lens:** T1555.004 (Credentials from Password Stores: Windows Credential Manager) + T1003 (OS Credential Dumping). Every Windows credential-theft TTP touches DPAPI master keys. The walker surfaces master-key METADATA (GUID, flags, iterations, creator SID, sizes) WITHOUT ever attempting decryption — which would be both a security risk AND a Rule #36 no-execute violation.

## What worked

- **Pattern P1 single-sub-agent + precedent reuse — Rule-of-Fourteen.** Sub-agent
  read ι.D EFS shape (Rule #45 precedent) + κ.B AppCompat shape (most-recent κ
  Windows walker) + κ.C linux_persistence_walker (file-glob detection precedent)
  and emitted the new walker with the master-key file format parser as the
  primary novelty.
- **Pure-Python struct parsing of the DPAPI master-key header.** Defensive shape:
  validates version ∈ {1, 2}, no-emits on truncation, optionally probes the
  master-key body PREAMBLE for `pbkdf2_iterations` + `salt_size` (which is always
  16 per the spec — recorded as constant, NOT as bytes). Body decryption is
  STRUCTURALLY UNAVAILABLE — the encrypted block boundary is identified but never
  crossed.
- **Rule #36 + #45 test gate with CANARY discipline.** The gate scans tokenized
  walker source for 13 forbidden patterns covering all known DPAPI decrypt entry
  points (`.decrypt(`, `CryptUnprotectData`, `fernet`, `asn1crypto cms/algos`,
  `impacket MasterKey()`, `pyDes`, `Crypto.Cipher`, etc.). The CANARY
  (`test_walker_no_decrypt_gate_actually_fires`) synthesizes a `.decrypt(`
  violation IN MEMORY and verifies the gate would catch it — Rule #17 / Rule #24
  canary discipline applied to a test-gate (not a CLI).
- **Worktree isolation continues holding zero-sweep.** No cross-stream commits;
  ff-merge clean across all 5 commits.

## What broke

**1 latent test-gate weakness discovered + fixed by the canary discipline (the WIN
of the canary).**

The tokenize-based docstring/comment stripper joins tokens with single spaces:
`obj.decrypt(` in source code becomes `obj . decrypt (` in stripped output. A
naïve forbidden-token regex `\.decrypt\(` does NOT match `. decrypt (`. The
synthetic-violation canary caught this BEFORE κ.D shipped — fixed by switching
the forbidden-token patterns to be tolerant of whitespace between tokens
(`\.\s*decrypt\s*\(`). **The ι.D EFS gate from last week would have ALSO failed
against synthetic violations under this same condition** — a latent gap exposed
retroactively by κ.D's canary discipline.

**Backfill action item for κ close OR κ.X carve-out:** retrofit the ι.D EFS
`test_walker_no_decrypt` regex patterns with the whitespace-tolerant shape from
κ.D. Without this, the ι.D gate is a Rule #17 silent-CLI-exit instance — passes
silently against ALL synthetic inputs because the regex structurally doesn't
match what `tokenize` actually emits.

**1 secondary issue during canary development.** The synthetic-violation canary
itself required two iterations: first attempt used an f-string to construct the
synthetic source (`f'def f(): obj.decrypt(b"x")'`), which made the ENTIRE
expression a string literal that tokenize stripped out (since strings are not
code tokens). Fixed by concatenating non-string code lines as a real `dedent`'d
source block, then calling `tokenize` on it. The author noted this in the
postmortem — sub-agent self-caught.

## Rule #17 canary discipline — Rule-of-Three promotion

The κ.D test-gate canary instance combined with prior Rule #17 + Rule #24
instances forms a **Rule-of-Three for canary discipline broadly**:

1. **Rule #17 (original):** `tsc -b` incremental cache exits 0 on no-change — canary
   with a known-bad input confirms the tool actually checks.
2. **Rule #24:** `npx tsc --noEmit` silently no-checks projects with `"files": []`
   — mandatory canary once per session.
3. **κ.D test-gate (NEW):** tokenize-based test gate's regex didn't match
   whitespace-separated tokens — synthetic-violation canary confirmed gate would
   catch a real violation.

Broader Rule-of-Three: **"Any test gate / verification mechanism that asserts
absence of something (no forbidden tokens, no type errors, no failing tests,
etc.) MUST have a CANARY that introduces a synthetic violation and confirms the
gate catches it. Without the canary, the gate's pass result is structurally
indistinguishable from 'the gate isn't actually checking.'"**

This is a strong candidate for codification as a top-level CLAUDE.md rule (Rule
#46 candidate). The pattern is: 3 instances across 3 distinct
verification-mechanism families (CLI exit code; whole-file typechecker; AST/token
scanner) = generalizable.

## Walker-test-fixture string-pattern Rule-of-Two candidate

κ.D did NOT hit the walker-test-fixture string-pattern issue from κ.B + κ.C
(Windows-path raw-string escapes / regex word-boundary at `/`). κ.D's string
constants were UTF-16LE GUID patterns + SID regex patterns — different family.
The Rule-of-Two candidate from κ.B + κ.C remains at Rule-of-Two; κ.E (UsnJrnl)
is the last chance for Rule-of-Three promotion within the campaign.

## Sub-agent observations

- **Path-pattern detection is the bottleneck for DPAPI walker accuracy.** Master-key
  files live under `Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>` —
  the recognizer must extract `<SID>` from the path AND match a GUID-shaped
  filename. Sub-agent used a compiled regex with explicit `(re.IGNORECASE)` flag
  and tested against canonical + lowercase + UTF-16LE-decoded variants.
- **Salt size is a CONSTANT.** DPAPI master-key format hardcodes 16-byte salts.
  Recording `salt_size=16` as a column makes the schema discoverable; recording
  the salt BYTES would aid attackers reconstructing the master key (rule #45
  parse-only violation).
- **HMAC iterations vary** (10000-32000 typical) — surfaced because operators may
  want to flag low-iteration master keys as weak.
- **Live canary test_do_dpapi_walk_persists_master_key_file** synthesizes a
  master-key file at a canonical DPAPI path, walks it, SELECTs the persisted row,
  and asserts `salt_size=16` + `salt_bytes` column DOES NOT EXIST on the ORM
  (negative-evidence). Rule #35b live-canary applied to security-sensitive
  metadata.

## Rule promotion confirmed

- **Rule #45 parse-only-metadata-walker — Rule-of-Two DURABLE BEYOND DEBATE.**
  Campaign-defining promotion.
- **Rule #36 EXTENSION (no-decrypt test gate) — Rule-of-Two.** ι.D + κ.D both
  ship the gate. Companion to Rule #36 base (no-execute).
- **Rule #44 cross-firmware aggregation — Rule-of-Eight DURABLE BEYOND DEBATE.**
- **Rule #39 walker triplet — Rule-of-Twenty-Two.**
- **Rule #25 single-slice exception #2 — Rule-of-Twenty-Six.**
- **Pattern P1 — Rule-of-Fourteen.**
- **Pattern P7 — Rule-of-Ten (decimal milestone).**
- **Rule #17 canary discipline EXTENSION — Rule-of-Three** (CANDIDATE FOR
  CODIFICATION as a new top-level CLAUDE.md rule — Rule #46 candidate).

## Forward signal

- **κ.E (UsnJrnl $J change-log walker) dispatches next.** Last stream of κ.
  dissect.ntfs reuse (η.A precedent). Watching for walker-test-fixture
  string-pattern Rule-of-Three promotion (currently Rule-of-Two from κ.B + κ.C).
- **κ close action items:**
  - Backfill ι.D EFS walker's `test_walker_no_decrypt` regex with κ.D's
    whitespace-tolerant pattern (1-line fix; could ship as κ.X or κ close).
  - Codify Rule #17 canary-discipline-for-test-gates broader form as Rule #46
    in CLAUDE.md (Rule-of-Three threshold met).
  - Campaign-level patterns/antipatterns extraction via /citadel:learn.
  - λ (memory-forensic-godmode-α) kickoff intake stub.
  - Backend+worker+migrator rebuild (4 new ORMs + 12 new alembic migrations).
  - /citadel:session-handoff at session close.
