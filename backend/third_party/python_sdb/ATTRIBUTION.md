# python-sdb — vendor attribution

## Source

- **Upstream:** https://github.com/williballenthin/python-sdb
- **Upstream master SHA:** `8ac378546e72a3f9f4bf00a1ea6a89fbb0f77c2e` (as of
  2026-05-12)
- **Author:** Willi Ballenthin (well-known Windows reverse engineer)
- **License:** Apache 2.0 (see `LICENSE`)
- **Vendoring date:** 2026-05-12 (Phase θ.D.A — wairz windows-coverage-godmode)

## Scope of vendoring

Application Compatibility Shim Database (`.sdb`) binary-format parsing
ONLY — sufficient to enumerate APPS, SHIMs, and PATCHEs in an attacker-
planted shim database (T1546.011 Application Shimming persistence).
Wairz does NOT vendor the upstream's `vivisect-vstruct-wb` dependency
nor the upstream `sdb/patchbits.py` PATCHBITS deserializer; the
wairz vendor is a clean-room minimal parser written from the upstream
format documentation. Specifically vendored:

- 4-byte file magic `sdbf` at offset 8 (per `SDBHeader`).
- The TAG / SIZE chunk format (one byte tag-low + one byte tag-high =
  uint16 tag; payload size derived from the type-bits encoded in the
  high nibble of the tag: 0x1000=NULL, 0x3000=WORD, 0x4000=DWORD,
  0x5000=QWORD, 0x6000=STRINGREF, 0x7000=LIST, 0x8000=STRING,
  0x9000=BINARY).
- The well-known TAG IDs published by upstream (TAG_DATABASE,
  TAG_LIBRARY, TAG_INDEXES, TAG_STRINGTABLE, TAG_INDEX, TAG_APP,
  TAG_EXE, TAG_SHIM, TAG_PATCH, TAG_LAYER, TAG_FILE, TAG_NAME,
  TAG_DESCRIPTION, TAG_MODULE, TAG_DLLFILE, TAG_COMMAND_LINE, etc.).
- The STRINGREF→string lookup pattern (a STRINGREF tag carries a DWORD
  offset into the STRINGTABLE list of TAG_STRINGTABLE_ITEM strings).

## Why a clean-room rewrite, not a verbatim vendor

The upstream depends on `vivisect-vstruct-wb==1.0.3` for binary parsing
(a fork of the heavyweight Vivisect reverse-engineering framework). To
avoid pulling this heavyweight transitive dependency into wairz's
worker container, the vendor is a clean-room minimal parser written
**from the upstream format documentation only** — the constants
(TAG IDs, type-bit masks, magic bytes) are reproduced under fair-use
reference, but no upstream code is copied. The parser uses only the
Python standard library (`struct`, `dataclasses`).

The upstream license is preserved (`LICENSE`) per Apache 2.0 §4(c)
("retain all copyright, patent, trademark, and attribution notices
from the Source form"). The constant tables are the upstream's
copyrightable contribution; we acknowledge them here.

## Adaptations from upstream

1. **No vstruct dependency.** Upstream uses
   `vivisect.vstruct.VStruct` for binary parsing. Wairz vendor uses
   `struct.unpack_from` directly against `bytes` slices.
2. **No file-path-based constructor.** Upstream offers
   `sdb = SDB(); sdb.vsParse(bytez)`. Wairz vendor exposes
   `parse_sdb(bytez: bytes) -> ParsedSDB` returning a dataclass
   aggregate of APP / SHIM / PATCH entries.
3. **Defensive caps added:** `max_file_bytes: int = 64 MiB` (DoS guard on
   attacker-planted pathologically-large `.sdb` files) and
   `max_chunks: int = 200_000` (DoS guard on attacker-planted
   nested-chunk loops).
4. **Type annotations + dataclasses** added throughout for type safety.
5. **No PATCHBITS sub-parser.** Upstream's `sdb/patchbits.py`
   deserializes the binary PATCH_BITS opcode stream. The wairz vendor
   exposes the raw PATCH_BITS bytes as `bytes` (the
   `app.services.sdb_walker` consumer surfaces them in evidence as
   hex, no opcode interpretation needed for triage).
6. **Two TAG-name views.** A reverse map from TAG-int → TAG-name is
   exposed (`tag_name_for(tag: int) -> str`) so the walker can
   produce human-readable evidence strings.

The **upstream TAG ID values + the type-bit masks are preserved
verbatim** — these are protocol-level constants, not copyrightable
expression, but cited above for attribution.

## CLAUDE.md Rule #36 no-execute compliance

This module is 100% binary parsing — `bytes` reads + `struct.unpack_from`
+ dictionary look-ups. The vendor file contains ZERO subprocess / shell
/ exec / eval / runpy / `importlib.import_module(<runtime_string>)` /
dynamic-execution activity. Wairz NEVER passes parsed shim payloads to
`sdbinst.exe`, `Mscoree.dll!CorBindToCurrentRuntimeHost`,
`AppHelp.dll`, or any other Windows shim infrastructure on the host —
the SDB entries are surfaced as DATA only via
`WindowsSdbEntry.shim_payload` + Finding evidence. Verified by:

```bash
grep -rn 'subprocess\.\|os\.system\|os\.execvp\|asyncio\.create_subprocess\|runpy\|eval(\|exec(\|sdbinst\|shim_eng' \
    backend/third_party/python_sdb/
```

Returns 0 matches. The test gate
`tests/test_python_sdb_vendor.py::test_no_execute_in_vendor` asserts
this discipline programmatically.

## Why this matters (security context)

`.sdb` files are loaded by Windows on every application launch when
the path matches `Windows/AppPatch/Custom/<exe>.sdb` (or via
`sdbinst.exe` installation into the registry). Adversaries (APT41,
FIN7, Carbanak, various ransomware affiliates) plant custom `.sdb`
shims for T1546.011 Application Shimming persistence — the shim is
loaded by Windows at AppHelp policy resolution, executing attacker
code (`InjectDll`, `RedirectEXE`, `GetCommandLineW`-hook, etc.) in
the target application's context.

Static parsing of these files is the only safe inspection method —
loading them on a Windows host literally executes them. The wairz
walker surfaces APP / SHIM / PATCH entries as DATA for operator
review only.

## Updates / re-syncing from upstream

If future Windows shim-database revisions add new TAG IDs (unlikely;
the format has been stable since Windows XP), follow this recipe:

1. Re-fetch the upstream raw file:
   `curl -sL https://raw.githubusercontent.com/williballenthin/python-sdb/master/sdb/sdb.py`
2. Diff against the TAG ID constants in the wairz vendor's `__init__.py`.
3. Extend the constant tables; do NOT introduce a vstruct / vivisect
   dependency.
4. Re-run the vendor test gate before commit.
5. Update this file's "Vendoring date" + add a "Re-sync" log entry.

## Re-sync log

- 2026-05-12: initial vendor (Phase θ.D.A). Upstream master SHA
  `8ac378546e72a3f9f4bf00a1ea6a89fbb0f77c2e`; clean-room parser
  implementation.
