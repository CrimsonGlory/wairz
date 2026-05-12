# PyWMIPersistenceFinder — vendor attribution

## Source

- **Upstream:** https://github.com/davidpany/WMI_Forensics
- **Upstream file:** `PyWMIPersistenceFinder.py` (Version 1.1, 2017-vintage)
- **Vendoring date:** 2026-05-12 (Phase θ.B.A — wairz windows-coverage-godmode)
- **Author:** David Pany — Mandiant (FireEye), Twitter `@DavidPany`
- **License:** MIT (see `LICENSE`)

## Scope of vendoring

Keyword-search WMI persistence detection only — identifies
`__FilterToConsumerBinding` records in WMI repository `OBJECTS.DATA`
files by regex matching, paired with the bound `EventConsumer` and
`EventFilter` details. Wairz does **not** vendor any full
WMI-repository emulation logic; that's the unmaintained
[flare-wmi / python-cim](https://github.com/fireeye/flare-wmi/tree/master/python-cim)
space and is out of scope for this campaign.

The keyword approach has a well-validated low false-positive rate: a
binding's two endpoints must BOTH match the canonical
`EventConsumer.Name="<name>"` / `_EventFilter.Name="<name>"` regex
shape paired with a `_FilterToConsumerBinding` marker in the same
rolling 4-line window.

## Adaptations from upstream

The upstream is a CLI-only script (`main()` reads `sys.argv[1]`,
prints to stdout). The wairz vendor refactors the regex / dict logic
into a callable programmatic API for direct consumption by
`app.services.wmi_walker`:

1. `find_persistence(path: str | Path) -> list[BindingResult]`
   instead of `main() -> None` (no `sys.argv` dependency, no stdout
   output).
2. Python-2 `.iteritems()` → Python-3 `.items()`.
3. Per-name set storage replaced with `list[ConsumerDetails]` /
   `list[FilterDetails]` for stable iteration order.
4. Upstream's "BVTConsumer-BVTFilter" / "SCM Event Log" benign
   annotation preserved as a `probably_benign: bool` field on each
   `BindingResult`.
5. Defensive caps added: `max_bindings: int = 500` (DoS guard on
   attacker-planted multi-thousand-binding files) and
   `max_file_bytes: int = 1 GiB` (DoS guard on attacker-planted
   pathologically-large OBJECTS.DATA).
6. Type annotations added throughout (consumer + binding result
   dataclasses, function signatures).
7. UTF-16-LE decoding added for BSTR-encoded WMI strings (the
   typical Windows-repository encoding for consumer / filter names).

The **upstream regex patterns are preserved verbatim** — only the
surrounding control flow is refactored. False-positive / false-
negative characteristics are unchanged.

## CLAUDE.md Rule #36 no-execute compliance

This module is 100% text parsing — file reads + regex matches. The
vendor file contains ZERO subprocess / shell / exec / eval / runpy
/ `importlib.import_module(<runtime_string>)` / dynamic-execution
activity. Verified by:

```bash
grep -rn 'subprocess\.\|os\.system\|os\.execvp\|asyncio\.create_subprocess\|runpy\|eval(\|exec(' \
    backend/third_party/pywmi_persistence_finder/
```

Returns 0 matches. The test gate
`tests/test_pywmi_persistence_finder.py::test_no_execute_in_vendor`
asserts this discipline programmatically.

## Updates / re-syncing from upstream

If a future change to wairz needs to incorporate upstream changes
(unlikely — the upstream has been stable since 2017), follow this
recipe:

1. Re-fetch the upstream raw file:
   `curl -sL https://raw.githubusercontent.com/davidpany/WMI_Forensics/master/PyWMIPersistenceFinder.py`
2. Diff against the current vendor's regex blocks.
3. Apply changes preserving the `find_persistence` API + the rule
   #36 no-execute discipline.
4. Re-run the vendor test gate before commit.
5. Update this file's "Vendoring date" + add a "Re-sync" log entry.

## Re-sync log

- 2026-05-12: initial vendor (Phase θ.B.A).
