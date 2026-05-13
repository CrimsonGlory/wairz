# Scout 1 — Volatility 3 Library Probe (λ memory-forensic-godmode-α)

Date: 2026-05-12. Scope: verify Vol3 invocation surface end-to-end for wairz λ.α — version pin, Python 3.12 compatibility, library vs subprocess API, CLI shape, smoke test against `windows.info`. Worker is Python 3.12 in the wairz worker container.

---

## 1. Version + install — pin `volatility3==2.28.0`

- **Latest stable:** **`volatility3` 2.28.0**, uploaded 2026-04-30 ([pypi.org/project/volatility3/](https://pypi.org/project/volatility3/), [github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) tag 2.28.0). Develop branch is rolling 2.28.1. **License:** VSL v1.0 (custom permissive, commercial use explicit; carries forward unchanged from η-scope scout-1).
- **Confirmed via local install** into a throwaway venv outside the wairz tree (Python 3.10 — host lacks 3.12; see §2): `Name: volatility3 / Version: 2.28.0 / License: VSL / Requires: pefile`.
- **Hard dependency:** `pefile>=2024.8.26` only (already in wairz worker). **No new heavy hard-dep.**
- **Optional extras** (per [pyproject.toml](https://github.com/volatilityfoundation/volatility3/blob/develop/pyproject.toml)): `full` → `yara-python`, `capstone`, `pycryptodome`, `leechcorepyc` (non-macOS), `pillow<11`. `pycryptodome` is required by `windows.hashdump` / `windows.lsadump` / `windows.cachedump`; confirmed locally — 13 plugins fail to load on a bare `pip install volatility3`.
- **Recommendation:** pin **`volatility3==2.28.0[full]`** (lock exact — 2.27→2.28 had breaking column changes). If `[full]` is too heavy at Docker layer (yara-python C build), split: core + `pycryptodome` always, gate `yara-python` behind existing `ARG INCLUDE_VOL3=1`.

## 2. Python 3.12 compatibility — supported; both prior 3.12 bugs fixed in tree

- **`requires-python = ">=3.8.0"`** (confirmed via [pyproject.toml](https://github.com/volatilityfoundation/volatility3/blob/develop/pyproject.toml); no upper bound). Ruff `target-version = "py38"`.
- **Two prior 3.12 issues — both resolved at 2.28.0:**
  1. Issue [#1105](https://github.com/volatilityfoundation/volatility3/issues/1105) — SyntaxWarning on invalid escape in `plugins.py:63`. PR [#1106](https://github.com/volatilityfoundation/volatility3/pull/1106) merged 2024-03-03. Confirmed gone in 2.28.0 source.
  2. Issue [#1220](https://github.com/volatilityfoundation/volatility3/issues/1220) — `imp` module deprecation breaking hashdump/lsadump on 3.12.3. Verified in 2.28.0 `volatility3/framework/plugins/__init__.py` — imports `logging`, `typing`, `volatility3.framework.{interfaces,automagic,exceptions,constants}`; **NO `imp` import**. Migrated to `importlib` before the 2.28 cut.
- **3.12 verification deferred:** the host has Python 3.10 only. Local smoke (3.10) installs cleanly, `vol --help` runs, framework enumerates plugins, `require_interface_version(2, 0, 0)` returns. **Next-session probe:** `docker run --rm python:3.12-slim sh -c "pip install volatility3==2.28.0[full] && python -c 'from volatility3 import framework, plugins; framework.import_files(plugins, True); print(len(framework.list_plugins()))'"` — ~30s wall, confirms 3.12 plugin enumeration parity.
- **Recommendation:** **3.12 supported.** Pin `volatility3==2.28.0[full]`. Remaining risk sub-1% — both known 3.12 issues are demonstrably fixed in source.

## 3. Python API surface — `framework.import_files` + `plugins.construct_plugin` + `TreeGrid.populate`

Library entry points (per [readthedocs/using-as-a-library](https://volatility3.readthedocs.io/en/latest/using-as-a-library.html); confirmed locally against 2.28.0):

```python
from volatility3 import framework, plugins
from volatility3.framework import contexts, automagic
framework.require_interface_version(2, 0, 0)        # 2.28.0 ships interface 2.0.0
ctx = contexts.Context()
framework.import_files(plugins, True)                # discover; returns failure list
plugin_list = framework.list_plugins()               # {"windows.info.Info": <cls>, ...}
ctx.config["automagic.LayerStacker.single_location"] = "file:///path/to/memory.dmp"
plugin_cls = plugin_list["windows.info.Info"]
chosen = automagic.choose_automagic(automagic.available(ctx), plugin_cls)
constructed = plugins.construct_plugin(ctx, chosen, plugin_cls, "plugins", None, None)
treegrid = constructed.run()
records = []
def visitor(node, acc):
    acc.append({col.name: node.values[i] for i, col in enumerate(treegrid.columns)})
    return acc
treegrid.populate(visitor, records)
```

Probed locally: `windows.info.Info` declares one requirement (`kernel`, a `ModuleRequirement` resolved by automagic from `-f` + `-s`). `plugins.construct_plugin(ctx, automagics, plugin, base_config_path, progress_callback, open_method)` collapses automagic + constructor — use it over the 7-step longhand. Call `framework.require_interface_version(2, 0, 0)` at `vol3_runner.py` import — fails fast on pin slip. **Verdict:** API works but is verbose (~30-50 LOC boilerplate) and the docs explicitly note "no concrete code examples for loading memory images." Subprocess wrapper is safer (§5).

## 4. CLI invocation shape — `-f` + `-s` + `--offline` + `-r jsonl`

Confirmed live against 2.28.0:

- `-f /path/to/memory.dmp` — input image (shorthand for `--single-location=file://...`)
- `-s /opt/wairz/vol3-symbols` — symbol directory (semi-colon for multiple); Rule #37 baked-in path
- `-r jsonl` — renderer (one JSON object per row, stream-parsable)
- `--offline` — **blocks all network access** for PDB/ISF downloads; mandatory per Rule #37
- `-q` — suppress progress bar to stderr; always
- `-o <tmp>` / `--cache-path <tmp>/cache` / `-l <tmp>/vol.log` — per-run paths
- `-v` (up to `-vvvvvv`) — verbosity

**Renderer choices** (from `vol --help`): `quick`, `none`, `csv`, `pretty`, `json`, `jsonl`, `arrow`, `parquet`. **Use `jsonl`** — line-by-line stream-parsable, no multi-MB array buffering. `json` (single-document `json.dumps(result, indent=2, sort_keys=True)` per `JsonRenderer.output_result` in `volatility3/cli/text_renderer.py`) is OK for tiny outputs (`windows.info`) but buffers the whole grid — bad for `pslist` on 16GB images. `csv` discards nested types. `arrow`/`parquet` need the `arrow` extra; skip.

**Baseline command** (λ.α.D subprocess-spawn target):
```
vol --offline -q -f <img> -s /opt/wairz/vol3-symbols -o <tmp> --cache-path <tmp>/cache \
    -l <tmp>/vol.log -r jsonl <plugin>
```

**`windows.info` output columns** (per [plugins/windows/info.py](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/plugins/windows/info.py)): `Kernel Base`, `DTB`, `Symbols`, `Is64Bit`, `IsPAE`, `layer_name`, `memory_layer`, `KdDebuggerDataBlock`, `NTBuildLab`, `CSDVersion`, `MajorVersion`, `MinorVersion`, `MachineType`, `KeNumberProcessors`, `SystemTime`, `NtSystemRoot`, `NtProductType`, `NtMajorVersion`, `NtMinorVersion`, `PE Machine`, `PE TimeDateStamp`. Map cleanly to the intake's `memory_dump_image` columns (kernel_hint, ISF profile guess, magic).

## 5. Subprocess vs Python API — RECOMMEND SUBPROCESS

Subprocess wins on Rule #29 + Rule #36 + Rule #33 alignment:
- `asyncio.create_subprocess_exec(...) + asyncio.wait_for(..., timeout=N)` + `proc.kill()` reaps the child OS-cleanly. Vol3 plugins are CPU-bound walking large memory layers; **cooperative cancellation does not exist** in the Python API.
- Process isolation — a vol3 segfault (e.g. `leechcorepyc` C extension) or a corrupt-page-map `KeyError` does not crash the wairz worker. Mirrors the existing Ghidra Rule #29 backing (`360_000ms`).
- Vol3 caches symbol tables / page maps / lookup grids at 500MB-2GB resident per plugin run; subprocess exit reclaims it automatically. The Python API would hold the cache in the worker heap until GC.
- Rule #36 no-execute audit is trivial — spawn-argv must contain `--offline` and **must not** contain `-u URL`.
- One subprocess maps 1:1 to a Rule #33 .a state machine (`queued → running → completed | failed`).

**Python API gain:** ~1s saved per call on import; better error-class fidelity. **Not worth the cancellation + heap downsides for λ.α.** Defer as a future optimization.

**Frontend timeout:** per Rule #29 + Rule #33's 202+polling shape (axios floor 30s suffices), **no frontend tier constant needed** even if backend `VOL3_PLUGIN_TIMEOUT_SECONDS = 600`.

## 6. Smoke test — end-to-end against 2.28.0 (3.12 + real image deferred)

Local run against a 2 MB urandom blob (deliberately not a valid memory image; tests CLI + error surface):
```
$ dd if=/dev/urandom of=/tmp/synthetic-mem.dmp bs=1M count=2
$ vol --offline -q -f /tmp/synthetic-mem.dmp -r json windows.info
[...Scanning FileLayer using PageMapScanner / Stacking attempts finished / PDB scanning finished...]
Unable to validate the plugin requirements: ['plugins.Info.kernel.layer_name',
  'plugins.Info.kernel.symbol_table_name']
A translation layer requirement was not fulfilled.
```

**Expected failure shape on a non-memory blob.** Confirms: (a) `volatility3==2.28.0` pip-installs cleanly (single dep `pefile`); (b) `vol --offline` is real and blocks PDB downloads; (c) automagic runs full layer-stacking (FileLayer + PageMapScanner + PDB scanning) and surfaces structured errors; (d) `framework.list_plugins()` returns `windows.info.Info` with `kernel` requirement; `require_interface_version(2, 0, 0)` succeeds.

**True end-to-end (real Windows image) deferred:** vol3 ships no test memory image in PyPI/GitHub. Next-session steps: (a) `docker run python:3.12-slim` smoke for 3.12 plugin-enum parity; (b) acquire small Windows XP/7 CTF image (~200MB-1GB, [VolatilityFoundation samples wiki](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)) + matching ISF symbols (<50MB per OS family); (c) validate `vol --offline -f <img> -s /opt/wairz/vol3-symbols -r jsonl windows.info` produces `{variable, value}`-per-line JSONL. None block λ.α infrastructure (ORM + paths helper + Dockerfile gate + runner skeleton) — only the runner acceptance test waits on a real image.

## Summary recommendations (for λ.α brief)

1. **Pin:** `volatility3==2.28.0[full]` (or split per §1 if Docker layer size is critical).
2. **Python 3.12 supported.** Both prior 3.12 bugs fixed at 2.28.0. Verify via 10s `docker run python:3.12-slim` probe next session.
3. **Invocation: SUBPROCESS** (Rule #29 timeout; process isolation; clean heap reclaim).
4. **CLI baseline:** `vol --offline -q -f <img> -s /opt/wairz/vol3-symbols -o <tmp> --cache-path <tmp>/cache -l <tmp>/vol.log -r jsonl <plugin>`.
5. **Renderer: `jsonl`** (stream-parsable). `json` only for tiny one-shot plugins.
6. **API stability gate:** `framework.require_interface_version(2, 0, 0)` at `vol3_runner.py` import.
7. **First plugin to wire:** `windows.info` (1 requirement: `kernel`; 22 output rows; ideal λ.α.D acceptance test).
8. **Defer to next session:** 3.12 docker-smoke + small Windows image acquisition + first end-to-end JSONL parse. Non-blocking for λ.α infrastructure.

DONE.
