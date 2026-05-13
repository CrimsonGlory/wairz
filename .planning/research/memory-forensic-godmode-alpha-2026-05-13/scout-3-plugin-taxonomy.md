---
scout: 3
campaign: memory-forensic-godmode-α
parent_intake: .planning/intake/memory-forensic-godmode-alpha-kickoff-2026-05-12.md
date: 2026-05-12
scope: Vol3 plugin API stability + plugin-family taxonomy for first 5 wairz walkers
sources:
  - https://volatility3.readthedocs.io/en/latest/volatility3.plugins.html
  - https://github.com/volatilityfoundation/volatility3/tree/develop/volatility3/framework/plugins
  - https://github.com/volatilityfoundation/volatility3/releases
  - Plugin source files cited inline (raw.githubusercontent.com paths)
---

# Scout 3 — Vol3 plugin taxonomy + first-5 walker decomposition

## 1. Vol3 plugin namespace enumeration (v2.28, develop branch as of 2026-05-12)

Source-of-truth: `volatility3/framework/plugins/{windows,linux,mac}/*.py` on the
`develop` branch (latest is v2.28.0, released 2024-04-30 per the GitHub
Releases page). I enumerated from the readthedocs plugin index and cross-checked
against the GitHub directory listing.

### 1.1 Windows plugins (78 user-facing modules + `malware/` subnamespace)

| Module | Class | Family (proposed) |
|---|---|---|
| `windows.amcache` | Amcache | persistence |
| `windows.bigpools` | BigPools | memory-mapping |
| `windows.cachedump` | Cachedump | credentials |
| `windows.callbacks` | Callbacks | persistence (kernel) |
| `windows.cmdline` | CmdLine | processes |
| `windows.cmdscan` | CmdScan | processes (console) |
| `windows.consoles` | Consoles | processes (console) |
| `windows.crashinfo` | Crashinfo | info |
| `windows.debugregisters` | DebugRegisters | injection |
| `windows.deskscan` | DeskScan | gui |
| `windows.desktops` | Desktops | gui |
| `windows.devicetree` | DeviceTree | drivers |
| `windows.direct_system_calls` | DirectSystemCalls | **malware/ wrapper** (deprecated) |
| `windows.dlllist` | DllList | dlls |
| `windows.driverirp` | DriverIrp | drivers |
| `windows.drivermodule` | DriverModule | **malware/ wrapper** (deprecated) |
| `windows.driverscan` | DriverScan | drivers |
| `windows.dumpfiles` | DumpFiles | files |
| `windows.envars` | Envars | processes |
| `windows.etwpatch` | EtwPatch | injection (anti-EDR) |
| `windows.filescan` | FileScan | files |
| `windows.getservicesids` | GetServiceSIDs | services |
| `windows.getsids` | GetSIDs | processes |
| `windows.handles` | Handles | handles |
| `windows.hashdump` | Hashdump | credentials |
| `windows.hollowprocesses` | HollowProcesses | **malware/ wrapper** (deprecated) |
| `windows.iat` | IAT | injection |
| `windows.indirect_system_calls` | IndirectSystemCalls | **malware/ wrapper** (deprecated) |
| `windows.info` | Info | info |
| `windows.joblinks` | JobLinks | processes |
| `windows.kpcrs` | KPCRs | kernel |
| `windows.ldrmodules` | LdrModules | **malware/ wrapper** (deprecated) |
| `windows.lsadump` | Lsadump | credentials |
| `windows.malfind` | Malfind | **malware/ wrapper** (deprecated) |
| `windows.mbrscan` | MBRScan | boot |
| `windows.memmap` | Memmap | memory-mapping |
| `windows.mftscan` | MFTScan | files (forensic) |
| `windows.modscan` | ModScan | modules |
| `windows.modules` | Modules | modules |
| `windows.mutantscan` | MutantScan | handles |
| `windows.netscan` | NetScan | network |
| `windows.netstat` | NetStat | network |
| `windows.orphan_kernel_threads` | Threads | threads |
| `windows.pe_symbols` | PESymbols | symbols |
| `windows.pedump` | PEDump | dumping |
| `windows.poolscanner` | PoolScanner | infrastructure |
| `windows.privileges` | Privs | processes |
| `windows.processghosting` | ProcessGhosting | **malware/ wrapper** (deprecated) |
| `windows.pslist` | PsList | processes |
| `windows.psscan` | PsScan | processes |
| `windows.pstree` | PsTree | processes |
| `windows.psxview` | PsXView | **malware/ wrapper** (deprecated) |
| `windows.scheduled_tasks` | ScheduledTasks | persistence |
| `windows.sessions` | Sessions | processes |
| `windows.shimcachemem` | ShimcacheMem | persistence |
| `windows.skeleton_key_check` | Skeleton_Key_Check | **malware/ wrapper** (deprecated) |
| `windows.ssdt` | SSDT | injection (kernel) |
| `windows.strings` | Strings | strings |
| `windows.suspended_threads` | SuspendedThreads | threads |
| `windows.suspicious_threads` | SuspiciousThreads | **malware/ wrapper** (deprecated) |
| `windows.svcdiff` | SvcDiff | **malware/ wrapper** (deprecated) |
| `windows.svclist` | SvcList | services |
| `windows.svcscan` | SvcScan | services |
| `windows.symlinkscan` | SymlinkScan | files |
| `windows.thrdscan` | ThrdScan | threads |
| `windows.threads` | Threads | threads |
| `windows.timers` | Timers | persistence (kernel) |
| `windows.truecrypt` | Passphrase | credentials |
| `windows.unhooked_system_calls` | unhooked_system_calls | **malware/ wrapper** (deprecated) |
| `windows.unloadedmodules` | UnloadedModules | modules |
| `windows.vadinfo` | VadInfo | memory-mapping |
| `windows.vadregexscan` | VadRegExScan | memory-mapping |
| `windows.vadwalk` | VadWalk | memory-mapping |
| `windows.vadyarascan` | VadYaraScan | memory-mapping |
| `windows.verinfo` | VerInfo | files |
| `windows.virtmap` | VirtMap | memory-mapping |
| `windows.windowstations` | WindowStations | gui |

**Important — `windows.malware.*` subnamespace (canonical, v2.26.2+):**
14 files: `direct_system_calls`, `drivermodule`, `hollowprocesses`,
`indirect_system_calls`, `ldrmodules`, `malfind`, `pebmasquerade`,
`processghosting`, `psxview`, `skeleton_key_check`, `suspicious_threads`,
`svcdiff`, `unhooked_system_calls`. **The top-level `windows.<name>`
counterparts are deprecation wrappers with scheduled removal date
2026-06-07** (per code comments in
`raw.githubusercontent.com/.../windows/hollowprocesses.py` etc.) — wairz MUST
target the `windows.malware.<name>` paths, not the deprecated top-level ones.
`pebmasquerade` is malware-only (no top-level wrapper exists).

### 1.2 Linux plugins (41 user-facing modules)

| Module | Class | Family (proposed) |
|---|---|---|
| `linux.bash` | Bash | processes (shell history) |
| `linux.boottime` | Boottime | info |
| `linux.capabilities` | Capabilities | processes |
| `linux.check_afinfo` | Check_afinfo | rootkit |
| `linux.check_creds` | Check_creds | rootkit |
| `linux.check_idt` | Check_idt | rootkit |
| `linux.check_modules` | Check_modules | rootkit |
| `linux.check_syscall` | Check_syscall | rootkit |
| `linux.ebpf` | EBPF | injection (eBPF) |
| `linux.elfs` | Elfs | processes |
| `linux.envars` | Envars | processes |
| `linux.hidden_modules` | Hidden_modules | rootkit |
| `linux.iomem` | IOMem | memory-mapping |
| `linux.ip` | Addr, Link | network |
| `linux.kallsyms` | Kallsyms | symbols |
| `linux.keyboard_notifiers` | Keyboard_notifiers | rootkit |
| `linux.kmsg` | Kmsg | logs |
| `linux.kthreads` | Kthreads | threads |
| `linux.library_list` | LibraryList | processes |
| `linux.lsmod` | Lsmod | modules |
| `linux.lsof` | Lsof | handles |
| `linux.malfind` | Malfind | injection |
| `linux.module_extract` | ModuleExtract | modules |
| `linux.modxview` | Modxview | modules |
| `linux.mountinfo` | MountInfo | filesystem |
| `linux.netfilter` | Netfilter | network |
| `linux.pagecache` | RecoverFs | files (forensic) |
| `linux.pidhashtable` | PIDHashTable | processes |
| `linux.proc` | Maps | memory-mapping |
| `linux.psaux` | PsAux | processes |
| `linux.pscallstack` | PsCallStack | processes |
| `linux.pslist` | PsList | processes |
| `linux.psscan` | PsScan | processes |
| `linux.pstree` | PsTree | processes |
| `linux.ptrace` | Ptrace | injection |
| `linux.sockscan` | Sockscan | network |
| `linux.sockstat` | Sockstat | network |
| `linux.tty_check` | tty_check | rootkit |
| `linux.vmaregexscan` | VmaRegExScan | memory-mapping |
| `linux.vmayarascan` | VmaYaraScan | memory-mapping |
| `linux.vmcoreinfo` | VMCoreInfo | info |

### 1.3 Mac plugins (23 modules) — **DEFERRED**

Per scope boundary, mac.* enumeration is documented in the source tree
(`bash, check_syscall, check_sysctl, check_trap_table, dmesg, ifconfig,
kauth_listeners, kauth_scopes, kevents, list_files, lsmod, lsof, malfind,
mount, netstat, proc_maps, psaux, pslist, pstree, socket_filters, timers,
trustedbsd, vfsevents`) but mac walkers are explicitly deferred until
Windows/Linux are shipped. macOS firmware corpus in wairz is currently
~0 — no current driver to ship a `mac_*_walker`.

## 2. Plugin-family grouping (analytical concerns)

Eleven analytical concerns map to wairz walkers; ONE walker per family per
the κ Scout 3 + λ intake decree:

| Family | Windows plugins | Linux plugins | Walker name |
|---|---|---|---|
| **info** (image metadata) | `info`, `crashinfo` | `boottime`, `vmcoreinfo` | `vol3_info_walker` (folded into λ.α.D probe — NOT a standalone walker) |
| **processes** | `pslist`, `psscan`, `pstree`, `cmdline`, `cmdscan`, `consoles`, `sessions`, `envars`, `privileges`, `getsids`, `joblinks` | `pslist`, `psscan`, `pstree`, `psaux`, `pscallstack`, `pidhashtable`, `elfs`, `envars`, `capabilities`, `library_list`, `bash` | `windows_processes_walker`, `linux_processes_walker` |
| **network** | `netstat`, `netscan` | `ip`, `sockscan`, `sockstat`, `netfilter` | `windows_network_walker`, `linux_network_walker` |
| **injection** | `malware.malfind`, `malware.hollowprocesses`, `malware.ldrmodules`, `malware.pebmasquerade`, `malware.processghosting`, `malware.psxview`, `malware.direct_system_calls`, `malware.indirect_system_calls`, `malware.unhooked_system_calls`, `iat`, `etwpatch` | `malfind`, `ptrace`, `ebpf` | `windows_injection_walker`, `linux_injection_walker` |
| **persistence** | `scheduled_tasks`, `amcache`, `shimcachemem`, `callbacks`, `timers` | (none — covered by registry-equivalents in Linux artefact walkers already shipped via systemd) | `windows_persistence_walker` |
| **dlls / modules** | `dlllist`, `modules`, `modscan`, `unloadedmodules`, `malware.drivermodule` | `lsmod`, `module_extract`, `modxview`, `hidden_modules` | `windows_modules_walker`, `linux_modules_walker` |
| **handles** | `handles`, `mutantscan` | `lsof` | `windows_handles_walker`, `linux_handles_walker` |
| **drivers** | `driverscan`, `driverirp`, `devicetree`, `ssdt`, `orphan_kernel_threads` | (kernel modules are in modules family) | `windows_drivers_walker` |
| **credentials** | `hashdump`, `cachedump`, `lsadump`, `truecrypt` | (none — Linux equivalents are passwd/shadow at filesystem layer) | **DEFER — Rule #45 no-decrypt boundary** (metadata-only surface candidate) |
| **rootkit** | `malware.skeleton_key_check`, `malware.svcdiff`, `malware.suspicious_threads` | `check_afinfo`, `check_creds`, `check_idt`, `check_modules`, `check_syscall`, `keyboard_notifiers`, `tty_check`, `hidden_modules` | `linux_rootkit_walker` (Linux-priority; Windows checks fold into injection) |
| **memory-mapping** | `vadinfo`, `vadwalk`, `vadregexscan`, `vadyarascan`, `memmap`, `virtmap`, `bigpools` | `proc`, `iomem`, `vmaregexscan`, `vmayarascan` | DEFERRED (low priority — used as evidence by other walkers) |

## 3. FIRST 5 wairz volatility walkers (per λ.β/.ε.+ roadmap)

### 3.1 `windows_processes_walker` (λ.β — first family shipped)

- **Plugins wrapped:** `windows.pslist`, `windows.psscan`, `windows.pstree`, `windows.cmdline`. Together: list-walk view + scanner view + tree relationships + command-line args.
- **Row shape (from each plugin source):**
  - `pslist`: `PID:int, PPID:int, ImageFileName:str, Offset:Hex, Threads:int, Handles:int, SessionId:int, Wow64:bool, CreateTime:datetime, ExitTime:datetime` (11 cols including `File output`)
  - `psscan`: same column set as `pslist` (subclasses it; pool-scanner discovers unlinked/terminated processes pslist misses)
  - `pstree`: same + indented hierarchy markers (parent-child via PPID)
  - `cmdline`: `PID:int, Process:str, Args:str` (3 cols)
- **De-dup strategy:** Persist ONE row per unique `(PID, ImageFileName, CreateTime)` triple in `volatility_process_records`. Add bitfield columns `seen_in_pslist:bool`, `seen_in_psscan:bool`, `seen_in_pstree:bool` to surface the "process visible in scanner but missing from EPROCESS list" anomaly (the canonical psscan-vs-pslist finding). `cmdline` output joins to the row as a separate `command_line:text` column on the same record.
- **Detection priorities:**
  - `windows_unlinked_process` finding (psscan-saw + pslist-missed) — high confidence rootkit indicator
  - `windows_terminated_process` (psscan-saw with ExitTime set + pslist-missed)
  - `windows_orphaned_process` (PPID has no live parent in any of the three views)
- **Cross-firmware MCP tool (Rule #44):** `lookup_volatility_process_across_firmwares` — keyed on `sha256(ImageFileName + command_line)` so two firmware images with the SAME suspicious process binary AND args (e.g. `powershell.exe -enc <base64>`) bucket together. `supply_chain_signal=True` if `match_count >= 2` AND `ImageFileName` is in a non-Microsoft signing path heuristic. Optional `scope: project|global` filter.
- **Argument shape:** Each plugin accepts `--pid <id>` for filtering — wairz invokes WITHOUT a filter to capture all processes; filter is applied at the walker's record-emit time using detection-priority heuristics. `--physical` BooleanRequirement → wairz passes default (virtual offsets). `--dump` BooleanRequirement → wairz NEVER passes True (per Rule #36 no-execute discipline applied to extracted artefacts; dumping a process image would leak Vol3-extracted EXE bytes onto disk where they could be re-executed by a future operator misclick).

### 3.2 `windows_network_walker` (λ.ε)

- **Plugins wrapped:** `windows.netstat`, `windows.netscan`. `netstat` walks `_TCP_LISTENER` / `_UDP_LISTENER` / `_TCP_ENDPOINT` pool tags from `netio.sys`'s partition table; `netscan` scans the same pool tags via signatures (catches unlinked/freed connection objects).
- **Row shape (from `netstat.py`):** `Offset:Hex, Proto:str, LocalAddr:str, LocalPort:int, ForeignAddr:str, ForeignPort:int, State:str, PID:int, Owner:str, Created:datetime` (10 cols). TCP-listener variant: `State="LISTENING"`, `ForeignPort=0`; UDP variant: state blank, foreign asterisks.
- **De-dup strategy:** `(Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, PID)` 6-tuple. `seen_in_netstat:bool` + `seen_in_netscan:bool` bitfields. The netscan-only rows are the high-signal ones (unlinked endpoints = current/terminated C2).
- **Detection priorities:** `windows_unlinked_network_endpoint`, `windows_suspicious_outbound_connection` (high port + non-loopback ForeignAddr + ImageFileName in user-writable path).
- **Cross-firmware MCP tool:** `lookup_volatility_network_across_firmwares` — keyed on `sha256(ForeignAddr + str(ForeignPort))` so multiple firmwares connecting to the SAME C2 endpoint bucket together — direct supply-chain compromise signal.
- **Argument shape:** `netstat` accepts `--include-corrupt` (BooleanRequirement default False) — wairz toggles this TRUE for the `netscan` portion to surface partial endpoint reads as `partial:bool` rows.

### 3.3 `windows_injection_walker` (λ.γ + λ.ε)

- **Plugins wrapped (target the `windows.malware.*` namespace, NOT the deprecated top-level wrappers):** `windows.malware.malfind`, `windows.malware.hollowprocesses`, `windows.malware.ldrmodules`, `windows.malware.processghosting`, `windows.malware.pebmasquerade`. (`psxview`, `direct_system_calls`, `indirect_system_calls`, `unhooked_system_calls`, `suspicious_threads`, `skeleton_key_check`, `svcdiff`, `drivermodule` are all rootkit/syscall-hooking heuristics — fold into `windows_rootkit_walker` in a later phase.)
- **Row shape (per plugin):**
  - `malfind`: `PID:int, Process:str, Start VPN:Hex, End VPN:Hex, Tag:str, Protection:str, CommitCharge:int, PrivateMemory:bool, File output:str, Notes:str, Hexdump:LayerData, Disasm:Disassembly` (12 cols)
  - `hollowprocesses`: `PID:int, Process:str, Notes:str` (3 cols; Notes describes detection — image-base-mismatch / VAD-protection-mismatch / DLL-protection-mismatch)
  - `ldrmodules`: PEB-vs-VAD list comparison (3 PEB lists vs VAD tree)
  - `pebmasquerade`: PEB string-field forgery detection (new in v2.27.0)
  - `processghosting`: PE files mapped from deleted-file-handles
- **De-dup strategy:** Per-PID-per-finding-type. `volatility_injection_records` has `(firmware_id, pid, process_name, finding_type, vad_start, vad_end, detection_notes)` shape. Same PID can produce N rows (one per finding-type).
- **Detection priorities (high-signal Λ.γ finding sources):**
  - `vol3_hollow_process` (intake λ.γ)
  - `vol3_unlinked_process` (intake λ.γ; cross-cut: also emitted by `windows_processes_walker` from psscan-vs-pslist)
  - `vol3_injected_code_region` (malfind PAGE_EXECUTE_READWRITE private VAD)
  - `vol3_peb_masquerade`
  - `vol3_ghosted_process`
- **Cross-firmware MCP tool:** `lookup_volatility_injection_across_firmwares` — keyed on `sha256(hexdump_first_64_bytes)` so the SAME injected shellcode prelude across firmwares buckets. Strongest supply-chain signal of the FIRST 5.
- **Argument shape:** `malfind` accepts `--pid` (we don't filter), `--max-size`, `--dump-dir` (we NEVER pass — Rule #36). `hollowprocesses` filters processes with <3 DLLs / <5 VADs by default (avoids smear false positives) — we accept the default.

### 3.4 `windows_persistence_walker` (λ.ε)

- **Plugins wrapped:** `windows.scheduled_tasks`, `windows.amcache`, `windows.shimcachemem`, `windows.callbacks`, `windows.timers`. Each surfaces a distinct persistence vector.
- **Cross-cut concern:** wairz ALREADY has `scheduled_task_walker.py`, `appcompat_walker.py` (Shimcache from registry), `wmi_walker.py` for the **on-disk** equivalents. The Vol3 versions surface the **in-memory** view — divergence between disk-state and memory-state IS the finding (e.g. shimcache entry visible in memory but missing from on-disk hive = anti-forensic cleanup in progress).
- **Detection priorities:** `vol3_memory_only_scheduled_task`, `vol3_amcache_disk_memory_divergence`, `vol3_unknown_kernel_callback`, `vol3_unknown_kernel_timer`. Joinable against the existing on-disk walker rows for divergence findings.
- **Cross-firmware MCP tool:** `lookup_volatility_persistence_across_firmwares` keyed on `(plugin_source, identifier)` where identifier is task-name / amcache-path / callback-routine-address.

### 3.5 `linux_processes_walker` (λ.ζ)

- **Plugins wrapped:** `linux.pslist`, `linux.psscan`, `linux.pstree`, `linux.psaux`, `linux.bash`. `psaux` adds argv from `mm_struct->arg_start/arg_end`; `bash` extracts shell command history from `bash` process memory.
- **Row shape (from `linux/pslist.py`):** `OFFSET(V):Hex, PID:int, TID:int, PPID:int, COMM:str, UID:int, GID:int, EUID:int, EGID:int, CREATION TIME:datetime, File output:str` (11 cols). Linux variant carries EUID/EGID/setuid-flag-equivalent that Windows pslist doesn't.
- **De-dup strategy:** `(PID, COMM, creation_time)` 3-tuple. `bash` history attaches as a separate `linux_bash_history_records` per-PID table.
- **Detection priorities:** `linux_unlinked_process` (psscan-vs-pslist gap), `linux_hidden_kthread`, `linux_euid_root_non_root_uid` (EUID=0 with UID≠0 = privilege escalation in flight). `bash` history → `linux_suspicious_shell_command` finding (curl-pipe-bash, base64-decoded payloads).
- **Cross-firmware MCP tool:** `lookup_volatility_linux_process_across_firmwares` keyed on `sha256(COMM + bash_history_entry)`.
- **Argument shape:** `pslist` accepts `--pid`, `--threads` (default False → wairz passes True for full thread visibility), `--decorate-comm` (default False → wairz leaves False; we surface ordering ourselves). `--dump` NEVER passed.

## 4. CLI invocation shape (from `cli/__init__.py`)

Authoritative CLI flags (the wairz `vol3_runner.py` per intake λ.α.D will
build commands using these):

```
vol -f <image_path> \
    -s /opt/wairz/vol3-symbols \
    -r json \
    -o /tmp/vol3-output \
    --offline \
    -q \
    <plugin.module.path> [--pid 1234] [--physical] ...
```

Critical flags:
- `-f, --file` — image path (shorthand for `--single-location=file://`)
- `-s, --symbol-dirs` — semicolon-separated paths; **wairz passes ONLY the
  baked-in `/opt/wairz/vol3-symbols` directory** to satisfy Rule #37 offline-trust-anchor discipline.
- `-r, --renderer` — choices include `quick`, `pretty`, `csv`, `json`, `jsonl`. **wairz uses `json`** for parseable output; `jsonl` is an alternative for streaming.
- `--offline` — disables online ISF JSON search. **wairz MUST pass this** per Rule #37 — the worker container has no business reaching out to `downloads.volatilityfoundation.org` at scan time.
- `-o, --output-dir` — directory for any plugin-generated files (e.g. dumped PE for `pedump`). wairz passes a per-invocation tmp directory under `$STORAGE_ROOT/projects/<id>/vol3/<invocation_uuid>/`.
- `-q, --quiet` — disables progress feedback (we don't want it in JSON output stream).
- `--cache-path` — Vol3 caches symbol lookups + per-image scan results. wairz sets this to `/tmp/vol3-cache/<firmware_id>/` for cross-plugin reuse within a single walker run.

Plugin-specific flags pass after the plugin module path:
```
vol -f image.raw windows.malware.malfind --pid 1234
```

## 5. Plugin output shape (`-r json` example for `windows.pslist`)

```json
[
  {
    "PID": 4,
    "PPID": 0,
    "ImageFileName": "System",
    "Offset(V)": "0xffff8e0c1e8a3040",
    "Threads": 142,
    "Handles": 0,
    "SessionId": null,
    "Wow64": false,
    "CreateTime": "2024-01-15T08:32:11+00:00",
    "ExitTime": null,
    "File output": "Disabled"
  },
  ...
]
```

Columns are **stable per major version** (per CHANGELOG: column additions
are minor-version, removals require deprecation cycle). Types: `Offset(V)`
is hex-string (NOT int), `CreateTime`/`ExitTime` are ISO-8601 with TZ,
nullable fields render as `null`.

`windows.netstat` JSON output:
```json
[
  {
    "Offset": "0xffffce05...",
    "Proto": "TCPv4",
    "LocalAddr": "0.0.0.0",
    "LocalPort": 445,
    "ForeignAddr": "*",
    "ForeignPort": 0,
    "State": "LISTENING",
    "PID": 4,
    "Owner": "System",
    "Created": "2024-01-15T08:32:30+00:00"
  }
]
```

## 6. API stability — what to trust, what to avoid

**Version timeline (from GitHub Releases):**

| Version | Date | Breaking notes |
|---|---|---|
| v2.4.1 | 2021-04-12 | Python 3.7 minimum (first stable v3) |
| v2.5.0 | 2021-09-27 | Linux process dumping |
| v2.7.0 | 2022-05-29 | Configuration file support |
| v2.8.0 | 2022-10-09 | **Python 3.7.3+** required |
| v2.11.0 | 2023-01-16 | **Python 3.8+** required |
| v2.26.0 | 2023-05-16 | 19 plugins added; modernized to `pyproject.toml` |
| v2.26.2 | 2023-09-25 | **Malware-plugin reorganization** under `windows.malware.*`; top-level wrappers deprecated, removal scheduled ~1 year (June 2026) |
| v2.27.0 | 2024-01-29 | `windows.pebmasquerade` added; arrow/parquet renderer |
| v2.28.0 | 2024-04-30 | General improvements |

**API-stable plugins (safe to wrap in λ session 1):** `windows.pslist`, `psscan`, `pstree`, `cmdline`, `netstat`, `netscan`, `info`, `scheduled_tasks`, `amcache`, `shimcachemem`, `svcscan`, `dlllist`, `linux.pslist`, `psscan`, `pstree`, `psaux`, `bash`, `lsmod`, `ip`, `sockscan`.

**Plugins to TARGET CAREFULLY (deprecation wrappers — use `windows.malware.<name>` instead):** `hollowprocesses`, `malfind`, `ldrmodules`, `processghosting`, `psxview`, `drivermodule`, `direct_system_calls`, `indirect_system_calls`, `unhooked_system_calls`, `suspicious_threads`, `skeleton_key_check`, `svcdiff`. Removal date 2026-06-07 — after that the top-level imports fail. wairz must wire to `windows.malware.malfind` etc.

**Plugins flagged experimental / fragile:** `linux.pscallstack` (depends on `kallsyms` symbol-resolution — fails on stripped kernels), `linux.ebpf` (BPF object format moves), `windows.etwpatch` (heuristic, false-positive prone on legitimate ETW configuration). Defer these to layered post-λ work.

**ISF symbol bundle format:** v2.26+ uses JSON-compressed ISF format (`.json.xz`); older releases also accept `.dwarf`/`.pdb`. wairz bakes ONLY the JSON-compressed flavour per Rule #37; refresh script verifies SHA256 against pinned manifest.

## 7. Recommended decomposition — `app/services/windows_processes_walker.py` (sketch for λ.β)

```python
# backend/app/services/windows_processes_walker.py

# Plugins wrapped (in order of invocation; one subprocess per plugin):
_PLUGINS = [
    "windows.pslist",   # canonical EPROCESS-list view
    "windows.psscan",   # pool-tag scanner (catches unlinked/terminated)
    "windows.pstree",   # hierarchy
    "windows.cmdline",  # per-PID command line from PEB
]

# Inner runner shape (per Rule #39 triplet — mirrors registry_hive_walker):
async def _do_windows_processes_walk(db, firmware_id) -> dict:
    firmware = await db.get(Firmware, firmware_id)
    images = list(_enumerate_memory_images(get_detection_roots(firmware)))
    aggregate = {
        "schema_version": 1,
        "image_count": len(images),
        "plugin_runs": [],         # one entry per (image, plugin) invocation
        "process_count": 0,
        "anomaly_count": 0,
        "anomaly_breakdown": {     # finding-type → count
            "windows_unlinked_process": 0,
            "windows_terminated_process": 0,
            "windows_orphaned_process": 0,
        },
    }
    for img in images:
        per_image_records = {}     # (pid, image_name, ctime) → record dict
        for plugin in _PLUGINS:
            rows = await _invoke_vol3(img.path, plugin)  # subprocess per Rule #29
            aggregate["plugin_runs"].append({
                "image_id": str(img.id),
                "plugin": plugin,
                "row_count": len(rows),
                "duration_ms": ...,
            })
            for row in rows:
                _merge_into_record(per_image_records, plugin, row)
        for rec in per_image_records.values():
            _classify_anomalies(rec, aggregate)
            db.add(VolatilityProcessRecord(firmware_id=firmware_id, **rec))
        aggregate["process_count"] += len(per_image_records)
    await db.flush()
    return aggregate

async def run_windows_processes_walk_background(firmware_id): ...  # Rule #33 .a
async def auto_windows_processes_walk_firmware_safe(firmware_id): ...  # unpack hook
```

**JSONB result aggregate (`firmware.windows_processes_walk_result`):**
```python
{
    "schema_version": 1,
    "image_count": int,
    "process_count": int,
    "anomaly_count": int,
    "anomaly_breakdown": {<finding_source>: count},
    "plugin_runs": [{"image_id":..., "plugin":..., "row_count":..., "duration_ms":...}],
}
```

**Per-record table `volatility_process_records`:**
```python
class VolatilityProcessRecord(Base):
    id: uuid.UUID (PK)
    firmware_id: uuid.UUID (FK)
    memory_image_id: uuid.UUID (FK)  # which dump-image row
    pid: int
    ppid: int | None
    image_filename: str(255)
    offset_virtual: str(20)  # hex string
    threads: int | None
    handles: int | None
    session_id: int | None
    wow64: bool | None
    create_time: datetime | None
    exit_time: datetime | None
    command_line: text | None   # from cmdline plugin
    seen_in_pslist: bool
    seen_in_psscan: bool
    seen_in_pstree: bool
    seen_in_cmdline: bool
    anomaly_flags: JSONB  # {"windows_unlinked_process": True, ...}
    # unique constraint on (firmware_id, memory_image_id, pid, image_filename, create_time)
```

**Cross-firmware MCP tool (`backend/app/ai/tools/volatility.py`):**

```python
registry.register(
    name="lookup_volatility_process_across_firmwares",
    description="Find firmware images containing matching process signatures (by sha256(image_filename + command_line)). Returns one row per firmware with match_count + supply_chain_signal.",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "image filename substring or sha256 prefix"},
            "scope": {"enum": ["project", "global"], "default": "project"},
            "min_match_count": {"type": "integer", "default": 1},
        },
        "required": ["query"],
    },
    handler=_handle_lookup_volatility_process_across_firmwares,
)
```

Aggregation SQL: `JOIN firmware ON VolatilityProcessRecord.firmware_id =
firmware.id`, `GROUP BY firmware.id`, `match_count` = count of rows
matching the query hash, `supply_chain_signal = match_count >= 2`.

**Finding sources to register (`schemas/volatility.py` + DB CHECK +
frontend mirror, λ.γ single-slice commit per Rule #25):**
- `vol3_unlinked_process`
- `vol3_terminated_process`
- `vol3_orphaned_process`
- (later families add `vol3_unlinked_network_endpoint`, `vol3_hollow_process`,
  `vol3_injected_code_region`, `vol3_peb_masquerade`, `vol3_ghosted_process`,
  `vol3_amcache_disk_memory_divergence`, etc.)

## 8. Open items / handoffs

- **Vol3 subprocess argv specifics** (Scout 1's scope) — confirm the
  exact module entry point: `python -m volatility3 ...` vs the
  installed `vol` console_scripts entry point. Both should work
  identically; `vol` is the documented form.
- **ISF bundle composition** (Scout 2's scope) — confirm which Windows
  build PDB JSONs ship in the official `downloads.volatilityfoundation.org`
  symbol bundle. The wairz refresh script SHA256-pins the entire
  bundle directory.
- **Mac plugin family** — DEFERRED; document the namespace but ship
  no walker until macOS firmware corpus exists.
- **Credentials family** — Vol3 ships `hashdump`, `cachedump`, `lsadump`,
  `truecrypt` (TrueCrypt passphrase recovery). All four perform genuine
  CREDENTIAL EXTRACTION — they are NOT metadata-only. Per Rule #45
  no-decrypt discipline, wairz should EITHER (a) defer wrapping entirely,
  OR (b) wrap with the `--dry-run`-equivalent (count-only) output mode
  if it exists, surfacing only `<N hashes available>` without the
  payload. Need explicit operator sign-off before authoring; flag in
  postmortem.
- **`unhooked_system_calls` performance** — known O(N²) on large dumps
  per the v2.27 release notes; wairz should set a Rule #29 timeout of
  600 s when invoking this plugin specifically.
