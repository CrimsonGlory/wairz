# RTOS Support

Wairz supports four firmware kinds end-to-end: **Linux**, **FreeRTOS**, **Zephyr**, and **baremetal Cortex-M**. Auto-detection runs when you upload and unpack a firmware image; you can override the result manually if it lands on the wrong category.

The kind discriminator drives:

- Which MCP tools are exposed to the AI (Linux-only tools are hidden on RTOS projects, RTOS-only tools are hidden on Linux projects).
- Which sub-pages appear in the project sidebar.
- The system prompt the MCP server gives to Claude — RTOS sessions get a knowledge block on FreeRTOS task models, Zephyr kernel symbols, and Cortex-M conventions, instead of the Linux QEMU / init-script / SBOM blocks.

## Auto-detection

When you upload + unpack firmware, Wairz first attempts standard Linux extraction (binwalk + custom dispatcher). If a Linux filesystem root is located, the kind is set to `linux`. If not, the RTOS detection service runs:

| Kind | Flavor | What it looks for |
|------|--------|-------------------|
| `rtos` | `freertos` | Byte-marker scan for `xTaskCreate`, `pxCurrentTCB`, `vTaskStartScheduler`, `prvIdleTask`, `vTaskDelay`, `xQueueGenericSend` (weighted score ≥ 2) |
| `rtos` | `zephyr` | `Booting Zephyr OS`, `ZEPHYR_BASE`, `z_thread_*`, `k_thread_create` markers |
| `rtos` | `baremetal-cortexm` | ARM ELF with a `.isr_vector` / `.vectors` / `.vector_table` section, OR a raw blob whose first 8 bytes are a Cortex-M reset vector (initial SP in SRAM, reset handler in flash with the thumb bit set) |
| `unknown` | — | No Linux rootfs and no recognised RTOS signature |

Detection results are written to the firmware row with `firmware_kind_source = 'detected'`. Re-unpacking the same firmware re-runs detection.

## Manual override

The kind dropdown on the project page (next to each firmware card) lets you pin the kind. Setting it manually flips `firmware_kind_source` to `'manual'`, and re-detection on subsequent unpacks will not overwrite your choice.

Override is the right move when:

- A vendor OTA wrapper hides the inner firmware blob and detection misses the markers
- The firmware is heavily stripped and standard symbols don't match
- You want to test the analysis flow for a different kind on a known-Linux image

## RTOS analysis tools

When `firmware_kind == "rtos"` is active, Claude gets a dedicated tool category:

- **`detect_rtos_kernel`** — re-runs detection and reports kind / flavor / evidence + ELF metadata
- **`enumerate_rtos_tasks`** — scans the `.symtab` for likely task entry-point functions and FreeRTOS / kernel infrastructure symbols
- **`analyze_vector_table`** — parses the Cortex-M vector table with handler-symbol resolution
- **`recover_base_address`** — returns LOAD-segment vaddr/paddr for ELFs, or infers a flash base from the reset vector for raw `.bin`
- **`analyze_memory_map`** — classifies allocated sections into flash (executable / read-only) vs RAM (writable)

These take their input from the firmware blob directly, exposed via `/firmware/<basename>` in the virtual filesystem.

## What's hidden on RTOS projects

The following Linux-specific MCP tools are tagged `applies_to=("linux",)` and hidden when an RTOS project is active:

- All emulation tools (15 — QEMU is Linux-userland-mode-only at present)
- `analyze_config_security`, `check_setuid_binaries`, `analyze_init_scripts`, `check_filesystem_permissions` (rootfs-walking security tools)
- `get_component_map` (component-graph generator, requires shared-library DAG)

The corresponding sidebar pages (Component Map, SBOM, Emulation, Fuzzing, Compare) are also hidden on RTOS projects.

## Project Files explorer for RTOS projects

RTOS projects have no rootfs to walk, but they still have `WAIRZ.md`, `SCRATCHPAD.md`, and any documents you upload. The sidebar exposes a **Project Files** tab on every project — for Linux it's the full firmware-tree explorer (relabelled "File Explorer"); for RTOS / unknown it shows only the documents pane, with the same Monaco-based inline editor.

## Limitations

- **No RTOS emulation yet.** Static analysis works; dynamic boot in QEMU's Cortex-M target (`mps2-an385` etc.) or Renode is on the roadmap but not in the current release.
- **SBOM returns empty for RTOS.** A v2 binary-symbol-pattern matcher against a known-component database is the planned path.
- **One kind per project.** Mixed-kind firmware (one device, two MCUs running different OSes) needs per-firmware kind storage and a UX for switching the active one. Today the model is single-kind; the dropdown on the project page changes the project-wide classification.
- **Vendor OTA wrappers.** Detection runs after binwalk has stripped standard container formats. Some vendors use proprietary OTA framing that binwalk doesn't unwrap; in those cases you'll either need to pre-strip the wrapper or use the manual kind override.
