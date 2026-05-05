<p align="center">
  <img src="assets/wairz_banner.png" alt="Wairz - Every Firmware Has Secrets... WAIRZ Finds Them" width="100%">
</p>

# WAIRZ

**AI-assisted firmware reverse engineering and security assessment platform.**

Upload firmware images, unpack them, explore the filesystem, analyze binaries, and conduct security assessments — all powered by AI analysis via [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

WAIRZ works with any MCP-compatible AI agent — Claude Code, Claude Desktop, OpenCode, Codex, Cursor, VS Code + Copilot, Gemini CLI, Windsurf, and more. See the [Connecting AI](getting-started/mcp-setup.md) guide for setup instructions.

---

## Demo

<div style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden;">
  <iframe src="https://www.youtube.com/embed/gDLhtMFMmMM" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
</div>

---

## Key Features

<div class="grid cards" markdown>

- :material-folder-search: **File Explorer**

    Browse extracted filesystems with a virtual tree, view text/binary/hex content, and search across files.

- :material-code-braces: **Binary Analysis**

    Disassemble and decompile binaries using Ghidra headless, with cross-references, dataflow tracing, and stack layout analysis.

- :material-shield-alert: **Security Assessment**

    Detect hardcoded credentials, crypto material, setuid binaries, insecure configs, and weak permissions.

- :material-format-list-checks: **SBOM & CVE Scanning**

    Generate Software Bill of Materials and scan components against the NVD for known vulnerabilities.

- :material-play-box: **Emulation**

    Boot firmware in QEMU (user-mode or system-mode) in isolated containers, with GDB debugging support.

- :material-bug: **Fuzzing**

    AFL++ with QEMU mode for cross-architecture binary fuzzing, with automatic dictionary/corpus generation and crash triage.

- :material-compare: **Firmware Comparison**

    Diff filesystem trees, binaries, and decompiled functions across firmware versions for patch analysis.

- :material-console: **UART Console**

    Connect to physical devices via a host-side serial bridge for interactive console access.

- :material-robot: **AI Analysis via MCP**

    172 analysis tools (across 21 categories) exposed to any MCP-compatible AI agent for autonomous security research — from filesystem exploration to vulnerability discovery.

- :material-file-document: **Findings & Reports**

    Record security findings with severity ratings and evidence, export as Markdown or PDF.

</div>

---

!!! warning "Public Beta"
    WAIRZ is currently in **public beta**. You may encounter bugs or rough edges. If you run into any issues, please [open an issue on GitHub](https://github.com/digitalandrew/wairz/issues) or reach out at andrew@digitalandrew.io.

    WAIRZ is primarily designed for **embedded Linux** firmware samples. Support for **RTOS and bare-metal** firmware (FreeRTOS, VxWorks, Zephyr, ThreadX, plus companion components like lwIP and FatFs) has shipped — feature coverage is broader for Linux but the RTOS detection + scanning paths are now in mainline.

---

## Quick Start

```bash
git clone https://github.com/digitalandrew/wairz.git
cd wairz
cp .env.example .env
docker compose up --build
```

Then open [http://localhost:3000](http://localhost:3000) to access the web interface.

See the [Installation Guide](getting-started/installation.md) for detailed setup instructions, or jump to [Connecting AI](getting-started/mcp-setup.md) to connect your preferred AI agent.

---

## How It Works

```
AI Agent (Claude Code, OpenCode, etc.)
        |
        | MCP (stdio)
        v
+------------------+     +------------------------------------+
|   wairz-mcp      |---->|         FastAPI Backend             |
|  (MCP server)    |     |                                      |
|  172 tools       |     |  Services: firmware, analysis,       |
+------------------+     |  emulation, fuzzing, sbom, uart      |
                         |                                      |
                         |  Ghidra headless - QEMU - AFL++      |
                         +-----------+--------------------------|
                                     |
+--------------+    +----------------+----------------+
|   React SPA  |--->|  PostgreSQL    |  Redis         |
|  (Frontend)  |    |                |                |
+--------------+    +----------------+----------------+
```

1. **Upload** a firmware image through the web UI
2. **WAIRZ unpacks** the firmware automatically (SquashFS, JFFS2, UBIFS, CramFS, ext, CPIO)
3. **Explore** the extracted filesystem, analyze binaries, and assess security — through the browser or AI
4. **Connect an AI agent** via MCP to run autonomous analysis with 172 specialized tools

---

## License

WAIRZ is open source under the [AGPL-3.0 License](https://github.com/digitalandrew/wairz/blob/main/LICENSE).
