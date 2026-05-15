# Connecting AI (MCP)

Wairz uses the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) to give AI agents access to 60+ firmware analysis tools. After starting the backend, register the MCP server with your preferred client.

## Getting Your Project ID

Each Wairz project has a unique ID. You can find it in the URL when viewing a project in the web UI, or copy it from the project settings page.

`--project-id` is **optional**. When omitted, the MCP server starts with no active project — the agent will call `list_projects` and ask you which one to switch into. Pin a project at boot when you almost always work on the same one; leave it off for shared or team instances where you jump between projects.

## Shared / team instance

If multiple users connect to one Wairz server (e.g. a VPN-gated EC2 instance with a shared Postgres), each user should register the MCP server **without** `--project-id`. Each user's session gets its own `ProjectState` (one process per SSH connection), and `switch_project` is independent across users while findings/scratchpads remain the single source of truth in the shared DB.

```bash
claude mcp add wairz -- ssh wairz-host docker exec -i wairz-backend-1 uv run wairz-mcp
```

Replace `wairz-host` with a `Host` entry in your `~/.ssh/config` that points at the Wairz server. When the agent asks for a project, call `list_projects`, pick one, and `switch_project` to it.

## Claude Code

```bash
claude mcp add wairz -- docker exec -i wairz-backend-1 uv run wairz-mcp --project-id <PROJECT_ID>
```

Replace `<PROJECT_ID>` with your actual project ID.

## Claude Desktop

Add to your Claude Desktop config file:

=== "Linux"

    `~/.config/Claude/claude_desktop_config.json`

=== "macOS"

    `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wairz": {
      "command": "docker",
      "args": [
        "exec", "-i", "wairz-backend-1",
        "uv", "run", "wairz-mcp",
        "--project-id", "<PROJECT_ID>"
      ]
    }
  }
}
```

## OpenCode

Add to your `opencode.json` (in the project root, or `~/.config/opencode/opencode.json` for global config):

```json
{
  "mcp": {
    "wairz": {
      "type": "local",
      "command": ["docker", "exec", "-i", "wairz-backend-1", "uv", "run", "wairz-mcp", "--project-id", "<PROJECT_ID>"],
      "timeout": 30000,
      "enabled": true
    }
  }
}
```

Replace `<PROJECT_ID>` with your actual project ID.

!!! warning "Common mistakes"
    - The `timeout` must be increased from the default (5000ms) — Wairz registers 90+ tools and the response exceeds 60KB, which needs more time to transfer through `docker exec`
    - The `command` field must be an **array**, not a string
    - Use `"environment"` (not `"env"`) for environment variables
    - The `"type": "local"` field is required

## Codex

Add to your Codex config (`~/.codex/config.toml` for global, or `.codex/config.toml` in the project root):

```toml
[mcp_servers.wairz]
command = "docker"
args = ["exec", "-i", "wairz-backend-1", "uv", "run", "wairz-mcp", "--project-id", "<PROJECT_ID>"]
startup_timeout_sec = 30
```

Replace `<PROJECT_ID>` with your actual project ID.

Or use the CLI:

```bash
codex mcp add wairz -- docker exec -i wairz-backend-1 uv run wairz-mcp --project-id <PROJECT_ID>
```

!!! note
    The default startup timeout is 10 seconds. Set `startup_timeout_sec = 30` because Wairz registers 90+ tools and the initial response exceeds 60KB.

## Cursor

Add to `.cursor/mcp.json` in your project root (or `~/.cursor/mcp.json` for global config):

```json
{
  "mcpServers": {
    "wairz": {
      "command": "docker",
      "args": [
        "exec", "-i", "wairz-backend-1",
        "uv", "run", "wairz-mcp",
        "--project-id", "<PROJECT_ID>"
      ]
    }
  }
}
```

Replace `<PROJECT_ID>` with your actual project ID.

!!! warning
    Cursor has a ~40 active tool limit across all MCP servers combined. Wairz registers 90+ tools, so you may need to disable other MCP servers or use Cursor's tool toggle to selectively enable the tools you need.

## VS Code + GitHub Copilot

Add to `.vscode/mcp.json` in your project root:

```json
{
  "servers": {
    "wairz": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "exec", "-i", "wairz-backend-1",
        "uv", "run", "wairz-mcp",
        "--project-id", "<PROJECT_ID>"
      ]
    }
  }
}
```

Replace `<PROJECT_ID>` with your actual project ID.

!!! note
    MCP tools only work in Copilot's **Agent mode** — select it from the chat panel dropdown. Ask and Edit modes do not support MCP tools.

## Gemini CLI

Add to `~/.gemini/settings.json` (global) or `.gemini/settings.json` (project-level):

```json
{
  "mcpServers": {
    "wairz": {
      "command": "docker",
      "args": [
        "exec", "-i", "wairz-backend-1",
        "uv", "run", "wairz-mcp",
        "--project-id", "<PROJECT_ID>"
      ],
      "timeout": 30000
    }
  }
}
```

Replace `<PROJECT_ID>` with your actual project ID.

Or use the CLI:

```bash
gemini mcp add --timeout 30000 wairz -- docker exec -i wairz-backend-1 uv run wairz-mcp --project-id <PROJECT_ID>
```

## Windsurf

Add to `~/.codeium/windsurf/mcp_config.json` (global only — no project-level config):

```json
{
  "mcpServers": {
    "wairz": {
      "command": "docker",
      "args": [
        "exec", "-i", "wairz-backend-1",
        "uv", "run", "wairz-mcp",
        "--project-id", "<PROJECT_ID>"
      ]
    }
  }
}
```

Replace `<PROJECT_ID>` with your actual project ID.

!!! note
    Windsurf has a 100-tool limit across all MCP servers. Wairz registers 90+ tools, leaving limited room for other MCP servers. You can toggle individual tools on/off in the Windsurf MCP settings.

## Other MCP Clients

Wairz works with any MCP client that supports stdio transport. The server command is:

```bash
docker exec -i wairz-backend-1 uv run wairz-mcp --project-id <PROJECT_ID>
```

Consult your client's documentation for how to register a stdio MCP server with this command.

## What Your AI Agent Can Do

Once connected, your AI agent has access to 60+ analysis tools and can autonomously:

- **Explore firmware** — Browse the filesystem, search for files, extract strings
- **Analyze binaries** — Decompile with Ghidra, trace dataflows, find vulnerabilities
- **Assess security** — Find credentials, crypto material, insecure configs, weak permissions
- **Generate SBOMs** — Identify software components and check for known CVEs
- **Run emulation** — Boot firmware in QEMU, test services, validate findings dynamically
- **Fuzz binaries** — Set up AFL++ campaigns with auto-generated dictionaries and corpus
- **Compare firmware** — Diff filesystems, binaries, and decompiled functions across versions
- **Record findings** — Document vulnerabilities with severity, evidence, and CWE/CVE references

## Dynamic Project Switching

The MCP server supports switching between projects without restarting. Your AI agent can use the `switch_project` tool to change the active project during a session.

## Verifying the Connection

After configuring MCP, start a conversation and ask your AI agent to check the connection:

> "What project am I connected to?"

The agent will use the `get_project_info` tool to confirm the connection and show project details.

See the [MCP Tools Reference](../mcp-tools.md) for a complete list of available tools.
