import { Link, useParams } from 'react-router-dom'
import { ChevronLeft, Database, ExternalLink, FileText, GitCompare } from 'lucide-react'

/**
 * Phase γ.7 — Registry Hive Page (skeleton).
 *
 * Lists every Windows registry hive walked for the active firmware
 * (regipy auto-walk on unpack from γ.4). Renders the persistence-
 * relevant subkey rollup per Persona-E #13.
 *
 * **Current state**: skeleton with γ.6 MCP-tool documentation. The
 * REST endpoints + dynamic data fetching land in a follow-up commit
 * (the γ.7 single-slice exception #2 bundle covers the cross-stack
 * alignment surfaces — DB CHECK + FE union + FE config — plus this
 * page skeleton; full data integration follows once the REST surface
 * is added).
 *
 * **MCP path** (works today via Claude Code / Desktop):
 * - ``list_hives`` to enumerate walked hives
 * - ``get_run_keys`` for Run / RunOnce / IFEO surface
 * - ``scan_persistence`` for the full persistence rollup
 * - ``walk_hive`` to re-walk on demand
 */
export default function RegistryHivePage() {
  const { projectId } = useParams<{ projectId: string }>()

  return (
    <div className="mx-auto max-w-5xl py-8">
      <div className="mb-2">
        <Link
          to={`/projects/${projectId}/windows`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
          Windows hub
        </Link>
      </div>

      <div className="mb-8 flex items-center gap-3">
        <Database className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Registry Hives</h1>
          <p className="text-sm text-muted-foreground">
            Per-hive walks via regipy (read-only). Persona-E #13 persistence rollup.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        <div className="rounded-lg border border-amber-500/30 bg-amber-50/50 p-4 dark:bg-amber-950/20">
          <p className="text-sm">
            <strong>Phase γ.7 skeleton.</strong> The walker (γ.4),
            schema (γ.1, γ.3), MCP tools (γ.6), and findings emitter
            (γ.8) are live; this page renders dynamic data once the
            REST surface lands. Use the MCP tools below in Claude
            Code / Desktop to query walked hives today.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <FileText className="h-4 w-4" />
            MCP tools (γ.6)
          </h2>
          <ul className="space-y-2 text-sm">
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">list_hives</code>{' '}
              — enumerate every WindowsRegistryExtract row for the active firmware (hive_path, hive_type, walk_status, key_count).
            </li>
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">get_run_keys</code>{' '}
              — Run / RunOnce / RunServices subkey set (filterable by hive_path).
            </li>
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">scan_persistence</code>{' '}
              — every persistence-related subkey across every walked hive (Run, IFEO, Winlogon hooks, Session Manager BootExecute, Active Setup, Services, AppInit_DLLs).
            </li>
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">dump_subkey</code>{' '}
              — return values at a specific subkey path inside one hive.
            </li>
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">walk_hive</code>{' '}
              — re-walk a hive on demand via regipy.
            </li>
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">trigger_registry_hive_walk</code>{' '}
              — schedule a fresh batch walk (Rule #33 .a 409-on-conflict).
            </li>
          </ul>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            Related pages
          </h2>
          <div className="flex flex-wrap gap-3">
            <Link
              to={`/projects/${projectId}/windows/registry/diff`}
              className="inline-flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm transition-colors hover:bg-accent"
            >
              <GitCompare className="h-4 w-4" />
              Diff hives
              <ExternalLink className="h-3 w-3 text-muted-foreground" />
            </Link>
            <Link
              to={`/projects/${projectId}/windows`}
              className="inline-flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm transition-colors hover:bg-accent"
            >
              <ChevronLeft className="h-4 w-4" />
              Back to Windows hub
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
