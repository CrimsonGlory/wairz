import { Link, useParams } from 'react-router-dom'
import { ChevronLeft, FileText, GitCompare } from 'lucide-react'

/**
 * Phase δ.8 — KB-vs-KB Update Diff Page (skeleton).
 *
 * Surfaces the per-DLL changeset between two Windows-Update KBs in the
 * firmware (added / removed / modified / unchanged), backed by the δ.5
 * background runner's persisted ``windows_update_dll_diffs`` rows + the
 * δ.3 ``firmware.windows_update_diff_*`` 5-column 202+poll status set.
 *
 * **MCP path**: ``diff_kb_packages`` from the δ.7 windows_update tool
 * category (returns by-type histogram + 50-row sample). The
 * ``trigger_dotnet_decompile`` shape applies to the .NET side; the
 * update-diff trigger MCP tool is a follow-up REST surface.
 *
 * **Current state**: skeleton with MCP-tool reference. Full UI
 * (KB pair picker + by-type histogram + per-DLL drill table + filter
 * by .NET vs native + R2R-stomp cross-link) lands once the REST
 * surface is added.
 */
export default function UpdateDiffPage() {
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
        <GitCompare className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">KB-vs-KB Update Diff</h1>
          <p className="text-sm text-muted-foreground">
            Per-DLL changeset between two Windows-Update KBs in this firmware.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        <div className="rounded-lg border border-amber-500/30 bg-amber-50/50 p-4 dark:bg-amber-950/20">
          <p className="text-sm">
            <strong>Phase δ.8 skeleton.</strong> The diff backend is live via
            the <code className="rounded bg-muted px-1 font-mono text-xs">diff_kb_packages</code> MCP tool;
            full diff UI lands once the REST surface is added.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <FileText className="h-4 w-4" />
            MCP path
          </h2>
          <p className="mb-3 text-sm">
            From Claude Code / Desktop, invoke the diff tool with two KB IDs:
          </p>
          <pre className="overflow-x-auto rounded bg-muted/50 p-3 text-xs">
            <code>{`diff_kb_packages(
  older_kb: "KB5034441",
  newer_kb: "KB5036893"
)`}</code>
          </pre>
          <p className="mt-3 text-sm text-muted-foreground">
            Returns the by-type histogram (added / removed / modified /
            unchanged) plus a 50-row sample from{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">windows_update_dll_diffs</code>.
            If no rows exist, the tool prompts the operator to trigger a
            new windows_update_diff run via the Rule #33 .a 202+poll
            trigger.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <FileText className="h-4 w-4" />
            Companion tools
          </h2>
          <ul className="space-y-2 text-sm">
            <li>
              <code className="rounded bg-muted px-1 font-mono text-xs">list_update_packages</code>{' '}
              — see every package + KB ID in the firmware.
            </li>
            <li>
              <code className="rounded bg-muted px-1 font-mono text-xs">get_supersedence_chain</code>{' '}
              — trace KB lineage forward and backward.
            </li>
            <li>
              <code className="rounded bg-muted px-1 font-mono text-xs">list_kb_files</code>{' '}
              — file BOM filtered to PE artefacts (.dll / .exe / .sys).
            </li>
          </ul>
        </div>
      </div>
    </div>
  )
}
