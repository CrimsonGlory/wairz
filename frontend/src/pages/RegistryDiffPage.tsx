import { Link, useParams } from 'react-router-dom'
import { ChevronLeft, FileText, GitCompare } from 'lucide-react'

/**
 * Phase γ.7 — Registry Diff Page (skeleton).
 *
 * Compares two registry hives (within a single firmware OR across
 * firmware images) and reports lhs_only / rhs_only / both_changed
 * subkey sets.
 *
 * **MCP path**: ``diff_hives`` from windows_registry tool category.
 *
 * **Current state**: skeleton with MCP-tool reference. Full UI
 * (hive picker + side-by-side subkey diff render + value comparison)
 * lands once the REST surface is added.
 */
export default function RegistryDiffPage() {
  const { projectId } = useParams<{ projectId: string }>()

  return (
    <div className="mx-auto max-w-5xl py-8">
      <div className="mb-2">
        <Link
          to={`/projects/${projectId}/windows/registry`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
          Registry hives
        </Link>
      </div>

      <div className="mb-8 flex items-center gap-3">
        <GitCompare className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Registry Diff</h1>
          <p className="text-sm text-muted-foreground">
            Compare two walked hives by subkey-set + value diff.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        <div className="rounded-lg border border-amber-500/30 bg-amber-50/50 p-4 dark:bg-amber-950/20">
          <p className="text-sm">
            <strong>Phase γ.7 skeleton.</strong> The diff backend is
            live via the <code className="rounded bg-muted px-1 font-mono text-xs">diff_hives</code> MCP tool;
            full diff UI lands once the REST surface is added.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <FileText className="h-4 w-4" />
            MCP path
          </h2>
          <p className="mb-3 text-sm">
            From Claude Code / Desktop, invoke the diff tool with two
            hive paths:
          </p>
          <pre className="overflow-x-auto rounded bg-muted/50 p-3 text-xs">
            <code>{`diff_hives(
  lhs_hive_path: "Windows/System32/config/SOFTWARE",
  rhs_hive_path: "Windows/System32/config/SYSTEM"
)`}</code>
          </pre>
          <p className="mt-3 text-sm text-muted-foreground">
            Returns <code className="rounded bg-muted px-1 font-mono text-xs">lhs_only</code>,{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">rhs_only</code>, and{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">both_changed</code> subkey sets.
            Both hives must already be walked (γ.4 auto-walk on unpack OR explicit{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">trigger_registry_hive_walk</code>).
          </p>
        </div>
      </div>
    </div>
  )
}
