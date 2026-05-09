import { Link, useParams } from 'react-router-dom'
import { ChevronLeft, FileText, ScrollText } from 'lucide-react'

/**
 * Phase ε.1.b.4 — EVTX Walk Page (skeleton).
 *
 * Surfaces the per-firmware Windows Event Log walk results: aggregate
 * counts (by provider, by status), per-file breakdown, and the
 * forensic-timeline trio (Sysmon EID 1, Security EID 4624 / 4625) that
 * the walk emits as Findings.
 *
 * **MCP path**: ``list_evtx_files`` / ``parse_evtx_file`` /
 * ``query_evtx_events`` / ``evtx_walk_status`` / ``trigger_evtx_walk``
 * / ``evtx_walk_summary`` from windows_event_log tool category (6 tools).
 *
 * **Current state**: skeleton with MCP-tool reference. Full UI
 * (per-file table + per-EID histogram + record sample browser) lands
 * once the REST surface is added.
 *
 * Mirrors the γ.7 RegistryDiffPage / δ.8 R2RStompPage pattern — the
 * MCP tools are live today; the FE renders a placeholder that points
 * operators at the MCP path.
 */
export default function EvtxWalkPage() {
  const { projectId } = useParams<{ projectId: string }>()

  return (
    <div className="mx-auto max-w-5xl py-8">
      <div className="mb-2">
        <Link
          to={`/projects/${projectId}`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
          Project
        </Link>
      </div>

      <div className="mb-8 flex items-center gap-3">
        <ScrollText className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">EVTX Walk</h1>
          <p className="text-sm text-muted-foreground">
            Forensic-timeline event surfacing across walked Windows Event Log files.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        <div className="rounded-lg border border-amber-500/30 bg-amber-50/50 p-4 dark:bg-amber-950/20">
          <p className="text-sm">
            <strong>Phase ε.1.b.4 skeleton.</strong> The EVTX walk backend
            is live via the{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">windows_event_log</code> MCP
            category (6 tools); full UI lands once the REST surface is added.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <FileText className="h-4 w-4" />
            MCP path
          </h2>
          <p className="mb-3 text-sm">
            From Claude Code / Desktop, the EVTX walk runs automatically
            on firmware unpack (auto-walk hook from{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">unpack.py</code>).
            For explicit re-walks or forensic-timeline pivots:
          </p>
          <pre className="overflow-x-auto rounded bg-muted/50 p-3 text-xs">
            <code>{`# Trigger / poll an EVTX walk:
trigger_evtx_walk()
evtx_walk_status()       // → idle | queued | running | completed | failed
evtx_walk_summary()      // by_provider, by_status, total_records
list_evtx_files()        // per-file path + record_count

# Forensic-timeline pivot:
query_evtx_events(eid=1, provider="Sysmon")        // process-create
query_evtx_events(eid=4624)                         // logon success
query_evtx_events(eid=4625, substring="0xc000006a") // wrong-password

# On-demand re-parse for a specific file:
parse_evtx_file(path="Windows/System32/winevt/Logs/Security.evtx",
                max_records=50)`}</code>
          </pre>
          <p className="mt-3 text-sm text-muted-foreground">
            The walk emits Findings with sources{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">windows_sysmon_proc_create</code>,{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">windows_logon_success</code>,
            and{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">windows_logon_failure</code>.
            Per ε.1.b campaign Decision #1, per-event row persistence is
            deferred to a future ζ.X phase; the MCP tools re-parse files
            on demand.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <FileText className="h-4 w-4" />
            Rule #36 no-execute discipline
          </h2>
          <p className="text-sm text-muted-foreground">
            python-evtx parses .evtx files AS DATA via mmap-based
            read-only record streams. wairz never invokes{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">wevtutil</code>,{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">Get-WinEvent</code>,
            or any scriptable event-replay primitive.
          </p>
        </div>
      </div>
    </div>
  )
}
