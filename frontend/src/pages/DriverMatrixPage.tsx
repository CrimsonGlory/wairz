import { Link, useParams } from 'react-router-dom'
import { ChevronLeft, Cpu, FileText, ShieldCheck } from 'lucide-react'

/**
 * Phase γ.7 — Driver Matrix Page (skeleton).
 *
 * Lists every Windows driver-package extracted for the active
 * firmware (γ.5 auto-extract). Surfaces the Persona-E #13 capability
 * badge (whql / attestation / cross_signed / unsigned / unknown) as
 * a histogram + filterable matrix.
 *
 * **MCP path**: ``list_drivers``, ``get_signing_tier_histogram``,
 * ``list_signed_drivers``, ``scan_inf_imports``, ``diff_driver_matrix``
 * from the windows_driver tool category.
 *
 * **Current state**: skeleton with MCP-tool reference. Full matrix
 * UI (sortable table + filter chips + histogram) lands once the REST
 * surface is added.
 */
export default function DriverMatrixPage() {
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
        <Cpu className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Driver Matrix</h1>
          <p className="text-sm text-muted-foreground">
            INF / CAT / SYS triplets with class GUID + PnP ID + signing tier (Persona-E #13).
          </p>
        </div>
      </div>

      <div className="space-y-4">
        <div className="rounded-lg border border-amber-500/30 bg-amber-50/50 p-4 dark:bg-amber-950/20">
          <p className="text-sm">
            <strong>Phase γ.7 skeleton.</strong> The driver extractor
            (γ.5) auto-runs on every firmware unpack and persists
            WindowsDriver rows; this page renders dynamic content
            once the REST surface is added.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <FileText className="h-4 w-4" />
            MCP tools (γ.6)
          </h2>
          <ul className="space-y-2 text-sm">
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">list_drivers</code>{' '}
              — full driver matrix with{' '}
              <code className="rounded bg-muted px-1 font-mono text-xs">class_guid_filter</code> +{' '}
              <code className="rounded bg-muted px-1 font-mono text-xs">manufacturer_filter</code>.
            </li>
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">get_signing_tier_histogram</code>{' '}
              — driver-count histogram across the 5 Persona-E #13 capability badges (whql / attestation / cross_signed / unsigned / unknown).
            </li>
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">list_signed_drivers</code>{' '}
              — filter to <code className="rounded bg-muted px-1 font-mono text-xs">catalog_signed=True</code>.
            </li>
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">scan_inf_imports</code>{' '}
              — flat list of every PnP hardware ID + compatible ID across the matrix.
            </li>
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">diff_driver_matrix</code>{' '}
              — diff against another firmware image's driver matrix by{' '}
              <code className="rounded bg-muted px-1 font-mono text-xs">rhs_firmware_id</code>.
            </li>
            <li>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">get_driver_info</code>{' '}
              — full per-driver record (paths, parsed inf_metadata, CAT signer, signing_tier).
            </li>
          </ul>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <ShieldCheck className="h-4 w-4" />
            Capability badge legend (Persona-E #13)
          </h2>
          <div className="space-y-2 text-sm">
            <div>
              <strong>WHQL</strong> — Microsoft-signed by the Windows Hardware Compatibility Publisher (passes Hyper-V Code Integrity HVCI gate).
            </div>
            <div>
              <strong>Attestation</strong> — Vendor-signed via the Microsoft Hardware Dev Center attestation root (Windows 10+).
            </div>
            <div>
              <strong>Cross-signed</strong> — Legacy vendor cert chained through a Microsoft cross-cert root (pre-Windows 10).
            </div>
            <div>
              <strong>Unsigned</strong> — No CAT, OR CAT signature parse failed, OR no Microsoft anchor in the chain.
            </div>
            <div>
              <strong>Unknown</strong> — CAT parses but doesn't fit any pattern (manual review needed).
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
