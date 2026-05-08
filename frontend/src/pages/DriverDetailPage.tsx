import { Link, useParams } from 'react-router-dom'
import { ChevronLeft, Cpu, FileText } from 'lucide-react'

/**
 * Phase γ.7 — Driver Detail Page (skeleton).
 *
 * Shows the full WindowsDriver record for one driver-package: INF /
 * CAT / SYS paths, parsed inf_metadata (Version block, Manufacturer
 * block, Models, Strings), all PnP hardware IDs, CAT signer subject
 * + issuer, signing_tier classification.
 *
 * **MCP path**: ``get_driver_info`` from the windows_driver tool
 * category.
 *
 * **Current state**: skeleton with MCP-tool reference. Full detail
 * UI (collapsible inf_metadata viewer + signature chain render +
 * "scan PE imports" link to PeHardeningPage) lands once the REST
 * surface is added.
 */
export default function DriverDetailPage() {
  const { projectId, driverId } = useParams<{ projectId: string; driverId: string }>()

  return (
    <div className="mx-auto max-w-5xl py-8">
      <div className="mb-2">
        <Link
          to={`/projects/${projectId}/windows/drivers`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
          Driver matrix
        </Link>
      </div>

      <div className="mb-8 flex items-center gap-3">
        <Cpu className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Driver Detail</h1>
          <p className="text-sm text-muted-foreground font-mono text-xs">
            driver_id={driverId}
          </p>
        </div>
      </div>

      <div className="space-y-4">
        <div className="rounded-lg border border-amber-500/30 bg-amber-50/50 p-4 dark:bg-amber-950/20">
          <p className="text-sm">
            <strong>Phase γ.7 skeleton.</strong> The full per-driver
            record is available via the{' '}
            <code className="rounded bg-muted px-1 font-mono text-xs">get_driver_info</code> MCP tool;
            this page renders dynamic content once the REST surface is added.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <FileText className="h-4 w-4" />
            MCP path
          </h2>
          <pre className="overflow-x-auto rounded bg-muted/50 p-3 text-xs">
            <code>{`get_driver_info(driver_path: "Windows/INF/<driver>.inf")`}</code>
          </pre>
          <p className="mt-3 text-sm text-muted-foreground">
            Returns the full WindowsDriver record: INF / CAT / SYS
            paths, parsed inf_metadata (Version block, Manufacturer
            block, Models, Strings, errors), PnP hardware + compatible
            IDs, catalog_signed flag, signer subject + issuer,
            signing_tier (whql / attestation / cross_signed / unsigned /
            unknown per Persona-E #13).
          </p>
        </div>
      </div>
    </div>
  )
}
