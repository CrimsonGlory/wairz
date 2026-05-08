import { Link, useParams } from 'react-router-dom'
import { ChevronLeft, FileText, Code } from 'lucide-react'

/**
 * Phase δ.8 — .NET Bundle Browser Page (skeleton).
 *
 * Surfaces the .NET single-file bundles detected by the δ.4 worker
 * (gated ARG INCLUDE_DOTNET=1; ilspycmd extraction) + per-bundle IL
 * output + δ.6 R2R-stomping classifier verdicts.
 *
 * **MCP path**: ``list_dotnet_bundles`` / ``get_bundle_metadata`` /
 * ``list_extracted_assemblies`` / ``get_assembly_il`` /
 * ``scan_r2r_stomping`` / ``trigger_dotnet_decompile`` from the δ.7
 * windows_dotnet tool category.
 *
 * **Current state**: skeleton with MCP-tool reference. Full UI
 * (bundle list + per-bundle assembly tree + IL viewer with Monaco +
 * R2R-stomp tier badges + capa-on-IL hits) lands once the REST surface
 * is added.
 */
export default function DotNetBrowserPage() {
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
        <Code className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">.NET Bundle Browser</h1>
          <p className="text-sm text-muted-foreground">
            Single-file bundle decompile + R2R-stomping detection per Persona-E #5.
          </p>
        </div>
      </div>

      <div className="space-y-4">
        <div className="rounded-lg border border-amber-500/30 bg-amber-50/50 p-4 dark:bg-amber-950/20">
          <p className="text-sm">
            <strong>Phase δ.8 skeleton.</strong> The decompile backend is
            live via the <code className="rounded bg-muted px-1 font-mono text-xs">windows_dotnet.*</code> MCP tools;
            full UI lands once the REST surface is added.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <FileText className="h-4 w-4" />
            MCP path
          </h2>
          <p className="mb-3 text-sm">
            From Claude Code / Desktop, list bundles + drill into one:
          </p>
          <pre className="overflow-x-auto rounded bg-muted/50 p-3 text-xs">
            <code>{`list_dotnet_bundles()
get_bundle_metadata(bundle_path: "Windows/SomeApp.exe")
list_extracted_assemblies(bundle_path: "Windows/SomeApp.exe")
get_assembly_il(assembly_path: "<decompile_target_dir>/Foo.il")
scan_r2r_stomping()
trigger_dotnet_decompile()  // Rule #33 .a 202+poll`}</code>
          </pre>
          <p className="mt-3 text-sm text-muted-foreground">
            The δ.4 worker requires <code className="rounded bg-muted px-1 font-mono text-xs">INCLUDE_DOTNET=1</code> at
            build time (dotnet-sdk-8.0 + ilspycmd). Without it, the
            decompile transitions to <code className="rounded bg-muted px-1 font-mono text-xs">failed</code> with a
            clear "ilspycmd not available — rebuild with INCLUDE_DOTNET=1"
            message.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            <FileText className="h-4 w-4" />
            R2R-stomping detection (Persona-E #5)
          </h2>
          <p className="text-sm">
            ReadyToRun (R2R) is a .NET feature that pre-compiles managed
            assemblies into native code. An R2R-stomping attack patches
            the native R2R code while leaving the IL intact — operators
            who only review the IL stream miss the modification.
          </p>
          <p className="mt-3 text-sm">
            <code className="rounded bg-muted px-1 font-mono text-xs">scan_r2r_stomping</code>{' '}
            runs the δ.6 classifier across every detected bundle and
            returns drafts at four confidence tiers:
          </p>
          <ul className="mt-2 space-y-1 text-sm text-muted-foreground">
            <li><strong>Tier 1 (LOW)</strong> — R2R-eligible review candidate (every R2R-promoted .NET PE).</li>
            <li><strong>Tier 2 (MEDIUM)</strong> — capa/IL divergence (missing IL for R2R-promoted PE).</li>
            <li><strong>Tier 3 (HIGH)</strong> — byte-level IL/native prologue mismatch (deferred).</li>
            <li><strong>Tier 4 (CRITICAL)</strong> — capa-rule promotion for known stomp patterns (deferred).</li>
          </ul>
          <p className="mt-3 text-sm text-muted-foreground">
            Findings persist with <code className="rounded bg-muted px-1 font-mono text-xs">source = "windows_r2r_stomp"</code>{' '}
            once the δ.8 emit hook + ck_findings_source extension lands
            (this commit).
          </p>
        </div>
      </div>
    </div>
  )
}
