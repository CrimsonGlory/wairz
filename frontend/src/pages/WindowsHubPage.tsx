import { Link, useParams } from 'react-router-dom'
import {
  Archive,
  CheckCircle2,
  ChevronRight,
  Clock,
  Cpu,
  FileText,
  HardDrive,
  Lock,
  Package,
  ShieldCheck,
} from 'lucide-react'

interface FormatStatus {
  name: string
  ext: string
  icon: React.ReactNode
  capability: 'full' | 'partial' | 'pending'
  description: string
}

const PHASE_ALPHA_FORMATS: FormatStatus[] = [
  {
    name: 'CAB',
    ext: '.cab',
    icon: <Archive className="h-5 w-5" />,
    capability: 'full',
    description: 'Microsoft Cabinet — foundation for MSU updates, CBS cabinets, driver packages, and signed installers. Extracted via cabextract.',
  },
  {
    name: 'MSI / MSP',
    ext: '.msi / .msp',
    icon: <Package className="h-5 w-5" />,
    capability: 'full',
    description: 'Windows Installer (OLE2 compound document). msitools msiextract walks the File table; custom-action payloads dump-only via the windows_archive MCP tools — never executed.',
  },
  {
    name: 'MSIX / AppX / MSIXBundle',
    ext: '.msix / .appx / .msixbundle',
    icon: <Package className="h-5 w-5" />,
    capability: 'full',
    description: 'Modern Windows app packages. ZIP-shaped with AppxManifest.xml + AppxBlockMap.xml + AppxSignature.p7x. Manifest parsing surfaces Capabilities, Applications, Dependencies.',
  },
  {
    name: 'MSU',
    ext: '.msu',
    icon: <Archive className="h-5 w-5" />,
    capability: 'full',
    description: 'Microsoft Update Standalone Package — CAB-of-CABs. Recursive inner-CAB extraction; PSF Express delta detection; KB metadata enumeration.',
  },
  {
    name: 'PSF',
    ext: '.psf',
    icon: <Clock className="h-5 w-5" />,
    capability: 'partial',
    description: 'Patch Storage File / Express install delta. Phase α validates magic (PA30/PA19/PA17) + extracts target RSDS GUID. Full reconstruction needs a baseline + the gated psfextract toolchain.',
  },
  {
    name: 'VHDX',
    ext: '.vhdx',
    icon: <HardDrive className="h-5 w-5" />,
    capability: 'full',
    description: 'Hyper-V / WSL2 virtual disk. Converted to raw NTFS via qemu-img. Browse the resulting disk.raw or use the windows_storage MCP tools (Phase β).',
  },
  {
    name: 'Driver Package',
    ext: 'CAB + INF + SYS + CAT',
    icon: <Cpu className="h-5 w-5" />,
    capability: 'full',
    description: 'Device-driver bundle. INF + SYS + CAT triplet detection with subtype classification (cab_inf_sys_cat / dch / driver_store_dir / cab_inf_only / unknown).',
  },
]

const ROADMAP = [
  {
    phase: 'α',
    title: 'Archive extraction',
    status: 'in_progress' as const,
    items: 'CAB, MSI, MSIX, MSU, PSF, VHDX, Driver Package — extraction + 6 MCP tools.',
  },
  {
    phase: 'β',
    title: 'Authenticode + ARM-arch',
    status: 'pending' as const,
    items: 'Authenticode chain validation, RICH header decoding, DBX revocation cross-reference, ARM64EC/X dual-view detection. PE Hardening Dashboard.',
  },
  {
    phase: 'γ',
    title: 'Registry + Drivers + Persistence',
    status: 'pending' as const,
    items: 'Registry hive parsing, INF/CAT validation, kernel-API capability inference, AmCache + persistence keys, WHQL/attestation/cross-signed driver tier classification.',
  },
  {
    phase: 'δ',
    title: '.NET + Update Diff + Storage',
    status: 'pending' as const,
    items: '.NET single-file bundle extraction, IL decompilation (gated dotnet-runtime), R2R-stomping detection, KB-vs-KB update diff, BCD + ESEDB + NTFS-ADS introspection.',
  },
]

function StatusBadge({ capability }: { capability: FormatStatus['capability'] }) {
  if (capability === 'full') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300">
        <CheckCircle2 className="h-3 w-3" />
        FULL
      </span>
    )
  }
  if (capability === 'partial') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-2 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-900/40 dark:text-amber-300">
        <Clock className="h-3 w-3" />
        PARTIAL
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-300">
      <Clock className="h-3 w-3" />
      PENDING
    </span>
  )
}

function PhaseBadge({ status, phase }: { status: 'in_progress' | 'pending'; phase: string }) {
  if (status === 'in_progress') {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-blue-50 px-2 py-0.5 text-xs font-semibold text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">
        Phase {phase} — IN PROGRESS
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
      Phase {phase} — PENDING
    </span>
  )
}

export default function WindowsHubPage() {
  const { projectId } = useParams<{ projectId: string }>()

  return (
    <div className="mx-auto max-w-5xl py-8">
      <div className="mb-6 flex items-center gap-3">
        <ShieldCheck className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Windows ecosystem coverage</h1>
          <p className="text-sm text-muted-foreground">
            God-mode Windows binary / archive / image / system-image format
            support. Phase α (archive extraction) shipped — α.6 cut-over rebuild
            activates the full toolchain.
          </p>
        </div>
      </div>

      <div className="mb-6 rounded-lg border border-border bg-card p-4">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <FileText className="h-4 w-4 text-muted-foreground" />
          How to use
        </h2>
        <ol className="ml-5 list-decimal space-y-1 text-sm text-muted-foreground">
          <li>
            Upload a Windows artefact (CAB / MSI / MSIX / MSU / PSF / VHDX) on
            the project page. Detection routes the file to the right Phase α
            handler automatically.
          </li>
          <li>
            Browse the extracted tree via the{' '}
            <Link
              to={projectId ? `/projects/${projectId}/explore` : '/projects'}
              className="text-primary underline-offset-2 hover:underline"
            >
              File Explorer
            </Link>
            .
          </li>
          <li>
            Use the AI assistant (MCP) with the new <code>windows_archive</code>{' '}
            tool category for manifest parsing, INF inspection, MSI custom-action
            dumping (extract-only — never executed), and PSF baseline GUID
            extraction.
          </li>
        </ol>
      </div>

      <h2 className="mb-3 text-base font-semibold">Phase β tools (shipped)</h2>
      <div className="mb-8 grid gap-3 md:grid-cols-2">
        <Link
          to={
            projectId
              ? `/projects/${projectId}/windows/pe-hardening`
              : '/projects'
          }
          className="group flex items-start justify-between gap-3 rounded-lg border border-border bg-card p-4 transition hover:border-primary hover:bg-accent/40"
        >
          <div className="flex items-start gap-3">
            <Lock className="mt-0.5 h-5 w-5 text-primary" />
            <div>
              <div className="font-semibold">PE Hardening Dashboard</div>
              <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                Per-PE Authenticode chain validation against bundled offline
                Microsoft roots, RICH header toolchain fingerprint, ARM64EC/X
                bimorphic detection, and DBX revocation cross-reference. Runs
                detached via the Phase β.8 background runner; results persist
                across sessions.
              </p>
            </div>
          </div>
          <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-muted-foreground transition group-hover:text-primary" />
        </Link>
      </div>

      <h2 className="mb-3 text-base font-semibold">Phase α formats (shipped)</h2>
      <div className="mb-8 grid gap-3 md:grid-cols-2">
        {PHASE_ALPHA_FORMATS.map((fmt) => (
          <div
            key={fmt.name}
            className="rounded-lg border border-border bg-card p-4"
          >
            <div className="mb-2 flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">{fmt.icon}</span>
                <div>
                  <div className="font-semibold">{fmt.name}</div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {fmt.ext}
                  </div>
                </div>
              </div>
              <StatusBadge capability={fmt.capability} />
            </div>
            <p className="text-sm leading-relaxed text-muted-foreground">
              {fmt.description}
            </p>
          </div>
        ))}
      </div>

      <h2 className="mb-3 text-base font-semibold">Campaign roadmap</h2>
      <div className="rounded-lg border border-border bg-card">
        {ROADMAP.map((phase, idx) => (
          <div
            key={phase.phase}
            className={`flex flex-col gap-2 p-4 ${idx !== ROADMAP.length - 1 ? 'border-b border-border' : ''}`}
          >
            <div className="flex items-center gap-3">
              <PhaseBadge status={phase.status} phase={phase.phase} />
              <span className="text-sm font-semibold">{phase.title}</span>
            </div>
            <p className="text-sm text-muted-foreground">{phase.items}</p>
          </div>
        ))}
      </div>

      <div className="mt-6 rounded-lg border border-dashed border-border p-4 text-xs text-muted-foreground">
        <p>
          <strong>Custom-action discipline:</strong> MSI custom actions and
          self-extracting installers are{' '}
          <span className="font-semibold">extracted as data only, never executed</span>
          . The <code>dump_msi_custom_actions</code> MCP tool emits Binary-table
          payloads (PE binaries, VBScript, etc.) for the operator's analysis via
          the existing binary tools — full stop.
        </p>
        <p className="mt-2">
          <strong>Offline trust anchor:</strong> Authenticode roots and DBX
          revocation lists are bundled at image build time and refreshed
          quarterly via cron. No cert chain fetching during scans.
        </p>
      </div>
    </div>
  )
}
