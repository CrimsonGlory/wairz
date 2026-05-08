import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Copy,
  Cpu,
  HelpCircle,
  Lock,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Unlock,
  XCircle,
} from 'lucide-react'
import {
  type WindowsPEChainStatus,
  type WindowsPESignatureDetail,
  getPeSignature,
} from '@/api/hardwareFirmware'
import { useProjectStore } from '@/stores/projectStore'
import { extractErrorMessage } from '@/utils/error'

// Mirrors the chain-status meta in PeHardeningPage. Kept inline (not
// extracted to a shared module) because the two pages render at
// different scales — list-row badges vs detail-page hero badge — and
// the inline copy is small enough that a shared module would add an
// import surface for ~30 LOC. If a third consumer appears (Phase γ
// driver-detail page, perhaps), promote then per Rule of Three.
type ChainStatusMeta = {
  label: string
  description: string
  badgeClass: string
  icon: React.ReactNode
}

const CHAIN_STATUS_META: Record<WindowsPEChainStatus, ChainStatusMeta> = {
  revoked: {
    label: 'Revoked',
    description: 'Cert in DBX OR CRL OR OCSP says no — assume hostile.',
    badgeClass:
      'bg-red-50 text-red-700 ring-1 ring-red-200 dark:bg-red-950/40 dark:text-red-300 dark:ring-red-800',
    icon: <XCircle className="h-4 w-4" />,
  },
  never_valid: {
    label: 'Never valid',
    description:
      'Signature never validated (test/dev cert, broken chain, or signify bailed).',
    badgeClass:
      'bg-orange-50 text-orange-700 ring-1 ring-orange-200 dark:bg-orange-950/40 dark:text-orange-300 dark:ring-orange-800',
    icon: <ShieldAlert className="h-4 w-4" />,
  },
  valid_at_signing: {
    label: 'Valid at signing',
    description:
      'Cert was good at the RFC 3161 counter-signature timestamp (TSA) but might not be today.',
    badgeClass:
      'bg-amber-50 text-amber-700 ring-1 ring-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:ring-amber-800',
    icon: <ShieldQuestion className="h-4 w-4" />,
  },
  valid_now: {
    label: 'Valid now',
    description: 'Cert + chain + revocation all OK as of this scan.',
    badgeClass:
      'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:ring-emerald-800',
    icon: <ShieldCheck className="h-4 w-4" />,
  },
  unknown: {
    label: 'Unknown',
    description:
      'Validation skipped (offline data missing, malformed PE, or signify raised).',
    badgeClass:
      'bg-slate-100 text-slate-700 ring-1 ring-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-700',
    icon: <HelpCircle className="h-4 w-4" />,
  },
}

function formatDate(value: string | null): string {
  if (!value) return '—'
  try {
    return new Date(value).toLocaleString()
  } catch {
    return value
  }
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setCopied(true)
          window.setTimeout(() => setCopied(false), 1200)
        } catch {
          /* clipboard write blocked — silently no-op */
        }
      }}
      className="inline-flex items-center gap-1 rounded p-1 text-muted-foreground transition hover:bg-muted hover:text-foreground"
      title={copied ? 'Copied' : 'Copy'}
    >
      <Copy className="h-3 w-3" />
    </button>
  )
}

function FieldRow({
  label,
  value,
  mono = false,
  copyable = false,
}: {
  label: string
  value: React.ReactNode
  mono?: boolean
  copyable?: boolean
}) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-3 border-b border-border/60 px-3 py-2 last:border-b-0">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div
        className={`flex min-w-0 items-center gap-1 break-all text-sm ${mono ? 'font-mono' : ''}`}
      >
        <span className="min-w-0 flex-1">{value}</span>
        {copyable && typeof value === 'string' && value !== '—' ? (
          <CopyButton value={value} />
        ) : null}
      </div>
    </div>
  )
}

function CollapsibleSection({
  title,
  defaultOpen = false,
  children,
  badge,
}: {
  title: string
  defaultOpen?: boolean
  children: React.ReactNode
  badge?: React.ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-lg border border-border bg-card">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm font-semibold transition hover:bg-muted/40"
      >
        <span className="flex items-center gap-2">
          <ChevronRight
            className={`h-4 w-4 transition-transform ${open ? 'rotate-90' : ''}`}
          />
          {title}
        </span>
        {badge}
      </button>
      {open ? <div className="border-t border-border">{children}</div> : null}
    </div>
  )
}

function JsonBlock({ value }: { value: unknown }) {
  let pretty = '—'
  try {
    pretty = JSON.stringify(value, null, 2)
  } catch {
    pretty = String(value)
  }
  return (
    <pre className="max-h-[40vh] overflow-auto whitespace-pre-wrap break-all bg-muted/30 p-3 font-mono text-xs">
      {pretty}
    </pre>
  )
}

// Render a RICH-header decoded shape if it looks like the
// rich_header_service output shape (entries / hash_md5 / xor_key);
// otherwise fall back to JSON.
function RichHeaderRender({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return null
  const entries = Array.isArray(data.entries)
    ? (data.entries as Array<Record<string, unknown>>)
    : null
  if (!entries) return <JsonBlock value={data} />
  return (
    <div className="space-y-2 p-3">
      <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-3">
        {data.xor_key !== undefined ? (
          <div>
            <div className="text-muted-foreground">XOR key</div>
            <div className="font-mono">
              {String(data.xor_key as string | number)}
            </div>
          </div>
        ) : null}
        {data.entry_count !== undefined ? (
          <div>
            <div className="text-muted-foreground">Entries</div>
            <div className="font-mono">{String(data.entry_count)}</div>
          </div>
        ) : null}
        {data.hash_md5 !== undefined ? (
          <div className="col-span-2 sm:col-span-1">
            <div className="text-muted-foreground">Cluster hash (MD5)</div>
            <div className="truncate font-mono" title={String(data.hash_md5)}>
              {String(data.hash_md5)}
            </div>
          </div>
        ) : null}
      </div>
      <div className="overflow-auto rounded border border-border">
        <table className="w-full text-xs">
          <thead className="bg-muted/40 text-muted-foreground">
            <tr className="border-b border-border">
              <th className="px-2 py-1 text-left">Comp ID</th>
              <th className="px-2 py-1 text-left">Build #</th>
              <th className="px-2 py-1 text-left">Product ID</th>
              <th className="px-2 py-1 text-right">Instances</th>
            </tr>
          </thead>
          <tbody>
            {entries.slice(0, 200).map((entry, idx) => (
              <tr key={idx} className="border-b border-border/60 font-mono">
                <td className="px-2 py-1">{String(entry.comp_id ?? '—')}</td>
                <td className="px-2 py-1">
                  {String(entry.build_number ?? '—')}
                </td>
                <td className="px-2 py-1">{String(entry.product_id ?? '—')}</td>
                <td className="px-2 py-1 text-right">
                  {String(entry.instances ?? '—')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {entries.length > 200 ? (
        <div className="text-xs text-muted-foreground">
          Showing first 200 of {entries.length} entries; full payload in raw
          JSON view.
        </div>
      ) : null}
    </div>
  )
}

function ArchViewRender({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return null
  const primary = data.primary as string | undefined
  const secondary = data.secondary as string | undefined
  const divergence = data.divergence_score as number | undefined
  return (
    <div className="grid gap-3 p-3 sm:grid-cols-3">
      <div>
        <div className="text-xs text-muted-foreground">Primary loader view</div>
        <div className="mt-1 inline-flex items-center gap-1 rounded bg-blue-50 px-2 py-0.5 font-mono text-sm text-blue-700 dark:bg-blue-950/40 dark:text-blue-300">
          {primary ?? '—'}
        </div>
      </div>
      <div>
        <div className="text-xs text-muted-foreground">
          Secondary loader view
        </div>
        <div className="mt-1 inline-flex items-center gap-1 rounded bg-purple-50 px-2 py-0.5 font-mono text-sm text-purple-700 dark:bg-purple-950/40 dark:text-purple-300">
          {secondary ?? '—'}
        </div>
      </div>
      <div>
        <div className="text-xs text-muted-foreground">Divergence score</div>
        <div className="mt-1 font-mono text-sm">
          {divergence !== undefined ? divergence.toString() : '—'}
        </div>
        <div className="text-xs text-muted-foreground">
          Higher = more functions diverge between views.
        </div>
      </div>
    </div>
  )
}

export default function AuthenticodeDetailPage() {
  const { projectId, signatureId } = useParams<{
    projectId: string
    signatureId: string
  }>()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)

  const [detail, setDetail] = useState<WindowsPESignatureDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    if (!projectId || !signatureId) return
    setLoading(true)
    setError(null)
    try {
      const d = await getPeSignature(projectId, signatureId, selectedFirmwareId)
      setDetail(d)
    } catch (e) {
      setError(extractErrorMessage(e, 'Failed to load PE signature'))
      setDetail(null)
    } finally {
      setLoading(false)
    }
  }, [projectId, signatureId, selectedFirmwareId])

  useEffect(() => {
    load()
  }, [load])

  if (!projectId || !signatureId) return null

  const status = detail?.chain_status
  // Rule #9 ?? fallback — defensive against an unknown backend status.
  const meta = status
    ? (CHAIN_STATUS_META[status] ?? CHAIN_STATUS_META.unknown)
    : null

  const basename = detail?.blob_path
    ? (detail.blob_path.split('/').pop() ?? detail.blob_path)
    : signatureId

  return (
    <div className="mx-auto max-w-5xl py-6">
      <div className="mb-4 flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
        <Link
          to={`/projects/${projectId}/windows/pe-hardening`}
          className="inline-flex items-center gap-1 hover:text-foreground"
        >
          <ChevronLeft className="h-4 w-4" />
          PE Hardening Dashboard
        </Link>
      </div>

      <div className="mb-6 flex flex-wrap items-start gap-3">
        <Lock className="mt-1 h-7 w-7 text-primary" />
        <div className="min-w-0 flex-1">
          <h1
            className="truncate text-2xl font-bold"
            title={detail?.blob_path ?? basename}
          >
            {basename}
          </h1>
          {detail?.blob_path ? (
            <p
              className="mt-1 truncate text-xs text-muted-foreground"
              title={detail.blob_path}
            >
              {detail.blob_path}
            </p>
          ) : null}
        </div>
        {meta ? (
          <span
            title={meta.description}
            className={`inline-flex items-center gap-1 rounded-full px-3 py-1 text-sm font-medium ${meta.badgeClass}`}
          >
            {meta.icon}
            {meta.label}
          </span>
        ) : null}
      </div>

      {error ? (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/20 dark:text-red-300">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <div>{error}</div>
        </div>
      ) : null}

      {loading && !detail ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
          Loading…
        </div>
      ) : null}

      {detail ? (
        <div className="space-y-4">
          {/* Quick-scan flags */}
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-lg border border-border bg-card p-3">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                {detail.signed ? (
                  <Lock className="h-3.5 w-3.5" />
                ) : (
                  <Unlock className="h-3.5 w-3.5" />
                )}
                Signed
              </div>
              <div className="mt-1 text-base font-semibold">
                {detail.signed ? 'yes' : 'no'}
              </div>
            </div>
            <div
              className={`rounded-lg border p-3 ${
                detail.dbx_revoked
                  ? 'border-red-200 bg-red-50/60 dark:border-red-900/40 dark:bg-red-950/20'
                  : 'border-border bg-card'
              }`}
            >
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <XCircle className="h-3.5 w-3.5" />
                DBX revoked
              </div>
              <div className="mt-1 text-base font-semibold">
                {detail.dbx_revoked ? (
                  <>
                    yes
                    {detail.dbx_revocation_kb ? (
                      <span className="ml-2 font-mono text-xs text-muted-foreground">
                        ({detail.dbx_revocation_kb})
                      </span>
                    ) : null}
                  </>
                ) : (
                  'no'
                )}
              </div>
            </div>
            <div className="rounded-lg border border-border bg-card p-3">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Cpu className="h-3.5 w-3.5" />
                Bimorphic arch
              </div>
              <div className="mt-1 text-base font-semibold">
                {detail.arch_view ? 'yes (ARM64EC/X)' : 'no'}
              </div>
            </div>
          </div>

          {/* Authenticode chain summary */}
          <CollapsibleSection title="Authenticode chain" defaultOpen>
            <div>
              <FieldRow
                label="Signer subject"
                value={detail.signer_subject ?? '—'}
              />
              <FieldRow
                label="Signer issuer"
                value={detail.signer_issuer ?? '—'}
              />
              <FieldRow
                label="Leaf serial"
                value={detail.leaf_serial ?? '—'}
                mono
                copyable
              />
              <FieldRow
                label="Sig hash algo"
                value={detail.sig_hash_algo ?? '—'}
                mono
              />
              <FieldRow
                label="TSA authority"
                value={detail.tsa_authority ?? '—'}
              />
              <FieldRow
                label="Counter-sig timestamp"
                value={formatDate(detail.signed_at)}
              />
            </div>
          </CollapsibleSection>

          {/* Raw chain JSON */}
          {detail.chain_json ? (
            <CollapsibleSection title="signify verification result (raw)">
              <JsonBlock value={detail.chain_json} />
            </CollapsibleSection>
          ) : null}

          {/* RICH header */}
          {detail.rich_header_json ? (
            <CollapsibleSection
              title="RICH header (toolchain fingerprint)"
              defaultOpen
            >
              <RichHeaderRender data={detail.rich_header_json} />
            </CollapsibleSection>
          ) : (
            <div className="rounded-lg border border-dashed border-border p-3 text-xs text-muted-foreground">
              No RICH header — non-Microsoft toolchain, stripped binary, or
              pre-VS2002.
            </div>
          )}

          {/* ARM64EC / ARM64X arch view */}
          {detail.arch_view ? (
            <CollapsibleSection
              title="Bimorphic arch view (ARM64EC / ARM64X)"
              defaultOpen
            >
              <ArchViewRender data={detail.arch_view} />
            </CollapsibleSection>
          ) : (
            <div className="rounded-lg border border-dashed border-border p-3 text-xs text-muted-foreground">
              Single-arch PE — no ARM64EC / ARM64X bimorphic split.
            </div>
          )}

          {/* Footer metadata */}
          <div className="rounded-lg border border-border bg-card">
            <FieldRow
              label="Signature row id"
              value={detail.id}
              mono
              copyable
            />
            <FieldRow label="Blob id" value={detail.blob_id} mono copyable />
            <FieldRow
              label="Persisted at"
              value={formatDate(detail.created_at)}
            />
            <FieldRow
              label="Last updated"
              value={formatDate(detail.updated_at)}
            />
          </div>
        </div>
      ) : null}
    </div>
  )
}
