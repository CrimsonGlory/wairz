import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  Cpu,
  HelpCircle,
  Loader2,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  ShieldQuestion,
  Unlock,
  XCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  type AuthenticodeChainAggregate,
  type AuthenticodeChainStatusResponse,
  type WindowsPEChainStatus,
  type WindowsPESignatureSummary,
  getAuthenticodeChainStatus,
  listPeSignatures,
  runAuthenticodeChain,
} from '@/api/hardwareFirmware'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import { useProjectStore } from '@/stores/projectStore'
import { extractErrorMessage } from '@/utils/error'
import FirmwareSelector from '@/components/projects/FirmwareSelector'

// chain_status histogram bucket ordering — mirrors
// WindowsPESignature.chain_status CHECK constraint values. Render order
// matches operator-priority (revoked first, unknown last). Per Rule #9
// every backend chain_status MUST have a Record<> entry — adding a new
// status in Phase γ/δ requires updating both this map AND the backend
// CHECK constraint in the same change set.
type ChainStatusMeta = {
  label: string
  description: string
  badgeClass: string
  icon: React.ReactNode
  priority: number
}

const CHAIN_STATUS_META: Record<WindowsPEChainStatus, ChainStatusMeta> = {
  revoked: {
    label: 'Revoked',
    description: 'Cert in DBX OR CRL OR OCSP says no — assume hostile.',
    badgeClass:
      'bg-red-50 text-red-700 ring-1 ring-red-200 dark:bg-red-950/40 dark:text-red-300 dark:ring-red-800',
    icon: <XCircle className="h-3.5 w-3.5" />,
    priority: 0,
  },
  never_valid: {
    label: 'Never valid',
    description:
      'Signature never validated (test/dev cert, broken chain, or signify bailed).',
    badgeClass:
      'bg-orange-50 text-orange-700 ring-1 ring-orange-200 dark:bg-orange-950/40 dark:text-orange-300 dark:ring-orange-800',
    icon: <ShieldAlert className="h-3.5 w-3.5" />,
    priority: 1,
  },
  valid_at_signing: {
    label: 'Valid at signing',
    description:
      'Cert was good at the RFC 3161 counter-signature timestamp (TSA) but might not be today.',
    badgeClass:
      'bg-amber-50 text-amber-700 ring-1 ring-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:ring-amber-800',
    icon: <ShieldQuestion className="h-3.5 w-3.5" />,
    priority: 2,
  },
  valid_now: {
    label: 'Valid now',
    description: 'Cert + chain + revocation all OK as of this scan.',
    badgeClass:
      'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:ring-emerald-800',
    icon: <ShieldCheck className="h-3.5 w-3.5" />,
    priority: 3,
  },
  unknown: {
    label: 'Unknown',
    description:
      'Validation skipped (offline data missing, malformed PE, or signify raised).',
    badgeClass:
      'bg-slate-100 text-slate-700 ring-1 ring-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-700',
    icon: <HelpCircle className="h-3.5 w-3.5" />,
    priority: 4,
  },
}

function ChainStatusBadge({ status }: { status: WindowsPEChainStatus }) {
  // Rule #9 ?? fallback — defensive against a backend status the
  // frontend hasn't been redeployed for yet.
  const meta = CHAIN_STATUS_META[status] ?? CHAIN_STATUS_META.unknown
  return (
    <span
      title={meta.description}
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${meta.badgeClass}`}
    >
      {meta.icon}
      {meta.label}
    </span>
  )
}

function formatDate(value: string | null): string {
  if (!value) return '—'
  try {
    return new Date(value).toLocaleString()
  } catch {
    return value
  }
}

function StatCard({
  icon,
  label,
  value,
  emphasis = 'default',
  hint,
}: {
  icon: React.ReactNode
  label: string
  value: number | string
  emphasis?: 'default' | 'danger' | 'warning' | 'good'
  hint?: string
}) {
  const tone =
    emphasis === 'danger'
      ? 'border-red-200 bg-red-50/60 dark:border-red-900/40 dark:bg-red-950/20'
      : emphasis === 'warning'
        ? 'border-amber-200 bg-amber-50/60 dark:border-amber-900/40 dark:bg-amber-950/20'
        : emphasis === 'good'
          ? 'border-emerald-200 bg-emerald-50/60 dark:border-emerald-900/40 dark:bg-emerald-950/20'
          : 'border-border bg-card'
  return (
    <div className={`rounded-lg border p-4 ${tone}`}>
      <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold tabular-nums">{value}</div>
      {hint ? (
        <div className="mt-1 text-xs text-muted-foreground">{hint}</div>
      ) : null}
    </div>
  )
}

const POLL_INTERVAL_MS = 2000
// 30-minute ceiling — Win11 23H2 ISO has 1000+ PEs at ~50-200 ms each
// signify cycle, so the full walk runs ~1-3 minutes typically. The 30-min
// ceiling is well past the worst case and bounded so a runaway runner
// can't pin the spinner forever.
const POLL_DEADLINE_MS = 30 * 60 * 1000

export default function PeHardeningPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const { firmwareList } = useFirmwareList(projectId)

  const [status, setStatus] = useState<AuthenticodeChainStatusResponse | null>(
    null,
  )
  const [signatures, setSignatures] = useState<WindowsPESignatureSummary[]>([])
  const [signatureTotal, setSignatureTotal] = useState(0)
  const [chainFilter, setChainFilter] =
    useState<WindowsPEChainStatus | null>(null)
  const [dbxOnly, setDbxOnly] = useState(false)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadAll = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    setError(null)
    try {
      const [statusResp, sigResp] = await Promise.all([
        getAuthenticodeChainStatus(projectId, selectedFirmwareId).catch(
          () => null,
        ),
        listPeSignatures(projectId, {
          firmwareId: selectedFirmwareId,
          chainStatus: chainFilter,
          dbxRevokedOnly: dbxOnly,
          limit: 200,
        }).catch(() => ({
          signatures: [] as WindowsPESignatureSummary[],
          total: 0,
          offset: 0,
          limit: 200,
        })),
      ])
      setStatus(statusResp)
      setSignatures(sigResp.signatures)
      setSignatureTotal(sigResp.total)
    } catch (e) {
      setError(extractErrorMessage(e, 'Failed to load PE-hardening data'))
    } finally {
      setLoading(false)
    }
  }, [projectId, selectedFirmwareId, chainFilter, dbxOnly])

  useEffect(() => {
    loadAll()
  }, [loadAll])

  // Poll while a run is queued/running so the operator sees the verdict
  // without having to refresh manually. Mirrors the cve-match polling
  // shape on HardwareFirmwarePage and the firmware-unpack polling shape
  // on ProjectDetailPage.
  useEffect(() => {
    if (!projectId) return
    if (status?.status !== 'queued' && status?.status !== 'running') return
    let cancelled = false
    const tick = async () => {
      try {
        const fresh = await getAuthenticodeChainStatus(
          projectId,
          selectedFirmwareId,
        )
        if (cancelled) return
        setStatus(fresh)
        if (fresh.status === 'completed' || fresh.status === 'failed') {
          // One more list reload so the table catches up with the row
          // set the runner just persisted.
          loadAll()
        }
      } catch {
        /* keep polling on transient errors */
      }
    }
    const id = window.setInterval(tick, POLL_INTERVAL_MS)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [projectId, selectedFirmwareId, status?.status, loadAll])

  const handleRun = useCallback(async () => {
    if (!projectId) return
    setRunning(true)
    setError(null)
    try {
      const ack = await runAuthenticodeChain(projectId, selectedFirmwareId)
      setStatus(ack)
      // The polling effect above takes over from here. Belt-and-braces
      // deadline so the spinner can't pin forever if the backend never
      // flips terminal.
      const deadline = Date.now() + POLL_DEADLINE_MS
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS))
        const fresh = await getAuthenticodeChainStatus(
          projectId,
          selectedFirmwareId,
        )
        if (fresh.status === 'completed' || fresh.status === 'failed') {
          setStatus(fresh)
          await loadAll()
          break
        }
      }
    } catch (e) {
      setError(extractErrorMessage(e, 'Failed to run authenticode-chain'))
    } finally {
      setRunning(false)
    }
  }, [projectId, selectedFirmwareId, loadAll])

  // Prefer the freshly-loaded list count over the persisted aggregate's
  // total_pe_count: the aggregate reflects the LAST run; the list count
  // reflects what's actually in the DB right now (e.g. zero before any
  // run, or a partial set if the run is still in flight).
  const aggregate: AuthenticodeChainAggregate | null = status?.result ?? null
  const filteredCount = signatures.length
  const unfilteredTotal = aggregate?.total_pe_count ?? signatureTotal

  const histogramRows = useMemo(() => {
    // Even when no run has produced an aggregate yet, render the
    // complete bucket set in operator-priority order so the user
    // understands what the page WILL show post-run.
    const buckets: WindowsPEChainStatus[] = [
      'revoked',
      'never_valid',
      'valid_at_signing',
      'valid_now',
      'unknown',
    ]
    return buckets.map((b) => ({
      status: b,
      count: aggregate?.by_chain_status[b] ?? 0,
    }))
  }, [aggregate])

  if (!projectId) {
    return null
  }

  return (
    <div className="mx-auto max-w-7xl py-6">
      <div className="mb-4 flex items-center gap-2 text-sm text-muted-foreground">
        <Link
          to={`/projects/${projectId}/windows`}
          className="inline-flex items-center gap-1 hover:text-foreground"
        >
          <ChevronLeft className="h-4 w-4" />
          Windows hub
        </Link>
      </div>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <Lock className="mt-1 h-7 w-7 text-primary" />
          <div>
            <h1 className="text-2xl font-bold">PE Hardening Dashboard</h1>
            <p className="text-sm text-muted-foreground">
              Per-PE Authenticode chain validation, RICH header fingerprint,
              ARM64EC/X bimorphic detection, and offline DBX revocation
              cross-reference. Backed by the Phase β.8 background runner +
              bundled Microsoft DBX (Phase β.10).
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <FirmwareSelector
            projectId={projectId}
            firmwareList={firmwareList}
            className="min-w-0 max-w-xs"
          />
          <Button
            onClick={handleRun}
            disabled={running || status?.status === 'queued' || status?.status === 'running'}
            size="sm"
          >
            {running || status?.status === 'queued' || status?.status === 'running' ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                {status?.status === 'running' ? 'Running…' : 'Queued…'}
              </>
            ) : (
              <>
                <RefreshCw className="mr-2 h-4 w-4" />
                {status?.status === 'completed' ? 'Re-run' : 'Run'} authenticode chain
              </>
            )}
          </Button>
        </div>
      </div>

      {error ? (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-900/40 dark:bg-red-950/20 dark:text-red-300">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <div>{error}</div>
        </div>
      ) : null}

      {status?.status === 'failed' && status.error ? (
        <div className="mb-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm dark:border-red-900/40 dark:bg-red-950/20">
          <div className="mb-1 font-semibold text-red-700 dark:text-red-300">
            Last run failed
          </div>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs text-red-700/80 dark:text-red-300/80">
            {status.error}
          </pre>
        </div>
      ) : null}

      {/* Run-status header strip */}
      <div className="mb-4 grid gap-2 rounded-lg border border-border bg-card p-3 text-xs sm:grid-cols-4">
        <div>
          <div className="text-muted-foreground">Last status</div>
          <div className="font-mono">{status?.status ?? 'idle'}</div>
        </div>
        <div>
          <div className="text-muted-foreground">Started</div>
          <div className="font-mono">{formatDate(status?.started_at ?? null)}</div>
        </div>
        <div>
          <div className="text-muted-foreground">Finished</div>
          <div className="font-mono">{formatDate(status?.finished_at ?? null)}</div>
        </div>
        <div>
          <div className="text-muted-foreground">Run wall-clock</div>
          <div className="font-mono">
            {aggregate?.run_seconds !== undefined
              ? `${aggregate.run_seconds.toFixed(2)}s`
              : '—'}
          </div>
        </div>
      </div>

      {/* Aggregate cards */}
      <div className="mb-6 grid gap-3 md:grid-cols-2 lg:grid-cols-5">
        <StatCard
          icon={<Cpu className="h-3.5 w-3.5" />}
          label="Total PEs"
          value={unfilteredTotal}
          hint="MZ-magic prefilter (sys / dll / exe / efi)"
        />
        <StatCard
          icon={<XCircle className="h-3.5 w-3.5" />}
          label="DBX revoked"
          value={aggregate?.dbx_revoked_count ?? 0}
          emphasis={aggregate && aggregate.dbx_revoked_count > 0 ? 'danger' : 'default'}
          hint="Leaf-serial in offline DBX bundle"
        />
        <StatCard
          icon={<Unlock className="h-3.5 w-3.5" />}
          label="Unsigned"
          value={aggregate?.unsigned_count ?? 0}
          emphasis={aggregate && aggregate.unsigned_count > 0 ? 'warning' : 'default'}
          hint="No Authenticode signature"
        />
        <StatCard
          icon={<ShieldOff className="h-3.5 w-3.5" />}
          label="Never valid"
          value={aggregate?.by_chain_status.never_valid ?? 0}
          emphasis={
            aggregate && (aggregate.by_chain_status.never_valid ?? 0) > 0
              ? 'warning'
              : 'default'
          }
          hint="Signed but chain never validated"
        />
        <StatCard
          icon={<CheckCircle2 className="h-3.5 w-3.5" />}
          label="Signed (good)"
          value={aggregate?.signed_count ?? 0}
          emphasis="good"
          hint={
            aggregate
              ? `${(aggregate.signed_pct * 100).toFixed(1)}% of total`
              : '— of total'
          }
        />
      </div>

      {/* chain_status histogram chips (also act as filters) */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-muted-foreground">
          Filter by chain status:
        </span>
        <button
          type="button"
          onClick={() => setChainFilter(null)}
          className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs ring-1 transition ${
            chainFilter === null
              ? 'bg-primary text-primary-foreground ring-primary'
              : 'bg-card text-foreground ring-border hover:bg-muted'
          }`}
        >
          All
          <span className="font-mono">{unfilteredTotal}</span>
        </button>
        {histogramRows.map(({ status: s, count }) => {
          const meta = CHAIN_STATUS_META[s] ?? CHAIN_STATUS_META.unknown
          const active = chainFilter === s
          return (
            <button
              key={s}
              type="button"
              onClick={() => setChainFilter(active ? null : s)}
              className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs transition ${
                active
                  ? 'bg-primary text-primary-foreground ring-1 ring-primary'
                  : meta.badgeClass + ' hover:opacity-80'
              }`}
              title={meta.description}
            >
              {meta.icon}
              {meta.label}
              <span className="font-mono">{count}</span>
            </button>
          )
        })}
        <label className="ml-2 inline-flex cursor-pointer items-center gap-1 text-xs">
          <input
            type="checkbox"
            checked={dbxOnly}
            onChange={(e) => setDbxOnly(e.target.checked)}
            className="h-3 w-3"
          />
          <span>DBX-revoked only</span>
        </label>
      </div>

      {/* Per-PE table */}
      <div className="overflow-hidden rounded-lg border border-border">
        <div className="flex items-center justify-between border-b border-border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
          <div>
            Showing <span className="font-semibold tabular-nums">{filteredCount}</span>{' '}
            of <span className="font-semibold tabular-nums">{signatureTotal}</span> signature row(s)
            {chainFilter ? ` filtered by ${CHAIN_STATUS_META[chainFilter].label}` : ''}
            {dbxOnly ? ' · DBX-revoked only' : ''}
          </div>
          {loading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
          ) : null}
        </div>
        {signatures.length === 0 ? (
          <div className="px-4 py-12 text-center text-sm text-muted-foreground">
            {status?.status === 'idle' || status?.status === undefined ? (
              <>
                No PE signature rows persisted yet. Click{' '}
                <span className="font-mono">Run authenticode chain</span> to walk
                every PE in this firmware.
              </>
            ) : status.status === 'queued' || status.status === 'running' ? (
              <>
                Run in flight — rows appear as the background runner persists
                them.
              </>
            ) : (
              <>No rows match the current filter.</>
            )}
          </div>
        ) : (
          <div className="max-h-[60vh] overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 bg-card">
                <tr className="border-b border-border text-xs text-muted-foreground">
                  <th className="px-3 py-2 text-left font-medium">Path</th>
                  <th className="px-3 py-2 text-left font-medium">Status</th>
                  <th className="px-3 py-2 text-left font-medium">Signer</th>
                  <th className="px-3 py-2 text-left font-medium">Hash</th>
                  <th className="px-3 py-2 text-left font-medium">Leaf serial</th>
                  <th className="px-3 py-2 text-center font-medium">DBX</th>
                  <th className="px-3 py-2 text-center font-medium">Arch</th>
                  <th className="px-3 py-2 text-center font-medium">RICH</th>
                </tr>
              </thead>
              <tbody>
                {signatures.map((sig) => {
                  const basename = sig.blob_path.split('/').pop() ?? sig.blob_path
                  return (
                    <tr
                      key={sig.id}
                      className="border-b border-border/60 hover:bg-muted/40"
                    >
                      <td className="px-3 py-1.5">
                        <Link
                          to={`/projects/${projectId}/windows/pe-hardening/${sig.id}`}
                          className="block max-w-[28rem] truncate text-primary hover:underline"
                          title={sig.blob_path}
                        >
                          {basename}
                        </Link>
                      </td>
                      <td className="px-3 py-1.5">
                        <ChainStatusBadge status={sig.chain_status} />
                      </td>
                      <td
                        className="max-w-[12rem] truncate px-3 py-1.5 text-xs text-muted-foreground"
                        title={sig.signer_subject ?? undefined}
                      >
                        {sig.signer_subject ?? (
                          <span className="italic">—</span>
                        )}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-xs">
                        {sig.sig_hash_algo ?? '—'}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-xs">
                        {sig.leaf_serial ? (
                          <span title={sig.leaf_serial} className="truncate">
                            {sig.leaf_serial.length > 16
                              ? `${sig.leaf_serial.slice(0, 16)}…`
                              : sig.leaf_serial}
                          </span>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td className="px-3 py-1.5 text-center">
                        {sig.dbx_revoked ? (
                          <span
                            className="inline-flex items-center gap-1 rounded bg-red-100 px-1.5 py-0.5 text-xs font-medium text-red-700 dark:bg-red-950/40 dark:text-red-300"
                            title={sig.dbx_revocation_kb ?? undefined}
                          >
                            <XCircle className="h-3 w-3" />
                            yes
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="px-3 py-1.5 text-center text-xs text-muted-foreground">
                        {sig.arch_view_present ? 'bimorphic' : '—'}
                      </td>
                      <td className="px-3 py-1.5 text-center text-xs text-muted-foreground">
                        {sig.rich_header_present ? 'yes' : '—'}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="mt-6 rounded-lg border border-dashed border-border p-4 text-xs text-muted-foreground">
        <p>
          <strong>Offline trust anchor (Rule #37):</strong> the DBX bundle at{' '}
          <span className="font-mono">/opt/wairz/dbxupdate.bin</span> is baked
          into the worker image at build time and refreshed quarterly via{' '}
          <span className="font-mono">scripts/refresh-ms-roots.sh</span>. No
          cert-chain or revocation fetch happens during scans. Microsoft
          Authenticode roots ship inside the signify package; both are
          air-gap-friendly.
        </p>
      </div>
    </div>
  )
}
