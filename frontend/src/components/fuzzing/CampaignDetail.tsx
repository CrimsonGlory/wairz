import { useState } from 'react'
import {
  Loader2,
  RefreshCw,
  AlertTriangle,
  ShieldAlert,
  Clock,
  Zap,
  Target,
  BarChart3,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { getCrashDetail } from '@/api/fuzzing'
import { createFinding } from '@/api/findings'
import type {
  FuzzingCampaign,
  FuzzingCrash,
  FuzzingStatus,
  CrashExploitability,
  Severity,
} from '@/types'

const STATUS_CONFIG: Record<FuzzingStatus, { label: string; className: string }> = {
  created: { label: 'Created', className: 'bg-gray-500 text-white' },
  queued: { label: 'Queued', className: 'bg-amber-500 text-white' },
  running: { label: 'Running', className: 'bg-green-500 text-white' },
  stopped: { label: 'Stopped', className: 'bg-zinc-600 text-white' },
  completed: { label: 'Completed', className: 'bg-blue-500 text-white' },
  error: { label: 'Error', className: 'bg-red-500 text-white' },
}

const EXPLOIT_CONFIG: Record<CrashExploitability, { label: string; className: string }> = {
  exploitable: { label: 'Exploitable', className: 'bg-red-600 text-white' },
  probably_exploitable: { label: 'Probably Exploitable', className: 'bg-orange-500 text-white' },
  probably_not: { label: 'Probably Not', className: 'bg-yellow-500 text-black' },
  unknown: { label: 'Unknown', className: 'bg-gray-500 text-white' },
}

function StatCard({
  icon: Icon,
  label,
  value,
  alert,
}: {
  icon?: React.ElementType
  label: string
  value: string
  alert?: boolean
}) {
  return (
    <div className={`rounded-lg border p-3 ${alert ? 'border-red-500/30 bg-red-500/5' : 'border-border'}`}>
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
        {Icon && <Icon className="h-3 w-3" />}
        {label}
      </div>
      <p className={`mt-1 text-lg font-bold ${alert ? 'text-red-500' : ''}`}>{value}</p>
    </div>
  )
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return `${h}h ${m}m`
}

function formatHexDump(hex: string): string {
  const bytes: number[] = []
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16))
  }
  const lines: string[] = []
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.slice(offset, offset + 16)
    const addr = offset.toString(16).padStart(8, '0')
    const hexPart = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ')
    const ascii = chunk
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'))
      .join('')
    lines.push(`${addr}  ${hexPart.padEnd(48)}  |${ascii}|`)
  }
  return lines.join('\n')
}

function exploitabilityToSeverity(e: CrashExploitability | null): Severity {
  switch (e) {
    case 'exploitable': return 'critical'
    case 'probably_exploitable': return 'high'
    case 'probably_not': return 'medium'
    default: return 'medium'
  }
}

export interface CampaignDetailProps {
  projectId: string
  campaign: FuzzingCampaign
  crashes: FuzzingCrash[]
  crashesLoading: boolean
  onTriage: (crashId: string) => void
  onRefresh: () => void
  onCrashUpdate: (crash: FuzzingCrash) => void
}

export function CampaignDetail({
  projectId,
  campaign,
  crashes,
  crashesLoading,
  onTriage,
  onRefresh,
  onCrashUpdate,
}: CampaignDetailProps) {
  const stats = campaign.stats
  const [expandedCrash, setExpandedCrash] = useState<string | null>(null)
  const [hexDumps, setHexDumps] = useState<Record<string, string | null>>({})
  const [hexLoading, setHexLoading] = useState<Record<string, boolean>>({})
  const [findingCreating, setFindingCreating] = useState<Record<string, boolean>>({})

  const loadHexDump = async (crashId: string) => {
    if (hexDumps[crashId] !== undefined) return
    setHexLoading((prev) => ({ ...prev, [crashId]: true }))
    try {
      const detail = await getCrashDetail(projectId, campaign.id, crashId)
      setHexDumps((prev) => ({ ...prev, [crashId]: detail.crash_input_hex }))
    } catch {
      setHexDumps((prev) => ({ ...prev, [crashId]: null }))
    } finally {
      setHexLoading((prev) => ({ ...prev, [crashId]: false }))
    }
  }

  const handleCreateFinding = async (crash: FuzzingCrash) => {
    setFindingCreating((prev) => ({ ...prev, [crash.id]: true }))
    try {
      const finding = await createFinding(projectId, {
        title: `Fuzzing crash: ${crash.signal || 'unknown signal'} in ${campaign.binary_path}`,
        severity: exploitabilityToSeverity(crash.exploitability),
        description: [
          `AFL++ fuzzing discovered a crash in \`${campaign.binary_path}\`.`,
          '',
          `- **Crash file:** ${crash.crash_filename}`,
          `- **Signal:** ${crash.signal || 'unknown'}`,
          `- **Exploitability:** ${crash.exploitability || 'not triaged'}`,
          crash.crash_size != null ? `- **Input size:** ${crash.crash_size} bytes` : '',
        ].filter(Boolean).join('\n'),
        evidence: crash.triage_output || crash.stack_trace || undefined,
        file_path: campaign.binary_path,
        source: 'fuzzing',
      })
      onCrashUpdate({ ...crash, finding_id: finding.id })
    } catch {
      // ignore
    } finally {
      setFindingCreating((prev) => ({ ...prev, [crash.id]: false }))
    }
  }

  return (
    <div className="space-y-6">
      {/* Campaign header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold">Campaign Details</h2>
            <Badge className={`text-[10px] ${STATUS_CONFIG[campaign.status]?.className}`}>
              {campaign.status}
            </Badge>
          </div>
          <p className="mt-0.5 text-sm font-mono text-muted-foreground">{campaign.binary_path}</p>
        </div>
        <Button variant="outline" size="sm" onClick={onRefresh}>
          <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>

      {/* Stats grid */}
      {stats && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatCard
            icon={Zap}
            label="Execs/sec"
            value={typeof stats.execs_per_sec === 'number' ? stats.execs_per_sec.toFixed(1) : '—'}
          />
          <StatCard
            icon={BarChart3}
            label="Total Execs"
            value={typeof stats.total_execs === 'number' ? stats.total_execs.toLocaleString() : '—'}
          />
          <StatCard
            icon={Target}
            label="Corpus"
            value={String(stats.corpus_count ?? 0)}
          />
          <StatCard
            icon={ShieldAlert}
            label="Crashes"
            value={String(stats.saved_crashes ?? 0)}
            alert={(stats.saved_crashes ?? 0) > 0}
          />
          <StatCard
            icon={AlertTriangle}
            label="Hangs"
            value={String(stats.saved_hangs ?? 0)}
          />
          <StatCard
            label="Stability"
            value={String(stats.stability ?? '—')}
          />
          <StatCard
            label="Coverage"
            value={String(stats.bitmap_cvg ?? '—')}
          />
          <StatCard
            icon={Clock}
            label="Run Time"
            value={formatDuration(Number(stats.run_time ?? 0))}
          />
        </div>
      )}

      {!stats && campaign.status === 'running' && (
        <div className="flex items-center gap-2 py-4 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Waiting for AFL++ stats...
        </div>
      )}

      {/* Crashes */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
          Crashes ({crashes.length})
        </h3>

        {crashesLoading && (
          <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" />
            Loading crashes...
          </div>
        )}

        {!crashesLoading && crashes.length === 0 && (
          <p className="py-4 text-center text-xs text-muted-foreground/60">
            {campaign.status === 'running'
              ? 'No crashes found yet — fuzzer is running...'
              : 'No crashes found for this campaign'}
          </p>
        )}

        {crashes.map((crash) => {
          const isExpanded = expandedCrash === crash.id
          const exploitCfg = crash.exploitability
            ? EXPLOIT_CONFIG[crash.exploitability]
            : null

          return (
            <div key={crash.id} className="rounded-lg border border-border">
              <button
                onClick={() => {
                  const next = isExpanded ? null : crash.id
                  setExpandedCrash(next)
                  if (next) loadHexDump(crash.id)
                }}
                className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-accent/50 transition-colors"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-medium">{crash.crash_filename}</span>
                    {crash.signal && (
                      <Badge variant="outline" className="text-[10px]">{crash.signal}</Badge>
                    )}
                    {exploitCfg && (
                      <Badge className={`text-[10px] ${exploitCfg.className}`}>
                        {exploitCfg.label}
                      </Badge>
                    )}
                    {crash.crash_size != null && (
                      <span className="text-[10px] text-muted-foreground">
                        {crash.crash_size} bytes
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {!crash.triage_output && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6 text-[10px] px-2"
                      onClick={(e) => {
                        e.stopPropagation()
                        onTriage(crash.id)
                      }}
                    >
                      Triage
                    </Button>
                  )}
                  {isExpanded ? (
                    <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" />
                  ) : (
                    <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                  )}
                </div>
              </button>

              {isExpanded && (
                <div className="border-t border-border bg-muted/30 px-4 py-3 space-y-3">
                  {crash.stack_trace && (
                    <div>
                      <p className="mb-1 text-xs font-medium text-muted-foreground">Stack Trace</p>
                      <pre className="max-h-40 overflow-auto rounded-md bg-[#0a0a0b] p-2 text-[11px] text-zinc-300 font-mono">
                        {crash.stack_trace}
                      </pre>
                    </div>
                  )}
                  {crash.triage_output && !crash.stack_trace && (
                    <div>
                      <p className="mb-1 text-xs font-medium text-muted-foreground">Triage Output</p>
                      <pre className="max-h-60 overflow-auto rounded-md bg-[#0a0a0b] p-2 text-[11px] text-zinc-300 font-mono">
                        {crash.triage_output}
                      </pre>
                    </div>
                  )}

                  {/* Hex dump of crash input */}
                  <div>
                    <p className="mb-1 text-xs font-medium text-muted-foreground">Crash Input</p>
                    {hexLoading[crash.id] ? (
                      <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
                        <Loader2 className="h-3 w-3 animate-spin" />
                        Loading crash input...
                      </div>
                    ) : hexDumps[crash.id] ? (
                      <pre className="max-h-48 overflow-auto rounded-md bg-[#0a0a0b] p-2 text-[11px] text-zinc-300 font-mono">
                        {formatHexDump(hexDumps[crash.id]!)}
                      </pre>
                    ) : hexDumps[crash.id] === null ? (
                      <p className="text-xs text-muted-foreground/60">Crash input not available</p>
                    ) : null}
                  </div>

                  {/* Create finding button */}
                  {crash.triage_output && !crash.finding_id && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs"
                      disabled={findingCreating[crash.id]}
                      onClick={() => handleCreateFinding(crash)}
                    >
                      {findingCreating[crash.id] ? (
                        <Loader2 className="mr-1.5 h-3 w-3 animate-spin" />
                      ) : (
                        <ShieldAlert className="mr-1.5 h-3 w-3" />
                      )}
                      Create Finding
                    </Button>
                  )}
                  {crash.finding_id && (
                    <div className="flex items-center gap-1.5 text-xs text-green-500">
                      <ShieldAlert className="h-3 w-3" />
                      Finding created
                    </div>
                  )}

                  {!crash.triage_output && !crash.finding_id && (
                    <p className="text-xs text-muted-foreground">
                      Click "Triage" to reproduce this crash and analyze exploitability.
                    </p>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
