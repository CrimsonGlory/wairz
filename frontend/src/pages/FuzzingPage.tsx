import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  Bug,
  Loader2,
  RefreshCw,
  AlertCircle,
  Search,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  analyzeTarget,
  createCampaign,
  startCampaign,
  stopCampaign,
  listCampaigns,
  getCampaign,
  listCrashes,
  triageCrash,
} from '@/api/fuzzing'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import { useProjectStore } from '@/stores/projectStore'
import FirmwareSelector from '@/components/projects/FirmwareSelector'
import { CampaignCard } from '@/components/fuzzing/CampaignCard'
import { CampaignDetail } from '@/components/fuzzing/CampaignDetail'
import { extractErrorMessage } from '@/utils/error'
import { useEventStream } from '@/hooks/useEventStream'
import type {
  FuzzingCampaign,
  FuzzingCrash,
  FuzzingTargetAnalysis,
} from '@/types'

export default function FuzzingPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const { firmwareList } = useFirmwareList(projectId)

  const [campaigns, setCampaigns] = useState<FuzzingCampaign[]>([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // New campaign form
  const [binaryPath, setBinaryPath] = useState('')
  const [timeoutPerExec, setTimeoutPerExec] = useState(1000)
  const [memoryLimit, setMemoryLimit] = useState(256)
  const [analysis, setAnalysis] = useState<FuzzingTargetAnalysis | null>(null)
  const [analyzing, setAnalyzing] = useState(false)

  // Selected campaign
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [crashes, setCrashes] = useState<FuzzingCrash[]>([])
  const [crashesLoading, setCrashesLoading] = useState(false)

  const selectedCampaign = campaigns.find((c) => c.id === selectedId)

  const campaignsRef = useRef(campaigns)
  campaignsRef.current = campaigns
  const selectedIdRef = useRef(selectedId)
  selectedIdRef.current = selectedId

  const loadCampaigns = useCallback(async () => {
    if (!projectId) return
    try {
      const data = await listCampaigns(projectId)
      setCampaigns(data)

      // Auto-select running or queued campaign. Queued campaigns are
      // waiting on the background container spawn; auto-selecting lets
      // the user see status transitions in real time.
      const running = data.find(
        (c) => c.status === 'running' || c.status === 'queued',
      )
      if (running && !selectedIdRef.current) {
        setSelectedId(running.id)
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    loadCampaigns()
  }, [loadCampaigns])

  // SSE: listen for fuzzing events and refresh on status changes.
  // "queued" rows also count — they are waiting on the background
  // container spawn, and we want the poll loop active until the status
  // transitions to "running" or "error". Matches the 202+polling
  // pattern on POST /campaigns/{id}/start (CLAUDE.md Rule #29).
  const hasRunningCampaign = campaigns.some(
    (c) => c.status === 'running' || c.status === 'queued',
  )
  const { lastEvent: fuzzEvent } = useEventStream<{ type: string; status: string }>(
    projectId,
    { types: ['fuzzing'], enabled: hasRunningCampaign },
  )

  useEffect(() => {
    if (!fuzzEvent || !projectId) return
    loadCampaigns()
    const currentSelectedId = selectedIdRef.current
    if (currentSelectedId) {
      listCrashes(projectId, currentSelectedId).then(setCrashes).catch(() => {})
    }
  }, [fuzzEvent, projectId, loadCampaigns])

  // Fallback poll while campaigns are running or queued (in case SSE
  // unavailable). Use a tighter 2 s cadence while any campaign is in
  // the "queued" state — we're waiting on the backend 202+polling
  // container spawn (typically <30 s, CLAUDE.md Rule #29), and the
  // user is staring at a "Starting..." indicator. Once no row is
  // queued, drop to 10 s for long-running stats refresh.
  const hasQueuedCampaign = campaigns.some((c) => c.status === 'queued')
  useEffect(() => {
    if (!projectId || !hasRunningCampaign) return

    const intervalMs = hasQueuedCampaign ? 2000 : 10000
    const interval = setInterval(async () => {
      await loadCampaigns()
      const currentSelectedId = selectedIdRef.current
      if (currentSelectedId) {
        const running = campaignsRef.current.find((c) => c.id === currentSelectedId && c.status === 'running')
        if (running) {
          try {
            const crashData = await listCrashes(projectId, currentSelectedId)
            setCrashes(crashData)
          } catch { /* ignore */ }
        }
      }
    }, intervalMs)
    return () => clearInterval(interval)
  }, [projectId, hasRunningCampaign, hasQueuedCampaign, loadCampaigns])

  // Load crashes when selected campaign changes
  useEffect(() => {
    if (!projectId || !selectedId) {
      setCrashes([])
      return
    }
    setCrashesLoading(true)
    listCrashes(projectId, selectedId)
      .then(setCrashes)
      .catch(() => setCrashes([]))
      .finally(() => setCrashesLoading(false))
  }, [projectId, selectedId])

  const handleAnalyze = async () => {
    if (!projectId || !binaryPath.trim()) return
    setAnalyzing(true)
    setAnalysis(null)
    try {
      const result = await analyzeTarget(projectId, binaryPath.trim(), selectedFirmwareId)
      setAnalysis(result)
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Analysis failed'))
    } finally {
      setAnalyzing(false)
    }
  }

  const handleCreate = async () => {
    if (!projectId || !binaryPath.trim()) return
    setCreating(true)
    setError(null)
    try {
      const campaign = await createCampaign(projectId, {
        binary_path: binaryPath.trim(),
        timeout_per_exec: timeoutPerExec,
        memory_limit: memoryLimit,
      }, selectedFirmwareId)
      // Auto-start
      const started = await startCampaign(projectId, campaign.id)
      setSelectedId(started.id)
      await loadCampaigns()
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Failed to create campaign'))
    } finally {
      setCreating(false)
    }
  }

  const handleStop = async (campaignId: string) => {
    if (!projectId) return
    try {
      await stopCampaign(projectId, campaignId)
      await loadCampaigns()
    } catch { /* ignore */ }
  }

  const handleTriage = async (crashId: string) => {
    if (!projectId || !selectedId) return
    try {
      const result = await triageCrash(projectId, selectedId, crashId)
      setCrashes((prev) => prev.map((c) => (c.id === result.id ? result : c)))
    } catch { /* ignore */ }
  }

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="border-b border-border bg-background px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold">Automated Fuzzing</h1>
            <p className="text-sm text-muted-foreground">
              AFL++ QEMU-mode fuzzing for cross-architecture firmware binaries
            </p>
          </div>
          <div className="flex min-w-0 items-center gap-3">
            <FirmwareSelector projectId={projectId!} firmwareList={firmwareList} className="min-w-0 max-w-xs" />
            <Button variant="outline" size="sm" onClick={loadCampaigns}>
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
              Refresh
            </Button>
          </div>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left panel — controls + campaign list */}
        <div className="w-96 shrink-0 overflow-y-auto border-r border-border p-4 space-y-6">
          {/* New Campaign */}
          <div className="space-y-4">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              New Campaign
            </h2>

            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Binary Path *
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={binaryPath}
                  onChange={(e) => setBinaryPath(e.target.value)}
                  placeholder="/usr/sbin/httpd"
                  className="flex-1 rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleAnalyze}
                  disabled={analyzing || !binaryPath.trim()}
                >
                  {analyzing ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Search className="h-3.5 w-3.5" />
                  )}
                </Button>
              </div>
            </div>

            {/* Analysis result */}
            {analysis && (
              <TargetAnalysisCard analysis={analysis} />
            )}

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Timeout (ms)
                </label>
                <input
                  type="number"
                  value={timeoutPerExec}
                  onChange={(e) => setTimeoutPerExec(parseInt(e.target.value) || 1000)}
                  min={100}
                  max={30000}
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Memory (MB)
                </label>
                <input
                  type="number"
                  value={memoryLimit}
                  onChange={(e) => setMemoryLimit(parseInt(e.target.value) || 256)}
                  min={64}
                  max={1024}
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                />
              </div>
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
                <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                {error}
              </div>
            )}

            <Button
              onClick={handleCreate}
              disabled={creating || !binaryPath.trim()}
              className="w-full"
            >
              {creating ? (
                <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
              ) : (
                <Bug className="mr-1.5 h-4 w-4" />
              )}
              {creating ? 'Starting...' : 'Create & Start Campaign'}
            </Button>
          </div>

          {/* Campaign list */}
          <div className="space-y-3">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Campaigns ({campaigns.length})
            </h2>

            {campaigns.length === 0 && (
              <p className="text-xs text-muted-foreground/60">No fuzzing campaigns yet</p>
            )}

            {campaigns.map((campaign) => (
              <CampaignCard
                key={campaign.id}
                campaign={campaign}
                isSelected={selectedId === campaign.id}
                onSelect={() => setSelectedId(campaign.id)}
                onStop={() => handleStop(campaign.id)}
              />
            ))}
          </div>
        </div>

        {/* Right panel — stats + crashes */}
        <div className="flex-1 overflow-y-auto p-6">
          {selectedCampaign ? (
            <CampaignDetail
              projectId={projectId!}
              campaign={selectedCampaign}
              crashes={crashes}
              crashesLoading={crashesLoading}
              onTriage={handleTriage}
              onCrashUpdate={(updated) =>
                setCrashes((prev) => prev.map((c) => (c.id === updated.id ? updated : c)))
              }
              onRefresh={async () => {
                if (!projectId || !selectedId) return
                try {
                  const updated = await getCampaign(projectId, selectedId)
                  setCampaigns((prev) => prev.map((c) => (c.id === updated.id ? updated : c)))
                  const crashData = await listCrashes(projectId, selectedId)
                  setCrashes(crashData)
                } catch { /* ignore */ }
              }}
            />
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
              <div className="text-center">
                <Bug className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
                <p>Select a campaign or start a new one</p>
                <p className="mt-1 text-xs text-muted-foreground/60">
                  Campaign stats and crash details will appear here
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Target Analysis Card ──

function TargetAnalysisCard({ analysis }: { analysis: FuzzingTargetAnalysis }) {
  const score = analysis.fuzzing_score
  const scoreColor =
    score >= 60 ? 'text-green-500' : score >= 30 ? 'text-yellow-500' : 'text-red-500'

  return (
    <div className="rounded-lg border border-border p-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground">Fuzzing Score</span>
        <span className={`text-lg font-bold ${scoreColor}`}>{score}/100</span>
      </div>

      <div className="h-1.5 rounded-full bg-muted">
        <div
          className={`h-full rounded-full ${
            score >= 60 ? 'bg-green-500' : score >= 30 ? 'bg-yellow-500' : 'bg-red-500'
          }`}
          style={{ width: `${score}%` }}
        />
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <span className="text-muted-foreground">Strategy: </span>
          <span className="font-medium">{analysis.recommended_strategy}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Functions: </span>
          <span className="font-medium">{analysis.function_count}</span>
        </div>
      </div>

      {analysis.dangerous_functions.length > 0 && (
        <div className="text-xs">
          <span className="text-muted-foreground">Dangerous sinks: </span>
          <span className="font-mono text-orange-500">
            {analysis.dangerous_functions.join(', ')}
          </span>
        </div>
      )}

      {analysis.input_sources.length > 0 && (
        <div className="text-xs">
          <span className="text-muted-foreground">Input functions: </span>
          <span className="font-mono">{analysis.input_sources.join(', ')}</span>
        </div>
      )}
    </div>
  )
}
