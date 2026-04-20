import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Play,
  Loader2,
  Square,
  AlertCircle,
  RefreshCw,
  Server,
  TerminalSquare,
  ChevronDown,
  ChevronUp,
  FileText,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  startSystemEmulation,
  getSystemEmulationStatus,
  getSystemEmulationServices,
  stopSystemEmulation,
  getSessionLogs,
  listSessions,
} from '@/api/emulation'
import { FirmwareServicesPanel } from './FirmwareServicesPanel'
import { extractErrorMessage } from '@/utils/error'
import { formatDate } from '@/utils/format'
import type { EmulationSession, FirmwareService, EmulationStatus } from '@/types'

const PIPELINE_STAGES = [
  { key: 'extracting', label: 'Extracting' },
  { key: 'detecting_arch', label: 'Detecting Arch' },
  { key: 'preparing_image', label: 'Preparing Image' },
  { key: 'booting', label: 'Booting' },
  { key: 'checking', label: 'Checking' },
  { key: 'running', label: 'Running' },
] as const

const STATUS_CONFIG: Record<EmulationStatus, { label: string; className: string }> = {
  created: { label: 'Created', className: 'bg-gray-500 text-white' },
  pending: { label: 'Queued', className: 'bg-yellow-500 text-black' },
  starting: { label: 'Starting', className: 'bg-yellow-500 text-black' },
  booting: { label: 'Booting', className: 'bg-yellow-500 text-black' },
  running: { label: 'Running', className: 'bg-green-500 text-white' },
  ready: { label: 'Ready', className: 'bg-green-500 text-white' },
  stopping: { label: 'Stopping...', className: 'bg-orange-500 text-white' },
  stopped: { label: 'Stopped', className: 'bg-zinc-600 text-white' },
  error: { label: 'Error', className: 'bg-red-500 text-white' },
}

function PipelineProgress({ currentStage }: { currentStage: string | null }) {
  const currentIdx = PIPELINE_STAGES.findIndex((s) => s.key === currentStage)

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        Pipeline Progress
      </h4>
      <div className="flex items-center gap-1">
        {PIPELINE_STAGES.map((stage, idx) => {
          const isCompleted = currentIdx > idx
          const isCurrent = currentIdx === idx
          const isPending = currentIdx < idx

          return (
            <div key={stage.key} className="flex items-center gap-1">
              {idx > 0 && (
                <div
                  className={`h-px w-3 ${
                    isCompleted ? 'bg-green-500' : 'bg-border'
                  }`}
                />
              )}
              <div className="flex flex-col items-center gap-0.5">
                <div
                  className={`h-2.5 w-2.5 rounded-full ${
                    isCompleted
                      ? 'bg-green-500'
                      : isCurrent
                        ? 'bg-yellow-500 animate-pulse'
                        : isPending
                          ? 'bg-zinc-600'
                          : 'bg-zinc-600'
                  }`}
                />
                <span
                  className={`text-[9px] leading-none ${
                    isCurrent
                      ? 'text-yellow-500 font-medium'
                      : isCompleted
                        ? 'text-green-500'
                        : 'text-muted-foreground/50'
                  }`}
                >
                  {stage.label}
                </span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export interface SystemEmulationPanelProps {
  projectId: string
  firmwareId: string | null
  onConnectTerminal?: (session: EmulationSession, port?: number) => void
}

export function SystemEmulationPanel({
  projectId,
  firmwareId,
  onConnectTerminal,
}: SystemEmulationPanelProps) {
  const [session, setSession] = useState<EmulationSession | null>(null)
  const [services, setServices] = useState<FirmwareService[]>([])
  const [loading, setLoading] = useState(false)
  const [starting, setStarting] = useState(false)
  const [stopping, setStopping] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [brand, setBrand] = useState('')
  const [showLogs, setShowLogs] = useState(false)
  const [logs, setLogs] = useState<string | null>(null)
  const [logsLoading, setLogsLoading] = useState(false)

  const sessionRef = useRef(session)
  sessionRef.current = session

  // Load existing system emulation sessions for this project
  const loadExistingSession = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    try {
      // Fetch all sessions and find a system-mode FirmAE one
      const sessions = await listSessions(projectId)
      // Find the latest system emulation session with system_emulation_stage set
      // (FirmAE sessions have system_emulation_stage, regular system-mode QEMU sessions don't)
      const systemSession = sessions
        .filter((s) => s.system_emulation_stage != null)
        .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())[0]

      if (systemSession) {
        setSession(systemSession)
        if (systemSession.status === 'running' && systemSession.discovered_services) {
          setServices(systemSession.discovered_services)
        }
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    loadExistingSession()
  }, [loadExistingSession])

  // Poll for status while pipeline is in progress. Note: FirmAE
  // system emulation has its own `system_emulation_stage` column
  // alongside the shared EmulationStatus. The 202-polling statuses
  // (pending/booting) belong to the user-mode path; for FirmAE they
  // never appear in practice (the /emulation/system endpoint has its
  // own state machine), but we include them here for exhaustiveness
  // against the new EmulationStatus union (Rule #9).
  useEffect(() => {
    if (!session || !projectId) return
    const isActive =
      session.status === 'starting' ||
      session.status === 'created' ||
      session.status === 'pending' ||
      session.status === 'booting' ||
      (session.status === 'running' &&
        session.system_emulation_stage != null &&
        session.system_emulation_stage !== 'running')

    if (!isActive) return

    const interval = setInterval(async () => {
      try {
        const updated = await getSystemEmulationStatus(projectId, session.id)
        setSession(updated)

        // If now running, load services
        if (updated.status === 'running' && updated.system_emulation_stage === 'running') {
          try {
            const svcList = await getSystemEmulationServices(projectId, session.id)
            setServices(svcList)
          } catch {
            // use discovered_services from the session if available
            if (updated.discovered_services) {
              setServices(updated.discovered_services)
            }
          }
        }
      } catch {
        // ignore poll errors
      }
    }, 2000)

    return () => clearInterval(interval)
  }, [projectId, session])

  // One-time service fetch when session transitions to running
  useEffect(() => {
    if (
      !session ||
      !projectId ||
      session.status !== 'running' ||
      session.system_emulation_stage !== 'running'
    )
      return
    if (services.length > 0) return // already have services

    getSystemEmulationServices(projectId, session.id)
      .then(setServices)
      .catch(() => {
        if (session.discovered_services) {
          setServices(session.discovered_services)
        }
      })
  }, [projectId, session, services.length])

  const handleStart = async () => {
    if (!projectId || !firmwareId) {
      setError('No firmware selected')
      return
    }

    setStarting(true)
    setError(null)
    setServices([])
    setLogs(null)
    setShowLogs(false)

    try {
      const newSession = await startSystemEmulation(
        projectId,
        firmwareId,
        brand.trim() ? { brand: brand.trim() } : undefined,
      )
      setSession(newSession)
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Failed to start system emulation'))
    } finally {
      setStarting(false)
    }
  }

  const handleStop = async () => {
    if (!projectId || !session) return
    setStopping(true)
    try {
      await stopSystemEmulation(projectId, session.id)
      setSession((prev) =>
        prev ? { ...prev, status: 'stopped' as const } : null,
      )
      setServices([])
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Failed to stop system emulation'))
    } finally {
      setStopping(false)
    }
  }

  const handleRetry = () => {
    setSession(null)
    setError(null)
    setServices([])
    setLogs(null)
    setShowLogs(false)
  }

  const handleViewLogs = async () => {
    if (showLogs) {
      setShowLogs(false)
      return
    }
    if (!session || !projectId) return
    setShowLogs(true)
    setLogsLoading(true)
    try {
      const logText = await getSessionLogs(projectId, session.id)
      setLogs(logText)
    } catch {
      setLogs('Failed to fetch logs')
    } finally {
      setLogsLoading(false)
    }
  }

  const handleRefreshServices = async () => {
    if (!session || !projectId) return
    try {
      const svcList = await getSystemEmulationServices(projectId, session.id)
      setServices(svcList)
    } catch {
      // ignore
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-4 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading...
      </div>
    )
  }

  // No active session
  if (!session || session.status === 'stopped') {
    return (
      <div className="space-y-4">
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-muted-foreground" />
            <h3 className="text-sm font-semibold">Full System Emulation</h3>
          </div>
          <p className="text-xs text-muted-foreground">
            Boot the entire firmware as a virtual machine using FirmAE. Automatically detects
            architecture, builds a disk image, boots the kernel, and discovers running network services.
          </p>

          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              Brand (optional)
            </label>
            <input
              type="text"
              value={brand}
              onChange={(e) => setBrand(e.target.value)}
              placeholder="e.g., netgear, tplink, dlink"
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
            />
            <p className="mt-0.5 text-xs text-muted-foreground/60">
              Helps FirmAE select the right NVRAM defaults for the firmware vendor
            </p>
          </div>

          {!firmwareId && (
            <div className="rounded-md border border-yellow-500/30 bg-yellow-500/5 px-3 py-2 text-xs text-yellow-500">
              <AlertCircle className="mr-1 inline h-3 w-3" />
              Select a firmware above before starting system emulation
            </div>
          )}

          {error && (
            <div className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {error}
            </div>
          )}

          <Button
            onClick={handleStart}
            disabled={starting || !firmwareId}
            className="w-full"
          >
            {starting ? (
              <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
            ) : (
              <Play className="mr-1.5 h-4 w-4" />
            )}
            {starting ? 'Starting...' : 'Start System Emulation'}
          </Button>
        </div>

        {/* Show previous session info if it was stopped */}
        {session && session.status === 'stopped' && (
          <div className="rounded-md border border-border p-3 space-y-2">
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] bg-zinc-600 text-white">Stopped</Badge>
              <span className="text-xs text-muted-foreground">
                Previous session ended {formatDate(session.stopped_at || session.created_at)}
              </span>
            </div>
            {session.kernel_used && (
              <p className="text-[10px] text-muted-foreground">
                Kernel: {session.kernel_used}
              </p>
            )}
          </div>
        )}
      </div>
    )
  }

  // Error state
  if (session.status === 'error') {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-destructive/30 bg-destructive/5 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-destructive" />
            <h3 className="text-sm font-semibold text-destructive">
              System Emulation Failed
            </h3>
          </div>

          {session.system_emulation_stage && (
            <PipelineProgress currentStage={session.system_emulation_stage} />
          )}

          {session.error_message && (
            <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-md bg-[#0a0a0b] p-3 text-[11px] text-zinc-300 font-mono">
              {session.error_message}
            </pre>
          )}

          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleRetry}>
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
              Retry
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleViewLogs}
            >
              <FileText className="mr-1 h-3 w-3" />
              Logs
              {showLogs ? <ChevronUp className="ml-1 h-3 w-3" /> : <ChevronDown className="ml-1 h-3 w-3" />}
            </Button>
          </div>

          {showLogs && (
            <div className="rounded-md border border-border bg-[#0a0a0b] p-2">
              {logsLoading ? (
                <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Loading logs...
                </div>
              ) : (
                <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-words text-[11px] text-zinc-300 font-mono">
                  {logs || 'No logs available'}
                </pre>
              )}
            </div>
          )}
        </div>
      </div>
    )
  }

  // Pipeline in progress (starting/created/pending/booting).
  // "pending" and "booting" are the 202-polling intermediate states
  // from the user-mode path; they don't normally appear via FirmAE
  // but are listed for exhaustiveness.
  const isPipelineActive =
    session.status === 'starting' ||
    session.status === 'created' ||
    session.status === 'pending' ||
    session.status === 'booting' ||
    (session.status === 'running' &&
      session.system_emulation_stage != null &&
      session.system_emulation_stage !== 'running')

  if (isPipelineActive) {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Loader2 className="h-4 w-4 animate-spin text-yellow-500" />
            <h3 className="text-sm font-semibold text-yellow-500">
              System Emulation Starting
            </h3>
          </div>

          <PipelineProgress currentStage={session.system_emulation_stage} />

          <p className="text-xs text-muted-foreground">
            FirmAE is preparing the firmware image. This can take several minutes
            depending on firmware size and complexity.
          </p>

          {session.architecture && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span>Architecture:</span>
              <Badge variant="outline" className="text-[10px]">
                {session.architecture}
              </Badge>
            </div>
          )}

          <Button
            variant="ghost"
            size="sm"
            onClick={handleViewLogs}
          >
            <FileText className="mr-1 h-3 w-3" />
            Logs
            {showLogs ? <ChevronUp className="ml-1 h-3 w-3" /> : <ChevronDown className="ml-1 h-3 w-3" />}
          </Button>

          {showLogs && (
            <div className="rounded-md border border-border bg-[#0a0a0b] p-2">
              {logsLoading ? (
                <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Loading logs...
                </div>
              ) : (
                <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-words text-[11px] text-zinc-300 font-mono">
                  {logs || 'No logs available'}
                </pre>
              )}
            </div>
          )}
        </div>
      </div>
    )
  }

  // Running state
  const statusCfg = STATUS_CONFIG[session.status] || STATUS_CONFIG.running

  return (
    <div className="space-y-4">
      {/* Session info card */}
      <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Badge className={`text-[10px] ${statusCfg.className}`}>
              {statusCfg.label}
            </Badge>
            <span className="text-sm font-medium">System Emulation</span>
          </div>
          <div className="flex items-center gap-2">
            {session.architecture && (
              <Badge variant="outline" className="text-[10px]">
                {session.architecture}
              </Badge>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs">
          {session.firmware_ip && (
            <div>
              <span className="text-muted-foreground">Firmware IP:</span>
              <span className="ml-1 font-mono text-foreground">{session.firmware_ip}</span>
            </div>
          )}
          {session.kernel_used && (
            <div>
              <span className="text-muted-foreground">Kernel:</span>
              <span className="ml-1 font-mono text-foreground truncate">
                {session.kernel_used}
              </span>
            </div>
          )}
          <div>
            <span className="text-muted-foreground">Services:</span>
            <span className="ml-1 text-foreground">{services.length} discovered</span>
          </div>
          <div>
            <span className="text-muted-foreground">Started:</span>
            <span className="ml-1 text-foreground">
              {formatDate(session.started_at || session.created_at)}
            </span>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          {onConnectTerminal && (
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              onClick={() => onConnectTerminal(session)}
            >
              <TerminalSquare className="mr-1 h-3 w-3" />
              Terminal
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs"
            onClick={handleRefreshServices}
          >
            <RefreshCw className="mr-1 h-3 w-3" />
            Refresh Services
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs"
            onClick={handleViewLogs}
          >
            <FileText className="mr-1 h-3 w-3" />
            Logs
            {showLogs ? <ChevronUp className="ml-1 h-3 w-3" /> : <ChevronDown className="ml-1 h-3 w-3" />}
          </Button>
          <Button
            variant="destructive"
            size="sm"
            className="h-7 text-xs"
            onClick={handleStop}
            disabled={stopping}
          >
            {stopping ? (
              <Loader2 className="mr-1 h-3 w-3 animate-spin" />
            ) : (
              <Square className="mr-1 h-3 w-3" />
            )}
            {stopping ? 'Stopping...' : 'Stop'}
          </Button>
        </div>

        {showLogs && (
          <div className="rounded-md border border-border bg-[#0a0a0b] p-2">
            {logsLoading ? (
              <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" />
                Loading logs...
              </div>
            ) : (
              <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-words text-[11px] text-zinc-300 font-mono">
                {logs || 'No logs available'}
              </pre>
            )}
          </div>
        )}
      </div>

      {/* Discovered services */}
      <FirmwareServicesPanel
        services={services}
        firmwareIp={session.firmware_ip}
        onConnectTerminal={
          onConnectTerminal
            ? (port) => onConnectTerminal(session, port)
            : undefined
        }
      />
    </div>
  )
}
