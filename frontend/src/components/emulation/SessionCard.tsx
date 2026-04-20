import { useEffect, useState } from 'react'
import {
  Square,
  Loader2,
  TerminalSquare,
  Trash2,
  Clock,
  AlertCircle,
  FileText,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { formatDate } from '@/utils/format'
import { getSessionLogs } from '@/api/emulation'
import type { EmulationSession, EmulationStatus } from '@/types'

const STATUS_CONFIG: Record<EmulationStatus, { label: string; className: string }> = {
  created: { label: 'Created', className: 'bg-gray-500 text-white' },
  // Rule #29 202+polling intermediate: request accepted, DB row created,
  // background task not yet running.
  pending: { label: 'Queued', className: 'bg-yellow-500 text-black' },
  starting: { label: 'Starting', className: 'bg-yellow-500 text-black' },
  // Rule #29 202+polling intermediate: container created, waiting on
  // health check (serial socket for system, chroot probe for user).
  booting: { label: 'Booting', className: 'bg-yellow-500 text-black' },
  running: { label: 'Running', className: 'bg-green-500 text-white' },
  // Rule #29 202+polling terminal: health probe succeeded, terminal
  // WebSocket is safe to attach.
  ready: { label: 'Ready', className: 'bg-green-500 text-white' },
  stopping: { label: 'Stopping...', className: 'bg-orange-500 text-white' },
  stopped: { label: 'Stopped', className: 'bg-zinc-600 text-white' },
  error: { label: 'Error', className: 'bg-red-500 text-white' },
}

export interface SessionCardProps {
  session: EmulationSession
  isActive: boolean
  projectId: string
  onConnect: () => void
  onStop: () => void
  onDismiss: () => void
}

export function SessionCard({ session, isActive, projectId, onConnect, onStop, onDismiss }: SessionCardProps) {
  const statusCfg = STATUS_CONFIG[session.status] || STATUS_CONFIG.stopped
  const [showLogs, setShowLogs] = useState(false)
  const [logs, setLogs] = useState<string | null>(null)
  const [logsLoading, setLogsLoading] = useState(false)

  // When the session finishes stopping, refresh logs if the panel is open
  useEffect(() => {
    if (session.status !== 'stopped' || !showLogs) return
    setLogsLoading(true)
    getSessionLogs(projectId, session.id)
      .then(setLogs)
      .catch(() => setLogs('Failed to fetch logs'))
      .finally(() => setLogsLoading(false))
  }, [projectId, session.id, session.status, showLogs])

  const handleViewLogs = async () => {
    if (showLogs) {
      setShowLogs(false)
      return
    }
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

  return (
    <div
      className={`rounded-lg border p-3 transition-colors ${
        isActive
          ? 'border-primary/50 bg-primary/5'
          : 'border-border hover:border-border/80'
      }`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Badge className={`text-[10px] ${statusCfg.className}`}>
            {statusCfg.label}
          </Badge>
          <span className="text-xs font-medium">
            {session.mode === 'qiling' ? 'Qiling' : session.mode === 'user' ? 'User' : 'System'} Mode
          </span>
          {session.mode === 'qiling' && (
            <Badge variant="outline" className="text-[10px] border-purple-500/50 text-purple-400">
              Qiling
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-2">
          {session.architecture && (
            <Badge variant="outline" className="text-[10px]">
              {session.architecture}
            </Badge>
          )}
          {(session.status === 'stopped' || session.status === 'error') && (
            <button
              onClick={onDismiss}
              className="text-muted-foreground hover:text-destructive transition-colors"
              title="Delete session"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {session.binary_path && (
        <p className="mt-1 truncate text-xs text-muted-foreground font-mono">
          {session.binary_path}
        </p>
      )}

      {/* System emulation (FirmAE) details */}
      {session.system_emulation_stage && (
        <div className="mt-1 flex flex-wrap items-center gap-1.5">
          <Badge variant="outline" className="text-[10px] border-cyan-500/30 text-cyan-400">
            {session.system_emulation_stage}
          </Badge>
          {session.firmware_ip && (
            <span className="text-[10px] text-muted-foreground font-mono">
              {session.firmware_ip}
            </span>
          )}
          {session.kernel_used && (
            <span className="text-[10px] text-muted-foreground truncate max-w-[180px]" title={session.kernel_used}>
              {session.kernel_used}
            </span>
          )}
          {session.discovered_services && session.discovered_services.length > 0 && (
            <Badge variant="outline" className="text-[10px]">
              {session.discovered_services.length} services
            </Badge>
          )}
        </div>
      )}

      <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
        <Clock className="h-3 w-3" />
        {formatDate(session.created_at)}
      </div>

      {/* Error message — only shown for errored sessions, not intentional stops */}
      {session.status === 'error' && session.error_message && (
        <div className="mt-2 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
          <div className="flex items-start gap-2">
            <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div className="min-w-0">
              <p className="font-medium">Emulation failed</p>
              <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words text-[11px] opacity-90 font-mono">
                {session.error_message}
              </pre>
            </div>
          </div>
        </div>
      )}

      <div className="mt-2 flex flex-wrap gap-2">
        {(session.status === 'running' || session.status === 'ready') && session.mode !== 'qiling' && (
          <>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              onClick={onConnect}
            >
              <TerminalSquare className="mr-1 h-3 w-3" />
              Connect
            </Button>
            <Button
              variant="destructive"
              size="sm"
              className="h-7 text-xs"
              onClick={onStop}
            >
              <Square className="mr-1 h-3 w-3" />
              Stop
            </Button>
          </>
        )}
        {session.status === 'stopping' && (
          <Button variant="outline" size="sm" className="h-7 text-xs" disabled>
            <Loader2 className="mr-1 h-3 w-3 animate-spin" />
            Stopping...
          </Button>
        )}
        {/* View Logs button — available for any session with a container */}
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
      </div>

      {/* Qiling output — shown inline for batch emulation results */}
      {session.mode === 'qiling' && session.logs && (
        <div className="mt-2 rounded-md border border-purple-500/20 bg-[#0a0a0b] p-2">
          <div className="mb-1 text-[10px] font-medium text-purple-400">Emulation Output</div>
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words text-[11px] text-zinc-300 font-mono">
            {session.logs}
          </pre>
        </div>
      )}

      {/* Expandable log viewer */}
      {showLogs && (
        <div className="mt-2 rounded-md border border-border bg-[#0a0a0b] p-2">
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
  )
}
