import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import {
  Play,
  Loader2,
  RefreshCw,
  TerminalSquare,
  Plus,
  Trash2,
  Cpu,
  AlertCircle,
  Save,
  BookOpen,
  Server,
  Network,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  startEmulation,
  stopEmulation,
  deleteSession,
  listSessions,
  getSessionStatus,
  listPresets,
  createPreset,
  deletePreset,
} from '@/api/emulation'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import { useProjectStore } from '@/stores/projectStore'
import FirmwareSelector from '@/components/projects/FirmwareSelector'
import KernelManager from '@/components/emulation/KernelManager'
import { SessionCard } from '@/components/emulation/SessionCard'
import { EmulationTerminal } from '@/components/emulation/EmulationTerminal'
import { SystemEmulationPanel } from '@/components/emulation/SystemEmulationPanel'
import { NetworkTrafficPanel } from '@/components/emulation/NetworkTrafficPanel'
import { extractErrorMessage } from '@/utils/error'
import { useEventStream } from '@/hooks/useEventStream'
import type {
  EmulationSession,
  EmulationMode,
  PortForward,
  EmulationPreset,
  StubProfile,
} from '@/types'

type PageTab = 'user' | 'system-firmae'

export default function EmulationPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const { firmwareList } = useFirmwareList(projectId)

  // Top-level page tab: user-mode emulation vs FirmAE system emulation
  const [pageTab, setPageTab] = useState<PageTab>('user')

  const [sessions, setSessions] = useState<EmulationSession[]>([])
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Start form state
  const [mode, setMode] = useState<EmulationMode>('user')
  const [binaryPath, setBinaryPath] = useState('')
  const [arguments_, setArguments] = useState('')
  const [portForwards, setPortForwards] = useState<PortForward[]>([])

  // Kernel selection (system mode)
  const [kernelName, setKernelName] = useState<string | null>(null)
  const [firmwareArch, setFirmwareArch] = useState<string | null>(null)
  const [firmwareKernelPath, setFirmwareKernelPath] = useState<string | null>(null)
  const [initPath, setInitPath] = useState('')
  const [preInitScript, setPreInitScript] = useState('')
  const [stubProfile, setStubProfile] = useState<StubProfile>('none')

  // Presets
  const [presets, setPresets] = useState<EmulationPreset[]>([])
  const [showSavePreset, setShowSavePreset] = useState(false)
  const [presetName, setPresetName] = useState('')
  const [presetDescription, setPresetDescription] = useState('')
  const [savingPreset, setSavingPreset] = useState(false)

  // Active session + terminal
  const [activeSession, setActiveSession] = useState<EmulationSession | null>(null)
  const [showTerminal, setShowTerminal] = useState(false)
  const [systemSubTab, setSystemSubTab] = useState<'terminal' | 'network'>('terminal')

  const activeSessionRef = useRef(activeSession)
  activeSessionRef.current = activeSession

  const loadSessions = useCallback(async () => {
    if (!projectId) return
    try {
      const data = await listSessions(projectId)
      setSessions(data)

      // Auto-select the first running/ready session. "ready" is the
      // new 202-polling terminal status; "running" stays as the legacy
      // equivalent from the synchronous MCP start path.
      const running = data.find((s) => s.status === 'running' || s.status === 'ready')
      if (running && !activeSessionRef.current) {
        setActiveSession(running)
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [projectId])

  const loadPresets = useCallback(async () => {
    if (!projectId) return
    try {
      const data = await listPresets(projectId)
      setPresets(data)
    } catch {
      // ignore
    }
  }, [projectId])

  // Pre-fill binary path from ?binary= query parameter
  useEffect(() => {
    const binary = searchParams.get('binary')
    if (binary) {
      setBinaryPath(binary)
      setMode('user')
      // Clear the query param so it doesn't persist on refresh
      setSearchParams({}, { replace: true })
    }
  }, [searchParams, setSearchParams])

  useEffect(() => {
    loadSessions()
    loadPresets()
  }, [loadSessions, loadPresets])

  // Derive firmware-specific state from the shared list.  Pre-fills
  // architecture, kernel path, and binary path based on the currently
  // selected firmware (or first entry if nothing selected).
  useEffect(() => {
    if (!firmwareList.length) return
    const fw = firmwareList.find((f) => f.id === selectedFirmwareId) ?? firmwareList[0]
    if (fw) {
      setFirmwareArch(fw.architecture ?? null)
      setFirmwareKernelPath(fw.kernel_path ?? null)
      // Pre-fill binary path for standalone binaries.  Use
      // extracted_filename (sanitised name on disk) rather than
      // original_filename which may have special chars replaced.
      if (fw.binary_info) {
        const fname = fw.binary_info.extracted_filename ?? fw.original_filename
        if (fname) setBinaryPath(fname)
      }
    }
  }, [firmwareList, selectedFirmwareId])

  // SSE: listen for emulation events and refresh on status changes.
  // Include the 202-polling intermediate states (pending, booting) so
  // the fallback poller keeps refreshing until the background task
  // transitions to ready/error.
  const hasActiveSession = sessions.some(
    (s) =>
      s.status === 'running' ||
      s.status === 'starting' ||
      s.status === 'pending' ||
      s.status === 'booting' ||
      s.status === 'ready',
  )
  const { lastEvent: emulationEvent } = useEventStream<{ type: string; status: string }>(
    projectId,
    { types: ['emulation'], enabled: hasActiveSession },
  )

  useEffect(() => {
    if (emulationEvent) loadSessions()
  }, [emulationEvent, loadSessions])

  // Fallback poll during active sessions. Use 2s while a session is in
  // the 202-polling transient states (pending/booting) so users see
  // status transitions quickly; fall back to 5s once the session has
  // stabilised at ready/running. Matches the firmware-unpack polling
  // cadence.
  const hasBootingSession = sessions.some(
    (s) => s.status === 'pending' || s.status === 'booting',
  )
  useEffect(() => {
    if (!projectId || !hasActiveSession) return
    const interval = setInterval(loadSessions, hasBootingSession ? 2000 : 5000)
    return () => clearInterval(interval)
  }, [projectId, hasActiveSession, hasBootingSession, loadSessions])

  // Auto-attach the terminal when the active session finishes health
  // check and transitions to ready. This is the core 202+polling UI
  // behaviour: after POST /start returns 202 with status=pending, the
  // poll loop above refreshes session rows; once status flips to ready,
  // this effect opens the terminal WebSocket. The backend WS gate
  // rejects any status other than ready/running (router line ~665), so
  // attaching earlier would fail-fast anyway — we just avoid the
  // round-trip.
  useEffect(() => {
    if (!activeSession) return
    const latest = sessions.find((s) => s.id === activeSession.id)
    if (!latest) return
    if (latest !== activeSession) {
      setActiveSession(latest)
    }
    if ((latest.status === 'ready' || latest.status === 'running') && !showTerminal) {
      setShowTerminal(true)
    }
  }, [sessions, activeSession, showTerminal])

  const handleStart = async () => {
    if (!projectId) return
    if (mode === 'user' && !binaryPath.trim()) {
      setError('Binary path is required for user-mode emulation')
      return
    }

    setStarting(true)
    setError(null)

    try {
      // POST /start returns 202 with the pending session row (Rule #29
      // 202+polling refactor). We do NOT attach the terminal here —
      // the fallback poll loop at `hasActiveSession` detects the row
      // and the `useEffect` below transitions to the terminal once
      // status flips to "ready" (health check passed in the backend
      // background task).
      const session = await startEmulation(projectId, {
        mode,
        binary_path: mode === 'user' ? binaryPath.trim() : undefined,
        arguments: mode === 'user' && arguments_.trim() ? arguments_.trim() : undefined,
        port_forwards: mode === 'system' && portForwards.length > 0 ? portForwards : undefined,
        kernel_name: mode === 'system' && kernelName ? kernelName : undefined,
        init_path: mode === 'system' && initPath.trim() ? initPath.trim() : undefined,
        pre_init_script: mode === 'system' && preInitScript.trim() ? preInitScript.trim() : undefined,
        stub_profile: mode === 'system' && stubProfile !== 'none' ? stubProfile : undefined,
      }, selectedFirmwareId)
      setActiveSession(session)
      // If the synchronous MCP path is somehow taken (e.g. tests), the
      // session may already be "running"; keep back-compat.
      if (session.status === 'running' || session.status === 'ready') {
        setShowTerminal(true)
      }
      await loadSessions()
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Failed to start emulation'))
    } finally {
      setStarting(false)
    }
  }

  const handleDismiss = async (sessionId: string) => {
    if (!projectId) return
    try {
      await deleteSession(projectId, sessionId)
      setSessions((prev) => prev.filter((s) => s.id !== sessionId))
    } catch {
      // ignore
    }
  }

  const handleStop = async (sessionId: string) => {
    if (!projectId) return
    setSessions((prev) =>
      prev.map((s) => (s.id === sessionId ? { ...s, status: 'stopping' as const } : s))
    )
    if (activeSession?.id === sessionId) {
      setShowTerminal(false)
      setActiveSession(null)
    }
    try {
      const updated = await stopEmulation(projectId, sessionId)
      setSessions((prev) => prev.map((s) => (s.id === sessionId ? updated : s)))
    } catch {
      await loadSessions()
    }
  }

  const handleConnect = async (session: EmulationSession) => {
    if (!projectId) return
    // Refresh status. "ready" is the 202-polling terminal status;
    // "running" stays for back-compat with the synchronous MCP path.
    try {
      const updated = await getSessionStatus(projectId, session.id)
      setActiveSession(updated)
      if (updated.status === 'running' || updated.status === 'ready') {
        setShowTerminal(true)
      }
    } catch {
      setActiveSession(session)
      if (session.status === 'running' || session.status === 'ready') {
        setShowTerminal(true)
      }
    }
  }

  const addPortForward = () => {
    setPortForwards([...portForwards, { host: 8080, guest: 80 }])
  }

  const removePortForward = (index: number) => {
    setPortForwards(portForwards.filter((_, i) => i !== index))
  }

  const updatePortForward = (index: number, field: 'host' | 'guest', value: number) => {
    const updated = [...portForwards]
    updated[index] = { ...updated[index], [field]: value }
    setPortForwards(updated)
  }

  const loadPresetIntoForm = (preset: EmulationPreset) => {
    setMode(preset.mode)
    setBinaryPath(preset.binary_path || '')
    setArguments(preset.arguments || '')
    setPortForwards(preset.port_forwards || [])
    setKernelName(preset.kernel_name || null)
    setInitPath(preset.init_path || '')
    setPreInitScript(preset.pre_init_script || '')
    setStubProfile(preset.stub_profile || 'none')
  }

  const handleSavePreset = async () => {
    if (!projectId || !presetName.trim()) return
    setSavingPreset(true)
    try {
      await createPreset(projectId, {
        name: presetName.trim(),
        description: presetDescription.trim() || undefined,
        mode,
        binary_path: mode === 'user' ? binaryPath.trim() || undefined : undefined,
        arguments: mode === 'user' && arguments_.trim() ? arguments_.trim() : undefined,
        architecture: firmwareArch || undefined,
        port_forwards: mode === 'system' && portForwards.length > 0 ? portForwards : undefined,
        kernel_name: mode === 'system' && kernelName ? kernelName : undefined,
        init_path: mode === 'system' && initPath.trim() ? initPath.trim() : undefined,
        pre_init_script: mode === 'system' && preInitScript.trim() ? preInitScript.trim() : undefined,
        stub_profile: mode === 'system' && stubProfile !== 'none' ? stubProfile : undefined,
      })
      setShowSavePreset(false)
      setPresetName('')
      setPresetDescription('')
      await loadPresets()
    } catch {
      // ignore
    } finally {
      setSavingPreset(false)
    }
  }

  const handleDeletePreset = async (presetId: string) => {
    if (!projectId) return
    try {
      await deletePreset(projectId, presetId)
      await loadPresets()
    } catch {
      // ignore
    }
  }

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  const handleSystemTerminalConnect = (session: EmulationSession, _port?: number) => {
    setActiveSession(session)
    if (session.status === 'running' || session.status === 'ready') {
      setShowTerminal(true)
    }
  }

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="border-b border-border bg-background px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold">Firmware Emulation</h1>
            <p className="text-sm text-muted-foreground">
              Run firmware binaries or boot the full OS using QEMU
            </p>
          </div>
          <div className="flex min-w-0 items-center gap-3">
            <FirmwareSelector projectId={projectId!} firmwareList={firmwareList} className="min-w-0 max-w-xs" />
            <Button variant="outline" size="sm" onClick={loadSessions}>
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
              Refresh
            </Button>
          </div>
        </div>

        {/* Page-level tabs */}
        <div className="mt-3 flex gap-1">
          <button
            onClick={() => setPageTab('user')}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
              pageTab === 'user'
                ? 'bg-primary/10 text-primary border border-primary/30'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent'
            }`}
          >
            <Cpu className="h-3.5 w-3.5" />
            User Mode
          </button>
          <button
            onClick={() => setPageTab('system-firmae')}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
              pageTab === 'system-firmae'
                ? 'bg-primary/10 text-primary border border-primary/30'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent'
            }`}
          >
            <Server className="h-3.5 w-3.5" />
            System Mode
            <Badge variant="outline" className="text-[9px] ml-0.5 px-1 py-0">FirmAE</Badge>
          </button>
        </div>
      </div>

      {/* System Mode (FirmAE) tab content */}
      {pageTab === 'system-firmae' && (
        <div className="flex flex-1 overflow-hidden">
          <div className="w-96 shrink-0 overflow-y-auto border-r border-border p-4">
            <SystemEmulationPanel
              projectId={projectId!}
              firmwareId={selectedFirmwareId ?? firmwareList[0]?.id ?? null}
              onConnectTerminal={handleSystemTerminalConnect}
            />
          </div>

          {/* Right panel: sub-tabs for Terminal and Network Traffic */}
          <div className="flex flex-1 flex-col overflow-hidden">
            {/* Sub-tab bar */}
            <div className="flex items-center gap-1 border-b border-border bg-background px-3 py-1.5">
              <button
                onClick={() => setSystemSubTab('terminal')}
                className={`flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                  systemSubTab === 'terminal'
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                }`}
              >
                <TerminalSquare className="h-3 w-3" />
                Terminal
              </button>
              <button
                onClick={() => setSystemSubTab('network')}
                className={`flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                  systemSubTab === 'network'
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                }`}
              >
                <Network className="h-3 w-3" />
                Network Traffic
              </button>
            </div>

            {/* Sub-tab content */}
            {systemSubTab === 'terminal' && (
              <div className="relative flex-1 bg-[#0a0a0b]">
                {showTerminal && activeSession && projectId ? (
                  <EmulationTerminal
                    projectId={projectId}
                    session={activeSession}
                    onClose={() => setShowTerminal(false)}
                  />
                ) : (
                  <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                    <div className="text-center">
                      <Server className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
                      <p>Start system emulation or connect to a running session</p>
                      <p className="mt-1 text-xs text-muted-foreground/60">
                        The terminal will appear here when a system emulation session is active
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {systemSubTab === 'network' && (
              <div className="flex-1 overflow-hidden bg-background">
                {activeSession && projectId ? (
                  <NetworkTrafficPanel
                    projectId={projectId}
                    sessionId={activeSession.id}
                  />
                ) : (
                  <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                    <div className="text-center">
                      <Network className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
                      <p>Start system emulation to capture network traffic</p>
                      <p className="mt-1 text-xs text-muted-foreground/60">
                        Capture and analyze protocols, DNS queries, and insecure services
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* User Mode tab content */}
      {pageTab === 'user' && (
      <div className="flex flex-1 overflow-hidden">
        {/* Left panel — controls + session list */}
        <div className="w-96 shrink-0 overflow-y-auto border-r border-border p-4 space-y-6">
          {/* Presets */}
          {presets.length > 0 && (
            <div className="space-y-2">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                <BookOpen className="mr-1.5 inline h-3.5 w-3.5" />
                Presets
              </h2>
              {presets.map((preset) => (
                <div
                  key={preset.id}
                  className="group flex items-center justify-between rounded-md border border-border px-3 py-2 hover:border-primary/50 transition-colors"
                >
                  <button
                    onClick={() => loadPresetIntoForm(preset)}
                    className="flex-1 text-left min-w-0"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-sm font-medium truncate">{preset.name}</span>
                      <Badge variant="outline" className="text-[10px]">
                        {preset.mode}
                      </Badge>
                      {preset.stub_profile && preset.stub_profile !== 'none' && (
                        <Badge variant="secondary" className="text-[10px]">
                          stubs: {preset.stub_profile}
                        </Badge>
                      )}
                    </div>
                    {preset.description && (
                      <p className="mt-0.5 text-xs text-muted-foreground truncate">
                        {preset.description}
                      </p>
                    )}
                  </button>
                  <button
                    onClick={() => handleDeletePreset(preset.id)}
                    className="ml-2 text-muted-foreground opacity-0 group-hover:opacity-100 hover:text-destructive transition-opacity"
                    title="Delete preset"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Start Emulation Form */}
          <div className="space-y-4">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Start Emulation
            </h2>

            {/* Mode selector */}
            <div className="flex gap-2">
              <button
                onClick={() => setMode('user')}
                className={`flex-1 rounded-md border px-3 py-2 text-sm font-medium transition-colors ${
                  mode === 'user'
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border text-muted-foreground hover:border-primary/50'
                }`}
              >
                <Cpu className="mb-1 inline h-4 w-4" /> User Mode
              </button>
              <button
                onClick={() => setMode('system')}
                className={`flex-1 rounded-md border px-3 py-2 text-sm font-medium transition-colors ${
                  mode === 'system'
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border text-muted-foreground hover:border-primary/50'
                }`}
              >
                <TerminalSquare className="mb-1 inline h-4 w-4" /> System Mode
              </button>
            </div>

            {/* Standalone binary indicator */}
            {(() => {
              const fw = firmwareList.find((f) => f.id === selectedFirmwareId) ?? firmwareList[0]
              if (fw?.binary_info) {
                const bi = fw.binary_info
                const isRaw = bi.format === 'unknown' && bi.arch_candidates && bi.arch_candidates.length > 0
                return (
                  <div className="rounded-md border border-blue-500/30 bg-blue-500/5 p-2.5 text-xs space-y-1">
                    <div className="font-medium text-blue-400">
                      {isRaw ? 'Raw Binary Mode' : 'Standalone Binary Mode'}
                    </div>
                    {isRaw ? (
                      <div className="space-y-1.5">
                        <div className="text-muted-foreground">
                          No recognized headers. Architecture detected via {bi.arch_detection_method ?? 'statistical analysis'}.
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-muted-foreground">Architecture:</span>
                          <select
                            className="rounded border border-border bg-background px-2 py-0.5 text-xs"
                            value={firmwareArch ?? bi.architecture ?? ''}
                            onChange={(e) => setFirmwareArch(e.target.value || null)}
                          >
                            {bi.arch_candidates!.map((c) => (
                              <option key={c.architecture} value={c.architecture}>
                                {c.raw_name} - {c.architecture} ({c.endianness ?? '?'}-endian) [{c.confidence}]
                              </option>
                            ))}
                          </select>
                        </div>
                      </div>
                    ) : (
                      <div className="text-muted-foreground">
                        {bi.format?.toUpperCase()} {bi.bits}-bit{' '}
                        {bi.is_static ? 'static' : 'dynamic'}
                        {bi.dependencies.length > 0 && (
                          <span> ({bi.dependencies.length} dependencies)</span>
                        )}
                        {bi.is_static && bi.format === 'elf' && (
                          <span className="ml-1 text-green-400">- no sysroot needed</span>
                        )}
                        {(bi.format === 'pe' || bi.format === 'macho') && (
                          <div className="mt-1 flex items-center gap-1.5">
                            <span className="rounded bg-purple-500/20 px-1.5 py-0.5 text-[10px] font-medium text-purple-400">
                              Qiling Emulation
                            </span>
                            <span className="text-[10px] text-muted-foreground">
                              {bi.format === 'pe' ? 'Windows' : 'macOS'} binary - batch execution, no interactive terminal
                            </span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              }
              return null
            })()}

            <p className="text-xs text-muted-foreground">
              {mode === 'user'
                ? 'Run a single binary in a chroot. Fast, good for testing specific programs.'
                : 'Boot the full firmware OS. Slower, good for testing services and network.'}
            </p>

            {/* User mode fields */}
            {mode === 'user' && (
              <>
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">
                    Binary Path *
                  </label>
                  <input
                    type="text"
                    value={binaryPath}
                    onChange={(e) => setBinaryPath(e.target.value)}
                    placeholder="/usr/sbin/httpd"
                    className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">
                    Arguments
                  </label>
                  <input
                    type="text"
                    value={arguments_}
                    onChange={(e) => setArguments(e.target.value)}
                    placeholder="--help"
                    className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                  />
                </div>
              </>
            )}

            {/* System mode fields */}
            {mode === 'system' && (
              <>
              <KernelManager
                firmwareArchitecture={firmwareArch}
                firmwareKernelPath={firmwareKernelPath}
                onKernelSelect={setKernelName}
                selectedKernel={kernelName}
              />
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Init Override
                </label>
                <input
                  type="text"
                  value={initPath}
                  onChange={(e) => setInitPath(e.target.value)}
                  placeholder="/bin/sh (leave empty for default /sbin/init)"
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                />
                <p className="mt-0.5 text-xs text-muted-foreground/60">
                  Override if /sbin/init is broken or wrong architecture
                </p>
              </div>
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <label className="text-xs font-medium text-muted-foreground">
                    Port Forwarding
                  </label>
                  <button
                    onClick={addPortForward}
                    className="flex items-center gap-1 text-xs text-primary hover:underline"
                  >
                    <Plus className="h-3 w-3" /> Add
                  </button>
                </div>
                {portForwards.length === 0 && (
                  <p className="text-xs text-muted-foreground/60">No port forwards configured</p>
                )}
                {portForwards.map((pf, i) => (
                  <div key={i} className="mb-1.5 flex items-center gap-2">
                    <input
                      type="number"
                      value={pf.host}
                      onChange={(e) => updatePortForward(i, 'host', parseInt(e.target.value) || 0)}
                      className="w-20 rounded border border-border bg-background px-2 py-1 text-xs"
                      placeholder="Host"
                    />
                    <span className="text-xs text-muted-foreground">→</span>
                    <input
                      type="number"
                      value={pf.guest}
                      onChange={(e) => updatePortForward(i, 'guest', parseInt(e.target.value) || 0)}
                      className="w-20 rounded border border-border bg-background px-2 py-1 text-xs"
                      placeholder="Guest"
                    />
                    <button
                      onClick={() => removePortForward(i)}
                      className="text-muted-foreground hover:text-destructive"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Stub Libraries
                </label>
                <select
                  value={stubProfile}
                  onChange={(e) => setStubProfile(e.target.value as StubProfile)}
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                >
                  <option value="none">None — no stubs injected</option>
                  <option value="generic">Generic — MTD flash + wireless ioctl stubs</option>
                  <option value="tenda">Tenda — generic + Tenda-specific stubs</option>
                </select>
                <p className="mt-0.5 text-xs text-muted-foreground/60">
                  LD_PRELOAD stub libraries for hardware emulation. Use &quot;generic&quot; for most firmware, &quot;tenda&quot; for Tenda devices.
                </p>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Pre-Init Script
                </label>
                <textarea
                  value={preInitScript}
                  onChange={(e) => setPreInitScript(e.target.value)}
                  placeholder={"# Runs before firmware init\n/bin/cfmd &\nsleep 1\n/bin/httpd &"}
                  rows={5}
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm font-mono focus:border-primary focus:outline-none resize-y"
                />
                <p className="mt-0.5 text-xs text-muted-foreground/60">
                  Shell script sourced before firmware init (service startup, config setup, etc.)
                </p>
              </div>
              </>
            )}

            {error && (
              <div className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
                <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                {error}
              </div>
            )}

            <div className="flex gap-2">
              <Button
                onClick={handleStart}
                disabled={starting}
                className="flex-1"
              >
                {starting ? (
                  <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                ) : (
                  <Play className="mr-1.5 h-4 w-4" />
                )}
                {starting ? 'Starting...' : 'Start'}
              </Button>
              <Button
                variant="outline"
                onClick={() => setShowSavePreset(!showSavePreset)}
                title="Save as preset"
              >
                <Save className="h-4 w-4" />
              </Button>
            </div>

            {/* Save as Preset dialog */}
            {showSavePreset && (
              <div className="rounded-md border border-border bg-card p-3 space-y-2">
                <p className="text-xs font-medium text-muted-foreground">Save current config as preset</p>
                <input
                  type="text"
                  value={presetName}
                  onChange={(e) => setPresetName(e.target.value)}
                  placeholder="Preset name"
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                />
                <input
                  type="text"
                  value={presetDescription}
                  onChange={(e) => setPresetDescription(e.target.value)}
                  placeholder="Description (optional)"
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                />
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    onClick={handleSavePreset}
                    disabled={savingPreset || !presetName.trim()}
                    className="flex-1"
                  >
                    {savingPreset ? (
                      <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Save className="mr-1.5 h-3.5 w-3.5" />
                    )}
                    Save
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setShowSavePreset(false)}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            )}
          </div>

          {/* Session list */}
          <div className="space-y-3">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Sessions ({sessions.filter((s) => s.mode === mode).length})
            </h2>

            {sessions.filter((s) => s.mode === mode).length === 0 && (
              <p className="text-xs text-muted-foreground/60">No {mode}-mode sessions yet</p>
            )}

            {sessions.filter((s) => s.mode === mode).map((session) => (
              <SessionCard
                key={session.id}
                session={session}
                isActive={activeSession?.id === session.id}
                projectId={projectId!}
                onConnect={() => handleConnect(session)}
                onStop={() => handleStop(session.id)}
                onDismiss={() => handleDismiss(session.id)}
              />
            ))}
          </div>
        </div>

        {/* Center panel — terminal or Qiling output */}
        <div className="relative flex-1 bg-[#0a0a0b]">
          {showTerminal && activeSession && activeSession.mode !== 'qiling' && projectId ? (
            <EmulationTerminal
              projectId={projectId}
              session={activeSession}
              onClose={() => setShowTerminal(false)}
            />
          ) : activeSession && activeSession.mode === 'qiling' ? (
            <div className="flex h-full flex-col p-4">
              <div className="mb-3 flex items-center gap-2">
                <Badge variant="outline" className="border-purple-500/50 text-purple-400 text-xs">
                  Qiling Emulation
                </Badge>
                <span className="text-xs text-muted-foreground">
                  {activeSession.status === 'stopped' ? 'Completed' : activeSession.status}
                  {activeSession.architecture && ` - ${activeSession.architecture}`}
                </span>
                <button
                  className="ml-auto text-xs text-muted-foreground hover:text-foreground"
                  onClick={() => { setActiveSession(null); setShowTerminal(false) }}
                >
                  Close
                </button>
              </div>
              {activeSession.error_message && (
                <div className="mb-3 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
                  <AlertCircle className="mr-1 inline h-3 w-3" />
                  {activeSession.error_message}
                </div>
              )}
              <pre className="flex-1 overflow-auto whitespace-pre-wrap break-words rounded-md bg-[#111] p-3 text-xs text-zinc-300 font-mono">
                {activeSession.logs || '(no output)'}
              </pre>
            </div>
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
              <div className="text-center">
                <TerminalSquare className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
                <p>Start an emulation session or connect to a running one</p>
                <p className="mt-1 text-xs text-muted-foreground/60">
                  The terminal will appear here when a session is active
                </p>
              </div>
            </div>
          )}

        </div>
      </div>
      )}
    </div>
  )
}
