/**
 * ApkScanTab — APK security scanning trigger and results display.
 *
 * Discovers APK files in firmware, lets users select one, triggers
 * multi-phase scans (manifest, bytecode, SAST), shows per-phase status
 * indicators, and displays results via SecurityScanResults.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  FileCode,
  Loader2,
  Play,
  Search,
  Shield,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Clock,
  XCircle,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Package,
  Filter,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import SecurityScanResults from './SecurityScanResults'
import type { ScanPhase } from './SecurityScanResults'
import { getDecompiledSource, type SourceFileResponse } from '@/api/apkScan'
import {
  scanApkManifest,
  scanApkBytecode,
  scanApkSast,
  scanApkAll,
} from '@/api/apkScan'
import type {
  ManifestScanResponse,
  BytecodeScanResponse,
  SastScanResponse,
} from '@/api/apkScan'
import { searchFiles } from '@/api/files'
import { extractErrorMessage } from '@/utils/error'

// ── Phase scan status ──

type PhaseStatus = 'idle' | 'scanning' | 'complete' | 'error'

interface PhaseState {
  status: PhaseStatus
  error?: string
  elapsedMs?: number
}

const INITIAL_PHASE: PhaseState = { status: 'idle' }

// ── Phase config ──

const PHASE_META: Record<
  ScanPhase,
  { label: string; description: string; icon: React.ElementType; color: string; estimate: string }
> = {
  manifest: {
    label: 'Manifest',
    description: '18 MobSF-equivalent checks (debuggable, allowBackup, exported components, etc.)',
    icon: FileCode,
    color: 'text-orange-500',
    estimate: '< 1s',
  },
  bytecode: {
    label: 'Bytecode',
    description: 'DEX bytecode patterns (insecure crypto, cleartext HTTP, disabled TLS, etc.)',
    icon: Shield,
    color: 'text-purple-500',
    estimate: '< 30s',
  },
  sast: {
    label: 'SAST',
    description: 'jadx decompilation + mobsfscan code pattern analysis',
    icon: Search,
    color: 'text-cyan-500',
    estimate: '< 3min',
  },
}

// ── Severity threshold options (ordered from most inclusive to most restrictive) ──

const SEVERITY_THRESHOLD_OPTIONS: { value: string; label: string; description: string }[] = [
  { value: 'info', label: 'All', description: 'Show all findings' },
  { value: 'low', label: 'Low+', description: 'Low severity and above' },
  { value: 'medium', label: 'Medium+', description: 'Medium severity and above' },
  { value: 'high', label: 'High+', description: 'High severity and above' },
  { value: 'critical', label: 'Critical', description: 'Critical findings only' },
]

// ── Props ──

interface ApkScanTabProps {
  projectId: string
  selectedFirmwareId: string | null
  initialApk?: string
  /** Finding title to auto-expand after loading cached results */
  initialFinding?: string
}

export default function ApkScanTab({ projectId, selectedFirmwareId, initialApk, initialFinding }: ApkScanTabProps) {
  // ── APK discovery ──
  const [apkFiles, setApkFiles] = useState<string[]>([])
  const [discoveryLoading, setDiscoveryLoading] = useState(false)
  const [discoveryError, setDiscoveryError] = useState<string | null>(null)
  const [selectedApk, setSelectedApk] = useState<string | null>(null)
  const [apkListExpanded, setApkListExpanded] = useState(false)

  // ── Batch scan state ──
  const [checkedApks, setCheckedApks] = useState<Set<string>>(new Set())
  const [batchScanning, setBatchScanning] = useState(false)
  const [batchProgress, setBatchProgress] = useState<{
    current: number
    total: number
    currentApk: string
    results: { apk: string; manifest: number; bytecode: number; sast: number; errors: string[] }[]
  } | null>(null)

  // ── Severity threshold ──
  const [minSeverity, setMinSeverity] = useState<string>('info')

  // ── Phase states ──
  const [manifestPhase, setManifestPhase] = useState<PhaseState>(INITIAL_PHASE)
  const [bytecodePhase, setBytecodePhase] = useState<PhaseState>(INITIAL_PHASE)
  const [sastPhase, setSastPhase] = useState<PhaseState>(INITIAL_PHASE)

  // ── Scan results ──
  const [manifestResult, setManifestResult] = useState<ManifestScanResponse | null>(null)
  const [bytecodeResult, setBytecodeResult] = useState<BytecodeScanResponse | null>(null)
  const [sastResult, setSastResult] = useState<SastScanResponse | null>(null)

  // ── Source viewer state ──
  const [sourceView, setSourceView] = useState<{
    source: SourceFileResponse
    highlightLine?: number
  } | null>(null)
  const [sourceLoading, setSourceLoading] = useState(false)

  const handleViewSource = useCallback(async (filePath: string, line?: number) => {
    if (!projectId || !selectedFirmwareId || !selectedApk) return
    setSourceLoading(true)
    try {
      const source = await getDecompiledSource(
        projectId, selectedFirmwareId, selectedApk, filePath,
      )
      setSourceView({ source, highlightLine: line })
      // Scroll to highlighted line after render
      requestAnimationFrame(() => {
        document.getElementById('highlighted-line')?.scrollIntoView({
          behavior: 'smooth',
          block: 'center',
        })
      })
    } catch {
      setSourceView(null)
    } finally {
      setSourceLoading(false)
    }
  }, [projectId, selectedFirmwareId, selectedApk])

  // ── Timer for elapsed display ──
  const timerRef = useRef<Record<ScanPhase, number | null>>({
    manifest: null,
    bytecode: null,
    sast: null,
  })
  const [elapsedTimers, setElapsedTimers] = useState<Record<ScanPhase, number>>({
    manifest: 0,
    bytecode: 0,
    sast: 0,
  })

  // Start/stop elapsed timers for scanning phases
  const startTimer = useCallback((phase: ScanPhase) => {
    setElapsedTimers((prev) => ({ ...prev, [phase]: 0 }))
    const start = Date.now()
    const id = window.setInterval(() => {
      setElapsedTimers((prev) => ({ ...prev, [phase]: Date.now() - start }))
    }, 200)
    timerRef.current[phase] = id
  }, [])

  const stopTimer = useCallback((phase: ScanPhase) => {
    if (timerRef.current[phase] != null) {
      clearInterval(timerRef.current[phase]!)
      timerRef.current[phase] = null
    }
  }, [])

  // Cleanup timers on unmount
  useEffect(() => {
    return () => {
      Object.values(timerRef.current).forEach((id) => {
        if (id != null) clearInterval(id)
      })
    }
  }, [])

  // ── Discover APK files when firmware changes ──
  const discoverApks = useCallback(async () => {
    if (!projectId || !selectedFirmwareId) {
      setApkFiles([])
      setSelectedApk(null)
      return
    }
    setDiscoveryLoading(true)
    setDiscoveryError(null)
    try {
      const result = await searchFiles(projectId, '*.apk', '/', selectedFirmwareId)
      const files = result.matches || []
      setApkFiles(files)
      if (files.length > 0) {
        // If deep-linked APK is in the list, select it; otherwise keep current or pick first
        if (initialApk && files.includes(initialApk)) {
          setSelectedApk(initialApk)
        } else if (!selectedApk || !files.includes(selectedApk)) {
          setSelectedApk(files[0])
        }
      } else {
        setSelectedApk(null)
      }
    } catch (e) {
      setDiscoveryError(extractErrorMessage(e, 'Failed to discover APK files'))
      setApkFiles([])
    } finally {
      setDiscoveryLoading(false)
    }
  }, [projectId, selectedFirmwareId, initialApk])

  useEffect(() => {
    discoverApks()
  }, [discoverApks])

  // Reset results when APK selection changes via user click (not deep-link)
  const initialApkHandled = useRef(false)
  const prevApk = useRef<string | null>(null)
  useEffect(() => {
    // Skip reset on first render and when set by deep-link
    if (prevApk.current !== null && prevApk.current !== selectedApk && selectedApk !== initialApk) {
      setManifestResult(null)
      setBytecodeResult(null)
      setSastResult(null)
      setManifestPhase(INITIAL_PHASE)
      setBytecodePhase(INITIAL_PHASE)
      setSastPhase(INITIAL_PHASE)
    }
    prevApk.current = selectedApk
  }, [selectedApk, initialApk])

  // ── Derived state ──
  const isAnyScanning = batchScanning ||
    manifestPhase.status === 'scanning' ||
    bytecodePhase.status === 'scanning' ||
    sastPhase.status === 'scanning'

  const hasAnyResult = manifestResult != null || bytecodeResult != null || sastResult != null

  // ── Scan handlers ──

  const runManifestScan = useCallback(async () => {
    if (!projectId || !selectedFirmwareId || !selectedApk) return
    setManifestPhase({ status: 'scanning' })
    setManifestResult(null)
    startTimer('manifest')
    try {
      const result = await scanApkManifest(projectId, selectedFirmwareId, selectedApk, true, minSeverity)
      setManifestResult(result)
      setManifestPhase({
        status: result.error ? 'error' : 'complete',
        error: result.error || undefined,
        elapsedMs: result.elapsed_ms ?? undefined,
      })
    } catch (e) {
      setManifestPhase({
        status: 'error',
        error: extractErrorMessage(e, 'Manifest scan failed'),
      })
    } finally {
      stopTimer('manifest')
    }
  }, [projectId, selectedFirmwareId, selectedApk, minSeverity, startTimer, stopTimer])

  const runBytecodeScan = useCallback(async () => {
    if (!projectId || !selectedFirmwareId || !selectedApk) return
    setBytecodePhase({ status: 'scanning' })
    setBytecodeResult(null)
    startTimer('bytecode')
    try {
      const result = await scanApkBytecode(projectId, selectedFirmwareId, selectedApk, minSeverity)
      setBytecodeResult(result)
      setBytecodePhase({
        status: result.error ? 'error' : 'complete',
        error: result.error || undefined,
        elapsedMs: result.elapsed_seconds != null ? result.elapsed_seconds * 1000 : undefined,
      })
    } catch (e) {
      setBytecodePhase({
        status: 'error',
        error: extractErrorMessage(e, 'Bytecode scan failed'),
      })
    } finally {
      stopTimer('bytecode')
    }
  }, [projectId, selectedFirmwareId, selectedApk, minSeverity, startTimer, stopTimer])

  const runSastScan = useCallback(async () => {
    if (!projectId || !selectedFirmwareId || !selectedApk) return
    setSastPhase({ status: 'scanning' })
    setSastResult(null)
    startTimer('sast')
    try {
      const result = await scanApkSast(projectId, selectedFirmwareId, selectedApk, {
        minSeverity,
      })
      setSastResult(result)
      setSastPhase({
        status: result.error ? 'error' : 'complete',
        error: result.error || undefined,
        elapsedMs: result.timing?.total_elapsed_ms ?? undefined,
      })
    } catch (e) {
      setSastPhase({
        status: 'error',
        error: extractErrorMessage(e, 'SAST scan failed'),
      })
    } finally {
      stopTimer('sast')
    }
  }, [projectId, selectedFirmwareId, selectedApk, minSeverity, startTimer, stopTimer])

  // Load cached results for an APK (no re-scan, just fetch from cache)
  const loadCachedResults = useCallback(async (apk: string) => {
    if (!projectId || !selectedFirmwareId) return

    setManifestPhase({ status: 'scanning' })
    setBytecodePhase({ status: 'scanning' })
    setSastPhase({ status: 'scanning' })
    setManifestResult(null)
    setBytecodeResult(null)
    setSastResult(null)

    const result = await scanApkAll(projectId, selectedFirmwareId, apk, { minSeverity })

    if (result.manifest) {
      setManifestResult(result.manifest)
      setManifestPhase({
        status: result.manifest.error ? 'error' : 'complete',
        error: result.manifest.error || undefined,
        elapsedMs: result.manifest.elapsed_ms ?? undefined,
      })
    } else {
      setManifestPhase({ status: 'idle' })
    }

    if (result.bytecode) {
      setBytecodeResult(result.bytecode)
      setBytecodePhase({
        status: result.bytecode.error ? 'error' : 'complete',
        error: result.bytecode.error || undefined,
        elapsedMs: result.bytecode.elapsed_seconds != null
          ? result.bytecode.elapsed_seconds * 1000
          : undefined,
      })
    } else {
      setBytecodePhase({ status: 'idle' })
    }

    if (result.sast) {
      setSastResult(result.sast)
      setSastPhase({
        status: result.sast.error ? 'error' : 'complete',
        error: result.sast.error || undefined,
        elapsedMs: result.sast.timing?.total_elapsed_ms ?? undefined,
      })
    } else {
      setSastPhase({ status: 'idle' })
    }
  }, [projectId, selectedFirmwareId, minSeverity])

  // Auto-select and load results when navigated to with an APK parameter
  useEffect(() => {
    if (initialApk && !initialApkHandled.current && selectedFirmwareId) {
      initialApkHandled.current = true
      setSelectedApk(initialApk)
      // Delay to let React process the selectedApk state before loading
      setTimeout(() => loadCachedResults(initialApk), 0)
    }
  }, [initialApk, selectedFirmwareId, loadCachedResults])

  const runAllScans = useCallback(async () => {
    if (!projectId || !selectedFirmwareId || !selectedApk) return

    // Reset all phases
    setManifestPhase({ status: 'scanning' })
    setBytecodePhase({ status: 'scanning' })
    setSastPhase({ status: 'scanning' })
    setManifestResult(null)
    setBytecodeResult(null)
    setSastResult(null)
    startTimer('manifest')
    startTimer('bytecode')
    startTimer('sast')

    // Use Promise.allSettled via the API client for concurrent execution
    const result = await scanApkAll(projectId, selectedFirmwareId, selectedApk, {
      minSeverity,
    })

    // Update manifest
    if (result.manifest) {
      setManifestResult(result.manifest)
      setManifestPhase({
        status: result.manifest.error ? 'error' : 'complete',
        error: result.manifest.error || undefined,
        elapsedMs: result.manifest.elapsed_ms ?? undefined,
      })
    } else {
      setManifestPhase({ status: 'error', error: 'Manifest scan failed' })
    }
    stopTimer('manifest')

    // Update bytecode
    if (result.bytecode) {
      setBytecodeResult(result.bytecode)
      setBytecodePhase({
        status: result.bytecode.error ? 'error' : 'complete',
        error: result.bytecode.error || undefined,
        elapsedMs: result.bytecode.elapsed_seconds != null
          ? result.bytecode.elapsed_seconds * 1000
          : undefined,
      })
    } else {
      setBytecodePhase({ status: 'error', error: 'Bytecode scan failed' })
    }
    stopTimer('bytecode')

    // Update SAST
    if (result.sast) {
      setSastResult(result.sast)
      setSastPhase({
        status: result.sast.error ? 'error' : 'complete',
        error: result.sast.error || undefined,
        elapsedMs: result.sast.timing?.total_elapsed_ms ?? undefined,
      })
    } else {
      setSastPhase({ status: 'error', error: 'SAST scan failed' })
    }
    stopTimer('sast')
  }, [projectId, selectedFirmwareId, selectedApk, minSeverity, startTimer, stopTimer])

  // ── APK path display helper ──
  const apkShortName = useCallback((path: string) => {
    const parts = path.split('/')
    return parts[parts.length - 1] || path
  }, [])

  // ── Batch scan ──
  const toggleApkCheck = useCallback((apk: string) => {
    setCheckedApks((prev) => {
      const next = new Set(prev)
      if (next.has(apk)) next.delete(apk)
      else next.add(apk)
      return next
    })
  }, [])

  const toggleAllApks = useCallback(() => {
    if (checkedApks.size === apkFiles.length) {
      setCheckedApks(new Set())
    } else {
      setCheckedApks(new Set(apkFiles))
    }
  }, [checkedApks.size, apkFiles])

  const runBatchScan = useCallback(async () => {
    if (!projectId || !selectedFirmwareId || checkedApks.size === 0) return
    const apksToScan = [...checkedApks]
    setBatchScanning(true)
    setBatchProgress({ current: 0, total: apksToScan.length, currentApk: '', results: [] })

    const results: typeof batchProgress extends null ? never : NonNullable<typeof batchProgress>['results'] = []

    for (let i = 0; i < apksToScan.length; i++) {
      const apk = apksToScan[i]
      setBatchProgress((prev) => prev ? { ...prev, current: i, currentApk: apk } : prev)

      const entry: { apk: string; manifest: number; bytecode: number; sast: number; errors: string[] } = {
        apk, manifest: 0, bytecode: 0, sast: 0, errors: [],
      }

      try {
        const result = await scanApkAll(projectId, selectedFirmwareId, apk, { minSeverity })
        entry.manifest = result.manifest?.findings?.length ?? 0
        entry.bytecode = result.bytecode?.findings?.length ?? 0
        entry.sast = result.sast?.findings?.length ?? 0
        if (result.manifest?.error) entry.errors.push(`manifest: ${result.manifest.error}`)
        if (result.bytecode?.error) entry.errors.push(`bytecode: ${result.bytecode.error}`)
        if (result.sast?.error) entry.errors.push(`sast: ${result.sast.error}`)
      } catch (err) {
        entry.errors.push(`scan failed: ${err}`)
      }

      results.push(entry)
      setBatchProgress((prev) => prev ? { ...prev, current: i + 1, results: [...results] } : prev)
    }

    setBatchScanning(false)
  }, [projectId, selectedFirmwareId, checkedApks, minSeverity])

  const apkParentDir = useCallback((path: string) => {
    const parts = path.split('/')
    if (parts.length <= 1) return ''
    return parts.slice(0, -1).join('/')
  }, [])

  // Group APKs by directory for better UX
  const groupedApks = useMemo(() => {
    const groups = new Map<string, string[]>()
    for (const apk of apkFiles) {
      const dir = apkParentDir(apk)
      const existing = groups.get(dir) || []
      existing.push(apk)
      groups.set(dir, existing)
    }
    return Array.from(groups.entries()).sort(([a], [b]) => a.localeCompare(b))
  }, [apkFiles, apkParentDir])

  // ── No firmware selected ──
  if (!selectedFirmwareId) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <Package className="h-12 w-12 mx-auto mb-3 opacity-30" />
        <p className="text-sm">Select a firmware to scan APK files.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* ── APK discovery & selection ── */}
      <Card>
        <CardContent className="py-3 px-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Package className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">APK Files</span>
              {!discoveryLoading && (
                <span className="text-xs text-muted-foreground">
                  ({apkFiles.length} found)
                </span>
              )}
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={discoverApks}
              disabled={discoveryLoading}
              className="h-7 text-xs"
            >
              {discoveryLoading ? (
                <Loader2 className="mr-1 h-3 w-3 animate-spin" />
              ) : (
                <RefreshCw className="mr-1 h-3 w-3" />
              )}
              Refresh
            </Button>
          </div>

          {discoveryError && (
            <div className="flex items-center gap-2 text-sm text-destructive">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              {discoveryError}
            </div>
          )}

          {discoveryLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
              <Loader2 className="h-4 w-4 animate-spin" />
              Discovering APK files in firmware...
            </div>
          ) : apkFiles.length === 0 ? (
            <p className="text-sm text-muted-foreground py-1">
              No APK files found in this firmware image.
            </p>
          ) : (
            <>
              {/* Selected APK display */}
              {selectedApk && (
                <div className="flex items-center gap-2 rounded-md bg-primary/5 border border-primary/20 px-3 py-2">
                  <FileCode className="h-4 w-4 text-primary shrink-0" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium truncate">{apkShortName(selectedApk)}</p>
                    <p className="text-xs text-muted-foreground truncate">{selectedApk}</p>
                  </div>
                </div>
              )}

              {/* Expandable APK list (shown when multiple APKs) */}
              {apkFiles.length > 1 && (
                <div>
                  <button
                    type="button"
                    onClick={() => setApkListExpanded(!apkListExpanded)}
                    className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {apkListExpanded ? (
                      <ChevronDown className="h-3 w-3" />
                    ) : (
                      <ChevronRight className="h-3 w-3" />
                    )}
                    {apkListExpanded ? 'Hide' : 'Show'} all {apkFiles.length} APK files
                  </button>

                  {apkListExpanded && (
                    <>
                      {/* Batch controls */}
                      <div className="mt-2 flex items-center gap-2 flex-wrap">
                        <button
                          type="button"
                          onClick={toggleAllApks}
                          className="text-xs text-primary hover:underline"
                        >
                          {checkedApks.size === apkFiles.length ? 'Deselect All' : 'Select All'}
                        </button>
                        {checkedApks.size > 0 && (
                          <>
                            <span className="text-xs text-muted-foreground">
                              {checkedApks.size} selected
                            </span>
                            <Button
                              size="sm"
                              className="h-6 text-xs"
                              onClick={runBatchScan}
                              disabled={batchScanning}
                            >
                              {batchScanning ? (
                                <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                              ) : (
                                <Play className="mr-1 h-3 w-3" />
                              )}
                              Scan {checkedApks.size} APK{checkedApks.size > 1 ? 's' : ''}
                            </Button>
                          </>
                        )}
                      </div>

                      <div className="mt-2 max-h-64 overflow-y-auto space-y-1 border rounded-md p-2 bg-muted/30">
                        {groupedApks.map(([dir, files]) => (
                          <div key={dir}>
                            {groupedApks.length > 1 && dir && (
                              <p className="text-xs text-muted-foreground font-mono mt-1 mb-0.5 px-1">
                                {dir}/
                              </p>
                            )}
                            {files.map((apk) => (
                              <div key={apk} className="flex items-center gap-1.5">
                                <input
                                  type="checkbox"
                                  checked={checkedApks.has(apk)}
                                  onChange={() => toggleApkCheck(apk)}
                                  className="h-3 w-3 rounded border-muted-foreground/30"
                                />
                                <button
                                  type="button"
                                  onClick={() => {
                                    setSelectedApk(apk)
                                    setApkListExpanded(false)
                                  }}
                                  className={`flex-1 text-left rounded px-2 py-1 text-xs font-mono truncate transition-colors ${
                                    selectedApk === apk
                                      ? 'bg-primary/10 text-primary'
                                      : 'text-foreground hover:bg-accent/50'
                                  }`}
                                >
                                  {apkShortName(apk)}
                                </button>
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* ── Batch scan progress ── */}
      {batchProgress && (
        <Card>
          <CardContent className="py-3 px-4 space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="font-medium">
                {batchScanning ? 'Batch Scanning...' : 'Batch Scan Complete'}
              </span>
              <span className="font-mono text-xs text-muted-foreground">
                {batchProgress.current}/{batchProgress.total}
              </span>
            </div>
            <div className="h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-primary rounded-full transition-all duration-300"
                style={{ width: `${(batchProgress.current / batchProgress.total) * 100}%` }}
              />
            </div>
            {batchScanning && batchProgress.currentApk && (
              <p className="text-xs text-muted-foreground font-mono truncate">
                Scanning: {batchProgress.currentApk}
              </p>
            )}
            {batchProgress.results.length > 0 && (
              <div className="max-h-48 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-muted-foreground border-b">
                      <th className="text-left py-1 pr-2 font-medium">APK</th>
                      <th className="text-right py-1 px-1 font-medium">Manifest</th>
                      <th className="text-right py-1 px-1 font-medium">Bytecode</th>
                      <th className="text-right py-1 px-1 font-medium">SAST</th>
                      <th className="text-right py-1 pl-1 font-medium">Total</th>
                    </tr>
                  </thead>
                  <tbody>
                    {batchProgress.results.map((r) => {
                      const total = r.manifest + r.bytecode + r.sast
                      return (
                        <tr
                          key={r.apk}
                          className="border-b border-border/30 hover:bg-muted/50 cursor-pointer"
                          onClick={() => {
                            setSelectedApk(r.apk)
                            setApkListExpanded(false)
                            loadCachedResults(r.apk)
                          }}
                        >
                          <td className="py-1 pr-2 font-mono truncate max-w-[200px]">
                            {apkShortName(r.apk)}
                            {r.errors.length > 0 && (
                              <span title={r.errors.join('\n')}>
                                {r.errors.every((e) => e.includes('No decompiled sources') || e.includes('no output')) ? (
                                  <span className="inline-block ml-1 text-[10px] text-muted-foreground" title="No DEX code to scan (resource-only APK)">
                                    (no code)
                                  </span>
                                ) : (
                                  <AlertTriangle className="inline ml-1 h-3 w-3 text-yellow-500" />
                                )}
                              </span>
                            )}
                          </td>
                          <td className="text-right py-1 px-1">{r.manifest || '-'}</td>
                          <td className="text-right py-1 px-1">{r.bytecode || '-'}</td>
                          <td className="text-right py-1 px-1">{r.sast || '-'}</td>
                          <td className="text-right py-1 pl-1 font-semibold">{total || '-'}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                  {!batchScanning && batchProgress.results.length > 0 && (
                    <tfoot>
                      <tr className="border-t font-semibold text-xs">
                        <td className="py-1 pr-2">
                          Total ({batchProgress.results.length} APKs)
                        </td>
                        <td className="text-right py-1 px-1">
                          {batchProgress.results.reduce((s, r) => s + r.manifest, 0)}
                        </td>
                        <td className="text-right py-1 px-1">
                          {batchProgress.results.reduce((s, r) => s + r.bytecode, 0)}
                        </td>
                        <td className="text-right py-1 px-1">
                          {batchProgress.results.reduce((s, r) => s + r.sast, 0)}
                        </td>
                        <td className="text-right py-1 pl-1">
                          {batchProgress.results.reduce((s, r) => s + r.manifest + r.bytecode + r.sast, 0)}
                        </td>
                      </tr>
                    </tfoot>
                  )}
                </table>
              </div>
            )}
            {!batchScanning && (
              <button
                type="button"
                onClick={() => setBatchProgress(null)}
                className="text-xs text-muted-foreground hover:text-foreground"
              >
                Dismiss
              </button>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Scan controls ── */}
      {selectedApk && (
        <Card>
          <CardContent className="py-3 px-4 space-y-3">
            {/* Run All button + severity threshold */}
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3">
                <Button
                  onClick={runAllScans}
                  disabled={isAnyScanning}
                  className="gap-2"
                >
                  {isAnyScanning ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="h-4 w-4" />
                  )}
                  {isAnyScanning ? 'Scanning...' : 'Run All Scans'}
                </Button>
                <p className="text-xs text-muted-foreground hidden sm:block">
                  Runs manifest + bytecode + SAST scans concurrently
                </p>
              </div>

              {/* Severity threshold selector */}
              <div className="flex items-center gap-2">
                <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                <label htmlFor="severity-threshold" className="text-xs text-muted-foreground whitespace-nowrap">
                  Min severity:
                </label>
                <select
                  id="severity-threshold"
                  value={minSeverity}
                  onChange={(e) => setMinSeverity(e.target.value)}
                  disabled={isAnyScanning}
                  className="h-7 rounded-md border border-input bg-background px-2 py-0.5 text-xs ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {SEVERITY_THRESHOLD_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Individual phase controls */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {(['manifest', 'bytecode', 'sast'] as const).map((phase) => {
                const meta = PHASE_META[phase]
                const state = phase === 'manifest' ? manifestPhase
                  : phase === 'bytecode' ? bytecodePhase
                  : sastPhase
                const handler = phase === 'manifest' ? runManifestScan
                  : phase === 'bytecode' ? runBytecodeScan
                  : runSastScan
                const Icon = meta.icon

                return (
                  <PhaseCard
                    key={phase}
                    phase={phase}
                    label={meta.label}
                    description={meta.description}
                    estimate={meta.estimate}
                    icon={Icon}
                    iconColor={meta.color}
                    state={state}
                    elapsedMs={elapsedTimers[phase]}
                    isScanning={state.status === 'scanning'}
                    disabled={isAnyScanning}
                    onRun={handler}
                  />
                )
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Results ── */}
      {selectedApk && (hasAnyResult || isAnyScanning) && (
        <>
        <SecurityScanResults
          manifest={manifestResult}
          bytecode={bytecodeResult}
          sast={sastResult}
          packageName={manifestResult?.package || bytecodeResult?.package}
          firmwareContext={
            manifestResult?.firmware_context ||
            bytecodeResult?.firmware_context ||
            sastResult?.firmware_context
          }
          isScanning={isAnyScanning}
          onViewSource={handleViewSource}
          initialFinding={initialFinding}
        />

        {/* Source viewer panel */}
        {sourceLoading && (
          <Card>
            <CardContent className="py-4 flex items-center gap-2 text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              Loading decompiled source...
            </CardContent>
          </Card>
        )}
        {sourceView && (
          <Card>
            <CardContent className="py-3 px-4">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-semibold font-mono">
                  {sourceView.source.path}
                  <span className="text-muted-foreground font-normal ml-2">
                    ({sourceView.source.line_count} lines)
                  </span>
                </h3>
                <button
                  type="button"
                  className="text-xs text-muted-foreground hover:text-foreground"
                  onClick={() => setSourceView(null)}
                >
                  Close
                </button>
              </div>
              <pre className="text-xs font-mono bg-muted/50 rounded p-3 max-h-[500px] overflow-auto whitespace-pre leading-5">
                {sourceView.source.source.split('\n').map((line, i) => {
                  const lineNum = i + 1
                  const isHighlighted = lineNum === sourceView.highlightLine
                  return (
                    <div
                      key={lineNum}
                      className={isHighlighted ? 'bg-yellow-200/30 -mx-3 px-3' : ''}
                      id={isHighlighted ? 'highlighted-line' : undefined}
                    >
                      <span className="inline-block w-10 text-right mr-4 text-muted-foreground select-none">
                        {lineNum}
                      </span>
                      {line}
                    </div>
                  )
                })}
              </pre>
            </CardContent>
          </Card>
        )}
        </>
      )}

      {/* Empty state */}
      {selectedApk && !hasAnyResult && !isAnyScanning && (
        <div className="text-center py-8 text-muted-foreground">
          <ShieldCheck className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">
            Click &ldquo;Run All Scans&rdquo; to perform multi-phase APK security analysis.
          </p>
          <p className="text-xs mt-1">
            Manifest checks ({PHASE_META.manifest.estimate}) + Bytecode patterns ({PHASE_META.bytecode.estimate}) + SAST analysis ({PHASE_META.sast.estimate})
          </p>
        </div>
      )}
    </div>
  )
}

// ── Phase Card ──

interface PhaseCardProps {
  phase: ScanPhase
  label: string
  description: string
  estimate: string
  icon: React.ElementType
  iconColor: string
  state: PhaseState
  elapsedMs: number
  isScanning: boolean
  disabled: boolean
  onRun: () => void
}

function PhaseCard({
  label,
  description,
  estimate,
  icon: Icon,
  iconColor,
  state,
  elapsedMs,
  isScanning,
  disabled,
  onRun,
}: PhaseCardProps) {
  return (
    <div className="rounded-lg border bg-card p-3 space-y-2">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className={`h-4 w-4 ${iconColor}`} />
          <span className="text-sm font-medium">{label}</span>
        </div>
        <PhaseStatusBadge status={state.status} />
      </div>

      {/* Description */}
      <p className="text-xs text-muted-foreground line-clamp-2">{description}</p>

      {/* Elapsed / estimate */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground flex items-center gap-1">
          <Clock className="h-3 w-3" />
          {isScanning ? (
            <span className="font-mono">{formatElapsed(elapsedMs)}</span>
          ) : state.elapsedMs != null ? (
            <span className="font-mono">{formatElapsed(state.elapsedMs)}</span>
          ) : (
            <span>Est. {estimate}</span>
          )}
        </span>

        <Button
          variant="outline"
          size="sm"
          className="h-7 text-xs gap-1"
          onClick={onRun}
          disabled={disabled}
        >
          {isScanning ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Play className="h-3 w-3" />
          )}
          {isScanning ? 'Running...' : 'Run'}
        </Button>
      </div>

      {/* Error display */}
      {state.error && (
        <div className="text-xs text-destructive flex items-start gap-1 mt-1">
          <AlertTriangle className="h-3 w-3 shrink-0 mt-0.5" />
          <span className="truncate" title={state.error}>{state.error}</span>
        </div>
      )}
    </div>
  )
}

// ── Phase Status Badge ──

function PhaseStatusBadge({ status }: { status: PhaseStatus }) {
  switch (status) {
    case 'idle':
      return (
        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
          <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/40" />
          Idle
        </span>
      )
    case 'scanning':
      return (
        <span className="inline-flex items-center gap-1 text-xs text-blue-500">
          <Loader2 className="h-3 w-3 animate-spin" />
          Scanning
        </span>
      )
    case 'complete':
      return (
        <span className="inline-flex items-center gap-1 text-xs text-green-500">
          <CheckCircle2 className="h-3 w-3" />
          Complete
        </span>
      )
    case 'error':
      return (
        <span className="inline-flex items-center gap-1 text-xs text-destructive">
          <XCircle className="h-3 w-3" />
          Error
        </span>
      )
  }
}

// ── Helpers ──

function formatElapsed(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  const mins = Math.floor(ms / 60000)
  const secs = Math.round((ms % 60000) / 1000)
  return `${mins}m ${secs}s`
}
