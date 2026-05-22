import { useCallback, useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Loader2,
  CheckCircle,
  XCircle,
  ChevronDown,
  ChevronUp,
  Smartphone,
  HardDrive,
  AlertCircle,
  ArrowRight,
  ArrowLeft,
  Download,
  RefreshCw,
  Square,
  ShieldCheck,
  ShieldAlert,
  Shield,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import {
  getDeviceBridgeStatus,
  listDevices,
  getDeviceInfo,
  startDump,
  getDumpStatus,
  cancelDump,
  importDump,
} from '@/api/device'
import { extractErrorMessage } from '@/utils/error'
import { formatFileSize } from '@/utils/format'
import type {
  BridgeStatus,
  DeviceInfo,
  DeviceDetail,
  DumpStatus,
  PartitionStatus,
} from '@/types/device'

const STEPS = ['Connect Bridge', 'Select Device', 'Dump Progress', 'Summary & Import'] as const

const DEFAULT_CHECKED_PARTITIONS = ['boot', 'super', 'system', 'vendor', 'boot_a', 'boot_b']

const PARTITION_STATUS_VARIANT: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  pending: 'outline',
  active: 'secondary',
  complete: 'default',
  failed: 'destructive',
  skipped: 'outline',
}

export default function DeviceAcquisitionPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()

  const [step, setStep] = useState(0)
  const [error, setError] = useState<string | null>(null)

  // Step 1: Bridge
  const [bridgeStatus, setBridgeStatus] = useState<BridgeStatus | null>(null)
  const [showSetup, setShowSetup] = useState(false)

  // Step 2: Device selection
  const [devices, setDevices] = useState<DeviceInfo[]>([])
  const [loadingDevices, setLoadingDevices] = useState(false)
  const [selectedDevice, setSelectedDevice] = useState<DeviceInfo | null>(null)
  const [deviceDetail, setDeviceDetail] = useState<DeviceDetail | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [selectedPartitions, setSelectedPartitions] = useState<Set<string>>(new Set())

  // Step 3: Dump progress
  const [dumpStatus, setDumpStatus] = useState<DumpStatus | null>(null)
  // Captured from POST /dumps's 202 ack; used for status polling, cancel,
  // and import. Persists for the duration of the wizard run.
  const [activeDumpId, setActiveDumpId] = useState<string | null>(null)
  const [cancelling, setCancelling] = useState(false)

  // Step 4: Import
  const [importing, setImporting] = useState(false)
  const [versionLabel, setVersionLabel] = useState('')

  // -- Step 1: Poll bridge status --
  const pollBridge = useCallback(async () => {
    if (!projectId) return
    try {
      const status = await getDeviceBridgeStatus(projectId)
      setBridgeStatus(status)
    } catch (e) {
      setBridgeStatus({
        connected: false,
        bridge_host: null,
        bridge_port: null,
        error: extractErrorMessage(e, 'Failed to check bridge status'),
      })
    }
  }, [projectId])

  useEffect(() => {
    if (step !== 0) return
    pollBridge()
    const interval = setInterval(pollBridge, 2000)
    return () => clearInterval(interval)
  }, [step, pollBridge])

  // -- Step 2: Fetch devices --
  const fetchDevices = useCallback(async () => {
    if (!projectId) return
    setLoadingDevices(true)
    setError(null)
    try {
      const devs = await listDevices(projectId)
      setDevices(devs)
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Failed to list devices'))
    } finally {
      setLoadingDevices(false)
    }
  }, [projectId])

  useEffect(() => {
    if (step === 1) {
      fetchDevices()
    }
  }, [step, fetchDevices])

  const handleSelectDevice = async (device: DeviceInfo) => {
    if (!projectId) return
    setSelectedDevice(device)
    setLoadingDetail(true)
    setError(null)
    try {
      const detail = await getDeviceInfo(projectId, device.serial)
      setDeviceDetail(detail)
      // Smart defaults for partition selection
      const defaults = new Set<string>()
      for (const p of detail.partitions) {
        if (DEFAULT_CHECKED_PARTITIONS.some((d) => p.toLowerCase().includes(d))) {
          defaults.add(p)
        }
      }
      setSelectedPartitions(defaults)
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Failed to get device info'))
    } finally {
      setLoadingDetail(false)
    }
  }

  const togglePartition = (partition: string) => {
    setSelectedPartitions((prev) => {
      const next = new Set(prev)
      if (next.has(partition)) {
        next.delete(partition)
      } else {
        next.add(partition)
      }
      return next
    })
  }

  // -- Step 3: Start dump and poll --
  const handleStartDump = async () => {
    if (!projectId || !selectedDevice) return
    setError(null)
    try {
      const status = await startDump(projectId, selectedDevice.serial, Array.from(selectedPartitions))
      setActiveDumpId(status.dump_id)
      setDumpStatus(status)
      setStep(2)
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Failed to start dump'))
    }
  }

  const pollDump = useCallback(async () => {
    if (!projectId || !activeDumpId) return
    try {
      const status = await getDumpStatus(projectId, activeDumpId)
      setDumpStatus(status)
      // Auto-advance when the dump reaches a successful terminal state.
      // 'completed' or 'partial' both mean at least one partition
      // finished — user can still import. 'failed' / 'cancelled' stay
      // on the progress page so the operator can see what went wrong.
      if (status.status === 'completed' || status.status === 'partial') {
        setStep(3)
      }
    } catch {
      // ignore transient errors
    }
  }, [projectId, activeDumpId])

  useEffect(() => {
    if (step !== 2) return
    // Bumped 1000 → 2000ms on 2026-05-22 (over-constraint sweep). Rule #33
    // prescribes 2s polling for 202+polling endpoints (firmware-unpack
    // precedent). 1s on a 30-min full-flash dump = 1800 GETs vs ~900 at
    // 2s — pure server-load reduction with no UX gain (operator can't
    // perceive sub-2s progress updates on partition dumps).
    const interval = setInterval(pollDump, 2000)
    return () => clearInterval(interval)
  }, [step, pollDump])

  const handleCancelDump = async () => {
    if (!projectId || !activeDumpId) return
    setCancelling(true)
    try {
      const status = await cancelDump(projectId, activeDumpId)
      setDumpStatus(status)
    } catch {
      // ignore
    } finally {
      setCancelling(false)
    }
  }

  // -- Step 4: Import --
  const handleImport = async () => {
    if (!projectId || !selectedDevice || !activeDumpId) return
    setImporting(true)
    setError(null)
    try {
      const result = await importDump(
        projectId,
        activeDumpId,
        selectedDevice.serial,
        versionLabel.trim() || undefined,
      )
      navigate(`/projects/${projectId}`, {
        state: { importedFirmwareId: result.firmware_id },
      })
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Failed to import dump'))
    } finally {
      setImporting(false)
    }
  }

  const handleReset = () => {
    setStep(0)
    setSelectedDevice(null)
    setDeviceDetail(null)
    setSelectedPartitions(new Set())
    setDumpStatus(null)
    setActiveDumpId(null)
    setError(null)
    setVersionLabel('')
  }

  // -- Helpers --
  const metadata = deviceDetail?.device_metadata ?? {}
  const getprop = deviceDetail?.getprop ?? {}

  const getSecurityIndicator = (key: string, goodValue: string) => {
    const val = getprop[key]
    if (val === undefined) return null
    const isGood = val === goodValue
    return { key, value: val, isGood }
  }

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="border-b border-border bg-background px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold">Device Acquisition</h1>
            <p className="text-sm text-muted-foreground">
              Dump firmware partitions from Android devices via ADB or MediaTek BROM
            </p>
          </div>
          <div className="text-sm text-muted-foreground">
            Step {step + 1} of {STEPS.length}: {STEPS[step]}
          </div>
        </div>
        {/* Step indicator */}
        <div className="mt-3 flex gap-1">
          {STEPS.map((_, i) => (
            <div
              key={i}
              className={`h-1 flex-1 rounded-full transition-colors ${
                i <= step ? 'bg-primary' : 'bg-muted'
              }`}
            />
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-2xl space-y-6">
          {error && (
            <div className="flex items-start gap-2 rounded-md bg-destructive/10 border border-destructive/20 px-3 py-2 text-sm text-destructive">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
              {error}
            </div>
          )}

          {/* ===== STEP 0: Connect Bridge ===== */}
          {step === 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Device Bridge Connection</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-3">
                  {bridgeStatus?.connected ? (
                    <>
                      <CheckCircle className="h-5 w-5 text-green-500" />
                      <div>
                        <p className="text-sm font-medium text-green-600">Bridge Connected</p>
                        <p className="text-xs text-muted-foreground">
                          {bridgeStatus.bridge_host}:{bridgeStatus.bridge_port}
                        </p>
                      </div>
                    </>
                  ) : (
                    <>
                      <XCircle className="h-5 w-5 text-red-500" />
                      <div>
                        <p className="text-sm font-medium text-red-600">Bridge Disconnected</p>
                        {bridgeStatus?.error && (
                          <p className="text-xs text-muted-foreground">{bridgeStatus.error}</p>
                        )}
                      </div>
                    </>
                  )}
                </div>

                {!bridgeStatus?.connected && (
                  <>
                    <button
                      onClick={() => setShowSetup(!showSetup)}
                      className="flex items-center gap-1 text-sm text-primary hover:underline"
                    >
                      {showSetup ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      Setup Instructions
                    </button>
                    {showSetup && (
                      <div className="rounded-md bg-muted/50 p-4 text-sm space-y-3">
                        <p className="font-medium">1. Start the bridge on your host machine:</p>
                        <pre className="rounded bg-background p-2 text-xs font-mono overflow-x-auto">
                          python3 scripts/wairz-device-bridge.py --bind 0.0.0.0 --port 9998
                        </pre>
                        <p className="font-medium">2. Allow Docker traffic:</p>
                        <pre className="rounded bg-background p-2 text-xs font-mono overflow-x-auto">
                          sudo iptables -I INPUT -i docker0 -p tcp --dport 9998 -j ACCEPT
                        </pre>
                      </div>
                    )}
                  </>
                )}

                <div className="flex justify-end">
                  <Button
                    onClick={() => setStep(1)}
                    disabled={!bridgeStatus?.connected}
                  >
                    Next
                    <ArrowRight className="ml-1.5 h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* ===== STEP 1: Select Device & Partitions ===== */}
          {step === 1 && (
            <>
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">Connected Devices</CardTitle>
                    <Button variant="outline" size="sm" onClick={fetchDevices} disabled={loadingDevices}>
                      <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${loadingDevices ? 'animate-spin' : ''}`} />
                      Refresh
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  {loadingDevices && devices.length === 0 && (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Scanning for devices...
                    </div>
                  )}
                  {!loadingDevices && devices.length === 0 && (
                    <p className="text-sm text-muted-foreground">
                      No devices found. Connect an Android device via USB (ADB authorized) or put a MediaTek device in BROM mode (power off, hold Vol Down, connect USB).
                    </p>
                  )}
                  {devices.map((dev) => {
                    const mode = dev.mode ?? undefined
                    const isMtk = mode === 'brom' || mode === 'preloader'
                    const mtkAvailable = dev.available !== false
                    const mtkError = dev.error ?? undefined
                    return (
                      <button
                        key={dev.serial}
                        onClick={() => mtkAvailable ? handleSelectDevice(dev) : undefined}
                        disabled={!mtkAvailable}
                        className={`w-full rounded-md border p-3 text-left transition-colors ${
                          selectedDevice?.serial === dev.serial
                            ? 'border-primary bg-primary/5'
                            : !mtkAvailable
                              ? 'border-border opacity-60 cursor-not-allowed'
                              : 'border-border hover:border-primary/50'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          {isMtk ? (
                            <HardDrive className="h-5 w-5 text-orange-500 shrink-0" />
                          ) : (
                            <Smartphone className="h-5 w-5 text-muted-foreground shrink-0" />
                          )}
                          <div className="min-w-0">
                            <p className="text-sm font-medium truncate">
                              {dev.model ?? dev.device ?? 'Unknown Device'}
                            </p>
                            <p className="text-xs text-muted-foreground font-mono">{dev.serial}</p>
                            {mtkError && (
                              <p className="text-xs text-destructive mt-0.5">{mtkError}</p>
                            )}
                          </div>
                          <div className="ml-auto flex items-center gap-1.5 shrink-0">
                            {isMtk && (
                              <Badge variant="outline" className="text-xs border-orange-500/50 text-orange-600">
                                BROM
                              </Badge>
                            )}
                            <Badge variant={dev.state === 'device' ? 'default' : isMtk ? 'secondary' : 'secondary'} className="text-xs">
                              {isMtk ? (mode ?? 'brom').toUpperCase() : dev.state}
                            </Badge>
                          </div>
                        </div>
                      </button>
                    )
                  })}
                </CardContent>
              </Card>

              {/* Device detail + partition selection */}
              {loadingDetail && (
                <div className="flex items-center gap-2 justify-center py-4 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Loading device info...
                </div>
              )}

              {deviceDetail && !loadingDetail && (
                <>
                  {/* Device metadata preview */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Device Info</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {Object.keys(getprop).length > 0 ? (
                        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                          {getprop['ro.product.model'] && (
                            <>
                              <dt className="text-muted-foreground">Model</dt>
                              <dd className="font-medium">{getprop['ro.product.model']}</dd>
                            </>
                          )}
                          {getprop['ro.build.version.release'] && (
                            <>
                              <dt className="text-muted-foreground">Android Version</dt>
                              <dd className="font-medium">{getprop['ro.build.version.release']}</dd>
                            </>
                          )}
                          {getprop['ro.build.version.security_patch'] && (
                            <>
                              <dt className="text-muted-foreground">Security Patch</dt>
                              <dd className="font-medium">{getprop['ro.build.version.security_patch']}</dd>
                            </>
                          )}
                          {getprop['ro.hardware.chipname'] && (
                            <>
                              <dt className="text-muted-foreground">Chipset</dt>
                              <dd className="font-medium">{getprop['ro.hardware.chipname']}</dd>
                            </>
                          )}
                          {getprop['ro.product.manufacturer'] && (
                            <>
                              <dt className="text-muted-foreground">Manufacturer</dt>
                              <dd className="font-medium">{getprop['ro.product.manufacturer']}</dd>
                            </>
                          )}
                        </dl>
                      ) : (
                        <div className="space-y-2 text-sm">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-xs border-orange-500/50 text-orange-600">BROM</Badge>
                            <span className="text-muted-foreground">MediaTek device in BootROM mode</span>
                          </div>
                          {deviceDetail.chipset && (
                            <dl className="grid grid-cols-2 gap-x-4 gap-y-1">
                              <dt className="text-muted-foreground">Chipset</dt>
                              <dd className="font-medium font-mono">{deviceDetail.chipset}</dd>
                            </dl>
                          )}
                          <p className="text-xs text-muted-foreground">
                            Device properties are not available in BROM mode. Partition table loaded from GPT.
                          </p>
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  {/* Partition selection */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">
                        Partitions ({selectedPartitions.size} of {deviceDetail.partitions.length} selected)
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {/* Preset buttons */}
                      <div className="flex flex-wrap gap-2">
                        <span className="text-xs text-muted-foreground self-center">Presets:</span>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => {
                            const minimal = deviceDetail.partitions.filter((p) =>
                              ['boot', 'super', 'boot_a', 'boot_b'].some((d) => p.toLowerCase().includes(d))
                            )
                            setSelectedPartitions(new Set(minimal))
                          }}
                        >
                          Minimal
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => {
                            const standard = deviceDetail.partitions.filter((p) =>
                              ['boot', 'super', 'system', 'vendor', 'product', 'boot_a', 'boot_b'].some((d) => p.toLowerCase().includes(d))
                            )
                            setSelectedPartitions(new Set(standard))
                          }}
                        >
                          Standard
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => {
                            const full = deviceDetail.partitions.filter((p) =>
                              !p.toLowerCase().includes('userdata')
                            )
                            setSelectedPartitions(new Set(full))
                          }}
                        >
                          Full (no userdata)
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs"
                          onClick={() => setSelectedPartitions(new Set())}
                        >
                          Clear
                        </Button>
                      </div>
                      <div className="grid grid-cols-2 gap-2 max-h-64 overflow-y-auto">
                        {deviceDetail.partitions.map((p) => {
                          const sizeInfo = deviceDetail.partition_sizes?.find((s) => s.name === p)
                          return (
                            <label
                              key={p}
                              className="flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-muted/50 cursor-pointer"
                            >
                              <Checkbox
                                checked={selectedPartitions.has(p)}
                                onCheckedChange={() => togglePartition(p)}
                              />
                              <HardDrive className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                              <span className="truncate font-mono text-xs">{p}</span>
                              {sizeInfo?.size != null && (
                                <span className="ml-auto text-[10px] text-muted-foreground/60 shrink-0">
                                  {formatFileSize(sizeInfo.size)}
                                </span>
                              )}
                            </label>
                          )
                        })}
                      </div>
                      {deviceDetail.partitions.length === 0 && (
                        <p className="text-sm text-muted-foreground">No partitions detected.</p>
                      )}
                    </CardContent>
                  </Card>
                </>
              )}

              <div className="flex justify-between">
                <Button variant="outline" onClick={() => setStep(0)}>
                  <ArrowLeft className="mr-1.5 h-4 w-4" />
                  Back
                </Button>
                <Button
                  onClick={handleStartDump}
                  disabled={!selectedDevice || selectedPartitions.size === 0}
                >
                  Start Dump
                  <ArrowRight className="ml-1.5 h-4 w-4" />
                </Button>
              </div>
            </>
          )}

          {/* ===== STEP 2: Dump Progress ===== */}
          {step === 2 && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">Dump Progress</CardTitle>
                  {dumpStatus && (
                    <Badge
                      variant={
                        dumpStatus.status === 'completed' ? 'default' :
                        dumpStatus.status === 'failed' || dumpStatus.status === 'cancelled' ? 'destructive' :
                        'secondary'
                      }
                    >
                      {(dumpStatus.status === 'queued' || dumpStatus.status === 'running') && (
                        <Loader2 className="mr-1 h-3 w-3 animate-spin" />
                      )}
                      {dumpStatus.status}
                    </Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {dumpStatus?.error && (
                  <div className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
                    <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    {dumpStatus.error}
                  </div>
                )}

                <div className="rounded-md border border-border">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border bg-muted/30">
                        <th className="px-3 py-2 text-left font-medium text-muted-foreground">Partition</th>
                        <th className="px-3 py-2 text-left font-medium text-muted-foreground">Status</th>
                        <th className="px-3 py-2 text-left font-medium text-muted-foreground min-w-[140px]">Progress</th>
                        <th className="px-3 py-2 text-right font-medium text-muted-foreground">Written</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(dumpStatus?.partitions ?? []).map((p: PartitionStatus) => (
                        <tr key={p.partition} className="border-b border-border/50 last:border-0">
                          <td className="px-3 py-2 font-mono text-xs">{p.partition}</td>
                          <td className="px-3 py-2">
                            <Badge variant={PARTITION_STATUS_VARIANT[p.status] ?? 'outline'} className="text-xs">
                              {p.status === 'active' && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}
                              {p.status}
                            </Badge>
                          </td>
                          <td className="px-3 py-2">
                            {p.status === 'active' && p.total_bytes && p.total_bytes > 0 ? (
                              <div className="space-y-1">
                                <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                                  <div
                                    className="h-full rounded-full bg-primary transition-all duration-300"
                                    style={{ width: `${Math.min(p.progress_percent ?? 0, 100)}%` }}
                                  />
                                </div>
                                <div className="flex justify-between text-[10px] text-muted-foreground">
                                  <span>{(p.progress_percent ?? 0).toFixed(1)}%</span>
                                  {p.throughput_mbps != null && <span>{p.throughput_mbps.toFixed(1)} MB/s</span>}
                                </div>
                              </div>
                            ) : p.status === 'complete' ? (
                              <span className="text-xs text-muted-foreground">100%</span>
                            ) : p.status === 'active' ? (
                              <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                                <div className="h-full w-1/3 rounded-full bg-primary/50 animate-pulse" />
                              </div>
                            ) : (
                              <span className="text-xs text-muted-foreground">-</span>
                            )}
                          </td>
                          <td className="px-3 py-2 text-right text-xs text-muted-foreground whitespace-nowrap">
                            {p.bytes_written > 0 ? (
                              <>
                                {formatFileSize(p.bytes_written)}
                                {p.total_bytes != null && p.total_bytes > 0 && (
                                  <span className="text-muted-foreground/50"> / {formatFileSize(p.total_bytes)}</span>
                                )}
                              </>
                            ) : '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="flex justify-end">
                  <Button
                    variant="destructive"
                    onClick={handleCancelDump}
                    disabled={
                      cancelling ||
                      !(dumpStatus?.status === 'queued' || dumpStatus?.status === 'running')
                    }
                  >
                    {cancelling ? (
                      <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                    ) : (
                      <Square className="mr-1.5 h-4 w-4" />
                    )}
                    Cancel Dump
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* ===== STEP 3: Summary & Import ===== */}
          {step === 3 && (
            <>
              {/* Device metadata */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Device Summary</CardTitle>
                </CardHeader>
                <CardContent>
                  <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                    {getprop['ro.product.model'] && (
                      <>
                        <dt className="text-muted-foreground">Model</dt>
                        <dd className="font-medium">{getprop['ro.product.model']}</dd>
                      </>
                    )}
                    {getprop['ro.build.version.release'] && (
                      <>
                        <dt className="text-muted-foreground">Android Version</dt>
                        <dd className="font-medium">{getprop['ro.build.version.release']}</dd>
                      </>
                    )}
                    {getprop['ro.build.version.security_patch'] && (
                      <>
                        <dt className="text-muted-foreground">Security Patch</dt>
                        <dd className="font-medium">{getprop['ro.build.version.security_patch']}</dd>
                      </>
                    )}
                    {getprop['ro.hardware.chipname'] && (
                      <>
                        <dt className="text-muted-foreground">Chipset</dt>
                        <dd className="font-medium">{getprop['ro.hardware.chipname']}</dd>
                      </>
                    )}
                    {(getprop['ro.bootloader'] || !!metadata['bootloader']) && (
                      <>
                        <dt className="text-muted-foreground">Bootloader</dt>
                        <dd className="font-medium">
                          {getprop['ro.bootloader'] ?? String(metadata['bootloader'])}
                        </dd>
                      </>
                    )}
                  </dl>
                </CardContent>
              </Card>

              {/* Security posture */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Security Posture</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {[
                    getSecurityIndicator('ro.secure', '1'),
                    getSecurityIndicator('ro.debuggable', '0'),
                    getSecurityIndicator('ro.boot.verifiedbootstate', 'green'),
                  ].filter(Boolean).map((ind) => ind && (
                    <div key={ind.key} className="flex items-center gap-2 text-sm">
                      {ind.isGood ? (
                        <ShieldCheck className="h-4 w-4 text-green-500" />
                      ) : (
                        <ShieldAlert className="h-4 w-4 text-amber-500" />
                      )}
                      <span className="text-muted-foreground font-mono text-xs">{ind.key}</span>
                      <span className="font-medium">{ind.value}</span>
                      <Badge variant={ind.isGood ? 'default' : 'secondary'} className="text-xs ml-auto">
                        {ind.isGood ? 'secure' : 'relaxed'}
                      </Badge>
                    </div>
                  ))}
                  {[
                    getSecurityIndicator('ro.secure', '1'),
                    getSecurityIndicator('ro.debuggable', '0'),
                    getSecurityIndicator('ro.boot.verifiedbootstate', 'green'),
                  ].every((v) => v === null) && (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <Shield className="h-4 w-4" />
                      No security properties available
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Partition results */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Partition Results</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="rounded-md border border-border">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border bg-muted/30">
                          <th className="px-3 py-2 text-left font-medium text-muted-foreground">Partition</th>
                          <th className="px-3 py-2 text-left font-medium text-muted-foreground">Status</th>
                          <th className="px-3 py-2 text-right font-medium text-muted-foreground">Size</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(dumpStatus?.partitions ?? []).map((p: PartitionStatus) => (
                          <tr key={p.partition} className="border-b border-border/50 last:border-0">
                            <td className="px-3 py-2 font-mono text-xs">{p.partition}</td>
                            <td className="px-3 py-2">
                              <Badge variant={PARTITION_STATUS_VARIANT[p.status] ?? 'outline'} className="text-xs">
                                {p.status}
                              </Badge>
                            </td>
                            <td className="px-3 py-2 text-right text-xs text-muted-foreground">
                              {p.bytes_written > 0 ? formatFileSize(p.bytes_written) : '-'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>

              {/* Import section */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Import to Project</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <label className="mb-1 block text-xs font-medium text-muted-foreground">
                      Version Label (optional)
                    </label>
                    <input
                      type="text"
                      value={versionLabel}
                      onChange={(e) => setVersionLabel(e.target.value)}
                      placeholder="e.g. factory-dump-2026-04"
                      className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                    />
                  </div>
                  <div className="flex gap-3">
                    <Button onClick={handleImport} disabled={importing}>
                      {importing ? (
                        <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                      ) : (
                        <Download className="mr-1.5 h-4 w-4" />
                      )}
                      Import to Project
                    </Button>
                    <Button variant="outline" onClick={handleReset}>
                      <RefreshCw className="mr-1.5 h-4 w-4" />
                      Start New Dump
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
