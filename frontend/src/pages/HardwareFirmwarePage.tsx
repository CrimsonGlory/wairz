import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  AlertTriangle,
  Cpu,
  Download,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { apiUrl } from '@/api/config'
import {
  getCveAggregate,
  getCveMatchStatus,
  getFirmwareDrivers,
  getHardwareFirmwareBlob,
  getHardwareFirmwareCves,
  listHardwareFirmware,
  listHardwareFirmwareCves,
  runCveMatch,
  type CveAggregate,
  type CveRow,
  type FirmwareCveMatch,
  type FirmwareDriver,
  type HardwareFirmwareBlob,
} from '@/api/hardwareFirmware'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import { useProjectStore } from '@/stores/projectStore'
import { extractErrorMessage } from '@/utils/error'
import FirmwareSelector from '@/components/projects/FirmwareSelector'
import StatsHeader from '@/components/hardware-firmware/StatsHeader'
import BlobFilters from '@/components/hardware-firmware/BlobFilters'
import BlobTable from '@/components/hardware-firmware/BlobTable'
import BlobDetail from '@/components/hardware-firmware/BlobDetail'
import DriversTable from '@/components/hardware-firmware/DriversTable'
import PartitionTree, {
  matchesQuery,
} from '@/components/hardware-firmware/PartitionTree'
import DriverGraph from '@/components/hardware-firmware/DriverGraph'
import CvesTab from '@/components/hardware-firmware/CvesTab'

export default function HardwareFirmwarePage() {
  const { projectId } = useParams<{ projectId: string }>()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)

  const { firmwareList } = useFirmwareList(projectId)
  const [blobs, setBlobs] = useState<HardwareFirmwareBlob[]>([])
  const [drivers, setDrivers] = useState<FirmwareDriver[]>([])
  const [cveRows, setCveRows] = useState<CveRow[]>([])
  const [cveRowsLoading, setCveRowsLoading] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [category, setCategory] = useState<string | null>(null)
  const [vendor, setVendor] = useState<string | null>(null)
  const [signedOnly, setSignedOnly] = useState(false)
  const [hideKernelModules, setHideKernelModules] = useState(true)
  const [dedupeBySha, setDedupeBySha] = useState(true)
  // Stat-card filters — mutually exclusive drill-ins.  Mapped to visibleBlobs
  // predicates below.
  const [focus, setFocus] = useState<'none' | 'cves' | 'kernel_cves' | 'not_signed'>('none')
  // Active tab as controlled state so focus-clicks can move the user to
  // the right view (e.g. "Kernel CVEs" card lands in Flat table because
  // kernel-module blobs aren't pretty in the Tree).
  const [activeTab, setActiveTab] = useState<'tree' | 'blobs' | 'cves' | 'drivers' | 'graph'>('tree')
  const [treeSortMode, setTreeSortMode] = useState<'blobs' | 'cves'>('blobs')

  const [selectedBlobId, setSelectedBlobId] = useState<string | null>(null)
  const [blobDetail, setBlobDetail] = useState<HardwareFirmwareBlob | null>(null)
  const [blobCves, setBlobCves] = useState<FirmwareCveMatch[]>([])
  const [cveLoading, setCveLoading] = useState(false)

  const [running, setRunning] = useState(false)
  const [runResult, setRunResult] = useState<string | null>(null)
  const [cveAggregate, setCveAggregate] = useState<CveAggregate | null>(null)

  // Debounced search — typing into the input updates `searchDraft`
  // immediately for responsiveness, and propagates to `searchQuery`
  // 200 ms later to drive the filter / highlight pipeline.
  const [searchDraft, setSearchDraft] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const searchTimeoutRef = useRef<number | null>(null)
  useEffect(() => {
    if (searchTimeoutRef.current !== null) {
      window.clearTimeout(searchTimeoutRef.current)
    }
    searchTimeoutRef.current = window.setTimeout(() => {
      setSearchQuery(searchDraft)
    }, 200)
    return () => {
      if (searchTimeoutRef.current !== null) {
        window.clearTimeout(searchTimeoutRef.current)
      }
    }
  }, [searchDraft])

  // Load firmware list for selector

  // Load blobs + drivers + firmware-wide CVE aggregate + CVE-centric rows
  // whenever the project / firmware / filters change.  The aggregate +
  // flat CVEs are cheap read-only counts so the header badge + CVEs tab
  // render on page load without re-running the matcher.  Filters don't
  // apply to the aggregate -- it's always firmware-wide.
  const loadAll = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    setCveRowsLoading(true)
    setError(null)
    try {
      const [blobsResp, driversResp, aggResp, cvesResp] = await Promise.all([
        listHardwareFirmware(projectId, {
          firmwareId: selectedFirmwareId,
          category: category ?? undefined,
          vendor: vendor ?? undefined,
          signedOnly,
        }),
        getFirmwareDrivers(projectId, selectedFirmwareId).catch(() => ({
          drivers: [] as FirmwareDriver[],
          total: 0,
        })),
        getCveAggregate(projectId, selectedFirmwareId).catch(() => null),
        listHardwareFirmwareCves(projectId, selectedFirmwareId).catch(() => ({
          cves: [] as CveRow[],
          total: 0,
        })),
      ])
      setBlobs(blobsResp.blobs)
      setDrivers(driversResp.drivers)
      setCveAggregate(aggResp)
      setCveRows(cvesResp.cves)
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to load hardware firmware data'))
    } finally {
      setLoading(false)
      setCveRowsLoading(false)
    }
  }, [projectId, selectedFirmwareId, category, vendor, signedOnly])

  useEffect(() => {
    loadAll()
  }, [loadAll])

  // Load detail + CVEs when a blob is selected
  useEffect(() => {
    if (!projectId || !selectedBlobId) {
      setBlobDetail(null)
      setBlobCves([])
      return
    }
    let cancelled = false
    setCveLoading(true)
    Promise.all([
      getHardwareFirmwareBlob(projectId, selectedBlobId, selectedFirmwareId),
      getHardwareFirmwareCves(projectId, selectedBlobId, selectedFirmwareId).catch(
        () => [] as FirmwareCveMatch[],
      ),
    ])
      .then(([blob, cves]) => {
        if (cancelled) return
        setBlobDetail(blob)
        setBlobCves(cves)
      })
      .catch((err) => {
        if (cancelled) return
        setBlobDetail(null)
        setBlobCves([])
        setError(extractErrorMessage(err, 'Failed to load blob detail'))
      })
      .finally(() => {
        if (!cancelled) setCveLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [projectId, selectedBlobId, selectedFirmwareId])

  const handleRunCveMatch = useCallback(async () => {
    if (!projectId) return
    setRunning(true)
    setRunResult(null)
    try {
      // Rule #29 202+polling: POST returns immediately with status="queued"
      // and the matcher runs detached on the backend. Poll every 2 s until
      // the status flips to "completed" (read .result for the aggregate)
      // or "failed" (surface .error).
      await runCveMatch(projectId, {
        forceRescan: false,
        firmwareId: selectedFirmwareId,
      })

      const POLL_INTERVAL_MS = 2000
      // 15-minute ceiling — well past the observed 7-minute Yocto runtime
      // so we never bail before the backend declares terminal status, but
      // bounded so a runaway matcher can't pin the spinner forever.
      const POLL_DEADLINE_MS = 15 * 60 * 1000
      const deadline = Date.now() + POLL_DEADLINE_MS
      let snapshot: Awaited<ReturnType<typeof getCveMatchStatus>> | null = null
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS))
        snapshot = await getCveMatchStatus(projectId, selectedFirmwareId)
        if (snapshot.status === 'completed' || snapshot.status === 'failed') {
          break
        }
      }
      if (!snapshot || (snapshot.status !== 'completed' && snapshot.status !== 'failed')) {
        setError('CVE matcher polling timed out — refresh to see the latest state.')
        return
      }
      if (snapshot.status === 'failed') {
        setError(snapshot.error ?? 'CVE matcher failed')
        return
      }
      const aggregate = snapshot.result
      if (aggregate) {
        const distinct = aggregate.count ?? 0
        const hwfw = aggregate.hw_firmware_cves ?? distinct
        const kernel = aggregate.kernel_cves ?? 0
        const kmodRows = aggregate.kernel_module_rows ?? 0
        const parts: string[] = []
        if (hwfw > 0) parts.push(`${hwfw} hw-firmware`)
        if (kernel > 0) parts.push(`${kernel} kernel (${kmodRows} projection rows across kmod blobs)`)
        const breakdown = parts.length ? ` — ${parts.join(', ')}` : ''
        setRunResult(`Found ${distinct} distinct CVE(s)${breakdown}.`)
      }
      // Refresh the list and any selected blob's CVEs.
      await loadAll()
      if (selectedBlobId) {
        const cves = await getHardwareFirmwareCves(
          projectId,
          selectedBlobId,
          selectedFirmwareId,
        ).catch(() => [] as FirmwareCveMatch[])
        setBlobCves(cves)
      }
    } catch (err) {
      setError(extractErrorMessage(err, 'CVE matcher failed'))
    } finally {
      setRunning(false)
    }
  }, [projectId, selectedFirmwareId, selectedBlobId, loadAll])

  // Client-side filtering — apply kernel-module hide + sha dedup + focus
  // filter on top of the server's category/vendor/signed filters, plus
  // an optional text search that applies to every tab.
  const visibleBlobs = useMemo(() => {
    let list = blobs
    // Focus card: "Kernel CVEs" narrows to kernel_module blobs and
    // overrides the hide-kernel-modules default so the user actually
    // sees them when drilling from that card.
    const kernelFocus = focus === 'kernel_cves'
    if (hideKernelModules && !kernelFocus) {
      list = list.filter((b) => b.category !== 'kernel_module')
    }
    if (dedupeBySha) {
      const seen = new Set<string>()
      list = list.filter((b) => {
        if (seen.has(b.blob_sha256)) return false
        seen.add(b.blob_sha256)
        return true
      })
    }
    if (focus === 'cves') {
      list = list.filter((b) => b.cve_count > 0)
    } else if (focus === 'kernel_cves') {
      list = list.filter(
        (b) => b.category === 'kernel_module' && b.cve_count > 0,
      )
    } else if (focus === 'not_signed') {
      list = list.filter(
        (b) =>
          b.signed === 'unsigned' ||
          b.signed === 'weakly_signed' ||
          b.signed === 'unknown',
      )
    }
    if (searchQuery.trim()) {
      list = list.filter((b) => matchesQuery(b, searchQuery.trim().toLowerCase()))
    }
    return list
  }, [blobs, hideKernelModules, dedupeBySha, focus, searchQuery])

  // Derived values (from the POST-FILTER list so stats match what the user sees)
  const totalBlobs = visibleBlobs.length
  const kernelModuleCount = useMemo(
    () => blobs.filter((b) => b.category === 'kernel_module').length,
    [blobs],
  )
  const hiddenDupCount = blobs.length - visibleBlobs.length - (hideKernelModules && focus !== 'kernel_cves' ? kernelModuleCount : 0)
  const notSignedCount = useMemo(
    () =>
      visibleBlobs.filter(
        (b) => b.signed === 'unsigned' || b.signed === 'weakly_signed' || b.signed === 'unknown',
      ).length,
    [visibleBlobs],
  )
  const vendorCount = useMemo(() => {
    const set = new Set<string>()
    for (const b of visibleBlobs) {
      if (b.vendor) set.add(b.vendor)
    }
    return set.size
  }, [visibleBlobs])
  const cveCount = blobCves.length

  const categories = useMemo(() => {
    const set = new Set<string>()
    for (const b of blobs) set.add(b.category)
    return [...set].sort()
  }, [blobs])

  const vendors = useMemo(() => {
    const set = new Set<string>()
    for (const b of blobs) {
      if (b.vendor) set.add(b.vendor)
    }
    return [...set].sort()
  }, [blobs])

  // Build the HBOM download URL.  The endpoint streams JSON directly, so
  // an anchor tag with `download` lets the browser save it without a
  // blob-URL round-trip through axios.
  const hbomUrl = useMemo(() => {
    if (!projectId) return '#'
    const base = apiUrl(`/api/v1/projects/${projectId}/hardware-firmware/cdx.json`)
    return selectedFirmwareId
      ? `${base}?firmware_id=${encodeURIComponent(selectedFirmwareId)}`
      : base
  }, [projectId, selectedFirmwareId])

  const hbomTooltip = useMemo(() => {
    const cveCountForHbom = cveAggregate
      ? cveAggregate.hw_firmware_cves + cveAggregate.kernel_cves
      : 0
    return `CycloneDX v1.6 JSON · ${blobs.length} blobs · ${cveCountForHbom} CVEs`
  }, [blobs.length, cveAggregate])

  const handleFocus = useCallback(
    (next: typeof focus) => {
      setFocus((prev) => (prev === next ? 'none' : next))
      // Land on the most useful view for the clicked card.
      if (next === 'cves') {
        setActiveTab('tree')
        setTreeSortMode('cves')
      } else if (next === 'kernel_cves') {
        setActiveTab('blobs')
      } else if (next === 'not_signed') {
        setActiveTab('blobs')
      }
    },
    [],
  )

  if (!projectId) {
    return null
  }

  if (loading && blobs.length === 0) {
    return (
      <div className="flex h-[calc(100vh-8rem)] items-center justify-center text-muted-foreground">
        <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        <span className="text-sm">Loading hardware firmware...</span>
      </div>
    )
  }

  const hasData = totalBlobs > 0

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <Cpu className="h-6 w-6 text-muted-foreground" />
          <div>
            <h1 className="text-lg font-semibold">Hardware Firmware</h1>
            <p className="text-sm text-muted-foreground">
              Vendor firmware blobs (modem, TEE, MCU, Wi-Fi, BT, GPU, DSP, camera, audio, NFC, sensor &amp; more),
              drivers, and six-tier CVE matching.
            </p>
          </div>
        </div>
        <div className="flex min-w-0 items-center gap-2">
          <FirmwareSelector projectId={projectId} firmwareList={firmwareList} className="min-w-0 max-w-xs" />
          <Button
            variant="outline"
            size="sm"
            onClick={handleRunCveMatch}
            disabled={running || !hasData}
          >
            {running ? (
              <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <ShieldAlert className="mr-1.5 h-3.5 w-3.5" />
            )}
            Run CVE match
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!hasData}
            asChild
            title={hbomTooltip}
          >
            <a
              href={hbomUrl}
              download={`hbom-${selectedFirmwareId ?? projectId}.cdx.json`}
            >
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Export HBOM
            </a>
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={loadAll}
            disabled={loading}
            title="Reload blobs and drivers"
          >
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      {runResult && (
        <div className="rounded-md border border-border bg-muted/30 px-3 py-2 text-xs">
          {runResult}
        </div>
      )}

      {error && (
        <div className="flex items-start gap-2 rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-600 dark:text-red-400">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {!hasData && focus === 'none' && searchQuery.trim() === '' ? (
        <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border p-10 text-center text-sm text-muted-foreground">
          <Cpu className="h-6 w-6 text-muted-foreground" />
          <p>No hardware firmware detected.</p>
          <p className="text-xs">
            Upload an Android firmware image to trigger automatic detection.
          </p>
        </div>
      ) : (
        <>
          <StatsHeader
            totalBlobs={totalBlobs}
            notSignedCount={notSignedCount}
            vendorCount={vendorCount}
            hardwareCveCount={cveAggregate?.hw_firmware_cves ?? 0}
            kernelCveCount={cveAggregate?.kernel_cves ?? 0}
            selectedBlobCveCount={selectedBlobId ? cveCount : undefined}
            advisoryCount={cveAggregate?.advisory_count ?? 0}
            severityCritical={cveAggregate?.hw_severity_critical ?? 0}
            severityHigh={cveAggregate?.hw_severity_high ?? 0}
            severityMedium={cveAggregate?.hw_severity_medium ?? 0}
            severityLow={cveAggregate?.hw_severity_low ?? 0}
            onHardwareCvesClick={() => handleFocus('cves')}
            onKernelCvesClick={() => handleFocus('kernel_cves')}
            onNotSignedClick={() => handleFocus('not_signed')}
            hardwareCvesActive={focus === 'cves'}
            kernelCvesActive={focus === 'kernel_cves'}
            notSignedActive={focus === 'not_signed'}
          />

          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[240px] max-w-md">
                <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search path, format, vendor, version, CVE…"
                  value={searchDraft}
                  onChange={(e) => setSearchDraft(e.target.value)}
                  className="h-8 w-full rounded-md border bg-background pl-8 pr-8 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
                />
                {searchDraft && (
                  <button
                    type="button"
                    onClick={() => setSearchDraft('')}
                    aria-label="Clear search"
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
              {focus !== 'none' && (
                <button
                  type="button"
                  onClick={() => setFocus('none')}
                  className="rounded-full border border-border px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-accent/30"
                >
                  Clear focus: {focus.replace('_', ' ')} ×
                </button>
              )}
            </div>

            <BlobFilters
              categories={categories}
              vendors={vendors}
              category={category}
              vendor={vendor}
              signedOnly={signedOnly}
              onCategory={setCategory}
              onVendor={setVendor}
              onSignedOnly={setSignedOnly}
            />
            <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
              <label className="inline-flex cursor-pointer items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={hideKernelModules}
                  onChange={(e) => setHideKernelModules(e.target.checked)}
                  className="h-3.5 w-3.5"
                />
                <span>
                  Hide kernel modules
                  {kernelModuleCount > 0 && (
                    <span className="ml-1 opacity-70">({kernelModuleCount})</span>
                  )}
                </span>
              </label>
              <label className="inline-flex cursor-pointer items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={dedupeBySha}
                  onChange={(e) => setDedupeBySha(e.target.checked)}
                  className="h-3.5 w-3.5"
                />
                <span>
                  Dedupe by SHA-256
                  {hiddenDupCount > 0 && (
                    <span className="ml-1 opacity-70">({hiddenDupCount} hidden)</span>
                  )}
                </span>
              </label>
              <label className="inline-flex cursor-pointer items-center gap-1.5">
                <span>Tree sort:</span>
                <select
                  value={treeSortMode}
                  onChange={(e) =>
                    setTreeSortMode(e.target.value as 'blobs' | 'cves')
                  }
                  className="h-6 rounded border bg-background px-1 text-[11px] focus:outline-none focus:ring-1 focus:ring-ring"
                >
                  <option value="blobs">Blob count (largest first)</option>
                  <option value="cves">CVE count (most findings first)</option>
                </select>
              </label>
            </div>
          </div>

          <Tabs
            value={activeTab}
            onValueChange={(v) =>
              setActiveTab(v as 'tree' | 'blobs' | 'cves' | 'drivers' | 'graph')
            }
            className="w-full"
          >
            <TabsList>
              <TabsTrigger value="tree">Tree ({totalBlobs})</TabsTrigger>
              <TabsTrigger value="blobs">Flat table ({totalBlobs})</TabsTrigger>
              <TabsTrigger value="cves">
                CVEs ({cveRows.length})
              </TabsTrigger>
              <TabsTrigger value="drivers">Drivers ({drivers.length})</TabsTrigger>
              <TabsTrigger value="graph">Driver graph</TabsTrigger>
            </TabsList>

            <TabsContent value="tree" className="pt-3">
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_minmax(360px,440px)]">
                <PartitionTree
                  blobs={visibleBlobs}
                  selectedId={selectedBlobId}
                  onSelect={setSelectedBlobId}
                  searchQuery={searchQuery}
                  sortMode={treeSortMode}
                />
                <BlobDetail
                  blob={blobDetail}
                  cves={blobCves}
                  loading={cveLoading}
                  projectId={projectId}
                  firmwareId={selectedFirmwareId}
                />
              </div>
            </TabsContent>

            <TabsContent value="blobs" className="pt-3">
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_minmax(360px,440px)]">
                <BlobTable
                  blobs={visibleBlobs}
                  selectedId={selectedBlobId}
                  onSelect={setSelectedBlobId}
                  searchQuery={searchQuery}
                />
                <BlobDetail
                  blob={blobDetail}
                  cves={blobCves}
                  loading={cveLoading}
                  projectId={projectId}
                  firmwareId={selectedFirmwareId}
                />
              </div>
            </TabsContent>

            <TabsContent value="cves" className="pt-3">
              <CvesTab
                cves={cveRows}
                blobs={blobs}
                loading={cveRowsLoading}
                searchQuery={searchQuery}
                onSelectBlob={(id) => {
                  setSelectedBlobId(id)
                  setActiveTab('tree')
                }}
              />
            </TabsContent>

            <TabsContent value="drivers" className="pt-3">
              <DriversTable drivers={drivers} />
            </TabsContent>

            <TabsContent value="graph" className="pt-3">
              <DriverGraph projectId={projectId} firmwareId={selectedFirmwareId} />
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  )
}
