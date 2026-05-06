import { useEffect, useMemo, useState, type CSSProperties } from 'react'
import { useParams } from 'react-router-dom'
import {
  GitCompareArrows,
  Loader2,
  Plus,
  Minus,
  FileEdit,
  Lock,
  Binary,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  Package,
  ArrowRightLeft,
  Code,
  Download,
} from 'lucide-react'
import { List, type RowComponentProps } from 'react-window'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import { useResponsiveListHeight } from '@/hooks/useResponsiveListHeight'
import { diffFirmware, diffBinary, diffTextFile, diffInstructions, diffDecompilation } from '@/api/comparison'
import { formatFileSize } from '@/utils/format'
import { extractErrorMessage } from '@/utils/error'
import type { FirmwareDiff, BinaryDiff, TextDiff, InstructionDiff, DecompilationDiff, FileDiffEntry } from '@/types'

/**
 * Fixed row height for the virtualized file-diff table.  Rows are one line
 * of py-1.5 + text-xs content; ~28-30px measured, padded to 32 to avoid
 * fused borders on recycled rows.
 */
const FILE_DIFF_ROW_HEIGHT = 32

/**
 * Column template shared between the header and each virtualized row so
 * the (path, status, sizeA, sizeB, delta, sha) columns stay aligned.
 */
const FILE_DIFF_COLUMN_TEMPLATE =
  'minmax(260px, 2.4fr) 96px 80px 80px 64px minmax(160px, 1fr)'

type Tab = 'files' | 'binaries' | 'binary-detail' | 'text-diff'

export default function ComparisonPage() {
  const { projectId } = useParams<{ projectId: string }>()

  const { firmwareList: allFirmware } = useFirmwareList(projectId)
  // ComparisonPage only makes sense for unpacked firmware.
  const firmwareList = allFirmware.filter((fw) => fw.extracted_path)
  const [fwAId, setFwAId] = useState('')
  const [fwBId, setFwBId] = useState('')
  const [loading, setLoading] = useState(false)
  const [fsDiff, setFsDiff] = useState<FirmwareDiff | null>(null)
  const [binDiff, setBinDiff] = useState<BinaryDiff | null>(null)
  const [binLoading, setBinLoading] = useState(false)
  const [textDiff, setTextDiff] = useState<TextDiff | null>(null)
  const [textLoading, setTextLoading] = useState(false)
  const [tab, setTab] = useState<Tab>('files')
  const { ref: fileDiffWrapperRef, height: fileDiffHeight } = useResponsiveListHeight({
    maxHeight: 640,
    minHeight: 240,
  })
  const [error, setError] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [expandedFunc, setExpandedFunc] = useState<string | null>(null)
  const [instrDiff, setInstrDiff] = useState<InstructionDiff | null>(null)
  const [instrLoading, setInstrLoading] = useState(false)
  const [importsExpanded, setImportsExpanded] = useState(false)
  const [exportsExpanded, setExportsExpanded] = useState(false)
  const [decompDiff, setDecompDiff] = useState<DecompilationDiff | null>(null)
  const [decompLoading, setDecompLoading] = useState(false)
  const [decompFunc, setDecompFunc] = useState<string | null>(null)

  // Auto-select the first two unpacked firmware once the list loads.
  // Runs on projectId transitions and when invalidation repopulates.
  useEffect(() => {
    if (!fwAId && !fwBId && firmwareList.length >= 2) {
      setFwAId(firmwareList[0].id)
      setFwBId(firmwareList[1].id)
    }
  }, [firmwareList, fwAId, fwBId])

  const handleCompare = async () => {
    if (!projectId || !fwAId || !fwBId) return
    setLoading(true)
    setError(null)
    setFsDiff(null)
    setBinDiff(null)
    setTab('files')
    try {
      const result = await diffFirmware(projectId, fwAId, fwBId)
      setFsDiff(result)
    } catch (e) {
      setError(extractErrorMessage(e, 'Comparison failed'))
    } finally {
      setLoading(false)
    }
  }

  const handleBinaryDiff = async (path: string) => {
    if (!projectId || !fwAId || !fwBId) return
    setBinLoading(true)
    setBinDiff(null)
    setExpandedFunc(null)
    setInstrDiff(null)
    setDecompFunc(null)
    setDecompDiff(null)
    setImportsExpanded(false)
    setExportsExpanded(false)
    setTab('binary-detail')
    try {
      const result = await diffBinary(projectId, fwAId, fwBId, path)
      setBinDiff(result)
    } catch {
      // ignore
    } finally {
      setBinLoading(false)
    }
  }

  const handleTextDiff = async (path: string) => {
    if (!projectId || !fwAId || !fwBId) return
    setTextLoading(true)
    setTextDiff(null)
    setTab('text-diff')
    try {
      const result = await diffTextFile(projectId, fwAId, fwBId, path)
      setTextDiff(result)
    } catch {
      // ignore
    } finally {
      setTextLoading(false)
    }
  }

  const handleInstrDiff = async (functionName: string) => {
    if (expandedFunc === functionName) {
      setExpandedFunc(null)
      setInstrDiff(null)
      return
    }
    if (!projectId || !fwAId || !fwBId || !binDiff) return
    setExpandedFunc(functionName)
    setInstrDiff(null)
    setInstrLoading(true)
    try {
      const result = await diffInstructions(projectId, fwAId, fwBId, binDiff.binary_path, functionName)
      setInstrDiff(result)
    } catch (e) {
      setInstrDiff({
        function_name: functionName,
        arch: '',
        diff_text: '',
        lines_added: 0,
        lines_removed: 0,
        error: extractErrorMessage(e, 'Failed to load instruction diff'),
      })
    } finally {
      setInstrLoading(false)
    }
  }

  const handleDecompDiff = async (functionName: string) => {
    if (decompFunc === functionName) {
      setDecompFunc(null)
      setDecompDiff(null)
      return
    }
    if (!projectId || !fwAId || !fwBId || !binDiff) return
    setDecompFunc(functionName)
    setDecompDiff(null)
    setDecompLoading(true)
    try {
      const result = await diffDecompilation(projectId, fwAId, fwBId, binDiff.binary_path, functionName)
      setDecompDiff(result)
    } catch (e) {
      setDecompDiff({
        function_name: functionName,
        binary_path: binDiff.binary_path,
        source_a: '',
        source_b: '',
        diff_text: '',
        lines_added: 0,
        lines_removed: 0,
        error: extractErrorMessage(e, 'Failed to load decompilation diff'),
      })
    } finally {
      setDecompLoading(false)
    }
  }

  const handleDownloadReport = () => {
    if (!fsDiff) return
    const report = {
      generated_at: new Date().toISOString(),
      firmware_a: { id: fwAId, filename: fwALabel?.original_filename },
      firmware_b: { id: fwBId, filename: fwBLabel?.original_filename },
      summary: {
        added: fsDiff.added.length,
        removed: fsDiff.removed.length,
        modified: fsDiff.modified.length,
        permissions_changed: fsDiff.permissions_changed.length,
        total_files_a: fsDiff.total_files_a,
        total_files_b: fsDiff.total_files_b,
      },
      filesystem_diff: {
        added: fsDiff.added,
        removed: fsDiff.removed,
        modified: fsDiff.modified,
        permissions_changed: fsDiff.permissions_changed,
      },
      ...(binDiff ? { binary_diff: binDiff } : {}),
      ...(textDiff ? { text_diff: textDiff } : {}),
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const nameA = fwALabel?.original_filename?.replace(/\.[^.]+$/, '') || fwAId.slice(0, 8)
    const nameB = fwBLabel?.original_filename?.replace(/\.[^.]+$/, '') || fwBId.slice(0, 8)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `comparison-${nameA}-vs-${nameB}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const fwALabel = firmwareList.find((fw) => fw.id === fwAId)
  const fwBLabel = firmwareList.find((fw) => fw.id === fwBId)

  const allEntries = useMemo<FileDiffEntry[]>(() =>
    fsDiff ? [...fsDiff.added, ...fsDiff.removed, ...fsDiff.modified, ...fsDiff.permissions_changed] : [],
    [fsDiff]
  )
  const filteredEntries = useMemo(() =>
    statusFilter === 'all' ? allEntries : allEntries.filter((e) => e.status === statusFilter),
    [allEntries, statusFilter]
  )

  // Identify modified ELF binaries (likely binaries: in /bin, /sbin, /usr/bin, /usr/lib, etc.)
  const modifiedBinaries = useMemo(() =>
    fsDiff?.modified.filter((e) => {
      const p = e.path.toLowerCase()
      return p.includes('/bin/') || p.includes('/sbin/') || p.includes('/lib/') ||
             p.endsWith('.so') || p.includes('.so.')
    }) ?? [],
    [fsDiff]
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <GitCompareArrows className="h-6 w-6" />
        <h1 className="text-2xl font-semibold tracking-tight">Compare Firmware Versions</h1>
      </div>

      {/* Firmware selectors */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-end gap-4 flex-wrap">
            <div className="flex-1 min-w-[200px]">
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Firmware A (older)</label>
              <select
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                value={fwAId}
                onChange={(e) => setFwAId(e.target.value)}
              >
                <option value="">Select firmware...</option>
                {firmwareList.map((fw) => (
                  <option key={fw.id} value={fw.id}>
                    {fw.original_filename}{fw.version_label ? ` (${fw.version_label})` : ''} - {fw.architecture || 'unknown'}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex-1 min-w-[200px]">
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Firmware B (newer)</label>
              <select
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                value={fwBId}
                onChange={(e) => setFwBId(e.target.value)}
              >
                <option value="">Select firmware...</option>
                {firmwareList.map((fw) => (
                  <option key={fw.id} value={fw.id}>
                    {fw.original_filename}{fw.version_label ? ` (${fw.version_label})` : ''} - {fw.architecture || 'unknown'}
                  </option>
                ))}
              </select>
            </div>
            <Button
              onClick={handleCompare}
              disabled={!fwAId || !fwBId || fwAId === fwBId || loading}
            >
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Compare
            </Button>
            {fsDiff && (
              <Button variant="outline" onClick={handleDownloadReport}>
                <Download className="mr-2 h-4 w-4" />
                Export JSON
              </Button>
            )}
          </div>
          {fwAId === fwBId && fwAId && (
            <p className="text-xs text-destructive mt-2">Select two different firmware versions</p>
          )}
          {error && <p className="text-sm text-destructive mt-2">{error}</p>}
        </CardContent>
      </Card>

      {/* Results */}
      {fsDiff && (
        <>
          {/* Summary */}
          <div className="flex gap-3 flex-wrap">
            <Card className="flex-1 min-w-[120px]">
              <CardContent className="pt-4 pb-3 text-center">
                <div className="text-2xl font-bold text-green-600">{fsDiff.added.length}</div>
                <div className="text-xs text-muted-foreground flex items-center justify-center gap-1">
                  <Plus className="h-3 w-3" /> Added
                </div>
              </CardContent>
            </Card>
            <Card className="flex-1 min-w-[120px]">
              <CardContent className="pt-4 pb-3 text-center">
                <div className="text-2xl font-bold text-red-600">{fsDiff.removed.length}</div>
                <div className="text-xs text-muted-foreground flex items-center justify-center gap-1">
                  <Minus className="h-3 w-3" /> Removed
                </div>
              </CardContent>
            </Card>
            <Card className="flex-1 min-w-[120px]">
              <CardContent className="pt-4 pb-3 text-center">
                <div className="text-2xl font-bold text-yellow-600">{fsDiff.modified.length}</div>
                <div className="text-xs text-muted-foreground flex items-center justify-center gap-1">
                  <FileEdit className="h-3 w-3" /> Modified
                </div>
              </CardContent>
            </Card>
            <Card className="flex-1 min-w-[120px]">
              <CardContent className="pt-4 pb-3 text-center">
                <div className="text-2xl font-bold text-blue-600">{fsDiff.permissions_changed.length}</div>
                <div className="text-xs text-muted-foreground flex items-center justify-center gap-1">
                  <Lock className="h-3 w-3" /> Perms
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Tabs */}
          <div className="flex gap-1 border-b">
            <button
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                tab === 'files' ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
              }`}
              onClick={() => setTab('files')}
            >
              Files ({allEntries.length})
            </button>
            <button
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                tab === 'binaries' ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
              }`}
              onClick={() => setTab('binaries')}
            >
              Binaries ({modifiedBinaries.length})
            </button>
            {binDiff && (
              <button
                className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                  tab === 'binary-detail' ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}
                onClick={() => setTab('binary-detail')}
              >
                <Binary className="inline h-3.5 w-3.5 mr-1" />
                {binDiff.binary_path.split('/').pop()}
              </button>
            )}
          </div>

          {/* Files tab */}
          {tab === 'files' && (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">File Differences</CardTitle>
                  <select
                    className="rounded border bg-background px-2 py-1 text-xs"
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                  >
                    <option value="all">All ({allEntries.length})</option>
                    <option value="added">Added ({fsDiff.added.length})</option>
                    <option value="removed">Removed ({fsDiff.removed.length})</option>
                    <option value="modified">Modified ({fsDiff.modified.length})</option>
                    <option value="permissions_changed">Perms ({fsDiff.permissions_changed.length})</option>
                  </select>
                </div>
              </CardHeader>
              <CardContent>
                {fsDiff.truncated && (
                  <p className="text-xs text-muted-foreground mb-2">Results truncated to 500 entries per category</p>
                )}
                <div className="overflow-x-auto">
                  {filteredEntries.length === 0 ? (
                    <p className="py-6 text-center text-xs text-muted-foreground">
                      No entries match the current filter.
                    </p>
                  ) : (
                    <div className="rounded-md border border-border">
                      {/* Header — CSS grid shares gridTemplateColumns with
                          each row so columns stay aligned through
                          virtualization. */}
                      <div
                        className="grid items-center border-b text-xs text-muted-foreground"
                        style={{ gridTemplateColumns: FILE_DIFF_COLUMN_TEMPLATE }}
                      >
                        <div className="pb-2 pt-2 pr-3 pl-3 font-medium">Path</div>
                        <div className="pb-2 pt-2 pr-3 font-medium">Status</div>
                        <div className="pb-2 pt-2 pr-3 font-medium text-right">Size A</div>
                        <div className="pb-2 pt-2 pr-3 font-medium text-right">Size B</div>
                        <div className="pb-2 pt-2 pr-3 font-medium text-right">Delta</div>
                        <div className="pb-2 pt-2 pr-3 font-medium">SHA256</div>
                      </div>
                      <div ref={fileDiffWrapperRef}>
                        <List
                          rowComponent={FileDiffRow}
                          rowCount={filteredEntries.length}
                          rowHeight={FILE_DIFF_ROW_HEIGHT}
                          rowProps={{
                            entries: filteredEntries,
                            onTextDiff: handleTextDiff,
                          }}
                          style={{
                            height: fileDiffHeight,
                            minHeight: 240,
                          }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Binaries tab */}
          {tab === 'binaries' && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Modified Binaries</CardTitle>
              </CardHeader>
              <CardContent>
                {modifiedBinaries.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No modified binaries detected</p>
                ) : (
                  <div className="space-y-1">
                    {modifiedBinaries.map((entry, i) => {
                      const delta = entry.size_a != null && entry.size_b != null && entry.size_a > 0
                        ? ((entry.size_b - entry.size_a) / entry.size_a * 100)
                        : null
                      return (
                        <div
                          key={i}
                          className="flex items-center justify-between rounded px-3 py-2 hover:bg-muted/50 cursor-pointer"
                          onClick={() => handleBinaryDiff(entry.path)}
                        >
                          <span className="font-mono text-xs">{entry.path}</span>
                          <div className="flex items-center gap-3 text-xs">
                            <span className="text-muted-foreground">
                              {entry.size_a != null ? formatFileSize(entry.size_a) : '?'} &rarr;{' '}
                              {entry.size_b != null ? formatFileSize(entry.size_b) : '?'}
                            </span>
                            {delta != null && (
                              <span className={delta > 0 ? 'text-green-600' : delta < 0 ? 'text-red-600' : ''}>
                                {delta > 0 ? '+' : ''}{delta.toFixed(1)}%
                              </span>
                            )}
                            <Button size="sm" variant="outline" className="h-6 text-xs">
                              Diff
                            </Button>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Binary detail tab */}
          {tab === 'text-diff' && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <FileEdit className="h-4 w-4" />
                  Text Diff: {textDiff?.path || 'Loading...'}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {textLoading && (
                  <div className="flex items-center gap-2 py-4 text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Computing diff...
                  </div>
                )}
                {textDiff && !textLoading && (
                  <div className="space-y-3">
                    {textDiff.error ? (
                      <p className="text-sm text-destructive">{textDiff.error}</p>
                    ) : textDiff.diff ? (
                      <>
                        <div className="flex gap-3 text-sm">
                          <Badge variant="outline" className="text-green-600">
                            +{textDiff.lines_added} added
                          </Badge>
                          <Badge variant="outline" className="text-red-600">
                            -{textDiff.lines_removed} removed
                          </Badge>
                          {textDiff.truncated && (
                            <Badge variant="outline" className="text-yellow-600">
                              truncated
                            </Badge>
                          )}
                        </div>
                        <pre className="max-h-[600px] overflow-auto rounded border bg-muted/30 p-3 text-xs font-mono leading-relaxed">
                          {textDiff.diff.split('\n').map((line, i) => {
                            let className = ''
                            if (line.startsWith('+++') || line.startsWith('---')) className = 'text-muted-foreground font-bold'
                            else if (line.startsWith('@@')) className = 'text-blue-500'
                            else if (line.startsWith('+')) className = 'text-green-600 bg-green-500/10'
                            else if (line.startsWith('-')) className = 'text-red-600 bg-red-500/10'
                            return (
                              <div key={i} className={className}>
                                {line}
                              </div>
                            )
                          })}
                        </pre>
                      </>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        No text differences found, or file is not a text file.
                      </p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {tab === 'binary-detail' && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Binary className="h-4 w-4" />
                  Binary Diff: {binDiff?.binary_path || 'Loading...'}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {binLoading && (
                  <div className="flex items-center gap-2 py-4 text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Analyzing binary differences...
                  </div>
                )}
                {binDiff && !binLoading && (
                  <div className="space-y-4">
                    <div className="flex gap-4 text-xs">
                      <span>A: {fwALabel?.version_label || fwALabel?.original_filename} ({formatFileSize(Number(binDiff.info_a?.file_size) || 0)})</span>
                      <span>B: {fwBLabel?.version_label || fwBLabel?.original_filename} ({formatFileSize(Number(binDiff.info_b?.file_size) || 0)})</span>
                    </div>

                    <div className="flex gap-3 text-sm">
                      <Badge variant="outline" className="text-green-600">
                        +{binDiff.functions_added.length} added
                      </Badge>
                      <Badge variant="outline" className="text-red-600">
                        -{binDiff.functions_removed.length} removed
                      </Badge>
                      <Badge variant="outline" className="text-yellow-600">
                        ~{binDiff.functions_modified.length} modified
                      </Badge>
                    </div>

                    {binDiff.functions_added.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-green-600 mb-1">Functions Added</h4>
                        <div className="space-y-0.5">
                          {binDiff.functions_added.map((f, i) => (
                            <div key={i} className="flex justify-between text-xs font-mono px-2 py-0.5 hover:bg-muted/50 rounded">
                              <span>{f.name}</span>
                              <span className="text-muted-foreground">{f.size_b} bytes</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {binDiff.functions_removed.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-red-600 mb-1">Functions Removed</h4>
                        <div className="space-y-0.5">
                          {binDiff.functions_removed.map((f, i) => (
                            <div key={i} className="flex justify-between text-xs font-mono px-2 py-0.5 hover:bg-muted/50 rounded">
                              <span>{f.name}</span>
                              <span className="text-muted-foreground">{f.size_a} bytes</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {binDiff.functions_modified.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-yellow-600 mb-1">Functions Modified</h4>
                        <div className="space-y-0.5">
                          {binDiff.functions_modified.map((f, i) => (
                            <div key={i}>
                              <div
                                className="flex justify-between items-center text-xs font-mono px-2 py-1 hover:bg-muted/50 rounded cursor-pointer"
                                onClick={() => handleInstrDiff(f.name)}
                              >
                                <span className="flex items-center gap-1.5">
                                  {expandedFunc === f.name
                                    ? <ChevronDown className="h-3 w-3 text-muted-foreground" />
                                    : <ChevronRight className="h-3 w-3 text-muted-foreground" />}
                                  {f.name}
                                </span>
                                <div className="flex items-center gap-2">
                                  <span className="text-muted-foreground">
                                    {f.size_a} &rarr; {f.size_b} bytes
                                  </span>
                                  <Button
                                    size="sm"
                                    variant="ghost"
                                    className="h-5 px-1.5 text-[10px]"
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      handleDecompDiff(f.name)
                                    }}
                                    disabled={decompLoading && decompFunc === f.name}
                                    title="View decompilation diff (Ghidra)"
                                  >
                                    {decompLoading && decompFunc === f.name
                                      ? <Loader2 className="h-3 w-3 animate-spin" />
                                      : <Code className="h-3 w-3" />}
                                  </Button>
                                </div>
                              </div>
                              {expandedFunc === f.name && (
                                <div className="ml-5 mt-1 mb-2 border rounded bg-muted/20 p-3">
                                  {instrLoading && (
                                    <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
                                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                      Loading instruction diff...
                                    </div>
                                  )}
                                  {instrDiff && !instrLoading && (
                                    <div className="space-y-2">
                                      {instrDiff.error ? (
                                        <p className="text-xs text-destructive">{instrDiff.error}</p>
                                      ) : (
                                        <>
                                          <div className="flex items-center gap-3 text-xs">
                                            <span className="font-medium">{instrDiff.function_name}</span>
                                            {instrDiff.arch && (
                                              <Badge variant="outline" className="text-[10px]">{instrDiff.arch}</Badge>
                                            )}
                                            <Badge variant="outline" className="text-green-600 text-[10px]">
                                              +{instrDiff.lines_added}
                                            </Badge>
                                            <Badge variant="outline" className="text-red-600 text-[10px]">
                                              -{instrDiff.lines_removed}
                                            </Badge>
                                          </div>
                                          {instrDiff.diff_text ? (
                                            <pre className="max-h-[400px] overflow-auto rounded border bg-muted/30 p-2 text-[11px] font-mono leading-relaxed">
                                              {instrDiff.diff_text.split('\n').map((line, li) => {
                                                let className = ''
                                                if (line.startsWith('+++') || line.startsWith('---')) className = 'text-muted-foreground font-bold'
                                                else if (line.startsWith('@@')) className = 'text-blue-500'
                                                else if (line.startsWith('+')) className = 'text-green-600 bg-green-500/10'
                                                else if (line.startsWith('-')) className = 'text-red-600 bg-red-500/10'
                                                return (
                                                  <div key={li} className={className}>
                                                    {line}
                                                  </div>
                                                )
                                              })}
                                            </pre>
                                          ) : (
                                            <p className="text-xs text-muted-foreground">No instruction-level diff available.</p>
                                          )}
                                        </>
                                      )}
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Decompilation diff viewer */}
                    {decompFunc && (
                      <div className="border rounded bg-muted/10 p-3 space-y-2">
                        <div className="flex items-center gap-2 text-xs font-medium">
                          <Code className="h-3.5 w-3.5" />
                          Decompilation Diff: <span className="font-mono">{decompFunc}</span>
                        </div>
                        {decompLoading && (
                          <div className="flex items-center gap-2 py-3 text-xs text-muted-foreground">
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            Decompiling with Ghidra (this may take 30-120s)...
                          </div>
                        )}
                        {decompDiff && !decompLoading && (
                          <div className="space-y-2">
                            {decompDiff.error ? (
                              <p className="text-xs text-destructive">{decompDiff.error}</p>
                            ) : (
                              <>
                                <div className="flex items-center gap-3 text-xs">
                                  <Badge variant="outline" className="text-green-600 text-[10px]">
                                    +{decompDiff.lines_added} added
                                  </Badge>
                                  <Badge variant="outline" className="text-red-600 text-[10px]">
                                    -{decompDiff.lines_removed} removed
                                  </Badge>
                                </div>
                                {decompDiff.diff_text ? (
                                  <pre className="max-h-[500px] overflow-auto rounded border bg-muted/30 p-2 text-[11px] font-mono leading-relaxed">
                                    {decompDiff.diff_text.split('\n').map((line, li) => {
                                      let className = ''
                                      if (line.startsWith('+++') || line.startsWith('---')) className = 'text-muted-foreground font-bold'
                                      else if (line.startsWith('@@')) className = 'text-blue-500'
                                      else if (line.startsWith('+')) className = 'text-green-600 bg-green-500/10'
                                      else if (line.startsWith('-')) className = 'text-red-600 bg-red-500/10'
                                      return (
                                        <div key={li} className={className}>
                                          {line}
                                        </div>
                                      )
                                    })}
                                  </pre>
                                ) : (
                                  <p className="text-xs text-muted-foreground">
                                    No decompilation differences found.
                                  </p>
                                )}
                              </>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {binDiff.functions_added.length === 0 &&
                     binDiff.functions_removed.length === 0 &&
                     binDiff.functions_modified.length === 0 && (
                      <div className="space-y-2">
                        {Boolean(binDiff.info_a?.stripped || binDiff.info_b?.stripped) && (
                          <p className="text-sm text-yellow-600">
                            Binary is stripped (no symbol table) — function-level analysis unavailable.
                          </p>
                        )}
                        {binDiff.info_a?.identical === true ? (
                          <p className="text-sm text-muted-foreground">
                            Binaries are identical (same SHA256 hash).
                          </p>
                        ) : binDiff.info_a?.identical === false ? (
                          <div className="text-sm space-y-1">
                            <p className="text-orange-500 font-medium">
                              Binaries differ (different content) but no symbol-level diff is available.
                            </p>
                            <div className="text-xs text-muted-foreground font-mono space-y-0.5">
                              <p>A: {String(binDiff.info_a?.sha256 || '').slice(0, 16)}... ({formatFileSize(Number(binDiff.info_a?.file_size) || 0)})</p>
                              <p>B: {String(binDiff.info_b?.sha256 || '').slice(0, 16)}... ({formatFileSize(Number(binDiff.info_b?.file_size) || 0)})</p>
                            </div>
                          </div>
                        ) : (
                          <p className="text-sm text-muted-foreground">
                            No function-level differences detected. Changes may be limited to data sections.
                          </p>
                        )}
                      </div>
                    )}

                    {/* Section diff fallback for stripped binaries */}
                    {binDiff.sections_changed && binDiff.sections_changed.length > 0 &&
                     binDiff.functions_added.length === 0 &&
                     binDiff.functions_removed.length === 0 &&
                     binDiff.functions_modified.length === 0 && (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2 rounded bg-yellow-500/10 border border-yellow-500/30 px-3 py-2">
                          <AlertTriangle className="h-4 w-4 text-yellow-600 shrink-0" />
                          <p className="text-xs text-yellow-700 dark:text-yellow-400">
                            Binary is stripped — showing section-level changes
                          </p>
                        </div>
                        <div className="overflow-x-auto">
                          <table className="w-full text-xs">
                            <thead>
                              <tr className="border-b text-left text-muted-foreground">
                                <th className="pb-2 pr-3 font-medium">Section</th>
                                <th className="pb-2 pr-3 font-medium w-24 text-right">Size A</th>
                                <th className="pb-2 pr-3 font-medium w-24 text-right">Size B</th>
                                <th className="pb-2 font-medium w-20 text-center">Changed</th>
                              </tr>
                            </thead>
                            <tbody>
                              {binDiff.sections_changed.map((sec, i) => (
                                <tr key={i} className="border-b border-border/30 hover:bg-muted/50">
                                  <td className="py-1.5 pr-3 font-mono">{sec.name}</td>
                                  <td className="py-1.5 pr-3 text-right">{formatFileSize(sec.size_a)}</td>
                                  <td className="py-1.5 pr-3 text-right">{formatFileSize(sec.size_b)}</td>
                                  <td className="py-1.5 text-center">
                                    {sec.changed ? (
                                      <span className="text-yellow-600 font-medium">Yes</span>
                                    ) : (
                                      <span className="text-muted-foreground">No</span>
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>

                        {/* Basic block stats for stripped binaries */}
                        {binDiff.basic_block_stats && (
                          <div className="rounded border border-blue-500/30 bg-blue-500/5 p-3 space-y-2">
                            <p className="text-xs font-medium text-blue-700 dark:text-blue-400">
                              Basic Block Analysis: {binDiff.basic_block_stats.blocks_a} blocks in A, {binDiff.basic_block_stats.blocks_b} blocks in B, {binDiff.basic_block_stats.unchanged_pct}% unchanged
                            </p>
                            <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
                              <div
                                className="h-full bg-blue-500 rounded-full transition-all"
                                style={{ width: `${binDiff.basic_block_stats.unchanged_pct}%` }}
                              />
                            </div>
                            <div className="flex gap-4 text-[10px] text-muted-foreground">
                              <span>{binDiff.basic_block_stats.common_count} common</span>
                              <span className="text-green-600">+{binDiff.basic_block_stats.added_count} added</span>
                              <span className="text-red-600">-{binDiff.basic_block_stats.removed_count} removed</span>
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Import changes */}
                    {((binDiff.imports_added && binDiff.imports_added.length > 0) ||
                      (binDiff.imports_removed && binDiff.imports_removed.length > 0)) && (
                      <ImportExportSection
                        title="Import Changes"
                        icon={<Package className="h-3.5 w-3.5" />}
                        added={binDiff.imports_added || []}
                        removed={binDiff.imports_removed || []}
                        expanded={importsExpanded}
                        onToggle={() => setImportsExpanded(!importsExpanded)}
                      />
                    )}

                    {/* Export changes */}
                    {((binDiff.exports_added && binDiff.exports_added.length > 0) ||
                      (binDiff.exports_removed && binDiff.exports_removed.length > 0)) && (
                      <ImportExportSection
                        title="Export Changes"
                        icon={<ArrowRightLeft className="h-3.5 w-3.5" />}
                        added={binDiff.exports_added || []}
                        removed={binDiff.exports_removed || []}
                        expanded={exportsExpanded}
                        onToggle={() => setExportsExpanded(!exportsExpanded)}
                      />
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Empty state */}
      {!fsDiff && !loading && (
        <div className="text-center py-12 text-muted-foreground">
          <GitCompareArrows className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">Select two firmware versions and click Compare to see differences</p>
          {firmwareList.length < 2 && (
            <p className="text-xs mt-2">
              Upload at least two firmware versions from the project overview to use this feature
            </p>
          )}
        </div>
      )}
    </div>
  )
}

const SECURITY_SENSITIVE_IMPORTS = new Set([
  'system', 'exec', 'execl', 'execle', 'execlp', 'execv', 'execve', 'execvp',
  'popen', 'dlopen', 'dlsym', 'socket', 'connect', 'bind', 'listen', 'accept',
])

function isSecuritySensitive(name: string): boolean {
  const base = name.replace(/^_+/, '').split('@')[0]
  return SECURITY_SENSITIVE_IMPORTS.has(base)
}

function ImportExportSection({
  title,
  icon,
  added,
  removed,
  expanded,
  onToggle,
}: {
  title: string
  icon: React.ReactNode
  added: string[]
  removed: string[]
  expanded: boolean
  onToggle: () => void
}) {
  return (
    <div className="border rounded">
      <button
        type="button"
        className="flex items-center justify-between w-full px-3 py-2 text-xs font-medium hover:bg-muted/50"
        onClick={onToggle}
      >
        <span className="flex items-center gap-2">
          {icon}
          {title}
          <Badge variant="outline" className="text-[10px]">
            {added.length + removed.length}
          </Badge>
        </span>
        {expanded
          ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
          : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
      </button>
      {expanded && (
        <div className="border-t px-3 py-2 space-y-2">
          {added.length > 0 && (
            <div>
              <p className="text-[10px] font-medium text-green-600 mb-1">Added ({added.length})</p>
              <div className="flex flex-wrap gap-1">
                {added.map((name, i) => (
                  <span
                    key={i}
                    className={`inline-block rounded px-1.5 py-0.5 text-[11px] font-mono ${
                      isSecuritySensitive(name)
                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 ring-1 ring-red-300 dark:ring-red-700'
                        : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    }`}
                    title={isSecuritySensitive(name) ? 'Security-sensitive function' : undefined}
                  >
                    {name}
                  </span>
                ))}
              </div>
            </div>
          )}
          {removed.length > 0 && (
            <div>
              <p className="text-[10px] font-medium text-red-600 mb-1">Removed ({removed.length})</p>
              <div className="flex flex-wrap gap-1">
                {removed.map((name, i) => (
                  <span
                    key={i}
                    className={`inline-block rounded px-1.5 py-0.5 text-[11px] font-mono ${
                      isSecuritySensitive(name)
                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 ring-1 ring-red-300 dark:ring-red-700'
                        : 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-400'
                    }`}
                    title={isSecuritySensitive(name) ? 'Security-sensitive function' : undefined}
                  >
                    {name}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { color: string; label: string }> = {
    added: { color: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400', label: 'Added' },
    removed: { color: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400', label: 'Removed' },
    modified: { color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400', label: 'Modified' },
    permissions_changed: { color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400', label: 'Perms' },
  }
  const c = config[status] || { color: 'bg-muted text-muted-foreground', label: status }
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium ${c.color}`}>
      {c.label}
    </span>
  )
}

interface FileDiffRowExtraProps {
  entries: FileDiffEntry[]
  onTextDiff: (path: string) => void
}

function FileDiffRow({
  index,
  style,
  entries,
  onTextDiff,
}: RowComponentProps<FileDiffRowExtraProps>) {
  const entry = entries[index]
  const delta =
    entry.size_a != null && entry.size_b != null && entry.size_a > 0
      ? ((entry.size_b - entry.size_a) / entry.size_a) * 100
      : null

  // react-window provides absolute positioning via `style`; overlay the
  // grid on top so row cells align with the div-grid header columns.
  const rowStyle: CSSProperties = {
    ...style,
    gridTemplateColumns: FILE_DIFF_COLUMN_TEMPLATE,
  }

  return (
    <div
      style={rowStyle}
      className="grid items-center border-b border-border/30 text-xs hover:bg-muted/50"
    >
      <div className="py-1.5 pl-3 pr-3 font-mono">
        <button
          type="button"
          className="block w-full truncate text-left hover:text-primary hover:underline"
          onClick={() => onTextDiff(entry.path)}
          title="View text diff"
        >
          {entry.path}
        </button>
      </div>
      <div className="py-1.5 pr-3">
        <StatusBadge status={entry.status} />
      </div>
      <div className="py-1.5 pr-3 text-right">
        {entry.size_a != null ? formatFileSize(entry.size_a) : '-'}
      </div>
      <div className="py-1.5 pr-3 text-right">
        {entry.size_b != null ? formatFileSize(entry.size_b) : '-'}
      </div>
      <div className="py-1.5 pr-3 text-right">
        {delta != null ? (
          <span className={delta > 0 ? 'text-green-600' : delta < 0 ? 'text-red-600' : ''}>
            {delta > 0 ? '+' : ''}
            {delta.toFixed(1)}%
          </span>
        ) : (
          '-'
        )}
      </div>
      <div className="py-1.5 pr-3 font-mono text-muted-foreground">
        {entry.hash_a && entry.hash_b && entry.hash_a !== entry.hash_b ? (
          <span title={`A: ${entry.hash_a}\nB: ${entry.hash_b}`}>
            {entry.hash_a.slice(0, 8)}&rarr;{entry.hash_b.slice(0, 8)}
          </span>
        ) : entry.hash_a ? (
          <span title={entry.hash_a}>{entry.hash_a.slice(0, 8)}</span>
        ) : entry.hash_b ? (
          <span title={entry.hash_b}>{entry.hash_b.slice(0, 8)}</span>
        ) : (
          '-'
        )}
      </div>
    </div>
  )
}
