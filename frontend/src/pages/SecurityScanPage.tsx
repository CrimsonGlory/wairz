import { useCallback, useEffect, useRef, useState, type CSSProperties } from 'react'
import { useParams, Link, useSearchParams } from 'react-router-dom'
import { Shield, Loader2, RefreshCw, Smartphone } from 'lucide-react'
import { List, type RowComponentProps } from 'react-window'

import { apiUrl } from '@/api/config'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  runSecurityAudit,
  runYaraScan,
  listFindings,
  type SecurityAuditResult,
  type YaraScanResult,
} from '@/api/findings'
import { runTool } from '@/api/tools'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import { useResponsiveListHeight } from '@/hooks/useResponsiveListHeight'
import { useProjectStore } from '@/stores/projectStore'
import { extractErrorMessage } from '@/utils/error'
import FirmwareSelector from '@/components/projects/FirmwareSelector'
import AttackSurfaceTab from '@/components/security/AttackSurfaceTab'
import CraChecklistTab from '@/components/security/CraChecklistTab'
import ThreatIntelTab from '@/components/security/ThreatIntelTab'
import { ApkScanTab } from '@/components/apk-scan'
import type { Finding, Severity } from '@/types'

type Tab = 'audit' | 'yara' | 'vulhunt' | 'apk-scan' | 'attack-surface' | 'threat-intel' | 'cra'

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
}

/**
 * Fixed row height for the virtualized findings table.  Rows are one line
 * of py-1.5 with text-xs content (severity badge + title + file path);
 * measured ~28-30px in Chrome, padded to 32 so borders don't fuse.
 */
const FINDINGS_ROW_HEIGHT = 32

/**
 * Column template shared between the div-grid header and each
 * virtualized row so the (Severity, Title, File) columns stay aligned.
 */
const FINDINGS_COLUMN_TEMPLATE =
  '80px minmax(200px, 2fr) minmax(160px, 1.2fr)'

export default function SecurityScanPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const [searchParams] = useSearchParams()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const initialTab = (searchParams.get('tab') as Tab) || 'audit'
  const initialApk = searchParams.get('apk') || undefined
  const initialFinding = searchParams.get('finding') || undefined
  const [tab, setTab] = useState<Tab>(initialTab)
  const { firmwareList } = useFirmwareList(projectId)
  const [auditing, setAuditing] = useState(false)
  const [auditResult, setAuditResult] = useState<SecurityAuditResult | null>(null)
  const [yaraScanning, setYaraScanning] = useState(false)
  const [yaraResult, setYaraResult] = useState<YaraScanResult | null>(null)
  const [vulhuntScanning, setVulhuntScanning] = useState(false)
  const [vulhuntResult, setVulhuntResult] = useState<{ output: string; success: boolean } | null>(null)
  const [vulhuntProgress, setVulhuntProgress] = useState<{
    scanned: number; total: number; findings: number; message: string
    current_binary?: string; results_text?: string
  } | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loadingFindings, setLoadingFindings] = useState(false)
  const vulhuntEventSourceRef = useRef<EventSource | null>(null)
  const { ref: findingsListWrapperRef, height: findingsListHeight } = useResponsiveListHeight({
    maxHeight: 560,
    minHeight: 240,
  })

  // Clean up EventSource on unmount
  useEffect(() => {
    return () => {
      vulhuntEventSourceRef.current?.close()
    }
  }, [])


  const source = tab === 'audit' ? 'security_audit' : tab === 'yara' ? 'yara_scan' : tab === 'vulhunt' ? 'vulhunt_scan' : 'attack_surface'

  const loadFindings = useCallback(async () => {
    if (!projectId) return
    setLoadingFindings(true)
    try {
      const params: Record<string, string> = { source }
      if (selectedFirmwareId) params.firmware_id = selectedFirmwareId
      const results = await listFindings(projectId, params)
      setFindings(results)
    } catch {
      setFindings([])
    } finally {
      setLoadingFindings(false)
    }
  }, [projectId, source, selectedFirmwareId])

  useEffect(() => {
    loadFindings()
  }, [loadFindings])

  const handleAudit = async () => {
    if (!projectId) return
    setAuditing(true)
    setAuditResult(null)
    try {
      const result = await runSecurityAudit(projectId)
      setAuditResult(result)
      await loadFindings()
    } catch (e) {
      setAuditResult({
        status: 'error',
        checks_run: 0,
        findings_created: 0,
        total_findings: 0,
        errors: [extractErrorMessage(e, 'Security audit failed')],
      })
    } finally {
      setAuditing(false)
    }
  }

  const handleYara = async () => {
    if (!projectId) return
    setYaraScanning(true)
    setYaraResult(null)
    try {
      const result = await runYaraScan(projectId)
      setYaraResult(result)
      await loadFindings()
    } catch (e) {
      setYaraResult({
        status: 'error',
        rules_loaded: 0,
        files_scanned: 0,
        files_matched: 0,
        findings_created: 0,
        errors: [extractErrorMessage(e, 'YARA scan failed')],
      })
    } finally {
      setYaraScanning(false)
    }
  }

  const handleVulhunt = async () => {
    if (!projectId) return
    // Re-entry guard — scan already in flight.  The button is disabled
    // while scanning, but a double-click in the brief window before
    // React flushes the disabled state can still fire two handlers.
    if (vulhuntEventSourceRef.current) return
    setVulhuntScanning(true)
    setVulhuntResult(null)
    setVulhuntProgress(null)

    // Subscribe to SSE for progress updates.  The re-entry guard above
    // ensures ref.current is null here, so no explicit close() is needed.
    const evtSource = new EventSource(
      apiUrl(`/api/v1/projects/${projectId}/events?types=vulhunt`),
    )
    vulhuntEventSourceRef.current = evtSource
    evtSource.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        if (data.type === 'vulhunt') {
          setVulhuntProgress({
            scanned: data.scanned ?? 0,
            total: data.total ?? 0,
            findings: data.findings ?? 0,
            message: data.message ?? '',
            current_binary: data.current_binary,
            results_text: data.results_text,
          })
        }
      } catch { /* ignore parse errors */ }
    }

    try {
      const result = await runTool(
        projectId,
        'vulhunt_scan_firmware',
        {},
        selectedFirmwareId || undefined,
      )
      setVulhuntResult(result)
    } catch {
      setVulhuntResult({ output: 'VulHunt scan failed. Is the vulhunt container running?', success: false })
    } finally {
      evtSource.close()
      vulhuntEventSourceRef.current = null
      setVulhuntScanning(false)
    }
  }

  // Group findings by severity
  const bySeverity = findings.reduce<Record<string, Finding[]>>((acc, f) => {
    acc[f.severity] = acc[f.severity] || []
    acc[f.severity].push(f)
    return acc
  }, {})

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-6 w-6 text-muted-foreground" />
          <div>
            <h1 className="text-lg font-semibold">Security Scanning</h1>
            <p className="text-sm text-muted-foreground">
              Automated security audit and YARA malware scanning
            </p>
          </div>
        </div>
      </div>

      {/* Firmware Selector */}
      {projectId && <FirmwareSelector projectId={projectId} firmwareList={firmwareList} className="max-w-md" />}

      {/* Tabs */}
      <div className="flex gap-1 border-b">
        <button
          type="button"
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            tab === 'audit'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setTab('audit')}
        >
          Security Audit
        </button>
        <button
          type="button"
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            tab === 'yara'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setTab('yara')}
        >
          YARA Scan
        </button>
        <button
          type="button"
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            tab === 'vulhunt'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setTab('vulhunt')}
        >
          VulHunt
        </button>
        <button
          type="button"
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            tab === 'apk-scan'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setTab('apk-scan')}
        >
          <span className="inline-flex items-center gap-1.5">
            <Smartphone className="h-3.5 w-3.5" />
            APK Scan
          </span>
        </button>
        <button
          type="button"
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            tab === 'attack-surface'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setTab('attack-surface')}
        >
          Attack Surface
        </button>
        <button
          type="button"
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            tab === 'threat-intel'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setTab('threat-intel')}
        >
          Threat Intel
        </button>
        <button
          type="button"
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
            tab === 'cra'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
          onClick={() => setTab('cra')}
        >
          CRA Compliance
        </button>
      </div>

      {/* Action buttons + results */}
      {tab === 'audit' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <Button onClick={handleAudit} disabled={auditing}>
              {auditing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              {auditing ? 'Scanning...' : 'Run Security Audit'}
            </Button>
            <p className="text-xs text-muted-foreground">
              Scans for hardcoded credentials, API keys, weak passwords, setuid binaries, insecure services, kernel hardening
            </p>
          </div>

          {auditResult && (
            <Card>
              <CardContent className="py-3 px-4">
                <span className="text-sm">
                  Audit complete: <strong>{auditResult.findings_created}</strong> finding{auditResult.findings_created !== 1 ? 's' : ''} from {auditResult.checks_run} checks
                  {auditResult.errors.length > 0 && (
                    <span className="text-xs text-destructive ml-2">({auditResult.errors.length} error{auditResult.errors.length !== 1 ? 's' : ''})</span>
                  )}
                </span>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {tab === 'yara' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <Button onClick={handleYara} disabled={yaraScanning}>
              {yaraScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              {yaraScanning ? 'Scanning...' : 'Run YARA Scan'}
            </Button>
            <p className="text-xs text-muted-foreground">
              Scans with 26 rules: IoT botnets, backdoors, crypto miners, web shells, private keys, weak crypto
            </p>
          </div>

          {yaraResult && (
            <Card>
              <CardContent className="py-3 px-4">
                <span className="text-sm">
                  YARA scan complete: <strong>{yaraResult.findings_created}</strong> finding{yaraResult.findings_created !== 1 ? 's' : ''} from {yaraResult.files_scanned} files ({yaraResult.rules_loaded} rules)
                  {yaraResult.errors.length > 0 && (
                    <span className="text-xs text-destructive ml-2">({yaraResult.errors.length} error{yaraResult.errors.length !== 1 ? 's' : ''})</span>
                  )}
                </span>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {tab === 'vulhunt' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <Button onClick={handleVulhunt} disabled={vulhuntScanning}>
              {vulhuntScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              {vulhuntScanning ? 'Scanning...' : 'Run VulHunt Scan'}
            </Button>
            <p className="text-xs text-muted-foreground">
              Deep binary vulnerability analysis on all ELF and UEFI PE32+ modules — dataflow tracking, pattern matching
            </p>
          </div>

          {vulhuntScanning && vulhuntProgress && vulhuntProgress.total > 0 && (
            <Card>
              <CardContent className="py-3 px-4 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{vulhuntProgress.message}</span>
                  <span className="font-mono">
                    {vulhuntProgress.scanned}/{vulhuntProgress.total}
                  </span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full transition-all duration-300"
                    style={{ width: `${(vulhuntProgress.scanned / vulhuntProgress.total) * 100}%` }}
                  />
                </div>
                {vulhuntProgress.findings > 0 && (
                  <p className="text-xs text-orange-500">
                    {vulhuntProgress.findings} vulnerability finding{vulhuntProgress.findings !== 1 ? 's' : ''} so far
                  </p>
                )}
                {vulhuntProgress.current_binary && (
                  <p className="text-xs text-muted-foreground font-mono truncate">
                    Scanning: {vulhuntProgress.current_binary}
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {vulhuntScanning && vulhuntProgress?.results_text && (
            <Card>
              <CardContent className="py-3 px-4">
                <pre className="text-xs whitespace-pre-wrap font-mono max-h-64 overflow-y-auto">
                  {vulhuntProgress.results_text}
                </pre>
              </CardContent>
            </Card>
          )}

          {vulhuntResult && (
            <Card>
              <CardContent className="py-3 px-4">
                <pre className="text-xs whitespace-pre-wrap font-mono max-h-96 overflow-y-auto">
                  {vulhuntResult.output}
                </pre>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {tab === 'apk-scan' && projectId && (
        <ApkScanTab projectId={projectId} selectedFirmwareId={selectedFirmwareId} initialApk={initialApk} initialFinding={initialFinding} />
      )}

      {tab === 'attack-surface' && projectId && (
        <AttackSurfaceTab projectId={projectId} selectedFirmwareId={selectedFirmwareId} />
      )}

      {tab === 'threat-intel' && projectId && (
        <ThreatIntelTab projectId={projectId} selectedFirmwareId={selectedFirmwareId} />
      )}

      {tab === 'cra' && projectId && (
        <CraChecklistTab projectId={projectId} selectedFirmwareId={selectedFirmwareId} />
      )}

      {/* Findings list (hidden on tabs that have their own display) */}
      {tab !== 'attack-surface' && tab !== 'threat-intel' && tab !== 'cra' && tab !== 'apk-scan' && (
        <>
          {loadingFindings ? (
            <div className="flex items-center gap-2 py-8 justify-center text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading findings...
            </div>
          ) : findings.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p className="text-sm">
                {tab === 'audit'
                  ? 'No security audit findings. Click "Run Security Audit" to scan.'
                  : tab === 'yara'
                  ? 'No YARA findings. Click "Run YARA Scan" to scan.'
                  : 'No VulHunt findings yet. Click "Run VulHunt Scan" to analyze binaries.'}
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Severity summary */}
              <div className="flex gap-3 flex-wrap">
                {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => {
                  const count = bySeverity[sev]?.length || 0
                  if (count === 0) return null
                  return (
                    <Badge key={sev} className={SEVERITY_COLORS[sev]}>
                      {sev}: {count}
                    </Badge>
                  )
                })}
                <span className="text-sm text-muted-foreground self-center">
                  {findings.length} total
                </span>
                <Button variant="link" size="sm" className="h-auto p-0" asChild>
                  <Link to={`/projects/${projectId}/findings?source=${source}`}>
                    View in Findings page
                  </Link>
                </Button>
              </div>

              {/* Findings table — virtualized via react-window */}
              <div className="rounded-md border border-border">
                {/* Header — CSS grid shares gridTemplateColumns with each
                    row so columns stay aligned through virtualization. */}
                <div
                  className="grid items-center border-b text-xs text-muted-foreground"
                  style={{ gridTemplateColumns: FINDINGS_COLUMN_TEMPLATE }}
                >
                  <div className="pb-2 pt-2 pr-3 pl-3 font-medium">Severity</div>
                  <div className="pb-2 pt-2 pr-3 font-medium">Title</div>
                  <div className="pb-2 pt-2 pr-3 font-medium">File</div>
                </div>
                <div ref={findingsListWrapperRef}>
                  <List
                    rowComponent={FindingRow}
                    rowCount={findings.length}
                    rowHeight={FINDINGS_ROW_HEIGHT}
                    rowProps={{
                      findings,
                      projectId: projectId ?? '',
                    }}
                    style={{
                      height: findingsListHeight,
                      minHeight: 240,
                    }}
                  />
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

interface FindingRowExtraProps {
  findings: Finding[]
  projectId: string
}

function FindingRow({
  index,
  style,
  findings,
  projectId,
}: RowComponentProps<FindingRowExtraProps>) {
  const f = findings[index]

  // react-window provides absolute positioning via `style`; we overlay the
  // grid on top so row cells align with the div-grid header columns.
  const rowStyle: CSSProperties = {
    ...style,
    gridTemplateColumns: FINDINGS_COLUMN_TEMPLATE,
  }

  return (
    <div
      style={rowStyle}
      className="grid items-center border-b border-border/30 text-xs hover:bg-muted/50"
    >
      <div className="py-1.5 pl-3 pr-3">
        <Badge
          variant="outline"
          className={`text-xs ${SEVERITY_COLORS[f.severity as Severity] || ''}`}
        >
          {f.severity}
        </Badge>
      </div>
      <div className="py-1.5 pr-3 truncate">
        <Link
          to={`/projects/${projectId}/findings`}
          state={{ findingId: f.id }}
          className="hover:underline hover:text-primary"
        >
          {f.title}
        </Link>
      </div>
      <div className="py-1.5 pr-3 font-mono text-muted-foreground truncate">
        {f.file_path ? (
          f.source?.startsWith('apk-') ? (
            <span className="text-muted-foreground">{f.file_path}</span>
          ) : (
            <Link
              to={`/projects/${projectId}/explore?path=${encodeURIComponent(f.file_path)}`}
              className="hover:underline hover:text-primary"
            >
              {f.file_path}
            </Link>
          )
        ) : (
          '-'
        )}
      </div>
    </div>
  )
}
