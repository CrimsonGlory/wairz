import { useState } from 'react'
import {
  Network,
  Download,
  Shield,
  AlertTriangle,
  Globe,
  Loader2,
  Play,
  ChevronDown,
  ChevronUp,
  Lock,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  captureNetworkTraffic,
  analyzeNetworkTraffic,
  getPcapDownloadUrl,
} from '@/api/emulation'
import type {
  PcapAnalysis,
  NetworkCaptureResult,
} from '@/api/emulation'
import { extractErrorMessage } from '@/utils/error'

const SEVERITY_CLASSES: Record<string, string> = {
  Critical: 'bg-red-500/15 text-red-400 border-red-500/40',
  High: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  Medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
  Low: 'bg-blue-500/15 text-blue-400 border-blue-500/40',
  Info: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/40',
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export interface NetworkTrafficPanelProps {
  projectId: string
  sessionId: string
}

export function NetworkTrafficPanel({
  projectId,
  sessionId,
}: NetworkTrafficPanelProps) {
  const [capturing, setCapturing] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [duration, setDuration] = useState(10)
  const [captureResult, setCaptureResult] = useState<NetworkCaptureResult | null>(null)
  const [analysis, setAnalysis] = useState<PcapAnalysis | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showConversations, setShowConversations] = useState(false)
  const [showTls, setShowTls] = useState(false)

  const handleCapture = async () => {
    setCapturing(true)
    setError(null)
    setCaptureResult(null)
    setAnalysis(null)

    try {
      const result = await captureNetworkTraffic(projectId, sessionId, duration)
      setCaptureResult(result)

      // Auto-analyze after capture
      setAnalyzing(true)
      try {
        const analysisResult = await analyzeNetworkTraffic(projectId, sessionId)
        setAnalysis(analysisResult)
      } catch (err: unknown) {
        const msg = extractErrorMessage(err, 'Analysis failed')
        setError(`Capture succeeded but analysis failed: ${msg}`)
      } finally {
        setAnalyzing(false)
      }
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Capture failed'))
    } finally {
      setCapturing(false)
    }
  }

  const handleAnalyzeOnly = async () => {
    setAnalyzing(true)
    setError(null)
    try {
      const analysisResult = await analyzeNetworkTraffic(projectId, sessionId)
      setAnalysis(analysisResult)
    } catch (err: unknown) {
      setError(extractErrorMessage(err, 'Analysis failed'))
    } finally {
      setAnalyzing(false)
    }
  }

  // No analysis yet -- show capture controls
  if (!analysis) {
    return (
      <div className="flex h-full flex-col items-center justify-center p-8">
        <Network className="mb-4 h-12 w-12 text-muted-foreground/30" />
        <h3 className="mb-2 text-sm font-semibold text-foreground">
          Network Traffic Analysis
        </h3>
        <p className="mb-6 max-w-md text-center text-xs text-muted-foreground">
          Capture network traffic from the running firmware and analyze protocols,
          DNS queries, insecure services, and more.
        </p>

        <div className="flex items-center gap-3 mb-4">
          <label className="text-xs text-muted-foreground">Duration:</label>
          <select
            value={duration}
            onChange={(e) => setDuration(Number(e.target.value))}
            disabled={capturing || analyzing}
            className="rounded-md border border-border bg-background px-2 py-1 text-xs focus:border-primary focus:outline-none"
          >
            <option value={10}>10 seconds</option>
            <option value={30}>30 seconds</option>
            <option value={60}>60 seconds</option>
          </select>
        </div>

        <div className="flex gap-2">
          <Button
            onClick={handleCapture}
            disabled={capturing || analyzing}
          >
            {capturing ? (
              <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
            ) : analyzing ? (
              <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
            ) : (
              <Play className="mr-1.5 h-4 w-4" />
            )}
            {capturing
              ? `Capturing (${duration}s)...`
              : analyzing
                ? 'Analyzing...'
                : 'Capture Traffic'}
          </Button>
          <Button
            variant="outline"
            onClick={handleAnalyzeOnly}
            disabled={capturing || analyzing}
            title="Analyze existing capture without re-capturing"
          >
            <Network className="mr-1.5 h-4 w-4" />
            Analyze Existing
          </Button>
        </div>

        {error && (
          <div className="mt-4 max-w-md rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
            <AlertTriangle className="mr-1 inline h-3 w-3" />
            {error}
          </div>
        )}
      </div>
    )
  }

  // Analysis results
  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center justify-between border-b border-border bg-background px-4 py-2.5">
        <div className="flex items-center gap-3">
          <Network className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Network Traffic</span>
          <Badge variant="outline" className="text-[10px]">
            {analysis.total_packets} packets
          </Badge>
          {captureResult && (
            <span className="text-[10px] text-muted-foreground">
              {formatBytes(captureResult.size_bytes)} / {captureResult.duration}s capture
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs"
            onClick={handleCapture}
            disabled={capturing || analyzing}
          >
            {capturing ? (
              <Loader2 className="mr-1 h-3 w-3 animate-spin" />
            ) : (
              <Play className="mr-1 h-3 w-3" />
            )}
            Re-capture
          </Button>
          <a
            href={getPcapDownloadUrl(projectId, sessionId)}
            download
            className="inline-flex"
          >
            <Button variant="outline" size="sm" className="h-7 text-xs">
              <Download className="mr-1 h-3 w-3" />
              PCAP
            </Button>
          </a>
        </div>
      </div>

      {/* Scrollable content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-5">
        {/* Protocol Breakdown */}
        <div className="space-y-2">
          <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            <Network className="h-3.5 w-3.5" />
            Protocol Breakdown
          </h4>
          <div className="space-y-1">
            {analysis.protocol_breakdown.map((proto) => (
              <div key={proto.protocol} className="flex items-center gap-2">
                <span className="w-24 truncate text-xs font-medium text-foreground">
                  {proto.protocol}
                </span>
                <div className="flex-1 h-3 rounded-full bg-muted overflow-hidden">
                  <div
                    className="h-full rounded-full bg-primary/60 transition-all"
                    style={{ width: `${Math.max(proto.percentage, 1)}%` }}
                  />
                </div>
                <span className="w-12 text-right text-[10px] text-muted-foreground">
                  {proto.packet_count}
                </span>
                <span className="w-12 text-right text-[10px] text-muted-foreground">
                  {proto.percentage.toFixed(1)}%
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Insecure Protocol Findings */}
        <div className="space-y-2">
          <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            <Shield className="h-3.5 w-3.5" />
            Security Findings
            {analysis.insecure_findings.length > 0 && (
              <Badge
                variant="outline"
                className={`text-[10px] ${SEVERITY_CLASSES[analysis.insecure_findings[0]?.severity] || ''}`}
              >
                {analysis.insecure_findings.length} issues
              </Badge>
            )}
          </h4>
          {analysis.insecure_findings.length === 0 ? (
            <div className="rounded-md border border-green-500/20 bg-green-500/5 px-3 py-2 text-xs text-green-400">
              No insecure protocols detected
            </div>
          ) : (
            <div className="space-y-1.5">
              {analysis.insecure_findings.map((finding, idx) => (
                <div
                  key={idx}
                  className="rounded-md border border-border px-3 py-2 space-y-1"
                >
                  <div className="flex items-center gap-2">
                    <Badge
                      variant="outline"
                      className={`text-[10px] ${SEVERITY_CLASSES[finding.severity] || ''}`}
                    >
                      {finding.severity}
                    </Badge>
                    <span className="text-xs font-medium text-foreground">
                      {finding.protocol}
                    </span>
                    <span className="text-[10px] text-muted-foreground font-mono">
                      port {finding.port}
                    </span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    {finding.description}
                  </p>
                  <p className="text-[10px] text-muted-foreground/70">
                    {finding.evidence}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* DNS Queries */}
        <div className="space-y-2">
          <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            <Globe className="h-3.5 w-3.5" />
            DNS Queries
            {analysis.dns_queries.length > 0 && (
              <Badge variant="outline" className="text-[10px]">
                {analysis.dns_queries.length}
              </Badge>
            )}
          </h4>
          {analysis.dns_queries.length === 0 ? (
            <p className="text-xs text-muted-foreground/60 py-1">
              No DNS queries observed
            </p>
          ) : (
            <div className="space-y-1">
              {analysis.dns_queries.map((q, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-2 rounded-md border border-border px-3 py-1.5"
                >
                  <Globe className="h-3 w-3 shrink-0 text-muted-foreground" />
                  <span className="flex-1 text-xs font-mono text-foreground truncate">
                    {q.domain}
                  </span>
                  <Badge variant="outline" className="text-[10px] shrink-0">
                    {q.query_type}
                  </Badge>
                  <span className="text-[10px] text-muted-foreground shrink-0 max-w-[120px] truncate">
                    {q.resolved_ips.length > 0 ? q.resolved_ips.join(', ') : 'unresolved'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* TLS Connections (collapsible) */}
        {analysis.tls_info.length > 0 && (
          <div className="space-y-2">
            <button
              onClick={() => setShowTls(!showTls)}
              className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground hover:text-foreground transition-colors"
            >
              <Lock className="h-3.5 w-3.5" />
              TLS Connections
              <Badge variant="outline" className="text-[10px]">
                {analysis.tls_info.length}
              </Badge>
              {showTls ? (
                <ChevronUp className="h-3 w-3" />
              ) : (
                <ChevronDown className="h-3 w-3" />
              )}
            </button>
            {showTls && (
              <div className="space-y-1">
                {analysis.tls_info.map((tls, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2 rounded-md border border-border px-3 py-1.5"
                  >
                    <Lock className="h-3 w-3 shrink-0 text-muted-foreground" />
                    <span className="flex-1 text-xs font-mono text-foreground truncate">
                      {tls.server}:{tls.port}
                    </span>
                    <Badge variant="outline" className="text-[10px]">
                      {tls.version}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Conversations (collapsible) */}
        <div className="space-y-2">
          <button
            onClick={() => setShowConversations(!showConversations)}
            className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground hover:text-foreground transition-colors"
          >
            <Network className="h-3.5 w-3.5" />
            Top Conversations
            <Badge variant="outline" className="text-[10px]">
              {analysis.conversations.length}
            </Badge>
            {showConversations ? (
              <ChevronUp className="h-3 w-3" />
            ) : (
              <ChevronDown className="h-3 w-3" />
            )}
          </button>
          {showConversations && (
            <div className="space-y-1">
              {analysis.conversations.slice(0, 20).map((conv, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-[11px]"
                >
                  <span className="font-mono text-foreground truncate">
                    {conv.src}:{conv.src_port}
                  </span>
                  <span className="text-muted-foreground shrink-0">&harr;</span>
                  <span className="font-mono text-foreground truncate">
                    {conv.dst}:{conv.dst_port}
                  </span>
                  <Badge variant="outline" className="text-[10px] shrink-0">
                    {conv.protocol}
                  </Badge>
                  <span className="ml-auto shrink-0 text-[10px] text-muted-foreground">
                    {conv.packet_count} pkts / {formatBytes(conv.byte_count)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
