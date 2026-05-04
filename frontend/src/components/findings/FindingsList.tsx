import { useState, useMemo, useEffect, useRef } from 'react'
import type { CSSProperties } from 'react'
import {
  ChevronDown,
  ChevronUp,
  ShieldAlert,
} from 'lucide-react'
import { List, type RowComponentProps } from 'react-window'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import type { Finding, Severity, FindingStatus, FindingSource } from '@/types'
import { formatDate } from '@/utils/format'
import { SEVERITY_CONFIG, FINDING_STATUS_CONFIG, FINDING_SOURCE_CONFIG } from '@/constants/statusConfig'

/**
 * Fixed row height. Rows are a two-line button:
 * - line 1: title + status badge + optional source badge
 * - line 2: file_path + created_at (single line)
 * With py-2.5 + gap-3 + text-sm/xs → ~72px is stable across themes.
 */
const ROW_HEIGHT = 72

interface FindingsListProps {
  findings: Finding[]
  selectedId: string | null
  onSelect: (finding: Finding) => void
  severityFilter: Severity | null
  statusFilter: FindingStatus | null
  sourceFilter: FindingSource | null
  onSeverityFilter: (s: Severity | null) => void
  onStatusFilter: (s: FindingStatus | null) => void
  onSourceFilter: (s: FindingSource | null) => void
}

type SortField = 'severity' | 'created_at'
type SortDir = 'asc' | 'desc'

export default function FindingsList({
  findings,
  selectedId,
  onSelect,
  severityFilter,
  statusFilter,
  sourceFilter,
  onSeverityFilter,
  onStatusFilter,
  onSourceFilter,
}: FindingsListProps) {
  const [sortField, setSortField] = useState<SortField>('severity')
  const [sortDir, setSortDir] = useState<SortDir>('asc')
  const listContainerRef = useRef<HTMLDivElement>(null)
  const [listHeight, setListHeight] = useState(300)

  useEffect(() => {
    const el = listContainerRef.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      const h = entries[0]?.contentRect.height ?? 0
      if (h > 0) setListHeight(h)
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDir('asc')
    }
  }

  const sorted = useMemo(() => {
    return [...findings].sort((a, b) => {
      let cmp: number
      if (sortField === 'severity') {
        cmp = SEVERITY_CONFIG[a.severity].order - SEVERITY_CONFIG[b.severity].order
      } else {
        cmp = new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [findings, sortField, sortDir])

  const SortIcon = sortField === 'severity'
    ? (sortDir === 'asc' ? ChevronUp : ChevronDown)
    : (sortDir === 'asc' ? ChevronUp : ChevronDown)

  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-3">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Severity:</span>
        {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => {
          const config = SEVERITY_CONFIG[sev]
          const active = severityFilter === sev
          return (
            <button
              key={sev}
              type="button"
              onClick={() => onSeverityFilter(active ? null : sev)}
              className={`rounded-full border px-2 py-0.5 text-xs font-medium transition-colors ${
                active
                  ? config.bg
                  : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {sev}
            </button>
          )
        })}

        <span className="ml-2 text-xs text-muted-foreground">Status:</span>
        {(['open', 'confirmed', 'false_positive', 'fixed'] as FindingStatus[]).map((st) => {
          const config = FINDING_STATUS_CONFIG[st]
          const active = statusFilter === st
          return (
            <button
              key={st}
              type="button"
              onClick={() => onStatusFilter(active ? null : st)}
              className={`rounded-full border px-2 py-0.5 text-xs font-medium transition-colors ${
                active
                  ? config.className + ' border-current'
                  : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {config.label}
            </button>
          )
        })}

        <span className="ml-2 text-xs text-muted-foreground">Source:</span>
        {(['manual', 'ai_discovered', 'sbom_scan', 'security_review', 'security_audit', 'unpack_audit', 'yara_scan', 'fuzzing', 'apk-manifest-scan'] as FindingSource[]).map((src) => {
          const config = FINDING_SOURCE_CONFIG[src]
          const active = sourceFilter === src
          const SourceIcon = config.icon
          return (
            <button
              key={src}
              type="button"
              onClick={() => onSourceFilter(active ? null : src)}
              className={`flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium transition-colors ${
                active
                  ? config.className + ' border-current'
                  : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              <SourceIcon className="h-3 w-3" />
              {config.label}
            </button>
          )
        })}
      </div>

      {/* Sort controls */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span>Sort by:</span>
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs"
          onClick={() => toggleSort('severity')}
        >
          Severity
          {sortField === 'severity' && <SortIcon className="ml-1 h-3 w-3" />}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs"
          onClick={() => toggleSort('created_at')}
        >
          Date
          {sortField === 'created_at' && <SortIcon className="ml-1 h-3 w-3" />}
        </Button>
        <span className="ml-auto">{findings.length} finding(s)</span>
      </div>

      {/* List — height measured from parent flex via ResizeObserver, not a fragile vh calc. */}
      <div ref={listContainerRef} className="min-h-0 min-w-0 flex-1">
        {sorted.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center py-12 text-muted-foreground">
            <ShieldAlert className="mb-2 h-8 w-8" />
            <p className="text-sm">No findings yet</p>
            <p className="text-xs">Use the AI assistant to analyze firmware and record findings</p>
          </div>
        ) : (
          <List
            rowComponent={FindingRow}
            rowCount={sorted.length}
            rowHeight={ROW_HEIGHT}
            rowProps={{ sorted, selectedId, onSelect }}
            style={{ height: listHeight }}
          />
        )}
      </div>
    </div>
  )
}

interface FindingRowExtraProps {
  sorted: Finding[]
  selectedId: string | null
  onSelect: (finding: Finding) => void
}

function FindingRow({
  index,
  style,
  sorted,
  selectedId,
  onSelect,
}: RowComponentProps<FindingRowExtraProps>) {
  const f = sorted[index]
  const sevConfig = SEVERITY_CONFIG[f.severity]
  const statConfig = FINDING_STATUS_CONFIG[f.status]
  const Icon = sevConfig.icon
  const isSelected = selectedId === f.id

  // Apply the positioning style provided by react-window but keep a small
  // vertical gap so rows don't visually fuse. pt/pb absorb gap-1-equivalent.
  const rowStyle: CSSProperties = { ...style, paddingTop: 2, paddingBottom: 2 }

  return (
    <div style={rowStyle} className="px-0">
      <button
        type="button"
        onClick={() => onSelect(f)}
        className={`flex h-full w-full items-start gap-3 rounded-md border px-3 py-2.5 text-left transition-colors ${
          isSelected
            ? 'border-primary/50 bg-primary/5'
            : 'border-transparent hover:bg-accent'
        }`}
      >
        <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded ${sevConfig.bg}`}>
          <Icon className="h-3 w-3" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 items-center gap-2">
            <span className="min-w-0 flex-1 truncate text-sm font-medium">{f.title}</span>
            <Badge variant="outline" className={`shrink-0 text-[10px] ${statConfig.className}`}>
              {statConfig.label}
            </Badge>
            {f.source && f.source !== 'manual' && (() => {
              const srcConfig = FINDING_SOURCE_CONFIG[f.source as FindingSource] ?? FINDING_SOURCE_CONFIG.manual
              const SrcIcon = srcConfig.icon
              return (
                <Badge variant="outline" className={`shrink-0 text-[10px] ${srcConfig.className}`}>
                  <SrcIcon className="mr-0.5 h-2.5 w-2.5" />
                  {srcConfig.label}
                </Badge>
              )
            })()}
          </div>
          <div className="mt-0.5 flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
            {f.file_path && (
              <span className="min-w-0 flex-1 truncate font-mono">{f.file_path}</span>
            )}
            <span className="shrink-0">{formatDate(f.created_at)}</span>
          </div>
        </div>
      </button>
    </div>
  )
}
