import { useMemo, useState, type CSSProperties } from 'react'
import { List, type RowComponentProps } from 'react-window'
import { Badge } from '@/components/ui/badge'
import { useResponsiveListHeight } from '@/hooks/useResponsiveListHeight'
import type { CveRow, HardwareFirmwareBlob } from '@/api/hardwareFirmware'
import { displayPath, highlightMatches } from './BlobTable'

interface CvesTabProps {
  cves: CveRow[]
  blobs: HardwareFirmwareBlob[]
  loading: boolean
  searchQuery?: string
  onSelectBlob: (blobId: string) => void
}

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-700 text-white',
  high: 'bg-red-600 text-white',
  medium: 'bg-amber-600 text-white',
  low: 'bg-yellow-600 text-black',
  unknown: 'bg-gray-500 text-white',
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
}

type SortKey = 'severity' | 'affected' | 'tier' | 'cve_id'

/**
 * Fixed height for a collapsed CVE row (py-1.5 + text-xs badge).
 * Chrome measures ~28-30px; padded to 32 for border clarity.
 */
const CVE_ROW_HEIGHT = 32

/**
 * Per-line height for an affected-blob entry in the expanded detail.
 * Each entry is a single-line <li> with font-mono text-[11px].
 */
const AFFECTED_BLOB_LINE_HEIGHT = 20

/**
 * Padding + "Affected blobs (N)" header + border/bg chrome inside the
 * detail block (px-4 + py-3 + mb-2 + mb-1 + border-t on the parent row).
 */
const DETAIL_CHROME_HEIGHT = 60

/**
 * Approximate characters per line when the description text wraps in the
 * detail panel.  Used to estimate description height before it's rendered.
 * A value of 100 matches the typical panel width at 1280-1920px viewports.
 */
const DESCRIPTION_CHARS_PER_LINE = 100

/**
 * Height per wrapped line of the description block (text-[11px] with
 * default line-height).
 */
const DESCRIPTION_LINE_HEIGHT = 18

/**
 * Column template shared between the div-grid header and virtualised rows
 * so columns stay aligned through scrolling.  5 columns: severity / CVE /
 * tier / blobs / formats.
 */
const COLUMN_TEMPLATE =
  'minmax(110px, 130px) minmax(140px, 1.1fr) minmax(80px, 0.7fr) 80px minmax(140px, 1fr)'

type Row =
  | { kind: 'cve'; cve: CveRow; isOpen: boolean }
  | { kind: 'detail'; cve: CveRow }

function filterCves(cves: CveRow[], query: string): CveRow[] {
  if (!query) return cves
  const q = query.toLowerCase()
  return cves.filter((c) =>
    [
      c.cve_id,
      c.severity,
      c.match_tier ?? '',
      c.description ?? '',
      c.affected_formats.join(' '),
    ]
      .join(' ')
      .toLowerCase()
      .includes(q),
  )
}

function sortCves(cves: CveRow[], key: SortKey): CveRow[] {
  const out = [...cves]
  out.sort((a, b) => {
    switch (key) {
      case 'severity': {
        const diff =
          (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)
        if (diff !== 0) return diff
        return b.affected_blob_count - a.affected_blob_count
      }
      case 'affected':
        return b.affected_blob_count - a.affected_blob_count
      case 'tier':
        return (a.match_tier ?? '').localeCompare(b.match_tier ?? '')
      case 'cve_id':
        return a.cve_id.localeCompare(b.cve_id)
    }
  })
  return out
}

export default function CvesTab({
  cves,
  blobs,
  loading,
  searchQuery,
  onSelectBlob,
}: CvesTabProps) {
  const [sortKey, setSortKey] = useState<SortKey>('severity')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const { ref: listWrapperRef, height: listHeight } = useResponsiveListHeight({
    maxHeight: 640,
    minHeight: 240,
  })

  const blobsById = useMemo(() => {
    const m = new Map<string, HardwareFirmwareBlob>()
    for (const b of blobs) m.set(b.id, b)
    return m
  }, [blobs])

  const sortedCves = useMemo(
    () => sortCves(filterCves(cves, (searchQuery ?? '').trim()), sortKey),
    [cves, searchQuery, sortKey],
  )

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = []
    for (const c of sortedCves) {
      const isOpen = expanded.has(c.cve_id)
      out.push({ kind: 'cve', cve: c, isOpen })
      if (isOpen) out.push({ kind: 'detail', cve: c })
    }
    return out
  }, [sortedCves, expanded])

  if (loading) {
    return (
      <div className="py-6 text-center text-xs text-muted-foreground">
        Loading CVEs…
      </div>
    )
  }
  if (sortedCves.length === 0) {
    return (
      <div className="py-6 text-center text-xs text-muted-foreground">
        No hardware-firmware CVEs detected. Run the matcher from the
        header to populate findings.
      </div>
    )
  }

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  /**
   * Variable row-height callback.  CVE headers are fixed; detail rows
   * are estimated from description length + affected-blob count so the
   * full block fits without clipping.
   */
  const itemSize = (index: number): number => {
    const row = rows[index]
    if (!row) return CVE_ROW_HEIGHT
    if (row.kind === 'cve') return CVE_ROW_HEIGHT
    const c = row.cve
    const descLines = c.description
      ? Math.max(1, Math.ceil(c.description.length / DESCRIPTION_CHARS_PER_LINE))
      : 0
    const descHeight = descLines * DESCRIPTION_LINE_HEIGHT
    const affectedLines = Math.max(1, c.affected_blob_ids.length)
    return (
      DETAIL_CHROME_HEIGHT +
      descHeight +
      affectedLines * AFFECTED_BLOB_LINE_HEIGHT
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span>Sort by:</span>
        {(
          [
            ['severity', 'Severity'],
            ['affected', 'Affected blobs'],
            ['tier', 'Match tier'],
            ['cve_id', 'CVE ID'],
          ] as const
        ).map(([k, label]) => (
          <button
            key={k}
            type="button"
            onClick={() => setSortKey(k)}
            className={`rounded-full border px-2 py-0.5 text-[11px] transition-colors ${
              sortKey === k
                ? 'border-primary/60 bg-primary/10 text-foreground'
                : 'border-border hover:bg-accent/30'
            }`}
          >
            {label}
          </button>
        ))}
        <span className="ml-auto">
          {sortedCves.length} CVE{sortedCves.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="overflow-x-auto rounded-md border border-border">
        {/* Header — CSS grid matches the row template so columns align even
            though the virtualised rows are <div>s, not <tr>s. */}
        <div
          className="grid items-center border-b border-border bg-muted/30 text-xs font-medium text-muted-foreground"
          style={{ gridTemplateColumns: COLUMN_TEMPLATE }}
        >
          <div className="py-2 pl-3 pr-3">Severity</div>
          <div className="py-2 pr-3">CVE</div>
          <div className="py-2 pr-3">Tier</div>
          <div className="py-2 pr-3 text-right">Blobs</div>
          <div className="py-2 pr-3">Formats</div>
        </div>
        <div ref={listWrapperRef}>
          <List
            rowComponent={CveRowComponent}
            rowCount={rows.length}
            rowHeight={itemSize}
            rowProps={{
              rows,
              toggle,
              blobsById,
              onSelectBlob,
              searchQuery,
            }}
            style={{ height: listHeight, minHeight: 240 }}
          />
        </div>
      </div>
    </div>
  )
}

interface CveRowExtraProps {
  rows: Row[]
  toggle: (id: string) => void
  blobsById: Map<string, HardwareFirmwareBlob>
  onSelectBlob: (blobId: string) => void
  searchQuery?: string
}

function CveRowComponent({
  index,
  style,
  rows,
  toggle,
  blobsById,
  onSelectBlob,
  searchQuery,
}: RowComponentProps<CveRowExtraProps>) {
  const row = rows[index]
  if (!row) return null

  if (row.kind === 'cve') {
    const c = row.cve
    // react-window provides absolute positioning via `style`; we overlay the
    // grid on top so row cells align with the header columns.
    const rowStyle: CSSProperties = {
      ...style,
      gridTemplateColumns: COLUMN_TEMPLATE,
    }
    return (
      <div
        style={rowStyle}
        onClick={() => toggle(c.cve_id)}
        className="grid cursor-pointer items-center border-b border-border/50 text-xs transition-colors hover:bg-accent/30"
      >
        <div className="py-1.5 pl-3 pr-3">
          <Badge
            className={`text-[10px] ${
              SEVERITY_STYLE[c.severity] ?? SEVERITY_STYLE.unknown
            }`}
          >
            {c.severity}
          </Badge>
          {c.cvss_score != null && (
            <span className="ml-1 text-[10px] tabular-nums text-muted-foreground">
              {c.cvss_score}
            </span>
          )}
        </div>
        <div className="py-1.5 pr-3 font-mono text-[11px] font-semibold truncate">
          {highlightMatches(c.cve_id, searchQuery)}
        </div>
        <div className="py-1.5 pr-3 font-mono text-[10px] text-muted-foreground truncate">
          {c.match_tier ?? '—'}
        </div>
        <div className="py-1.5 pr-3 text-right font-mono tabular-nums">
          {c.affected_blob_count}
        </div>
        <div className="py-1.5 pr-3 font-mono text-[10px] text-muted-foreground truncate">
          {c.affected_formats.join(', ')}
        </div>
      </div>
    )
  }

  // kind === 'detail'
  const c = row.cve
  // Detail renders as a single full-width block.  Don't apply the grid
  // template — we want free-form layout under the parent CVE row.
  const rowStyle: CSSProperties = { ...style }
  return (
    <div
      style={rowStyle}
      className="border-b border-border/50 bg-muted/20 px-4 py-3 text-[11px] overflow-y-auto"
    >
      {c.description && (
        <p className="mb-2 text-muted-foreground">{c.description}</p>
      )}
      <p className="mb-1 text-xs font-medium text-muted-foreground">
        Affected blobs ({c.affected_blob_count})
      </p>
      <ul className="space-y-0.5">
        {c.affected_blob_ids.map((bid) => {
          const blob = blobsById.get(bid)
          if (!blob) {
            return (
              <li
                key={bid}
                className="break-all font-mono text-[10px] text-muted-foreground"
              >
                {bid}
              </li>
            )
          }
          return (
            <li key={bid}>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  onSelectBlob(bid)
                }}
                className="break-all text-left font-mono text-[11px] text-blue-500 hover:underline"
              >
                {displayPath(blob.blob_path)}
              </button>
              <span className="ml-2 font-mono text-[10px] text-muted-foreground">
                {blob.format}
              </span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
