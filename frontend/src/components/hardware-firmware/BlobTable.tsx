import { Fragment, type CSSProperties, type ReactNode } from 'react'
import { List, type RowComponentProps } from 'react-window'
import { Badge } from '@/components/ui/badge'
import { useResponsiveListHeight } from '@/hooks/useResponsiveListHeight'
import type { HardwareFirmwareBlob } from '@/api/hardwareFirmware'

interface BlobTableProps {
  blobs: HardwareFirmwareBlob[]
  selectedId: string | null
  onSelect: (id: string) => void
  searchQuery?: string
}

/**
 * Fixed row height for react-window.  Rows are a single line with py-1.5 and
 * text-[11px]/text-xs, which measures ~28-30px in Chrome.  We pad to 32 so
 * the bottom border doesn't visually fuse with the next row.
 */
const ROW_HEIGHT = 32

/**
 * Column template shared with the header.  Matches the 7 columns of the
 * legacy table exactly (path, category, vendor, format, size, CVEs, signed).
 * Path is the flex column; the trailing columns are sized to their content
 * so the right-hand labels don't shimmy as virtualized rows recycle.
 */
const COLUMN_TEMPLATE =
  'minmax(220px, 2fr) minmax(110px, 1fr) minmax(90px, 1fr) minmax(80px, 1fr) minmax(70px, 0.8fr) minmax(80px, 0.9fr) minmax(100px, 1fr)'

// Exhaustive Record fallback per CLAUDE.md rule 9.
const SIGNED_STYLE: Record<string, string> = {
  signed: 'border-green-500/50 text-green-600 dark:text-green-400',
  unsigned: 'border-red-500/50 text-red-600 dark:text-red-400',
  unknown: 'border-gray-500/50 text-gray-500',
  weakly_signed: 'border-orange-500/50 text-orange-600 dark:text-orange-400',
}

function cveBadgeClass(severity: string | null | undefined): string {
  switch (severity) {
    case 'critical':
      return 'bg-red-700'
    case 'high':
      return 'bg-red-600'
    case 'medium':
      return 'bg-amber-600'
    case 'low':
      return 'bg-yellow-600'
    default:
      return 'bg-red-600'
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// Strip storage prefix so paths display as "partition_4_erofs/lib/modules/foo.ko"
// instead of the full container storage path.  Matches any path containing
// "/extracted/rootfs/", "/extracted/", or "/firmware/<uuid>/extracted".
export function displayPath(abs: string): string {
  const markers = ['/extracted/rootfs/', '/extracted/']
  for (const m of markers) {
    const idx = abs.indexOf(m)
    if (idx >= 0) return abs.slice(idx + m.length)
  }
  return abs
}

/**
 * Render ``text`` with every case-insensitive occurrence of ``query``
 * wrapped in a <mark> element so search hits are visually obvious.
 * Empty / whitespace queries short-circuit to the raw string.  Query
 * characters are escaped before being compiled as a regex literal so
 * paths with dots / dashes don't turn into surprise regex operators.
 */
export function highlightMatches(text: string, query: string | undefined): ReactNode {
  const q = (query ?? '').trim()
  if (!q) return text
  const safe = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  // Split with a capture group returns alternating non-match / match
  // segments, so odd indices are the hits — no need to re-test, which
  // would be unreliable with the global flag's stateful lastIndex.
  const re = new RegExp(`(${safe})`, 'gi')
  const parts = text.split(re)
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <mark
        key={i}
        className="rounded-sm bg-amber-300/50 px-0.5 text-foreground dark:bg-amber-400/30"
      >
        {part}
      </mark>
    ) : (
      <Fragment key={i}>{part}</Fragment>
    ),
  )
}

export default function BlobTable({
  blobs,
  selectedId,
  onSelect,
  searchQuery,
}: BlobTableProps) {
  const { ref: listWrapperRef, height: listHeight } = useResponsiveListHeight({
    maxHeight: 640,
    minHeight: 240,
  })

  if (blobs.length === 0) {
    return (
      <div className="py-6 text-center text-xs text-muted-foreground">
        No hardware firmware blobs match the current filters.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-md border border-border">
      {/* Header — CSS grid matches the row template below so columns align
          even though the virtualized rows are <div>s, not <tr>s. */}
      <div
        className="grid items-center border-b border-border bg-muted/30 text-xs font-medium text-muted-foreground"
        style={{ gridTemplateColumns: COLUMN_TEMPLATE }}
      >
        <div className="py-2 pl-3 pr-3">Path</div>
        <div className="py-2 pr-3">Category</div>
        <div className="py-2 pr-3">Vendor</div>
        <div className="py-2 pr-3">Format</div>
        <div className="py-2 pr-3 text-right">Size</div>
        <div className="py-2 pr-3">CVEs</div>
        <div className="py-2 pr-3">Signed</div>
      </div>
      <div ref={listWrapperRef}>
        <List
          rowComponent={BlobRow}
          rowCount={blobs.length}
          rowHeight={ROW_HEIGHT}
          rowProps={{ blobs, selectedId, onSelect, searchQuery }}
          style={{ height: listHeight, minHeight: 240 }}
        />
      </div>
    </div>
  )
}

interface BlobRowExtraProps {
  blobs: HardwareFirmwareBlob[]
  selectedId: string | null
  onSelect: (id: string) => void
  searchQuery?: string
}

function BlobRow({
  index,
  style,
  blobs,
  selectedId,
  onSelect,
  searchQuery,
}: RowComponentProps<BlobRowExtraProps>) {
  const b = blobs[index]
  const isSelected = selectedId === b.id
  const signedStyle =
    SIGNED_STYLE[b.signed] ?? 'border-border text-muted-foreground'

  // react-window provides absolute positioning via `style`; we overlay the
  // grid on top of that so row cells align with the header columns.
  const rowStyle: CSSProperties = {
    ...style,
    gridTemplateColumns: COLUMN_TEMPLATE,
  }

  return (
    <div
      style={rowStyle}
      onClick={() => onSelect(b.id)}
      className={`grid cursor-pointer items-center border-b border-border/50 text-xs transition-colors ${
        isSelected ? 'bg-accent/60' : 'hover:bg-accent/30'
      }`}
    >
      <div className="py-1.5 pl-3 pr-3 font-mono text-[11px]" title={b.blob_path}>
        <div className="truncate">
          {highlightMatches(displayPath(b.blob_path), searchQuery)}
        </div>
      </div>
      <div className="py-1.5 pr-3 text-muted-foreground truncate">{b.category}</div>
      <div className="py-1.5 pr-3 truncate">{b.vendor ?? '—'}</div>
      <div className="py-1.5 pr-3 font-mono text-[11px] truncate">{b.format}</div>
      <div className="py-1.5 pr-3 text-right tabular-nums">
        {formatBytes(b.file_size)}
      </div>
      <div className="py-1.5 pr-3">
        {b.cve_count > 0 ? (
          <Badge
            className={`text-[10px] text-white ${cveBadgeClass(b.max_severity)}`}
            title={`max severity: ${b.max_severity ?? 'unknown'}`}
          >
            {b.cve_count}
          </Badge>
        ) : (
          <span className="text-muted-foreground/60">—</span>
        )}
        {b.advisory_count > 0 && (
          <Badge
            className="ml-1 text-[10px] bg-amber-600 text-white"
            title={`${b.advisory_count} advisory flag(s)`}
          >
            ADV
          </Badge>
        )}
      </div>
      <div className="py-1.5 pr-3">
        <Badge variant="outline" className={`text-[10px] ${signedStyle}`}>
          {b.signed}
        </Badge>
      </div>
    </div>
  )
}
