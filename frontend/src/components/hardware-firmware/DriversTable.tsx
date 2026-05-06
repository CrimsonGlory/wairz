import { useMemo, useState, type CSSProperties } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { List, type RowComponentProps } from 'react-window'
import { useResponsiveListHeight } from '@/hooks/useResponsiveListHeight'
import { Badge } from '@/components/ui/badge'
import type { FirmwareDriver } from '@/api/hardwareFirmware'

interface DriversTableProps {
  drivers: FirmwareDriver[]
}

/**
 * Fixed height (px) for a collapsed driver row.  Row content is py-1.5 with
 * text-xs; chrome measures ~28-30px.  We pad to 32 so borders don't fuse.
 */
const DRIVER_ROW_HEIGHT = 32

/**
 * Per-dep height when a driver is expanded.  Each dep renders a single-line
 * flex row with text-[11px]; measures ~20-22px in chrome.
 */
const DETAIL_DEP_HEIGHT = 22

/**
 * Padding added around the expanded detail block (py-2 + pl-2 + border).
 * Includes the "No firmware dependencies recorded." placeholder minimum.
 */
const DETAIL_CHROME_HEIGHT = 22

/**
 * Column template shared between the div-grid header and each virtualised
 * row so columns stay aligned through scrolling.  Matches the 5 columns of
 * the legacy table: chevron / driver path / format / resolved / unresolved.
 */
const COLUMN_TEMPLATE =
  '24px minmax(220px, 3fr) minmax(80px, 0.8fr) 80px 80px'

/**
 * Flat row model.  We flatten the (driver, optional detail) pair into two
 * rows so the virtualiser sees a single indexable list.
 */
type Row =
  | { kind: 'driver'; driver: FirmwareDriver; isOpen: boolean }
  | { kind: 'detail'; driver: FirmwareDriver }

export default function DriversTable({ drivers }: DriversTableProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const { ref: listWrapperRef, height: listHeight } = useResponsiveListHeight({
    maxHeight: 560,
    minHeight: 240,
  })

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = []
    for (const d of drivers) {
      const isOpen = expanded.has(d.driver_path)
      out.push({ kind: 'driver', driver: d, isOpen })
      if (isOpen) {
        out.push({ kind: 'detail', driver: d })
      }
    }
    return out
  }, [drivers, expanded])

  if (drivers.length === 0) {
    return (
      <div className="py-6 text-center text-xs text-muted-foreground">
        No drivers requesting firmware were detected.
      </div>
    )
  }

  const toggle = (path: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(path)) next.delete(path)
      else next.add(path)
      return next
    })
  }

  /**
   * Variable row-height callback for react-window.  Driver header rows
   * have a fixed height; detail rows are sized proportional to the number
   * of firmware deps so every item fits without clipping.
   */
  const itemSize = (index: number): number => {
    const row = rows[index]
    if (!row) return DRIVER_ROW_HEIGHT
    if (row.kind === 'driver') return DRIVER_ROW_HEIGHT
    const depCount = Math.max(1, row.driver.firmware_deps.length)
    return DETAIL_CHROME_HEIGHT + depCount * DETAIL_DEP_HEIGHT
  }

  return (
    <div className="overflow-x-auto rounded-md border border-border">
      {/* Header — CSS grid matches the row template below so columns align
          even though the virtualised rows are <div>s, not <tr>s. */}
      <div
        className="grid items-center border-b border-border bg-muted/30 text-xs font-medium text-muted-foreground"
        style={{ gridTemplateColumns: COLUMN_TEMPLATE }}
      >
        <div className="py-2 pl-3 pr-3"></div>
        <div className="py-2 pr-3">Driver</div>
        <div className="py-2 pr-3">Format</div>
        <div className="py-2 pr-3 text-right">Resolved</div>
        <div className="py-2 pr-3 text-right">Unresolved</div>
      </div>
      <div ref={listWrapperRef}>
        <List
          rowComponent={DriverRowComponent}
          rowCount={rows.length}
          rowHeight={itemSize}
          rowProps={{ rows, toggle }}
          style={{ height: listHeight, minHeight: 240 }}
        />
      </div>
    </div>
  )
}

interface DriverRowExtraProps {
  rows: Row[]
  toggle: (path: string) => void
}

function DriverRowComponent({
  index,
  style,
  rows,
  toggle,
}: RowComponentProps<DriverRowExtraProps>) {
  const row = rows[index]
  if (!row) return null

  if (row.kind === 'driver') {
    const d = row.driver
    const isOpen = row.isOpen
    const resolvedCount = d.firmware_blobs.length
    const unresolvedCount = Math.max(0, d.total - resolvedCount)
    // react-window provides absolute positioning via `style`; we overlay the
    // grid on top of that so row cells align with the header columns.
    const rowStyle: CSSProperties = {
      ...style,
      gridTemplateColumns: COLUMN_TEMPLATE,
    }
    return (
      <div
        style={rowStyle}
        onClick={() => toggle(d.driver_path)}
        className="grid cursor-pointer items-center border-b border-border/50 text-xs hover:bg-accent/30"
      >
        <div className="py-1.5 pl-3 pr-3">
          {isOpen ? (
            <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
          )}
        </div>
        <div
          className="py-1.5 pr-3 font-mono text-[11px] truncate"
          title={d.driver_path}
        >
          {d.driver_path}
        </div>
        <div className="py-1.5 pr-3 font-mono text-[11px] truncate">
          {d.format}
        </div>
        <div className="py-1.5 pr-3 text-right">
          <Badge
            variant="outline"
            className="border-green-500/40 text-green-600 text-[10px] dark:text-green-400"
          >
            {resolvedCount}
          </Badge>
        </div>
        <div className="py-1.5 pr-3 text-right">
          {unresolvedCount > 0 ? (
            <Badge
              variant="outline"
              className="border-red-500/40 text-red-600 text-[10px] dark:text-red-400"
            >
              {unresolvedCount}
            </Badge>
          ) : (
            <span className="text-muted-foreground">0</span>
          )}
        </div>
      </div>
    )
  }

  // kind === 'detail'
  const d = row.driver
  // Keep the absolute positioning from react-window but don't apply the grid
  // template to the detail row — we want a single full-width block under
  // the driver row, visually nested via left padding.
  const rowStyle: CSSProperties = { ...style }
  return (
    <div
      style={rowStyle}
      className="border-b border-border/50 bg-muted/10 pl-10 pr-3 py-2"
    >
      <div className="space-y-1">
        {d.firmware_deps.length === 0 ? (
          <p className="text-[11px] italic text-muted-foreground">
            No firmware dependencies recorded.
          </p>
        ) : (
          d.firmware_deps.map((dep, idx) => {
            const resolved = d.firmware_blobs[idx]
            return (
              <div
                key={`${d.driver_path}-${dep}-${idx}`}
                className="flex items-start gap-2 text-[11px]"
              >
                <span className="font-mono">{dep}</span>
                {resolved ? (
                  <Badge
                    variant="outline"
                    className="border-green-500/40 text-green-600 text-[9px] dark:text-green-400"
                  >
                    resolved
                  </Badge>
                ) : (
                  <Badge
                    variant="outline"
                    className="border-red-500/40 text-red-600 text-[9px] dark:text-red-400"
                  >
                    missing
                  </Badge>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
