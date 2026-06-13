import { useCallback, useEffect, useState } from 'react'
import { Loader2, RefreshCw, Shield } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  getAllAttackSurface,
  triggerAttackSurfaceScan,
  type AttackSurfaceEntry,
  type AttackSurfaceSummary,
} from '@/api/attackSurface'

interface AttackSurfaceTabProps {
  projectId: string
  selectedFirmwareId: string | null
}

const SCORE_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-500 text-black',
  LOW: 'bg-gray-500 text-white',
}

function scoreBadge(score: number): { label: string; className: string } {
  if (score >= 75) return { label: 'CRITICAL', className: SCORE_BADGE.CRITICAL }
  if (score >= 50) return { label: 'HIGH', className: SCORE_BADGE.HIGH }
  if (score >= 25) return { label: 'MEDIUM', className: SCORE_BADGE.MEDIUM }
  return { label: 'LOW', className: SCORE_BADGE.LOW }
}

type SortKey = 'attack_surface_score' | 'binary_name' | 'file_size'

export default function AttackSurfaceTab({ projectId, selectedFirmwareId }: AttackSurfaceTabProps) {
  const [entries, setEntries] = useState<AttackSurfaceEntry[]>([])
  const [summary, setSummary] = useState<AttackSurfaceSummary | null>(null)
  const [loading, setLoading] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [sortKey, setSortKey] = useState<SortKey>('attack_surface_score')
  const [sortDesc, setSortDesc] = useState(true)

  const loadEntries = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (selectedFirmwareId) params.firmware_id = selectedFirmwareId
      const data = await getAllAttackSurface(projectId, params)
      setEntries(data)
      // Compute summary from data
      if (data.length > 0) {
        const s: AttackSurfaceSummary = {
          total_binaries: data.length,
          critical_count: data.filter((e) => e.attack_surface_score >= 75).length,
          high_count: data.filter((e) => e.attack_surface_score >= 50 && e.attack_surface_score < 75).length,
          medium_count: data.filter((e) => e.attack_surface_score >= 25 && e.attack_surface_score < 50).length,
          low_count: data.filter((e) => e.attack_surface_score < 25).length,
          top_categories: [...new Set(data.flatMap((e) => e.input_categories))].sort(),
        }
        setSummary(s)
      } else {
        setSummary(null)
      }
    } catch {
      setEntries([])
      setSummary(null)
    } finally {
      setLoading(false)
    }
  }, [projectId, selectedFirmwareId])

  useEffect(() => {
    loadEntries()
  }, [loadEntries])

  const handleScan = async () => {
    setScanning(true)
    try {
      const result = await triggerAttackSurfaceScan(projectId, true)
      setEntries(result.entries)
      setSummary(result.summary)
    } catch {
      // keep existing state
    } finally {
      setScanning(false)
    }
  }

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDesc(!sortDesc)
    } else {
      setSortKey(key)
      setSortDesc(key === 'attack_surface_score')
    }
  }

  const sorted = [...entries].sort((a, b) => {
    let cmp = 0
    if (sortKey === 'attack_surface_score') {
      cmp = a.attack_surface_score - b.attack_surface_score
    } else if (sortKey === 'binary_name') {
      cmp = a.binary_name.localeCompare(b.binary_name)
    } else if (sortKey === 'file_size') {
      cmp = (a.file_size ?? 0) - (b.file_size ?? 0)
    }
    return sortDesc ? -cmp : cmp
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Button onClick={handleScan} disabled={scanning}>
          {scanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
          {scanning ? 'Scanning...' : 'Scan Attack Surface'}
        </Button>
        <p className="text-xs text-muted-foreground">
          Analyzes all ELF binaries for network listeners, setuid, CGI handlers, dangerous imports, and missing protections
        </p>
      </div>

      {summary && (
        <Card>
          <CardContent className="py-3 px-4">
            <div className="flex items-center gap-4 flex-wrap">
              <span className="text-sm font-medium">{summary.total_binaries} binaries analyzed</span>
              {summary.critical_count > 0 && (
                <Badge className={SCORE_BADGE.CRITICAL}>Critical: {summary.critical_count}</Badge>
              )}
              {summary.high_count > 0 && (
                <Badge className={SCORE_BADGE.HIGH}>High: {summary.high_count}</Badge>
              )}
              {summary.medium_count > 0 && (
                <Badge className={SCORE_BADGE.MEDIUM}>Medium: {summary.medium_count}</Badge>
              )}
              {summary.low_count > 0 && (
                <Badge className={SCORE_BADGE.LOW}>Low: {summary.low_count}</Badge>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {loading ? (
        <div className="flex items-center gap-2 py-8 justify-center text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading attack surface data...
        </div>
      ) : entries.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">
            No attack surface data yet. Click &quot;Scan Attack Surface&quot; to analyze firmware binaries.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b text-left text-muted-foreground">
                <th
                  className="pb-2 pr-3 font-medium w-16 cursor-pointer hover:text-foreground"
                  onClick={() => handleSort('attack_surface_score')}
                >
                  Score {sortKey === 'attack_surface_score' ? (sortDesc ? '\u25BC' : '\u25B2') : ''}
                </th>
                <th className="pb-2 pr-3 font-medium w-20">Severity</th>
                <th
                  className="pb-2 pr-3 font-medium cursor-pointer hover:text-foreground"
                  onClick={() => handleSort('binary_name')}
                >
                  Binary {sortKey === 'binary_name' ? (sortDesc ? '\u25BC' : '\u25B2') : ''}
                </th>
                <th className="pb-2 pr-3 font-medium">Path</th>
                <th className="pb-2 pr-3 font-medium">Categories</th>
                <th className="pb-2 pr-3 font-medium">Key Imports</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((e) => {
                const badge = scoreBadge(e.attack_surface_score)
                return (
                  <tr key={e.id} className="border-b border-border/30 hover:bg-muted/50">
                    <td className="py-1.5 pr-3 font-mono font-medium">{e.attack_surface_score}</td>
                    <td className="py-1.5 pr-3">
                      <Badge variant="outline" className={`text-xs ${badge.className}`}>
                        {badge.label}
                      </Badge>
                    </td>
                    <td className="py-1.5 pr-3 font-mono font-medium">{e.binary_name}</td>
                    <td className="py-1.5 pr-3 font-mono text-muted-foreground truncate max-w-[250px]">
                      {e.binary_path}
                    </td>
                    <td className="py-1.5 pr-3">
                      <div className="flex gap-1 flex-wrap">
                        {e.input_categories.slice(0, 3).map((cat) => (
                          <Badge key={cat} variant="secondary" className="text-[10px] px-1.5 py-0">
                            {cat}
                          </Badge>
                        ))}
                        {e.input_categories.length > 3 && (
                          <span className="text-muted-foreground">+{e.input_categories.length - 3}</span>
                        )}
                      </div>
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-muted-foreground truncate max-w-[200px]">
                      {e.dangerous_imports.slice(0, 4).join(', ') || '-'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {sorted.length > 200 && (
            <p className="text-xs text-muted-foreground mt-2">
              Showing first 200 of {sorted.length} binaries.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
