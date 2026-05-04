import { useEffect, useRef, useState, useCallback } from 'react'
import { useParams, useLocation } from 'react-router-dom'
import { ShieldAlert, Loader2 } from 'lucide-react'
import { listFindings, updateFinding, deleteFinding } from '@/api/findings'
import { useProjectStore } from '@/stores/projectStore'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import type { Finding, FindingUpdate, Severity, FindingStatus, FindingSource } from '@/types'
import FirmwareSelector from '@/components/projects/FirmwareSelector'
import FindingsList from '@/components/findings/FindingsList'
import FindingDetail from '@/components/findings/FindingDetail'
import ReportExport from '@/components/findings/ReportExport'

export default function FindingsPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const location = useLocation()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const { firmwareList } = useFirmwareList(projectId)

  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedId, setSelectedId] = useState<string | null>(
    (location.state as { findingId?: string } | null)?.findingId ?? null,
  )
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null)
  const [statusFilter, setStatusFilter] = useState<FindingStatus | null>(null)
  const [sourceFilter, setSourceFilter] = useState<FindingSource | null>(null)

  const initialLoadDone = useRef(false)
  const fetchFindings = useCallback(async () => {
    if (!projectId) return
    if (!initialLoadDone.current) setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (severityFilter) params.severity = severityFilter
      if (statusFilter) params.status = statusFilter
      if (sourceFilter) params.source = sourceFilter
      if (selectedFirmwareId) params.firmware_id = selectedFirmwareId
      const data = await listFindings(projectId, params)
      setFindings(data)
    } catch (err) {
      console.error('Failed to load findings:', err)
    } finally {
      setLoading(false)
      initialLoadDone.current = true
    }
  }, [projectId, severityFilter, statusFilter, sourceFilter, selectedFirmwareId])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  const handleSelect = useCallback((finding: Finding) => {
    setSelectedId((prev) => (prev === finding.id ? null : finding.id))
  }, [])

  const handleUpdate = useCallback(
    async (findingId: string, updates: FindingUpdate) => {
      if (!projectId) return
      try {
        const updated = await updateFinding(projectId, findingId, updates)
        setFindings((prev) =>
          prev.map((f) => (f.id === findingId ? updated : f)),
        )
      } catch (err) {
        console.error('Failed to update finding:', err)
      }
    },
    [projectId],
  )

  const handleDelete = useCallback(
    async (findingId: string) => {
      if (!projectId) return
      try {
        await deleteFinding(projectId, findingId)
        setFindings((prev) => prev.filter((f) => f.id !== findingId))
        if (selectedId === findingId) setSelectedId(null)
      } catch (err) {
        console.error('Failed to delete finding:', err)
      }
    },
    [projectId, selectedId],
  )

  const selectedFinding = findings.find((f) => f.id === selectedId) ?? null

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-12 justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span>Loading findings...</span>
      </div>
    )
  }

  return (
    <div className="-m-6 flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Left panel: findings list */}
      <div className="flex w-96 shrink-0 flex-col overflow-hidden border-r border-border">
        <div className="flex flex-col gap-2 border-b border-border px-4 py-2">
          <div className="flex min-w-0 items-center gap-2">
            <ShieldAlert className="h-4 w-4 shrink-0 text-muted-foreground" />
            <span className="shrink-0 text-sm font-medium">Findings</span>
            <div className="ml-auto shrink-0">
              {projectId && <ReportExport projectId={projectId} />}
            </div>
          </div>
          <FirmwareSelector projectId={projectId!} firmwareList={firmwareList} className="w-full" />
        </div>
        <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden px-3 py-2">
          <FindingsList
            findings={findings}
            selectedId={selectedId}
            onSelect={handleSelect}
            severityFilter={severityFilter}
            statusFilter={statusFilter}
            sourceFilter={sourceFilter}
            onSeverityFilter={setSeverityFilter}
            onStatusFilter={setStatusFilter}
            onSourceFilter={setSourceFilter}
          />
        </div>
      </div>

      {/* Center panel: finding detail */}
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {selectedFinding ? (
          <div className="min-w-0 flex-1 overflow-y-auto p-6">
            <FindingDetail
              key={selectedFinding.id}
              finding={selectedFinding}
              onUpdate={handleUpdate}
              onDelete={handleDelete}
            />
          </div>
        ) : (
          <div className="flex flex-1 flex-col items-center justify-center text-muted-foreground">
            <ShieldAlert className="mb-3 h-12 w-12" />
            <p className="text-sm">Select a finding to view details</p>
          </div>
        )}
      </div>
    </div>
  )
}
