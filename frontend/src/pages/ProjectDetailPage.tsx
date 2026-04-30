import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft,
  Trash2,
  Loader2,
  Plus,
  Download,
} from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import { deleteFirmware, updateFirmware, uploadRootfs } from '@/api/firmware'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { formatDate } from '@/utils/format'
import FirmwareUpload from '@/components/projects/FirmwareUpload'
import FirmwareMetadataCard from '@/components/projects/FirmwareMetadataCard'
import FirmwareVersionCard from '@/components/projects/FirmwareVersionCard'
import ProjectActionButtons from '@/components/projects/ProjectActionButtons'
import DocumentsCard from '@/components/projects/DocumentsCard'
import { exportProject } from '@/api/exportImport'
import { useEventStream } from '@/hooks/useEventStream'
import { PROJECT_STATUS_VARIANT } from '@/constants/statusConfig'
import { extractErrorMessage } from '@/utils/error'

export default function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()
  const {
    currentProject: project,
    loading,
    unpacking,
    fetchProject,
    removeProject,
    unpackFirmware,
    clearCurrentProject,
  } = useProjectStore()
  const invalidateFirmwareList = useProjectStore((s) => s.invalidateFirmwareList)

  const { firmwareList } = useFirmwareList(projectId)
  const [showUpload, setShowUpload] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const [editingVersionLabel, setEditingVersionLabel] = useState<string | null>(null)
  const [versionLabelDraft, setVersionLabelDraft] = useState('')
  const [uploadingRootfs, setUploadingRootfs] = useState<string | null>(null)
  const [rootfsError, setRootfsError] = useState<string | null>(null)
  const [expandedLogs, setExpandedLogs] = useState<Set<string>>(new Set())
  const versionInputRef = useRef<HTMLInputElement>(null)
  const rootfsInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (projectId) fetchProject(projectId)
    return () => clearCurrentProject()
  }, [projectId, fetchProject, clearCurrentProject])

  // When project-level status transitions (e.g. 'unpacking' → 'ready'),
  // invalidate the cache so other pages see the fresh firmware state.
  // The useFirmwareList hook re-loads automatically on invalidation.
  useEffect(() => {
    if (projectId && project) {
      invalidateFirmwareList()
    }
  }, [projectId, project?.id, project?.status, invalidateFirmwareList])

  // SSE: listen for unpacking events and refresh on status changes
  const isUnpacking = project?.status === 'unpacking'
  const { lastEvent: unpackEvent } = useEventStream<{ type: string; status: string }>(
    projectId,
    { types: ['unpacking'], enabled: isUnpacking },
  )

  const refreshProject = useCallback(() => {
    if (!projectId) return
    fetchProject(projectId)
    invalidateFirmwareList()
  }, [projectId, fetchProject, invalidateFirmwareList])

  // When an SSE event arrives, refresh data
  useEffect(() => {
    if (unpackEvent) refreshProject()
  }, [unpackEvent, refreshProject])

  // Fallback poll while unpacking (in case SSE is unavailable)
  useEffect(() => {
    if (!projectId || !isUnpacking) return
    const interval = setInterval(refreshProject, 5000)
    return () => clearInterval(interval)
  }, [projectId, isUnpacking, refreshProject])

  if (loading || !project) {
    return (
      <div className="flex items-center gap-2 py-12 justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span>Loading project...</span>
      </div>
    )
  }

  const firmware = project.firmware ?? []
  const status = project.status
  const hasUnpacked = firmwareList.some((fw) => fw.extracted_path)
  const unpackedCount = firmwareList.filter((fw) => fw.extracted_path).length

  const handleDelete = async () => {
    if (window.confirm('Delete this project and all its data? This cannot be undone.')) {
      try {
        await removeProject(project.id)
        navigate('/projects')
      } catch {
        // error shown via store
      }
    }
  }

  const handleUnpack = async (firmwareId: string) => {
    if (projectId) {
      try {
        await unpackFirmware(projectId, firmwareId)
        // Refresh firmware list
        invalidateFirmwareList()
      } catch {
        // error shown via store
      }
    }
  }

  const handleDeleteFirmware = async (firmwareId: string) => {
    if (!projectId) return
    if (!window.confirm('Delete this firmware version? This cannot be undone.')) return
    try {
      await deleteFirmware(projectId, firmwareId)
      fetchProject(projectId)
      invalidateFirmwareList()
    } catch {
      // error handled by caller
    }
  }

  const handleExport = async () => {
    if (!projectId) return
    setExporting(true)
    setExportError(null)
    try {
      const blob = await exportProject(projectId)
      const safeName = project.name.replace(/\s+/g, '_').replace(/\//g, '_')
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${safeName}.wairz`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      setExportError(extractErrorMessage(err, 'Export failed'))
    } finally {
      setExporting(false)
    }
  }

  const startEditingVersionLabel = (fwId: string, current: string | null) => {
    setEditingVersionLabel(fwId)
    setVersionLabelDraft(current ?? '')
    setTimeout(() => versionInputRef.current?.focus(), 0)
  }

  const saveVersionLabel = async (fwId: string) => {
    if (!projectId) return
    const label = versionLabelDraft.trim() || null
    try {
      await updateFirmware(projectId, fwId, { version_label: label })
      fetchProject(projectId)
      invalidateFirmwareList()
    } catch {
      // error handled by caller
    }
    setEditingVersionLabel(null)
  }

  const handleRootfsUpload = async (firmwareId: string, file: File) => {
    if (!projectId) return
    setUploadingRootfs(firmwareId)
    setRootfsError(null)
    try {
      await uploadRootfs(projectId, firmwareId, file)
      fetchProject(projectId)
      invalidateFirmwareList()
    } catch (e) {
      setRootfsError(extractErrorMessage(e, 'Upload failed'))
    } finally {
      setUploadingRootfs(null)
    }
  }

  const handleUploadComplete = () => {
    setShowUpload(false)
    if (projectId) {
      fetchProject(projectId)
      invalidateFirmwareList()
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">{project.name}</h1>
            <Badge
              variant={PROJECT_STATUS_VARIANT[status] ?? 'outline'}
              className={status === 'unpacking' ? 'animate-pulse' : ''}
            >
              {status}
            </Badge>
          </div>
          {project.description && (
            <p className="text-sm text-muted-foreground">{project.description}</p>
          )}
          <p className="text-xs text-muted-foreground">Created {formatDate(project.created_at)}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" asChild>
            <Link to="/projects">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Link>
          </Button>
          <Button variant="outline" size="sm" onClick={handleExport} disabled={exporting}>
            {exporting ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Download className="mr-2 h-4 w-4" />
            )}
            Export
          </Button>
          <Button variant="destructive" size="sm" onClick={handleDelete}>
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
        </div>
      </div>

      {exportError && (
        <div className="rounded bg-destructive/10 border border-destructive/20 p-3 text-sm text-destructive">
          Export failed: {exportError}
        </div>
      )}

      {/* Firmware cards */}
      {firmware.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Firmware ({firmware.length})
            </h2>
            <Button size="sm" variant="outline" onClick={() => setShowUpload(!showUpload)}>
              <Plus className="mr-1 h-3.5 w-3.5" />
              Upload Version
            </Button>
          </div>

          {firmware.map((fw) => (
            <FirmwareVersionCard
              key={fw.id}
              fw={fw}
              fwDetail={firmwareList.find((f) => f.id === fw.id)}
              status={status}
              unpacking={unpacking}
              editingVersionLabel={editingVersionLabel}
              versionLabelDraft={versionLabelDraft}
              versionInputRef={versionInputRef}
              onSetVersionLabelDraft={setVersionLabelDraft}
              handleUnpack={handleUnpack}
              handleDeleteFirmware={handleDeleteFirmware}
              startEditingVersionLabel={startEditingVersionLabel}
              saveVersionLabel={saveVersionLabel}
              cancelEditingVersionLabel={() => setEditingVersionLabel(null)}
              handleRootfsUpload={handleRootfsUpload}
              uploadingRootfs={uploadingRootfs}
              rootfsError={rootfsError}
              rootfsInputRef={rootfsInputRef}
              expandedLogs={expandedLogs}
              setExpandedLogs={setExpandedLogs}
            />
          ))}
        </div>
      )}

      {/* Upload section */}
      {(showUpload || firmware.length === 0) && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Upload Firmware</CardTitle>
          </CardHeader>
          <CardContent>
            <FirmwareUpload
              projectId={project.id}
              onComplete={handleUploadComplete}
              showVersionLabel
            />
          </CardContent>
        </Card>
      )}

      {/* Project documents */}
      <DocumentsCard projectId={project.id} />

      {/* Firmware metadata cards for unpacked firmware */}
      {firmwareList
        .filter((fw) => fw.extracted_path)
        .map((fw) => (
          <FirmwareMetadataCard key={fw.id} projectId={project.id} firmwareId={fw.id} />
        ))}

      {/* Action buttons when ready */}
      {hasUnpacked && (
        <ProjectActionButtons
          project={project}
          unpackedCount={unpackedCount}
        />
      )}
    </div>
  )
}
