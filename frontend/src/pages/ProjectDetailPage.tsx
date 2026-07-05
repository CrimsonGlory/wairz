import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft,
  Trash2,
  Loader2,
  Plus,
  Download,
  Upload,
  Pencil,
  Check,
  X,
  ChevronDown,
  FileText,
  Tag,
  AlertCircle,
  Cpu,
  HardDrive,
  Hash,
} from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import {
  deleteFirmware,
  updateFirmware,
  updateFirmwareArchInfo,
  updateFirmwareKind,
  uploadRootfs,
} from '@/api/firmware'
import type { FirmwareDetail, FirmwareKind, RtosFlavor } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { formatFileSize, formatDate } from '@/utils/format'
import FirmwareUpload from '@/components/projects/FirmwareUpload'
import FirmwareMetadataCard from '@/components/projects/FirmwareMetadataCard'
import ProjectActionButtons from '@/components/projects/ProjectActionButtons'
import DocumentsCard from '@/components/projects/DocumentsCard'
import { exportProject } from '@/api/exportImport'
import { useEventStream } from '@/hooks/useEventStream'
import { PROJECT_STATUS_VARIANT } from '@/constants/statusConfig'
import { extractErrorMessage } from '@/utils/error'

function formatKind(kind: FirmwareKind | undefined, flavor: RtosFlavor | null | undefined): string {
  if (kind === 'rtos') {
    if (flavor === 'freertos') return 'RTOS · FreeRTOS'
    if (flavor === 'zephyr') return 'RTOS · Zephyr'
    if (flavor === 'baremetal-cortexm') return 'Bare-metal Cortex-M'
    if (flavor === 'baremetal-mips16e') return 'Bare-metal MIPS16e'
    return 'RTOS'
  }
  if (kind === 'linux') return 'Linux'
  return 'Unknown'
}

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
  const isReady = (fw: FirmwareDetail) =>
    !!fw.extracted_path || (fw.firmware_kind === 'rtos' && !!fw.storage_path)
  const hasUnpacked = firmwareList.some(isReady)
  const unpackedCount = firmwareList.filter(isReady).length

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

  const handleKindChange = async (
    firmwareId: string,
    kind: FirmwareKind,
    flavor: RtosFlavor | null,
  ) => {
    if (!projectId) return
    try {
      await updateFirmwareKind(projectId, firmwareId, kind, flavor)
      fetchProject(projectId)
      invalidateFirmwareList()
    } catch {
      // error surfacing handled at a higher level if needed
    }
  }

  const handleArchChange = async (firmwareId: string, architecture: string | null) => {
    if (!projectId) return
    try {
      await updateFirmwareArchInfo(projectId, firmwareId, { architecture })
      fetchProject(projectId)
      invalidateFirmwareList()
    } catch { /* silent */ }
  }

  const handleEndianChange = async (firmwareId: string, endianness: 'little' | 'big' | null) => {
    if (!projectId) return
    try {
      await updateFirmwareArchInfo(projectId, firmwareId, { endianness })
      fetchProject(projectId)
      invalidateFirmwareList()
    } catch { /* silent */ }
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

          {firmware.map((fw) => {
            const fwDetail = firmwareList.find((f) => f.id === fw.id)
            const isUnpacked = !!fwDetail && isReady(fwDetail)
            const hasError = fwDetail?.unpack_log && !isUnpacked && status === 'error'

            return (
              <Card key={fw.id}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      {fw.original_filename}
                      {editingVersionLabel === fw.id ? (
                        <span className="inline-flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                          <Input
                            ref={versionInputRef}
                            value={versionLabelDraft}
                            onChange={(e) => setVersionLabelDraft(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') saveVersionLabel(fw.id)
                              if (e.key === 'Escape') setEditingVersionLabel(null)
                            }}
                            placeholder="e.g. v1.0.3"
                            className="h-6 w-32 text-xs"
                          />
                          <Button size="icon" variant="ghost" className="h-5 w-5" onClick={() => saveVersionLabel(fw.id)}>
                            <Check className="h-3 w-3" />
                          </Button>
                          <Button size="icon" variant="ghost" className="h-5 w-5" onClick={() => setEditingVersionLabel(null)}>
                            <X className="h-3 w-3" />
                          </Button>
                        </span>
                      ) : fw.version_label ? (
                        <Badge
                          variant="secondary"
                          className="text-xs cursor-pointer hover:bg-secondary/80"
                          onClick={() => startEditingVersionLabel(fw.id, fw.version_label ?? null)}
                        >
                          <Tag className="mr-1 h-3 w-3" />
                          {fw.version_label}
                          <Pencil className="ml-1 h-2.5 w-2.5 opacity-50" />
                        </Badge>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-5 px-1.5 text-xs text-muted-foreground"
                          onClick={() => startEditingVersionLabel(fw.id, null)}
                        >
                          <Tag className="mr-1 h-3 w-3" />
                          Add version
                        </Button>
                      )}
                      {isUnpacked && (
                        <Badge variant="default" className="text-xs">unpacked</Badge>
                      )}
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Badge
                            variant="outline"
                            className="text-xs cursor-pointer hover:bg-secondary/50"
                          >
                            {formatKind(fw.firmware_kind, fw.rtos_flavor)}
                            <ChevronDown className="ml-1 h-2.5 w-2.5 opacity-60" />
                          </Badge>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="start">
                          <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                            Kind ({fw.firmware_kind_source ?? 'unset'})
                          </DropdownMenuLabel>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem onClick={() => handleKindChange(fw.id, 'linux', null)}>
                            Linux
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleKindChange(fw.id, 'rtos', 'freertos')}>
                            RTOS · FreeRTOS
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleKindChange(fw.id, 'rtos', 'zephyr')}>
                            RTOS · Zephyr
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleKindChange(fw.id, 'rtos', 'baremetal-cortexm')}>
                            Bare-metal Cortex-M
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleKindChange(fw.id, 'rtos', 'baremetal-mips16e')}>
                            Bare-metal MIPS16e
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem onClick={() => handleKindChange(fw.id, 'unknown', null)}>
                            Unknown
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </CardTitle>
                    <div className="flex gap-1">
                      {!isUnpacked && !hasError && (
                        <Button size="sm" onClick={() => handleUnpack(fw.id)} disabled={unpacking}>
                          {unpacking && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
                          Unpack
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive hover:text-destructive"
                        onClick={() => handleDeleteFirmware(fw.id)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
                    <div className="flex items-center gap-2">
                      <HardDrive className="h-4 w-4 text-muted-foreground" />
                      <dt className="text-muted-foreground">Size:</dt>
                      <dd className="font-medium">
                        {fw.file_size != null ? formatFileSize(fw.file_size) : 'N/A'}
                      </dd>
                    </div>
                    {(fw.architecture || fw.firmware_kind === 'rtos') && (
                      <div className="flex items-center gap-2 flex-wrap col-span-2">
                        <Cpu className="h-4 w-4 text-muted-foreground shrink-0" />
                        <dt className="text-muted-foreground">Architecture:</dt>
                        <dd className="flex items-center gap-1.5">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Badge variant="outline" className="text-xs cursor-pointer hover:bg-secondary/50">
                                {fw.architecture ?? '?'}
                                <ChevronDown className="ml-1 h-2.5 w-2.5 opacity-60" />
                              </Badge>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="start">
                              <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                                Architecture
                              </DropdownMenuLabel>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onClick={() => handleArchChange(fw.id, null)} className="text-muted-foreground">
                                Unknown (clear)
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onClick={() => handleArchChange(fw.id, 'mips32')}>mips32</DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleArchChange(fw.id, 'mips64')}>mips64</DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onClick={() => handleArchChange(fw.id, 'arm')}>arm</DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleArchChange(fw.id, 'arm64')}>arm64</DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleArchChange(fw.id, 'x86')}>x86</DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleArchChange(fw.id, 'x86_64')}>x86_64</DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleArchChange(fw.id, 'powerpc')}>powerpc</DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleArchChange(fw.id, 'riscv32')}>riscv32</DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleArchChange(fw.id, 'riscv64')}>riscv64</DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Badge variant="outline" className="text-xs cursor-pointer hover:bg-secondary/50">
                                {fw.endianness === 'little' ? 'LE' : fw.endianness === 'big' ? 'BE' : '?'}
                                <ChevronDown className="ml-1 h-2.5 w-2.5 opacity-60" />
                              </Badge>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="start">
                              <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                                Endianness
                              </DropdownMenuLabel>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onClick={() => handleEndianChange(fw.id, null)} className="text-muted-foreground">
                                Unknown (clear)
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onClick={() => handleEndianChange(fw.id, 'little')}>
                                Little-endian (LE)
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleEndianChange(fw.id, 'big')}>
                                Big-endian (BE)
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </dd>
                      </div>
                    )}
                    <div className="flex items-center gap-2 col-span-2">
                      <Hash className="h-4 w-4 text-muted-foreground" />
                      <dt className="text-muted-foreground">SHA256:</dt>
                      <dd className="font-mono text-xs truncate">{fw.sha256}</dd>
                    </div>
                  </dl>

                  {hasError && fwDetail?.unpack_log && (
                    <div className="mt-3 rounded bg-destructive/5 border border-destructive/20 p-3">
                      <div className="flex items-center gap-2 text-sm text-destructive mb-2">
                        <AlertCircle className="h-4 w-4" />
                        Unpacking Failed
                      </div>
                      <pre className="max-h-40 overflow-auto text-xs">{fwDetail.unpack_log}</pre>
                      <div className="flex gap-2 mt-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleUnpack(fw.id)}
                          disabled={unpacking}
                        >
                          {unpacking && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
                          Retry
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => rootfsInputRef.current?.click()}
                          disabled={uploadingRootfs === fw.id}
                        >
                          {uploadingRootfs === fw.id ? (
                            <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Upload className="mr-2 h-3.5 w-3.5" />
                          )}
                          Upload Rootfs
                        </Button>
                        <input
                          ref={rootfsInputRef}
                          type="file"
                          accept=".tar,.tar.gz,.tgz,.zip"
                          className="hidden"
                          onChange={(e) => {
                            const file = e.target.files?.[0]
                            if (file) handleRootfsUpload(fw.id, file)
                            e.target.value = ''
                          }}
                        />
                      </div>
                      {rootfsError && uploadingRootfs === null && (
                        <p className="text-xs text-destructive mt-1">{rootfsError}</p>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            )
          })}

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
        .filter(isReady)
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
