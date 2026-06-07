import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  Archive,
  Code2,
  Download,
  Loader2,
  Play,
  RefreshCw,
  Trash2,
  Upload,
  AlertCircle,
  CheckCircle2,
  Clock,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  deleteGhidraResearchFile,
  getGhidraArchiveImportStatus,
  getGhidraResearchDownloadUrl,
  listGhidraResearchFiles,
  triggerGhidraArchiveImport,
  uploadGhidraResearchFile,
  readGhidraScriptContent,
} from '@/api/ghidra_research'
import type { GhidraResearchFile, GhidraImportStatus } from '@/types'

const ACCEPTED_EXTENSIONS = '.gzf,.py,.java,.jy'
const POLLING_INTERVAL_MS = 2000

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function ImportStatusBadge({ status }: { status: GhidraImportStatus }) {
  switch (status) {
    case 'completed':
      return <Badge className="bg-green-600 text-white"><CheckCircle2 className="mr-1 h-3 w-3" />Imported</Badge>
    case 'running':
      return <Badge className="bg-blue-600 text-white"><Loader2 className="mr-1 h-3 w-3 animate-spin" />Importing...</Badge>
    case 'queued':
      return <Badge className="bg-yellow-600 text-white"><Clock className="mr-1 h-3 w-3" />Queued</Badge>
    case 'failed':
      return <Badge variant="destructive"><AlertCircle className="mr-1 h-3 w-3" />Failed</Badge>
    default:
      return null
  }
}

export default function GhidraResearchPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const [files, setFiles] = useState<GhidraResearchFile[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [uploadProgress, setUploadProgress] = useState<number | null>(null)
  const [selectedScript, setSelectedScript] = useState<{ id: string; filename: string; content: string } | null>(null)
  const [scriptLoading, setScriptLoading] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const archives = files.filter((f) => f.file_category === 'ghidra_archive')
  const scripts = files.filter((f) => f.file_category !== 'ghidra_archive')

  const load = useCallback(async () => {
    if (!projectId) return
    try {
      const data = await listGhidraResearchFiles(projectId)
      setFiles(data)
      setError(null)
    } catch {
      setError('Failed to load Ghidra research files.')
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    load()
  }, [load])

  // Poll import status while any archive is queued/running
  useEffect(() => {
    const inProgress = archives.filter((f) =>
      f.import_status === 'queued' || f.import_status === 'running',
    )
    if (inProgress.length === 0) {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
      return
    }
    if (pollingRef.current) return
    pollingRef.current = setInterval(async () => {
      if (!projectId) return
      for (const f of inProgress) {
        const updated = await getGhidraArchiveImportStatus(projectId, f.id).catch(() => null)
        if (!updated) continue
        if (updated.import_status !== 'queued' && updated.import_status !== 'running') {
          setFiles((prev) => prev.map((x) => (x.id === updated.id ? updated : x)))
        }
      }
      // Refresh full list to sync
      const data = await listGhidraResearchFiles(projectId).catch(() => null)
      if (data) setFiles(data)
    }, POLLING_INTERVAL_MS)
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [archives, projectId])

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !projectId) return
    setUploadProgress(0)
    setError(null)
    try {
      const record = await uploadGhidraResearchFile(projectId, file, undefined, setUploadProgress)
      setFiles((prev) => [record, ...prev])
    } catch {
      setError(`Upload failed for '${file.name}'.`)
    } finally {
      setUploadProgress(null)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const handleDelete = async (fileId: string) => {
    if (!projectId) return
    if (!confirm('Delete this file? This cannot be undone.')) return
    try {
      await deleteGhidraResearchFile(projectId, fileId)
      setFiles((prev) => prev.filter((f) => f.id !== fileId))
      if (selectedScript?.id === fileId) setSelectedScript(null)
    } catch {
      setError('Delete failed.')
    }
  }

  const handleImport = async (fileId: string) => {
    if (!projectId) return
    try {
      const updated = await triggerGhidraArchiveImport(projectId, fileId)
      setFiles((prev) => prev.map((f) => (f.id === fileId ? updated : f)))
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Import trigger failed.'
      setError(msg)
    }
  }

  const handleViewScript = async (file: GhidraResearchFile) => {
    if (!projectId) return
    setScriptLoading(true)
    try {
      const result = await readGhidraScriptContent(projectId, file.id)
      setSelectedScript({ id: file.id, filename: file.original_filename, content: result.content })
    } catch {
      setError(`Failed to read '${file.original_filename}'.`)
    } finally {
      setScriptLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Ghidra Research</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Upload .gzf Ghidra archives and .py/.java analysis scripts from prior research.
            The AI can import archives and read scripts via MCP.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Button size="sm" onClick={() => fileInputRef.current?.click()} disabled={uploadProgress !== null}>
            {uploadProgress !== null ? (
              <><Loader2 className="mr-2 h-4 w-4 animate-spin" />{uploadProgress}%</>
            ) : (
              <><Upload className="mr-2 h-4 w-4" />Upload File</>
            )}
          </Button>
          <input
            ref={fileInputRef}
            type="file"
            accept={ACCEPTED_EXTENSIONS}
            className="hidden"
            onChange={handleUpload}
          />
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Ghidra Archives */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Archive className="h-4 w-4" />
            Ghidra Archives (.gzf)
            <Badge variant="secondary" className="ml-auto">{archives.length}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {archives.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No Ghidra archives uploaded. Upload a .gzf file exported from Ghidra
              (File → Export Program → Ghidra Zip Format).
            </p>
          ) : (
            <div className="space-y-3">
              {archives.map((f) => (
                <div
                  key={f.id}
                  className="flex items-center justify-between rounded-md border p-3"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-mono text-sm font-medium">
                        {f.original_filename}
                      </span>
                      <ImportStatusBadge status={f.import_status} />
                    </div>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {formatBytes(f.file_size)}
                      {f.description && ` — ${f.description}`}
                    </p>
                    {f.import_status === 'failed' && f.import_error && (
                      <p className="mt-1 truncate text-xs text-destructive">{f.import_error}</p>
                    )}
                    {f.import_status === 'completed' && f.import_result && (
                      <p className="mt-1 text-xs text-green-600">
                        {(f.import_result.functions as unknown[])?.length ?? 0} functions extracted
                      </p>
                    )}
                  </div>
                  <div className="ml-3 flex shrink-0 items-center gap-2">
                    {(f.import_status === 'idle' || f.import_status === 'failed' || f.import_status === 'completed') && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleImport(f.id)}
                      >
                        <Play className="mr-1 h-3.5 w-3.5" />
                        {f.import_status === 'completed' ? 'Re-import' : 'Import to Ghidra'}
                      </Button>
                    )}
                    <a href={getGhidraResearchDownloadUrl(projectId!, f.id)} download={f.original_filename}>
                      <Button variant="ghost" size="sm">
                        <Download className="h-4 w-4" />
                      </Button>
                    </a>
                    <Button variant="ghost" size="sm" onClick={() => handleDelete(f.id)}>
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Analysis Scripts */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Code2 className="h-4 w-4" />
            Analysis Scripts (.py / .java / .jy)
            <Badge variant="secondary" className="ml-auto">{scripts.length}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {scripts.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No analysis scripts uploaded. Upload .py or .java scripts used
              in the prior Ghidra research session.
            </p>
          ) : (
            <div className="grid gap-4 lg:grid-cols-2">
              {/* Script list */}
              <div className="space-y-2">
                {scripts.map((f) => (
                  <div
                    key={f.id}
                    className={`flex cursor-pointer items-center justify-between rounded-md border p-2.5 transition-colors hover:bg-accent/50 ${
                      selectedScript?.id === f.id ? 'border-primary bg-accent/30' : ''
                    }`}
                    onClick={() => handleViewScript(f)}
                  >
                    <div className="min-w-0">
                      <p className="truncate font-mono text-sm">{f.original_filename}</p>
                      <p className="text-xs text-muted-foreground">
                        {formatBytes(f.file_size)}
                        {f.description && ` — ${f.description}`}
                      </p>
                    </div>
                    <div className="ml-2 flex shrink-0 items-center gap-1">
                      <a
                        href={getGhidraResearchDownloadUrl(projectId!, f.id)}
                        download={f.original_filename}
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Button variant="ghost" size="sm">
                          <Download className="h-3.5 w-3.5" />
                        </Button>
                      </a>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => { e.stopPropagation(); handleDelete(f.id) }}
                      >
                        <Trash2 className="h-3.5 w-3.5 text-destructive" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>

              {/* Script viewer */}
              <div className="rounded-md border bg-muted/30">
                {scriptLoading ? (
                  <div className="flex h-48 items-center justify-center">
                    <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                  </div>
                ) : selectedScript ? (
                  <div className="flex h-full flex-col">
                    <div className="border-b px-3 py-2 text-xs font-medium text-muted-foreground">
                      {selectedScript.filename}
                    </div>
                    <pre className="flex-1 overflow-auto p-3 font-mono text-xs leading-relaxed">
                      {selectedScript.content}
                    </pre>
                  </div>
                ) : (
                  <div className="flex h-48 items-center justify-center text-sm text-muted-foreground">
                    Click a script to view its contents
                  </div>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
