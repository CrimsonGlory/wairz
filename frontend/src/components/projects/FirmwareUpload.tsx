import { useCallback, useEffect, useRef, useState } from 'react'
import { Upload, CheckCircle, AlertCircle, Loader2, Info } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import {
  uploadFirmware as apiUploadFirmware,
  unpackFirmware as apiUnpackFirmware,
  getFirmwareUploadStatus,
} from '@/api/firmware'
import { getProject } from '@/api/projects'
import { extractErrorMessage } from '@/utils/error'
import { Progress } from '@/components/ui/progress'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import type { FirmwareUploadStatus, UploadStage } from '@/types'

// Phase 'finalizing' added 2026-05-12 per intake ux-upload-progress-multistage-2026-05-12.md
// (Scout-fleet Shape 1, ~15 LOC frontend-only). Closes the operator-visible
// gap between onUploadProgress=100% and the 202 ack — for multi-GB
// uploads that gap can be 5-25+ min (nginx forwarding + backend streaming
// SHA256 + dedup + INSERT) and the prior "Uploading firmware..." at 100%
// looked indefinitely stuck.
type Phase = 'idle' | 'uploading' | 'finalizing' | 'processing' | 'done' | 'error'

interface FirmwareUploadProps {
  projectId: string
  onComplete?: () => void
  showVersionLabel?: boolean
}

// Map backend upload_stage values to the human-readable label rendered
// below the spinner. Linked to UploadStage in types/index.ts and to the
// CHECK constraint ck_firmware_upload_stage on the backend.
const STAGE_LABELS: Record<UploadStage, string> = {
  uploading: 'Uploading bytes',
  hashing: 'Computing hash',
  detecting: 'Detecting format',
  extracting: 'Extracting archive',
  analyzing: 'Analyzing filesystem',
  ready: 'Ready',
  failed: 'Failed',
}

function stageLabel(stage: UploadStage | undefined): string {
  if (!stage) return 'Working...'
  return STAGE_LABELS[stage] ?? stage
}

export default function FirmwareUpload({ projectId, onComplete, showVersionLabel }: FirmwareUploadProps) {
  const [phase, setPhase] = useState<Phase>('idle')
  const [errorMsg, setErrorMsg] = useState('')
  const [dragActive, setDragActive] = useState(false)
  const [versionLabel, setVersionLabel] = useState('')
  const [statusSnapshot, setStatusSnapshot] = useState<FirmwareUploadStatus | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const { uploadProgress } = useProjectStore()
  const setStore = useProjectStore.setState

  // Stop polling on unmount or terminal-state transition.
  useEffect(() => {
    return () => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current)
        pollTimerRef.current = null
      }
    }
  }, [])

  // Transition uploading → finalizing the moment the browser→nginx leg hits
  // 100%. The post-100% gap (nginx→backend forwarding + streaming SHA256 +
  // dedup + INSERT) takes seconds for typical uploads and 5-25+ min for
  // multi-GB firmware — without this transition the "Uploading firmware..."
  // copy + bar at 100% looks indefinitely stuck.
  useEffect(() => {
    if (phase === 'uploading' && uploadProgress >= 100) {
      setPhase('finalizing')
    }
  }, [phase, uploadProgress])

  const finishWithSuccess = useCallback(
    async (firmwareId: string) => {
      // Auto-trigger /unpack so existing UX (immediate "unpacking" state
      // on the project page) is preserved post-Rule-#33-refactor.
      await apiUnpackFirmware(projectId, firmwareId).catch(() => {})
      const project = await getProject(projectId)
      setStore({ currentProject: project })
      setPhase('done')
      onComplete?.()
    },
    [projectId, onComplete, setStore],
  )

  const startPolling = useCallback(
    (firmwareId: string) => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current)
      }
      // 2 s cadence matches the firmware-unpack precedent and the SBOM
      // vuln-scan polling shape (commit 7da91a6).
      pollTimerRef.current = setInterval(async () => {
        try {
          const snap = await getFirmwareUploadStatus(projectId, firmwareId)
          setStatusSnapshot(snap)
          if (snap.upload_stage === 'ready') {
            if (pollTimerRef.current) {
              clearInterval(pollTimerRef.current)
              pollTimerRef.current = null
            }
            await finishWithSuccess(firmwareId)
          } else if (snap.upload_stage === 'failed') {
            if (pollTimerRef.current) {
              clearInterval(pollTimerRef.current)
              pollTimerRef.current = null
            }
            setErrorMsg(snap.upload_stage_error || 'Upload post-processing failed')
            setPhase('error')
          }
        } catch (e) {
          // Transient poll failures are non-fatal — the next tick retries.
          // Persistent failures will eventually surface as the user-visible
          // error via the spinner staying stuck; future enhancement could
          // count consecutive failures and surface after N.
           
          console.warn('upload-status poll failed', e)
        }
      }, 2000)
    },
    [projectId, finishWithSuccess],
  )

  const handleFile = useCallback(
    async (file: File) => {
      setPhase('uploading')
      setErrorMsg('')
      setStatusSnapshot(null)
      try {
        setStore({ uploading: true, uploadProgress: 0 })
        const ack = await apiUploadFirmware(
          projectId,
          file,
          versionLabel || undefined,
          (pct) => setStore({ uploadProgress: pct }),
        )
        setStore({ uploading: false, uploadProgress: 100 })
        // 202 ack returned: backend is now post-processing. Switch the
        // UI to the polling phase and let the timer drive the rest.
        setStatusSnapshot(ack)
        setPhase('processing')
        startPolling(ack.id)
      } catch (e) {
        setStore({ uploading: false })
        setErrorMsg(extractErrorMessage(e, 'Upload failed'))
        setPhase('error')
      }
    },
    [projectId, versionLabel, setStore, startPolling],
  )

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragActive(false)
      const file = e.dataTransfer.files[0]
      if (file) handleFile(file)
    },
    [handleFile],
  )

  const onInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (file) handleFile(file)
    },
    [handleFile],
  )

  const retry = () => {
    setPhase('idle')
    setErrorMsg('')
    setStatusSnapshot(null)
  }

  if (phase === 'done') {
    return (
      <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-8">
        <CheckCircle className="h-8 w-8 text-green-500" />
        <p className="text-sm font-medium">Firmware uploaded — unpacking in progress</p>
        {statusSnapshot?.detected_format && (
          <FormatBanner status={statusSnapshot} />
        )}
      </div>
    )
  }

  if (phase === 'error') {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-destructive/50 p-8">
        <AlertCircle className="h-8 w-8 text-destructive" />
        <p className="text-sm text-destructive">{errorMsg}</p>
        <Button size="sm" variant="outline" onClick={retry}>
          Try Again
        </Button>
      </div>
    )
  }

  if (phase === 'uploading') {
    return (
      <div
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className="flex flex-col items-center gap-3 rounded-lg border border-dashed p-8"
      >
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        <p className="text-sm font-medium">Uploading firmware to server...</p>
        <Progress value={uploadProgress} className="w-full max-w-xs" />
        <p className="text-xs text-muted-foreground">{uploadProgress}%</p>
      </div>
    )
  }

  if (phase === 'finalizing') {
    return (
      <div
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className="flex flex-col items-center gap-3 rounded-lg border border-dashed p-8"
      >
        <CheckCircle className="h-6 w-6 text-green-500" />
        <p className="text-xs text-muted-foreground">Upload bytes received ✓</p>
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        <p className="text-sm font-medium">Server is finalizing (hashing + deduplicating)...</p>
        <p className="text-xs text-muted-foreground">
          This can take several minutes for multi-GB firmware. Feel free to navigate away;
          the upload will continue processing on the server.
        </p>
      </div>
    )
  }

  if (phase === 'processing') {
    const stage = statusSnapshot?.upload_stage
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed p-8">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        <p className="text-sm font-medium">{stageLabel(stage)}…</p>
        <p className="text-xs text-muted-foreground">
          The upload is on the server. wairz is processing it now — feel free to navigate away;
          this will continue running.
        </p>
        {statusSnapshot?.detected_format && (
          <FormatBanner status={statusSnapshot} />
        )}
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {showVersionLabel && (
        <div className="space-y-1">
          <Label htmlFor="version-label" className="text-xs">Version Label (optional)</Label>
          <Input
            id="version-label"
            placeholder="e.g. v1.0, v1.1-patched"
            value={versionLabel}
            onChange={(e) => setVersionLabel(e.target.value)}
            className="h-8 text-sm"
          />
        </div>
      )}
      <div
        className={`flex cursor-pointer flex-col items-center gap-3 rounded-lg border-2 border-dashed p-8 transition-colors ${
          dragActive ? 'border-primary bg-primary/5' : 'border-muted-foreground/25 hover:border-muted-foreground/50'
        }`}
        onDragOver={(e) => {
          e.preventDefault()
          setDragActive(true)
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
      >
        <Upload className="h-8 w-8 text-muted-foreground" />
        <div className="text-center">
          <p className="text-sm font-medium">Drop firmware file here or click to browse</p>
          <p className="text-xs text-muted-foreground mt-1">
            Multi-OS: Linux / Android / Windows installer ISO / QNX / RTOS. wairz detects the
            format and tells you what it can extract.
          </p>
        </div>
        <input ref={inputRef} type="file" className="hidden" onChange={onInputChange} />
      </div>
    </div>
  )
}

/**
 * Format-detection banner. Renders a per-capability message under the
 * upload spinner once the backend has classified the upload. Copy comes
 * from CAPABILITY_NOTES in app/services/format_detection.py — keeping
 * the user-facing message near the detection logic so the two evolve
 * together.
 */
function FormatBanner({ status }: { status: FirmwareUploadStatus }) {
  const cap = status.extraction_capability
  if (!cap || cap === 'full') {
    // 'full' capability: no banner needed — the standard flow proceeds
    // without a UX nudge. Same for unknown capability shapes.
    return null
  }
  const tone =
    cap === 'none'
      ? 'border-amber-500/50 bg-amber-500/5 text-amber-700 dark:text-amber-400'
      : 'border-blue-500/50 bg-blue-500/5 text-blue-700 dark:text-blue-400'
  const label = cap === 'none' ? 'No native extractor' : 'Partial extraction'
  return (
    <div
      className={`mt-2 flex items-start gap-2 rounded-md border px-3 py-2 text-xs ${tone}`}
      role="status"
    >
      <Info className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
      <div className="space-y-1">
        <p className="font-medium">
          {label} — detected format: {status.detected_format}
        </p>
        {status.capability_note && <p>{status.capability_note}</p>}
      </div>
    </div>
  )
}
