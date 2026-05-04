import type { RefObject } from 'react'
import { Link } from 'react-router-dom'
import {
  Trash2,
  Cpu,
  HardDrive,
  Hash,
  FileText,
  Loader2,
  AlertCircle,
  Tag,
  Upload,
  Pencil,
  Check,
  X,
  ChevronDown,
  Terminal,
  Microchip,
  ShieldAlert,
  KeyRound,
  ArrowRight,
} from 'lucide-react'
import type { FirmwareSummary, FirmwareDetail } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { formatFileSize } from '@/utils/format'

interface FirmwareVersionCardProps {
  fw: FirmwareSummary
  fwDetail: FirmwareDetail | undefined
  status: string
  unpacking: boolean
  editingVersionLabel: string | null
  versionLabelDraft: string
  versionInputRef: RefObject<HTMLInputElement | null>
  onSetVersionLabelDraft: (value: string) => void
  handleUnpack: (firmwareId: string) => void
  handleDeleteFirmware: (firmwareId: string) => void
  startEditingVersionLabel: (fwId: string, current: string | null) => void
  saveVersionLabel: (fwId: string) => void
  cancelEditingVersionLabel: () => void
  handleRootfsUpload: (firmwareId: string, file: File) => void
  uploadingRootfs: string | null
  rootfsError: string | null
  rootfsInputRef: RefObject<HTMLInputElement | null>
  expandedLogs: Set<string>
  setExpandedLogs: React.Dispatch<React.SetStateAction<Set<string>>>
}

export default function FirmwareVersionCard({
  fw,
  fwDetail,
  status,
  unpacking,
  editingVersionLabel,
  versionLabelDraft,
  versionInputRef,
  onSetVersionLabelDraft,
  handleUnpack,
  handleDeleteFirmware,
  startEditingVersionLabel,
  saveVersionLabel,
  cancelEditingVersionLabel,
  handleRootfsUpload,
  uploadingRootfs,
  rootfsError,
  rootfsInputRef,
  expandedLogs,
  setExpandedLogs,
}: FirmwareVersionCardProps) {
  const isUnpacked = fwDetail?.extracted_path
  const hasError = fwDetail?.unpack_log && !isUnpacked && (status as string) === 'error'

  return (
    <Card>
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
                  onChange={(e) => onSetVersionLabelDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') saveVersionLabel(fw.id)
                    if (e.key === 'Escape') cancelEditingVersionLabel()
                  }}
                  placeholder="e.g. v1.0.3"
                  className="h-6 w-32 text-xs"
                />
                <Button size="icon" variant="ghost" className="h-5 w-5" onClick={() => saveVersionLabel(fw.id)}>
                  <Check className="h-3 w-3" />
                </Button>
                <Button size="icon" variant="ghost" className="h-5 w-5" onClick={() => cancelEditingVersionLabel()}>
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
            {fwDetail?.device_metadata?.extraction_diagnostics?.partial_extraction && (
              <Badge
                variant="outline"
                className="text-xs border-amber-500 text-amber-700 dark:text-amber-400"
                title={fwDetail.device_metadata.extraction_diagnostics.summary}
              >
                <ShieldAlert className="mr-1 h-3 w-3" />
                partial extraction
              </Badge>
            )}
            {fwDetail?.binary_info && (
              <Badge variant="outline" className="text-xs">standalone binary</Badge>
            )}
          </CardTitle>
          <div className="flex gap-1">
            {!isUnpacked && !hasError && !unpacking && !fwDetail?.unpack_stage && status !== 'unpacking' && (
              <Button size="sm" onClick={() => handleUnpack(fw.id)}>
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
          {fw.architecture && (
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-muted-foreground" />
              <dt className="text-muted-foreground">Architecture:</dt>
              <dd className="font-medium">
                {fw.architecture}
                {fw.endianness ? ` (${fw.endianness})` : ''}
              </dd>
            </div>
          )}
          {(() => {
            const osInfo = fw.os_info ? (() => { try { return JSON.parse(fw.os_info) } catch { return null } })() : null
            const rtos = osInfo?.rtos
            const hexMeta = osInfo?.hex_metadata
            return (
              <>
                {rtos && (
                  <div className="flex items-center gap-2">
                    <Microchip className="h-4 w-4 text-muted-foreground" />
                    <dt className="text-muted-foreground">OS/RTOS:</dt>
                    <dd className="font-medium">
                      {rtos.name}
                      {rtos.version ? ` v${rtos.version}` : ''}
                      <Badge variant="outline" className="ml-2 text-[10px]">{rtos.confidence}</Badge>
                    </dd>
                  </div>
                )}
                {osInfo?.format === 'intel_hex' && hexMeta && (
                  <div className="flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-muted-foreground" />
                    <dt className="text-muted-foreground">Memory:</dt>
                    <dd className="font-mono text-xs">
                      {hexMeta.regions?.map((r: { start: number; size: number }, i: number) => (
                        <span key={i} className="mr-2">
                          0x{r.start.toString(16).toUpperCase().padStart(8, '0')} ({(r.size / 1024).toFixed(0)} KB)
                        </span>
                      ))}
                      {hexMeta.entry_point != null && (
                        <span className="text-muted-foreground ml-1">entry: 0x{hexMeta.entry_point.toString(16).toUpperCase().padStart(8, '0')}</span>
                      )}
                    </dd>
                  </div>
                )}
                {osInfo?.companion_components?.length > 0 && (
                  <div className="flex items-center gap-2 col-span-2">
                    <Microchip className="h-4 w-4 text-muted-foreground" />
                    <dt className="text-muted-foreground">Components:</dt>
                    <dd className="text-xs">
                      {osInfo.companion_components.map((c: { name: string; version?: string }, i: number) => (
                        <Badge key={i} variant="outline" className="mr-1 text-[10px]">
                          {c.name}{c.version ? ` v${c.version}` : ''}
                        </Badge>
                      ))}
                    </dd>
                  </div>
                )}
              </>
            )
          })()}
          {fwDetail?.binary_info && (
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-muted-foreground" />
              <dt className="text-muted-foreground">Binary:</dt>
              <dd className="font-medium">
                {fwDetail.binary_info.format?.toUpperCase() ?? 'Unknown'}
                {fwDetail.binary_info.bits ? ` ${fwDetail.binary_info.bits}-bit` : ''}
                {' '}
                {fwDetail.binary_info.is_static ? 'static' : 'dynamic'}
                {fwDetail.binary_info.is_pie ? ', PIE' : ''}
              </dd>
            </div>
          )}
          {fwDetail?.binary_info && fwDetail.binary_info.dependencies.length > 0 && (
            <div className="flex items-start gap-2 col-span-2">
              <Cpu className="h-4 w-4 text-muted-foreground mt-0.5" />
              <dt className="text-muted-foreground">Dependencies:</dt>
              <dd className="font-mono text-xs">
                {fwDetail.binary_info.dependencies.join(', ')}
              </dd>
            </div>
          )}
          <div className="flex items-center gap-2 col-span-2">
            <Hash className="h-4 w-4 text-muted-foreground" />
            <dt className="text-muted-foreground">SHA256:</dt>
            <dd className="font-mono text-xs truncate">{fw.sha256}</dd>
          </div>
        </dl>

        {status === 'unpacking' && fwDetail && !isUnpacked && fwDetail.unpack_stage && (
          <div className="mt-3 rounded bg-muted/50 border p-3 space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                {fwDetail.unpack_stage}
              </span>
              {fwDetail.unpack_progress != null && (
                <span className="text-muted-foreground text-xs">{fwDetail.unpack_progress}%</span>
              )}
            </div>
            {fwDetail.unpack_progress != null && (
              <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full rounded-full bg-primary transition-all duration-500"
                  style={{ width: `${Math.min(fwDetail.unpack_progress, 100)}%` }}
                />
              </div>
            )}
          </div>
        )}

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

        {fwDetail?.device_metadata?.extraction_diagnostics?.partial_extraction && (
          <div className="mt-3 rounded border border-amber-500/40 bg-amber-500/5 p-3 text-xs">
            <div className="flex items-center gap-2 font-medium text-amber-700 dark:text-amber-400 mb-1">
              <ShieldAlert className="h-3.5 w-3.5" />
              Partial extraction
            </div>
            <p className="text-muted-foreground mb-2">
              {fwDetail.device_metadata.extraction_diagnostics.summary}
            </p>
            {fwDetail.device_metadata.extraction_diagnostics.encrypted_archives.length > 0 && (
              <ul className="space-y-1">
                {fwDetail.device_metadata.extraction_diagnostics.encrypted_archives.slice(0, 8).map((e, i) => (
                  <li key={i} className="font-mono">
                    <span className="text-amber-700 dark:text-amber-400">{e.vendor ?? '?'}</span>
                    {' '}{e.path}
                    {' '}<span className="text-muted-foreground">({formatFileSize(e.size_bytes)})</span>
                  </li>
                ))}
              </ul>
            )}
            {fwDetail.device_metadata.extraction_diagnostics.encrypted_archives[0]?.note && (
              <p className="text-muted-foreground mt-2 italic">
                {fwDetail.device_metadata.extraction_diagnostics.encrypted_archives[0].note}
              </p>
            )}
            {fwDetail.project_id && (
              <Link
                to={`/projects/${fwDetail.project_id}/findings?firmware_id=${fw.id}&source=unpack_audit`}
                className="mt-3 inline-flex items-center gap-1 text-amber-700 hover:text-amber-800 dark:text-amber-400 dark:hover:text-amber-300"
              >
                View unpack-audit findings <ArrowRight className="h-3 w-3" />
              </Link>
            )}
          </div>
        )}

        {/* Vendor-AES auto-decrypt success — renders when post-decrypt
            recompute resolved every encrypted archive. Source of the
            unpack_audit findings (AES-key triple, IV reuse, cleartext
            key, signed-container). Click-through to view them. */}
        {fwDetail?.device_metadata?.extraction_diagnostics
          && !fwDetail.device_metadata.extraction_diagnostics.partial_extraction
          && (fwDetail.device_metadata.extraction_diagnostics.decrypted_archives_count ?? 0) > 0
          && (
          <div className="mt-3 rounded border border-cyan-500/40 bg-cyan-500/5 p-3 text-xs">
            <div className="flex items-center gap-2 font-medium text-cyan-700 dark:text-cyan-400 mb-1">
              <KeyRound className="h-3.5 w-3.5" />
              Vendor-AES auto-decrypted
            </div>
            <p className="text-muted-foreground mb-2">
              {fwDetail.device_metadata.extraction_diagnostics.summary}
            </p>
            {fwDetail.project_id && (
              <Link
                to={`/projects/${fwDetail.project_id}/findings?firmware_id=${fw.id}&source=unpack_audit`}
                className="inline-flex items-center gap-1 text-cyan-700 hover:text-cyan-800 dark:text-cyan-400 dark:hover:text-cyan-300"
              >
                View unpack-audit findings <ArrowRight className="h-3 w-3" />
              </Link>
            )}
          </div>
        )}

        {isUnpacked && fwDetail?.unpack_log && (
          <div className="mt-3">
            <button
              type="button"
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
              onClick={() => setExpandedLogs((prev) => {
                const next = new Set(prev)
                if (next.has(fw.id)) next.delete(fw.id)
                else next.add(fw.id)
                return next
              })}
            >
              <ChevronDown className={`h-3.5 w-3.5 transition-transform ${expandedLogs.has(fw.id) ? '' : '-rotate-90'}`} />
              <Terminal className="h-3.5 w-3.5" />
              Unpack Log
            </button>
            {expandedLogs.has(fw.id) && (
              <pre className="mt-2 max-h-48 overflow-auto rounded bg-muted/50 border p-3 text-xs">
                {fwDetail.unpack_log}
              </pre>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
