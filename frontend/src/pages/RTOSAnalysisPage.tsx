import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Cpu, Loader2, AlertCircle, FileCode, Hash, Terminal } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { listFirmware } from '@/api/firmware'
import { formatFileSize } from '@/utils/format'
import type { FirmwareDetail } from '@/types'

interface RtosTool {
  name: string
  description: string
}

const RTOS_TOOLS: RtosTool[] = [
  {
    name: 'detect_rtos_kernel',
    description:
      'Re-run RTOS detection and report the matching evidence plus ELF metadata.',
  },
  {
    name: 'enumerate_rtos_tasks',
    description:
      'List likely task entry-point functions and FreeRTOS infrastructure symbols (requires unstripped ELF).',
  },
  {
    name: 'analyze_vector_table',
    description:
      'Parse the Cortex-M vector table from .isr_vector or first executable segment, with handler symbols.',
  },
  {
    name: 'recover_base_address',
    description:
      'Return LOAD-segment vaddr/paddr for ELFs, or infer a flash base from the reset vector for raw .bin.',
  },
  {
    name: 'analyze_memory_map',
    description:
      'Classify allocated sections into flash (executable / read-only) vs RAM (writable).',
  },
]

function flavorLabel(flavor: FirmwareDetail['rtos_flavor']): string {
  switch (flavor) {
    case 'freertos':
      return 'FreeRTOS'
    case 'zephyr':
      return 'Zephyr'
    case 'baremetal-cortexm':
      return 'Baremetal Cortex-M'
    default:
      return 'RTOS'
  }
}

export default function RTOSAnalysisPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const [firmware, setFirmware] = useState<FirmwareDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!projectId) return
    let cancelled = false
    setLoading(true)
    setError(null)
    listFirmware(projectId)
      .then((items) => {
        if (cancelled) return
        // Match the MCP server's "active firmware" rule — most recent upload.
        const active = items
          .slice()
          .sort((a, b) => b.created_at.localeCompare(a.created_at))[0]
        setFirmware(active ?? null)
      })
      .catch((e) => {
        if (!cancelled) {
          setError(e?.response?.data?.detail || e.message || 'Failed to load firmware')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [projectId])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="rounded border border-destructive/20 bg-destructive/10 p-4 text-sm text-destructive">
        <AlertCircle className="mr-2 inline h-4 w-4" />
        {error}
      </div>
    )
  }

  if (!firmware) {
    return (
      <div className="rounded border border-border bg-muted/30 p-6 text-sm text-muted-foreground">
        No firmware uploaded yet for this project.
      </div>
    )
  }

  const isRtos = firmware.firmware_kind === 'rtos'

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <Cpu className="h-5 w-5" />
            RTOS Analysis
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Single-binary firmware analysis. Use the MCP tools below to inspect the image.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge variant="secondary">{flavorLabel(firmware.rtos_flavor)}</Badge>
          {firmware.architecture && (
            <Badge variant="outline">{firmware.architecture}</Badge>
          )}
          {firmware.endianness && (
            <Badge variant="outline">{firmware.endianness}-endian</Badge>
          )}
        </div>
      </div>

      {!isRtos && (
        <div className="rounded border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
          This project's firmware is currently classified as
          <span className="mx-1 font-semibold">{firmware.firmware_kind}</span>
          rather than <span className="font-semibold">rtos</span>. RTOS-specific
          MCP tools won't be exposed until you change the kind on the project
          overview page.
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileCode className="h-4 w-4" />
            Firmware
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div>
              <div className="text-muted-foreground">Filename</div>
              <div className="font-mono">{firmware.original_filename ?? '(unknown)'}</div>
            </div>
            <div>
              <div className="text-muted-foreground">Size</div>
              <div>{firmware.file_size != null ? formatFileSize(firmware.file_size) : '?'}</div>
            </div>
            <div className="sm:col-span-2">
              <div className="text-muted-foreground">SHA-256</div>
              <div className="break-all font-mono text-xs">
                <Hash className="mr-1 inline h-3 w-3" />
                {firmware.sha256}
              </div>
            </div>
            <div>
              <div className="text-muted-foreground">Detection source</div>
              <div>{firmware.firmware_kind_source ?? '—'}</div>
            </div>
            <div>
              <div className="text-muted-foreground">OS info</div>
              <div className="font-mono text-xs">{firmware.os_info?.trim() || '—'}</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Terminal className="h-4 w-4" />
            MCP tools for this firmware
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-sm text-muted-foreground">
            These tools operate on the firmware blob via the Wairz MCP server.
            Connect from Claude Code or Claude Desktop and invoke them by name.
          </p>
          <ul className="space-y-2 text-sm">
            {RTOS_TOOLS.map((tool) => (
              <li
                key={tool.name}
                className="rounded border border-border bg-muted/20 px-3 py-2"
              >
                <code className="font-mono text-xs font-semibold">{tool.name}</code>
                <p className="mt-1 text-xs text-muted-foreground">{tool.description}</p>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  )
}
