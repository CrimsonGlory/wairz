import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { Loader2, AlertTriangle } from 'lucide-react'
import { getComponentMap } from '@/api/componentMap'
import { useProjectStore } from '@/stores/projectStore'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import { extractErrorMessage } from '@/utils/error'
import type { ComponentGraph } from '@/types'
import FirmwareSelector from '@/components/projects/FirmwareSelector'
import ComponentMap from '@/components/component-map/ComponentMap'

export default function ComponentMapPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const { firmwareList } = useFirmwareList(projectId)
  const [graph, setGraph] = useState<ComponentGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!projectId) return

    let cancelled = false
    setLoading(true)
    setError(null)

    getComponentMap(projectId, selectedFirmwareId)
      .then((data) => {
        if (!cancelled) setGraph(data)
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(extractErrorMessage(err, 'Failed to load component map'))
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [projectId, selectedFirmwareId])

  if (loading) {
    return (
      <div className="-m-6 flex h-[calc(100vh-3.5rem)] items-center justify-center">
        <div className="flex flex-col items-center gap-3 text-muted-foreground">
          <Loader2 className="h-8 w-8 animate-spin" />
          <div className="text-sm">Building component map...</div>
          <div className="text-xs">This may take a few seconds on first load</div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="-m-6 flex h-[calc(100vh-3.5rem)] items-center justify-center">
        <div className="flex flex-col items-center gap-3 text-muted-foreground">
          <AlertTriangle className="h-8 w-8 text-destructive" />
          <div className="text-sm">{error}</div>
        </div>
      </div>
    )
  }

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="-m-6 flex h-[calc(100vh-3.5rem)] items-center justify-center">
        <div className="text-sm text-muted-foreground">
          No components found. Make sure firmware is unpacked first.
        </div>
      </div>
    )
  }

  return (
    <div className="-m-6 flex h-[calc(100vh-3.5rem)] flex-col overflow-hidden">
      {firmwareList.filter((fw) => fw.extracted_path).length > 1 && (
        <div className="min-w-0 shrink-0 border-b border-border px-4 py-2">
          <FirmwareSelector projectId={projectId!} firmwareList={firmwareList} className="w-full max-w-md" />
        </div>
      )}
      <div className="relative min-h-0 min-w-0 flex-1 overflow-hidden">
        <ComponentMap graph={graph} />
      </div>
    </div>
  )
}
