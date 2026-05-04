import { useEffect } from 'react'
import { useProjectStore } from '@/stores/projectStore'
import type { FirmwareDetail } from '@/types'

interface FirmwareSelectorProps {
  projectId: string
  firmwareList: FirmwareDetail[]
  className?: string
}

export default function FirmwareSelector({ firmwareList, className }: FirmwareSelectorProps) {
  const { selectedFirmwareId, setSelectedFirmware } = useProjectStore()

  const unpacked = firmwareList.filter((fw) => fw.extracted_path)

  // Auto-select the latest unpacked firmware if none selected
  useEffect(() => {
    if (!selectedFirmwareId && unpacked.length > 0) {
      setSelectedFirmware(unpacked[unpacked.length - 1].id)
    }
    // If selected firmware is not in the list, reset
    if (selectedFirmwareId && !unpacked.find((fw) => fw.id === selectedFirmwareId)) {
      if (unpacked.length > 0) {
        setSelectedFirmware(unpacked[unpacked.length - 1].id)
      } else {
        setSelectedFirmware(null)
      }
    }
  }, [unpacked.length, selectedFirmwareId, setSelectedFirmware])

  if (unpacked.length <= 1) return null

  return (
    <div className={`flex min-w-0 items-center gap-2 ${className ?? ''}`}>
      <label className="shrink-0 text-xs font-medium text-muted-foreground">Firmware:</label>
      <select
        className="min-w-0 flex-1 truncate rounded-md border bg-background px-2 py-1 text-sm"
        value={selectedFirmwareId || ''}
        onChange={(e) => setSelectedFirmware(e.target.value || null)}
        title={unpacked.find((fw) => fw.id === selectedFirmwareId)?.original_filename ?? undefined}
      >
        {unpacked.map((fw) => (
          <option key={fw.id} value={fw.id}>
            {fw.original_filename}{fw.version_label ? ` (${fw.version_label})` : ''}
          </option>
        ))}
      </select>
    </div>
  )
}
