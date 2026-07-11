import { ChevronDown, Check, HardDrive, AlertTriangle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useProjectStore } from '@/stores/projectStore'
import { firmwareLabel, isFirmwareLoadable } from '@/utils/firmware'
import type { FirmwareKind } from '@/types'

const KIND_LABEL: Record<FirmwareKind, string> = {
  linux: 'Linux',
  rtos: 'RTOS',
  unknown: 'Unknown',
}

interface FirmwareVersionPickerProps {
  projectId: string
}

export default function FirmwareVersionPicker({ projectId }: FirmwareVersionPickerProps) {
  const currentProject = useProjectStore((s) => s.currentProject)
  const activeFirmwareId = useProjectStore((s) => s.activeFirmwareId)
  const setActiveFirmware = useProjectStore((s) => s.setActiveFirmware)

  // Only render once the matching project is loaded and has firmware.
  if (!currentProject || currentProject.id !== projectId) return null
  const versions = currentProject.firmware
  if (versions.length === 0) return null

  // Newest first, matching how users think about versions.
  const ordered = [...versions].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  )
  const active = versions.find((fw) => fw.id === activeFirmwareId) ?? null

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm hover:bg-accent"
          title="Active firmware version"
        >
          <HardDrive className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">
            {active ? firmwareLabel(active) : 'Select version'}
          </span>
          {active && (
            <Badge variant="outline" className="text-[10px]">
              {KIND_LABEL[active.firmware_kind]}
            </Badge>
          )}
          <ChevronDown className="h-3.5 w-3.5 opacity-70" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72">
        <DropdownMenuLabel>Firmware version</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {ordered.map((fw) => {
          const loadable = isFirmwareLoadable(fw)
          const isActive = fw.id === activeFirmwareId
          return (
            <DropdownMenuItem
              key={fw.id}
              onClick={() => setActiveFirmware(fw.id)}
              className="flex items-start gap-2"
            >
              <span className="mt-0.5 w-3.5 shrink-0">
                {isActive && <Check className="h-3.5 w-3.5" />}
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-1.5">
                  <span className="truncate font-medium">{firmwareLabel(fw)}</span>
                  <Badge variant="outline" className="text-[10px]">
                    {KIND_LABEL[fw.firmware_kind]}
                  </Badge>
                </span>
                <span className="mt-0.5 flex items-center gap-1 text-xs text-muted-foreground">
                  {loadable ? (
                    'Unpacked'
                  ) : (
                    <>
                      <AlertTriangle className="h-3 w-3 text-yellow-500" />
                      Not unpacked
                    </>
                  )}
                </span>
              </span>
            </DropdownMenuItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
