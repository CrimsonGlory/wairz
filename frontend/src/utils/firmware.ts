import type { FirmwareSummary } from '@/types'

/** A version is browsable if it has an unpacked rootfs, or is an RTOS blob. */
export function isFirmwareLoadable(fw: FirmwareSummary): boolean {
  if (fw.extracted_path) return true
  if (fw.firmware_kind === 'rtos' && fw.storage_path) return true
  return false
}

/** Human label for a firmware version: version label, else filename, else short id. */
export function firmwareLabel(fw: {
  version_label: string | null
  original_filename: string | null
  id: string
}): string {
  return fw.version_label || fw.original_filename || fw.id.slice(0, 8)
}

/**
 * Default "active" firmware id for a project: the most recently uploaded
 * *loadable* version, so a newer upload that failed to unpack never becomes the
 * default. Falls back to the newest version overall, or null when there are none.
 */
export function pickActiveFirmwareId(list: FirmwareSummary[]): string | null {
  if (list.length === 0) return null
  const loadable = list.filter(isFirmwareLoadable)
  const pool = loadable.length > 0 ? loadable : list
  const newest = pool.reduce((a, b) =>
    new Date(b.created_at).getTime() > new Date(a.created_at).getTime() ? b : a,
  )
  return newest.id
}

/**
 * Keep the current selection if it still exists in the list; otherwise fall
 * back to the default. Used when (re)loading a project's firmware.
 */
export function resolveActiveFirmwareId(
  currentId: string | null,
  list: FirmwareSummary[],
): string | null {
  if (currentId && list.some((fw) => fw.id === currentId)) return currentId
  return pickActiveFirmwareId(list)
}
