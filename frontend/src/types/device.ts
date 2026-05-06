export interface BridgeStatus {
  connected: boolean
  bridge_host: string | null
  bridge_port: number | null
  error: string | null
}

/**
 * Acquisition mode emitted by the device bridge
 * (scripts/wairz-device-bridge.py). Listed modes are EXACTLY what the bridge
 * currently reports — do not add speculative values like 'edl' or 'fastboot'.
 * Backend keeps the field loosely typed (`str | None`) for forward compat;
 * the frontend narrows it here, with a `null` / `undefined` fallback for
 * ADB devices that don't populate these fields.
 */
export type DeviceMode = 'adb' | 'brom' | 'preloader'

export interface DeviceInfo {
  serial: string
  model: string | null
  device: string | null
  transport_id: string | null
  state: string
  /**
   * Populated for MediaTek BROM/preloader devices. ADB devices return
   * null/undefined — the backend `DeviceInfo` schema makes all three
   * acquisition-mode fields Optional (default None).
   */
  mode?: DeviceMode | null
  available?: boolean | null
  error?: string | null
}

export interface PartitionInfo {
  name: string
  size: number | null
}

export interface DeviceDetail {
  device: DeviceInfo
  getprop: Record<string, string>
  partitions: string[]
  partition_sizes: PartitionInfo[]
  device_metadata: Record<string, unknown> | null
  /**
   * MediaTek chipset identifier (e.g. "MT6765") for BROM/preloader devices.
   * ADB devices surface the same info via getprop['ro.hardware.chipname']
   * instead, and leave this null.
   */
  chipset?: string | null
}

export interface PartitionStatus {
  partition: string
  status: 'pending' | 'active' | 'complete' | 'failed' | 'skipped'
  bytes_written: number
  total_bytes: number | null
  progress_percent: number | null
  throughput_mbps: number | null
  size: number | null
  error: string | null
  path: string | null
}

/**
 * Dump-session status enum. Mirrors `DumpStatus = Literal[...]` in
 * `backend/app/schemas/device.py` and the
 * `ck_device_dump_sessions_status` CHECK constraint in alembic
 * `b0c1a2d3e4f5_add_device_dump_sessions.py`. Per CLAUDE.md Rule #33c the
 * three (Pydantic enum, DB CHECK, frontend union) must stay in sync.
 *
 * Distinct from the legacy in-process state ('idle' | 'dumping') —
 * 'idle' no longer exists because every dump is its own row, and
 * 'dumping' was renamed to 'running' to align with cve-match /
 * emulation / fuzzing.
 */
export type DumpStatusValue =
  | 'queued'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled'

export interface DumpStatus {
  /**
   * UUID assigned by `POST /dumps`. Frontend persists this for the duration
   * of the wizard run and uses it for status polling, cancel, and import.
   */
  dump_id: string
  status: DumpStatusValue
  device_id: string
  partitions: PartitionStatus[]
  bytes_written: number
  total_bytes: number | null
  error: string | null
  started_at: string | null
  finished_at: string | null
  created_at: string | null
}

export interface ImportResult {
  firmware_id: string
  device_metadata: Record<string, unknown> | null
  message: string
}
