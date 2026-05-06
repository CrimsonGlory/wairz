import apiClient from './client'
import type {
  BridgeStatus,
  DeviceInfo,
  DeviceDetail,
  DumpStatus,
  ImportResult,
} from '@/types/device'

export async function getDeviceBridgeStatus(
  projectId: string,
): Promise<BridgeStatus> {
  const { data } = await apiClient.get<BridgeStatus>(
    `/projects/${projectId}/device/status`,
  )
  return data
}

export async function listDevices(
  projectId: string,
): Promise<DeviceInfo[]> {
  const { data } = await apiClient.get<{ devices: DeviceInfo[] }>(
    `/projects/${projectId}/device/devices`,
  )
  return data.devices
}

export async function getDeviceInfo(
  projectId: string,
  deviceId: string,
): Promise<DeviceDetail> {
  const { data } = await apiClient.get<DeviceDetail>(
    `/projects/${projectId}/device/devices/${deviceId}/info`,
  )
  return data
}

// importDump and startDump previously needed a 5 min timeout because the
// dump POST and the import POST were synchronous: the backend held the
// HTTP request open while the bridge enumerated partitions / the unpack
// pipeline kicked off. After the audit-2026-05-04 F-A-01 refactor (Rule
// #33 202+polling) `POST /dumps` returns within sub-seconds with a row
// id; the actual partition-dump work runs in `_run_dump_background`. So
// `startDump` no longer needs an override — the apiClient default 30 s
// floor is correct.
//
// `importDump` still does synchronous SHA-256 + Firmware-row insert
// before scheduling the unpack background task, so it keeps the long
// timeout for now (multi-GB dumps stretch the SHA + insert work). A
// follow-up Rule #33 conversion of /import is in scope for a separate
// intake; this commit's scope is just the dump-state global removal.
const DEVICE_BRIDGE_TIMEOUT = 300_000

export async function startDump(
  projectId: string,
  deviceId: string,
  partitions: string[],
): Promise<DumpStatus> {
  const { data } = await apiClient.post<DumpStatus>(
    `/projects/${projectId}/device/dumps`,
    { device_id: deviceId, partitions },
  )
  return data
}

export async function getDumpStatus(
  projectId: string,
  dumpId: string,
): Promise<DumpStatus> {
  const { data } = await apiClient.get<DumpStatus>(
    `/projects/${projectId}/device/dumps/${dumpId}/status`,
  )
  return data
}

export async function cancelDump(
  projectId: string,
  dumpId: string,
): Promise<DumpStatus> {
  const { data } = await apiClient.post<DumpStatus>(
    `/projects/${projectId}/device/dumps/${dumpId}/cancel`,
  )
  return data
}

export async function importDump(
  projectId: string,
  dumpId: string,
  deviceId: string,
  versionLabel?: string,
): Promise<ImportResult> {
  const { data } = await apiClient.post<ImportResult>(
    `/projects/${projectId}/device/import`,
    { dump_id: dumpId, device_id: deviceId, version_label: versionLabel },
    { timeout: DEVICE_BRIDGE_TIMEOUT },
  )
  return data
}
