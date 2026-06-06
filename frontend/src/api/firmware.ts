import apiClient from './client'
import type {
  FirmwareDetail,
  FirmwareKind,
  FirmwareMetadata,
  FirmwareSummary,
  FirmwareUploadStatus,
  RtosFlavor,
} from '@/types'

// Firmware UPLOADS still need a long timeout because the multipart body
// itself takes minutes to stream over a 100 Mbps link for a 2 GB file.
const UPLOAD_TIMEOUT = 1_800_000

export async function uploadFirmware(
  projectId: string,
  file: File,
  versionLabel?: string,
  onProgress?: (percent: number) => void,
): Promise<FirmwareUploadStatus> {
  const form = new FormData()
  form.append('file', file)
  if (versionLabel) {
    form.append('version_label', versionLabel)
  }

  const { data } = await apiClient.post<FirmwareUploadStatus>(
    `/projects/${projectId}/firmware`,
    form,
    {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: UPLOAD_TIMEOUT,
      onUploadProgress: (e) => {
        if (e.total && onProgress) {
          onProgress(Math.round((e.loaded * 100) / e.total))
        }
      },
    },
  )
  return data
}

/**
 * Poll the upload-stage state machine after a 202 from POST /firmware.
 * Frontend should poll every 2 s until ``upload_stage`` flips to
 * ``ready`` or ``failed``. Mirrors the firmware-unpack and SBOM
 * vuln-scan polling shape.
 */
export async function getFirmwareUploadStatus(
  projectId: string,
  firmwareId: string,
): Promise<FirmwareUploadStatus> {
  const { data } = await apiClient.get<FirmwareUploadStatus>(
    `/projects/${projectId}/firmware/${firmwareId}/upload-status`,
  )
  return data
}

export async function listFirmware(
  projectId: string,
): Promise<FirmwareDetail[]> {
  const { data } = await apiClient.get<FirmwareDetail[]>(
    `/projects/${projectId}/firmware`,
  )
  return data
}

export async function getSingleFirmware(
  projectId: string,
  firmwareId: string,
): Promise<FirmwareDetail> {
  const { data } = await apiClient.get<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}`,
  )
  return data
}

export async function updateFirmware(
  projectId: string,
  firmwareId: string,
  data: { version_label?: string | null },
): Promise<FirmwareDetail> {
  const { data: result } = await apiClient.patch<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}`,
    data,
  )
  return result
}

export async function deleteFirmware(
  projectId: string,
  firmwareId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/firmware/${firmwareId}`)
}

export async function updateFirmwareKind(
  projectId: string,
  firmwareId: string,
  kind: FirmwareKind,
  rtosFlavor: RtosFlavor | null = null,
): Promise<FirmwareDetail> {
  const { data } = await apiClient.patch<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}/kind`,
    { kind, rtos_flavor: rtosFlavor },
  )
  return data
}

export async function updateFirmwareArchInfo(
  projectId: string,
  firmwareId: string,
  patch: { architecture?: string | null; endianness?: 'little' | 'big' | null },
): Promise<FirmwareDetail> {
  const { data } = await apiClient.patch<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}`,
    patch,
  )
  return data
}

export async function unpackFirmware(
  projectId: string,
  firmwareId: string,
): Promise<FirmwareDetail> {
  const { data } = await apiClient.post<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}/unpack`,
  )
  return data
}

export async function uploadRootfs(
  projectId: string,
  firmwareId: string,
  file: File,
  onProgress?: (percent: number) => void,
): Promise<FirmwareDetail> {
  const form = new FormData()
  form.append('file', file)

  const { data } = await apiClient.post<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}/upload-rootfs`,
    form,
    {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: UPLOAD_TIMEOUT,
      onUploadProgress: (e) => {
        if (e.total && onProgress) {
          onProgress(Math.round((e.loaded * 100) / e.total))
        }
      },
    },
  )
  return data
}

export async function getFirmwareMetadata(
  projectId: string,
  firmwareId: string,
): Promise<FirmwareMetadata> {
  const { data } = await apiClient.get<FirmwareMetadata>(
    `/projects/${projectId}/firmware/${firmwareId}/metadata`,
  )
  return data
}
