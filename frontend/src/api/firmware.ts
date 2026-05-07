import apiClient from './client'
import type {
  FirmwareDetail,
  FirmwareMetadata,
  FirmwareUploadStatus,
} from '@/types'

// Firmware UPLOADS still need a long timeout because the multipart body
// itself takes minutes to stream over a 100 Mbps link for a 2 GB file.
// Post-Rule-#33 refactor (commit 847eae9) the BACKEND ack is now <1 s
// after the body finishes — but axios's onUploadProgress + the actual
// network upload still need a generous ceiling. Matches the
// SECURITY_SCAN_TIMEOUT tier already established in findings.ts /
// exportImport.ts.
//
// Applies to POST /firmware (now returns 202 with FirmwareUploadStatus)
// and POST /firmware/{id}/upload-rootfs (rootfs can be similarly large).
const UPLOAD_TIMEOUT = 600_000

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
