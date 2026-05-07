import apiClient from './client'
import { SECURITY_SCAN_TIMEOUT } from './timeouts'
import type {
  SbomComponent,
  SbomGenerateResponse,
  SbomSummary,
  SbomVulnerability,
  VulnerabilityUpdate,
  VulnerabilityScanStatus,
} from '@/types'

// Backend list endpoints return a Page envelope
// ``{ items, total, offset, limit }``.  ``getSbomComponents`` and
// ``getVulnerabilities`` keep their existing ``T[]`` return shape so
// every caller keeps working; new ``*Page`` variants expose the full
// envelope for any consumer that wants the total.
interface PageEnvelope<T> {
  items: T[]
  total: number
  offset: number
  limit: number
}

function unwrap<T>(data: PageEnvelope<T> | T[]): T[] {
  return Array.isArray(data) ? data : (data?.items ?? [])
}

export async function generateSbom(
  projectId: string,
  forceRescan = false,
  firmwareId?: string,
): Promise<SbomGenerateResponse> {
  const { data } = await apiClient.post<SbomGenerateResponse>(
    `/projects/${projectId}/sbom/generate`,
    null,
    {
      params: { force_rescan: forceRescan, firmware_id: firmwareId },
      timeout: SECURITY_SCAN_TIMEOUT,
    },
  )
  return data
}

export async function getSbomComponents(
  projectId: string,
  filters?: { type?: string; name?: string; firmware_id?: string; limit?: number; offset?: number },
): Promise<SbomComponent[]> {
  const { data } = await apiClient.get<PageEnvelope<SbomComponent> | SbomComponent[]>(
    `/projects/${projectId}/sbom`,
    { params: filters },
  )
  return unwrap(data)
}

export async function getSbomComponentsPage(
  projectId: string,
  filters?: { type?: string; name?: string; firmware_id?: string; limit?: number; offset?: number },
): Promise<PageEnvelope<SbomComponent>> {
  const { data } = await apiClient.get<PageEnvelope<SbomComponent>>(
    `/projects/${projectId}/sbom`,
    { params: filters },
  )
  return data
}

export async function exportSbom(
  projectId: string,
  format = 'cyclonedx-json',
  firmwareId?: string,
): Promise<Blob> {
  const { data } = await apiClient.get(
    `/projects/${projectId}/sbom/export`,
    {
      params: { format, firmware_id: firmwareId },
      responseType: 'blob',
      timeout: SECURITY_SCAN_TIMEOUT,
    },
  )
  return data
}

// Vulnerability scan now returns 202 immediately and runs in the background
// (Rule #33 / commit 8f54a24). The frontend polls
// /sbom/vulnerabilities/scan/status every 2 s — see SbomPage.handleScan.
// No timeout override needed: the 202 ack is sub-second so the default
// 30 s axios floor on apiClient is correct.

export async function runVulnerabilityScan(
  projectId: string,
  forceRescan = false,
  firmwareId?: string,
): Promise<VulnerabilityScanStatus> {
  const { data } = await apiClient.post<VulnerabilityScanStatus>(
    `/projects/${projectId}/sbom/vulnerabilities/scan`,
    null,
    {
      params: { force_rescan: forceRescan, firmware_id: firmwareId },
    },
  )
  return data
}

export async function getVulnerabilityScanStatus(
  projectId: string,
  firmwareId?: string,
): Promise<VulnerabilityScanStatus> {
  const { data } = await apiClient.get<VulnerabilityScanStatus>(
    `/projects/${projectId}/sbom/vulnerabilities/scan/status`,
    { params: { firmware_id: firmwareId } },
  )
  return data
}

export async function getVulnerabilities(
  projectId: string,
  filters?: { severity?: string; component_id?: string; cve_id?: string; resolution_status?: string; limit?: number; offset?: number; firmware_id?: string },
): Promise<SbomVulnerability[]> {
  const { data } = await apiClient.get<PageEnvelope<SbomVulnerability> | SbomVulnerability[]>(
    `/projects/${projectId}/sbom/vulnerabilities`,
    { params: filters },
  )
  return unwrap(data)
}

export async function getVulnerabilitiesPage(
  projectId: string,
  filters?: { severity?: string; component_id?: string; cve_id?: string; resolution_status?: string; limit?: number; offset?: number; firmware_id?: string },
): Promise<PageEnvelope<SbomVulnerability>> {
  const { data } = await apiClient.get<PageEnvelope<SbomVulnerability>>(
    `/projects/${projectId}/sbom/vulnerabilities`,
    { params: filters },
  )
  return data
}

export async function updateVulnerability(
  projectId: string,
  vulnerabilityId: string,
  body: VulnerabilityUpdate,
): Promise<SbomVulnerability> {
  const { data } = await apiClient.patch<SbomVulnerability>(
    `/projects/${projectId}/sbom/vulnerabilities/${vulnerabilityId}`,
    body,
  )
  return data
}

export async function getVulnerabilitySummary(
  projectId: string,
  firmwareId?: string,
): Promise<SbomSummary> {
  const { data } = await apiClient.get<SbomSummary>(
    `/projects/${projectId}/sbom/vulnerabilities/summary`,
    { params: { firmware_id: firmwareId } },
  )
  return data
}
