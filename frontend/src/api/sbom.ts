import apiClient from './client'
import { SECURITY_SCAN_TIMEOUT } from './timeouts'
import type {
  SbomComponent,
  SbomGenerateResponse,
  SbomSummary,
  SbomVulnerability,
  VulnerabilityUpdate,
  VulnerabilityScanResult,
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

// Vulnerability scan iterates every SBOM component and queries NVD (or the
// local cache) for each PURL. On firmware with ~200 components and a cold
// NVD cache the call routinely takes 2-5 minutes; the default axios 30 s
// fires and surfaces a fake "scan failed". Matches SECURITY_SCAN_TIMEOUT
// tier used in findings.ts for the other full-tree security scans.

export async function runVulnerabilityScan(
  projectId: string,
  forceRescan = false,
  firmwareId?: string,
): Promise<VulnerabilityScanResult> {
  const { data } = await apiClient.post<VulnerabilityScanResult>(
    `/projects/${projectId}/sbom/vulnerabilities/scan`,
    null,
    {
      params: { force_rescan: forceRescan, firmware_id: firmwareId },
      timeout: SECURITY_SCAN_TIMEOUT,
    },
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
