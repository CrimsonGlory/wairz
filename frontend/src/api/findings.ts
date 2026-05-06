import apiClient from './client'
import { HASH_SCAN_TIMEOUT, SECURITY_SCAN_TIMEOUT } from './timeouts'
import type { Finding, FindingCreate, FindingUpdate } from '@/types'

// Backend ``list_findings`` now returns a Page envelope.  ``listFindings()``
// still returns ``Finding[]`` to keep every caller working; ``listFindingsPage()``
// exposes the full ``{ items, total, offset, limit }`` for new consumers.
interface PageEnvelope<T> {
  items: T[]
  total: number
  offset: number
  limit: number
}

function unwrap<T>(data: PageEnvelope<T> | T[]): T[] {
  return Array.isArray(data) ? data : (data?.items ?? [])
}

export interface SecurityAuditResult {
  status: string
  checks_run: number
  findings_created: number
  total_findings: number
  errors: string[]
}

export interface YaraScanResult {
  status: string
  rules_loaded: number
  files_scanned: number
  files_matched: number
  findings_created: number
  errors: string[]
}

export interface AbusechScanResult {
  status: string
  binaries_checked: number
  malwarebazaar_hits: number
  threatfox_hits: number
  yaraify_hits: number
  findings_created: number
  details: Record<string, unknown>
  errors: string[]
}

export interface KnownGoodFile {
  path: string
  sha256: string
  source: string
  product: string
  vendor: string
}

export interface KnownGoodScanResult {
  status: string
  binaries_checked: number
  known_good_count: number
  unknown_count: number
  known_good_files: KnownGoodFile[]
  errors: string[]
}

export async function runAbusechScan(
  projectId: string,
): Promise<AbusechScanResult> {
  const { data } = await apiClient.post<AbusechScanResult>(
    `/projects/${projectId}/security/abusech-scan`,
    null,
    { timeout: HASH_SCAN_TIMEOUT },
  )
  return data
}

export async function runKnownGoodScan(
  projectId: string,
): Promise<KnownGoodScanResult> {
  const { data } = await apiClient.post<KnownGoodScanResult>(
    `/projects/${projectId}/security/known-good-scan`,
    null,
    { timeout: HASH_SCAN_TIMEOUT },
  )
  return data
}

export async function runSecurityAudit(
  projectId: string,
): Promise<SecurityAuditResult> {
  const { data } = await apiClient.post<SecurityAuditResult>(
    `/projects/${projectId}/security/audit`,
    null,
    { timeout: SECURITY_SCAN_TIMEOUT },
  )
  return data
}

export async function runYaraScan(
  projectId: string,
): Promise<YaraScanResult> {
  const { data } = await apiClient.post<YaraScanResult>(
    `/projects/${projectId}/security/yara`,
    null,
    { timeout: SECURITY_SCAN_TIMEOUT },
  )
  return data
}

export async function listFindings(
  projectId: string,
  params?: { severity?: string; status?: string; source?: string; firmware_id?: string; limit?: number; offset?: number },
): Promise<Finding[]> {
  const { data } = await apiClient.get<PageEnvelope<Finding> | Finding[]>(
    `/projects/${projectId}/findings`,
    { params },
  )
  return unwrap(data)
}

export async function listFindingsPage(
  projectId: string,
  params?: { severity?: string; status?: string; source?: string; firmware_id?: string; limit?: number; offset?: number },
): Promise<PageEnvelope<Finding>> {
  const { data } = await apiClient.get<PageEnvelope<Finding>>(
    `/projects/${projectId}/findings`,
    { params },
  )
  return data
}

export async function getFinding(
  projectId: string,
  findingId: string,
): Promise<Finding> {
  const { data } = await apiClient.get<Finding>(
    `/projects/${projectId}/findings/${findingId}`,
  )
  return data
}

export async function createFinding(
  projectId: string,
  body: FindingCreate,
): Promise<Finding> {
  const { data } = await apiClient.post<Finding>(
    `/projects/${projectId}/findings`,
    body,
  )
  return data
}

export async function updateFinding(
  projectId: string,
  findingId: string,
  body: FindingUpdate,
): Promise<Finding> {
  const { data } = await apiClient.patch<Finding>(
    `/projects/${projectId}/findings/${findingId}`,
    body,
  )
  return data
}

export async function deleteFinding(
  projectId: string,
  findingId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/findings/${findingId}`)
}

export async function exportFindings(
  projectId: string,
  format: 'markdown' | 'pdf' = 'markdown',
): Promise<Blob> {
  const { data } = await apiClient.post(
    `/projects/${projectId}/findings/export`,
    null,
    { params: { format }, responseType: 'blob' },
  )
  return data
}
