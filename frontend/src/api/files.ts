import apiClient, { appendApiKey } from './client'
import { apiUrl } from './config'
import type { DirectoryListing, FileContent, FileInfo } from '@/types'

export interface SearchResult {
  pattern: string
  matches: string[]
  truncated: boolean
}

export async function searchFiles(
  projectId: string,
  pattern: string,
  path: string = '/',
  firmwareId?: string,
): Promise<SearchResult> {
  const { data } = await apiClient.get<SearchResult>(
    `/projects/${projectId}/files/search`,
    { params: { pattern, path, firmware_id: firmwareId } },
  )
  return data
}

export async function listDirectory(
  projectId: string,
  path: string = '',
  firmwareId?: string,
): Promise<DirectoryListing> {
  const { data } = await apiClient.get<DirectoryListing>(
    `/projects/${projectId}/files`,
    { params: { path, firmware_id: firmwareId } },
  )
  return data
}

export async function readFile(
  projectId: string,
  path: string,
  offset?: number,
  length?: number,
  format?: string,
  firmwareId?: string,
): Promise<FileContent> {
  const { data } = await apiClient.get<FileContent>(
    `/projects/${projectId}/files/read`,
    { params: { path, offset, length, format, firmware_id: firmwareId } },
  )
  return data
}

export function getFileDownloadUrl(projectId: string, path: string, firmwareId?: string): string {
  const params = new URLSearchParams({ path })
  if (firmwareId) params.set('firmware_id', firmwareId)
  return appendApiKey(apiUrl(`/api/v1/projects/${projectId}/files/download?${params.toString()}`))
}

export interface UefiSection {
  type: string
  size: number
  is_pe: boolean
}

export interface UefiModule {
  guid: string
  type: string
  name: string
  size: string
  path: string
  sections: UefiSection[]
  has_pe32: boolean
  pe32_path: string | null
  text: string
  checksum_valid: boolean
}

export interface UefiModulesResponse {
  modules: UefiModule[]
  total: number
  is_uefi: boolean
}

export async function getUefiModules(
  projectId: string,
  firmwareId?: string,
): Promise<UefiModulesResponse> {
  const { data } = await apiClient.get<UefiModulesResponse>(
    `/projects/${projectId}/files/uefi-modules`,
    { params: { firmware_id: firmwareId } },
  )
  return data
}

export interface UefiScanResult {
  status: string
  modules_scanned: number
  findings_created: number
  summary: Record<string, number>
  errors: string[]
}

// UEFI scan iterates every PE32 section in every UEFI module and runs
// pe-header + string-match checks. Large BIOS images (~32 MB, ~180 modules)
// comfortably exceed the default axios 30 s timeout; the server continues
// to completion while the browser surfaces a fake "scan failed". Matches
// the SECURITY_SCAN_TIMEOUT tier used for security/audit + yara in findings.ts.
const SECURITY_SCAN_TIMEOUT = 600_000

export async function scanUefiModules(projectId: string): Promise<UefiScanResult> {
  const { data } = await apiClient.post<UefiScanResult>(
    `/projects/${projectId}/security/uefi-scan`,
    null,
    { timeout: SECURITY_SCAN_TIMEOUT },
  )
  return data
}

export async function getFileInfo(
  projectId: string,
  path: string,
  firmwareId?: string,
): Promise<FileInfo> {
  const { data } = await apiClient.get<FileInfo>(
    `/projects/${projectId}/files/info`,
    { params: { path, firmware_id: firmwareId } },
  )
  return data
}
