import apiClient, { appendApiKey } from './client'
import { apiUrl } from './config'

export interface HardwareFirmwareBlob {
  id: string
  firmware_id: string
  blob_path: string
  partition: string | null
  blob_sha256: string
  file_size: number
  category: string
  vendor: string | null
  format: string
  version: string | null
  signed: string
  signature_algorithm: string | null
  cert_subject: string | null
  chipset_target: string | null
  driver_references: string[] | null
  sbom_component_id?: string | null
  metadata: Record<string, unknown>
  detection_source: string
  detection_confidence: string
  created_at: string
  // Per-blob CVE rollup populated by the list endpoint.  cve_count
  // excludes ADVISORY-* entries; advisory_count tracks them separately
  // so the UI can color severity correctly.  max_severity is the worst
  // severity across both buckets.
  cve_count: number
  advisory_count: number
  max_severity: 'critical' | 'high' | 'medium' | 'low' | null
}

export interface HardwareFirmwareListResponse {
  blobs: HardwareFirmwareBlob[]
  total: number
}

export interface FirmwareCveMatch {
  id: string
  blob_id: string | null
  cve_id: string
  severity: string
  cvss_score: number | null
  description: string | null
  match_confidence: string | null
  match_tier: string | null
  resolution_status: string
  created_at: string | null
}

export interface FirmwareEdge {
  driver_path: string
  firmware_name: string
  firmware_blob_path: string | null
  source: string
}

export interface FirmwareEdgesResponse {
  edges: FirmwareEdge[]
  kmod_drivers: number
  dtb_sources: number
  unresolved_count: number
}

export interface FirmwareDriver {
  driver_path: string
  format: string
  firmware_deps: string[]
  firmware_blobs: string[]
  total: number
}

export interface FirmwareDriversListResponse {
  drivers: FirmwareDriver[]
  total: number
}

export async function listHardwareFirmware(
  projectId: string,
  filters?: { category?: string; vendor?: string; signedOnly?: boolean; firmwareId?: string | null },
): Promise<HardwareFirmwareListResponse> {
  const params: Record<string, unknown> = {}
  if (filters?.category) params.category = filters.category
  if (filters?.vendor) params.vendor = filters.vendor
  if (filters?.signedOnly) params.signed_only = true
  if (filters?.firmwareId) params.firmware_id = filters.firmwareId
  const { data } = await apiClient.get<HardwareFirmwareListResponse>(
    `/projects/${projectId}/hardware-firmware`,
    { params },
  )
  return data
}

export async function getHardwareFirmwareBlob(
  projectId: string,
  blobId: string,
  firmwareId?: string | null,
): Promise<HardwareFirmwareBlob> {
  const { data } = await apiClient.get<HardwareFirmwareBlob>(
    `/projects/${projectId}/hardware-firmware/${blobId}`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

export async function getHardwareFirmwareCves(
  projectId: string,
  blobId: string,
  firmwareId?: string | null,
): Promise<FirmwareCveMatch[]> {
  const { data } = await apiClient.get<FirmwareCveMatch[]>(
    `/projects/${projectId}/hardware-firmware/${blobId}/cves`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

export interface CveMatchRunResult {
  count: number           // distinct CVE IDs across all tiers
  rows: number            // total persisted match rows (cartesian kernel_cve × kmod included)
  hw_firmware_cves: number
  kernel_cves: number
  kernel_module_rows: number
}

export type CveMatchStatus = 'idle' | 'queued' | 'running' | 'completed' | 'failed'

export interface CveMatchStatusResponse {
  firmware_id: string
  status: CveMatchStatus
  started_at: string | null
  finished_at: string | null
  error: string | null
  result: CveMatchRunResult | null
}

// POST /cve-match returns 202 + a CveMatchStatusResponse with status="queued"
// per Rule #29 (cve-match-residual-oom-2026-04-25 follow-up). The previous
// SECURITY_SCAN_TIMEOUT=600_000 axios override was a workaround for the
// then-synchronous endpoint that ran ~7 minutes on Yocto firmware; the 202
// ack is sub-second now and the default 30 s axios floor is correct.
// Frontend callers must follow the POST with a 2 s poll loop on
// getCveMatchStatus until status flips to "completed" (read .result) or
// "failed" (read .error).
export async function runCveMatch(
  projectId: string,
  options?: { forceRescan?: boolean; firmwareId?: string | null },
): Promise<CveMatchStatusResponse> {
  const params: Record<string, unknown> = {}
  if (options?.forceRescan) params.force_rescan = true
  if (options?.firmwareId) params.firmware_id = options.firmwareId
  const { data } = await apiClient.post<CveMatchStatusResponse>(
    `/projects/${projectId}/hardware-firmware/cve-match`,
    null,
    { params },
  )
  return data
}

// GET /cve-match/status — polled every 2 s by HardwareFirmwarePage while a
// run is queued/running. Cheap (one row read).
export async function getCveMatchStatus(
  projectId: string,
  firmwareId?: string | null,
): Promise<CveMatchStatusResponse> {
  const { data } = await apiClient.get<CveMatchStatusResponse>(
    `/projects/${projectId}/hardware-firmware/cve-match/status`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

export interface CveAggregate {
  hw_firmware_cves: number
  kernel_cves: number
  advisory_count: number
  last_match_at: string | null
  // Per-severity breakdown of ``hw_firmware_cves`` (NOT kernel-tier).
  hw_severity_critical: number
  hw_severity_high: number
  hw_severity_medium: number
  hw_severity_low: number
}

export async function getCveAggregate(
  projectId: string,
  firmwareId?: string | null,
): Promise<CveAggregate> {
  const { data } = await apiClient.get<CveAggregate>(
    `/projects/${projectId}/hardware-firmware/cve-aggregate`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

// CVE-centric aggregation — one row per distinct hw-firmware CVE with
// the affected-blob list and distinct formats rolled up.  Backed by
// GET .../hardware-firmware/cves.
export interface CveRow {
  cve_id: string
  severity: string
  cvss_score: number | null
  match_tier: string | null
  match_confidence: string | null
  description: string | null
  affected_blob_count: number
  affected_blob_ids: string[]
  affected_formats: string[]
}

export interface CveListResponse {
  cves: CveRow[]
  total: number
}

export async function listHardwareFirmwareCves(
  projectId: string,
  firmwareId?: string | null,
): Promise<CveListResponse> {
  const { data } = await apiClient.get<CveListResponse>(
    `/projects/${projectId}/hardware-firmware/cves`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

// Build the download URL for a blob — the backend streams the file
// with Content-Disposition: attachment so the browser handles it via
// a plain `<a href download>` anchor.
export function buildBlobDownloadUrl(
  projectId: string,
  blobId: string,
  firmwareId?: string | null,
): string {
  const base = apiUrl(`/api/v1/projects/${projectId}/hardware-firmware/${blobId}/download`)
  const withFirmware = firmwareId
    ? `${base}?firmware_id=${encodeURIComponent(firmwareId)}`
    : base
  return appendApiKey(withFirmware)
}

export async function getFirmwareEdges(
  projectId: string,
  firmwareId?: string | null,
): Promise<FirmwareEdgesResponse> {
  const { data } = await apiClient.get<FirmwareEdgesResponse>(
    `/projects/${projectId}/hardware-firmware/firmware-edges`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

export async function getFirmwareDrivers(
  projectId: string,
  firmwareId?: string | null,
): Promise<FirmwareDriversListResponse> {
  const { data } = await apiClient.get<FirmwareDriversListResponse>(
    `/projects/${projectId}/hardware-firmware/drivers`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

// ── Phase β.8 — Authenticode-chain 202+polling ────────────────────────────────
//
// Mirrors the cve-match flow above: POST returns 202 immediately, then the
// frontend polls GET /authenticode-chain/status every 2 s until status flips
// to 'completed' (read .result for the aggregate) or 'failed' (read .error).
// Default 30 s axios floor is correct — both the POST ack and the GET status
// are sub-second ops (Rule #29).

export type AuthenticodeChainStatus =
  | 'idle'
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'

export type WindowsPEChainStatus =
  | 'valid_at_signing'
  | 'valid_now'
  | 'revoked'
  | 'never_valid'
  | 'unknown'

export interface AuthenticodeChainAggregate {
  signed_count: number
  signed_pct: number
  unsigned_count: number
  dbx_revoked_count: number
  by_chain_status: Record<string, number>
  run_seconds: number
  total_pe_count: number
  errors: { blob_path: string; error: string }[]
}

export interface AuthenticodeChainStatusResponse {
  firmware_id: string
  status: AuthenticodeChainStatus
  started_at: string | null
  finished_at: string | null
  error: string | null
  result: AuthenticodeChainAggregate | null
}

export async function runAuthenticodeChain(
  projectId: string,
  firmwareId?: string | null,
): Promise<AuthenticodeChainStatusResponse> {
  const { data } = await apiClient.post<AuthenticodeChainStatusResponse>(
    `/projects/${projectId}/hardware-firmware/authenticode-chain`,
    null,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

export async function getAuthenticodeChainStatus(
  projectId: string,
  firmwareId?: string | null,
): Promise<AuthenticodeChainStatusResponse> {
  const { data } = await apiClient.get<AuthenticodeChainStatusResponse>(
    `/projects/${projectId}/hardware-firmware/authenticode-chain/status`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

// ── Phase β.11 — Per-PE WindowsPESignature read endpoints ────────────────────

export interface WindowsPESignatureSummary {
  id: string
  blob_id: string
  blob_path: string
  signed: boolean
  chain_status: WindowsPEChainStatus
  signer_subject: string | null
  signer_issuer: string | null
  leaf_serial: string | null
  sig_hash_algo: string | null
  tsa_authority: string | null
  signed_at: string | null
  dbx_revoked: boolean
  dbx_revocation_kb: string | null
  arch_view_present: boolean
  rich_header_present: boolean
  created_at: string
}

export interface WindowsPESignatureListResponse {
  signatures: WindowsPESignatureSummary[]
  total: number
  offset: number
  limit: number
}

export interface WindowsPESignatureDetail {
  id: string
  blob_id: string
  blob_path: string
  signed: boolean
  chain_status: WindowsPEChainStatus
  signer_subject: string | null
  signer_issuer: string | null
  leaf_serial: string | null
  sig_hash_algo: string | null
  tsa_authority: string | null
  signed_at: string | null
  chain_json: Record<string, unknown> | null
  dbx_revoked: boolean
  dbx_revocation_kb: string | null
  rich_header_json: Record<string, unknown> | null
  arch_view: Record<string, unknown> | null
  created_at: string
  updated_at: string
}

export interface ListPeSignaturesFilters {
  chainStatus?: WindowsPEChainStatus | null
  dbxRevokedOnly?: boolean
  offset?: number
  limit?: number
  firmwareId?: string | null
}

export async function listPeSignatures(
  projectId: string,
  filters?: ListPeSignaturesFilters,
): Promise<WindowsPESignatureListResponse> {
  const params: Record<string, unknown> = {}
  if (filters?.chainStatus) params.chain_status = filters.chainStatus
  if (filters?.dbxRevokedOnly) params.dbx_revoked_only = true
  if (filters?.offset !== undefined) params.offset = filters.offset
  if (filters?.limit !== undefined) params.limit = filters.limit
  if (filters?.firmwareId) params.firmware_id = filters.firmwareId
  const { data } = await apiClient.get<WindowsPESignatureListResponse>(
    `/projects/${projectId}/hardware-firmware/pe-signatures`,
    { params: Object.keys(params).length > 0 ? params : undefined },
  )
  return data
}

export async function getPeSignature(
  projectId: string,
  signatureId: string,
  firmwareId?: string | null,
): Promise<WindowsPESignatureDetail> {
  const { data } = await apiClient.get<WindowsPESignatureDetail>(
    `/projects/${projectId}/hardware-firmware/pe-signatures/${signatureId}`,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}
