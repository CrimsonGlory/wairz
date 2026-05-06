import apiClient from './client'
import { SECURITY_SCAN_TIMEOUT } from './timeouts'
import type {
  ManifestScanResponse,
  BytecodeScanResponse,
  SastScanResponse,
  ApkFullScanResult,
  ApkScanOptions,
} from '@/types/apkScan'

// Re-export all types so existing consumers can import from here too
export type {
  FirmwareContextResponse,
  ManifestFindingResponse,
  ManifestScanSummary,
  ConfidenceSummary,
  ManifestScanResponse,
  BytecodeFindingLocation,
  BytecodeFindingResponse,
  BytecodeScanSummary,
  BytecodeScanResponse,
  SastFindingResponse,
  SastScanTimingResponse,
  SastScanSummary,
  SastScanResponse,
  ApkFullScanResult,
  ApkScanOptions,
  ApkScanSeverity,
  ApkScanConfidence,
} from '@/types/apkScan'

// ---------------------------------------------------------------------------
// API client functions
// ---------------------------------------------------------------------------

function basePath(projectId: string, firmwareId: string): string {
  return `/projects/${projectId}/firmware/${firmwareId}/apk-scan`
}

/**
 * Run Phase 1 manifest security scan on an APK.
 *
 * Performs 18 MobSF-equivalent manifest security checks including debuggable,
 * allowBackup, usesCleartextTraffic, exported components, and more.
 * Results are cached by APK SHA256. Typically completes under 500ms.
 */
export async function scanApkManifest(
  projectId: string,
  firmwareId: string,
  apkPath: string,
  persistFindings: boolean = true,
  minSeverity?: string,
): Promise<ManifestScanResponse> {
  const { data } = await apiClient.post<ManifestScanResponse>(
    `${basePath(projectId, firmwareId)}/manifest`,
    undefined,
    {
      params: {
        apk_path: apkPath,
        persist_findings: persistFindings,
        ...(minSeverity != null && { min_severity: minSeverity }),
      },
    },
  )
  return data
}

/**
 * Run Phase 2a bytecode security scan on an APK.
 *
 * Scans DEX bytecode for insecure API usage patterns including insecure crypto,
 * cleartext HTTP, disabled TLS validation, world-readable storage, and more.
 * Results are cached by APK SHA256. Typically completes under 30s.
 */
export async function scanApkBytecode(
  projectId: string,
  firmwareId: string,
  apkPath: string,
  minSeverity?: string,
  minConfidence?: string,
): Promise<BytecodeScanResponse> {
  const { data } = await apiClient.post<BytecodeScanResponse>(
    `${basePath(projectId, firmwareId)}/bytecode`,
    undefined,
    {
      params: {
        apk_path: apkPath,
        ...(minSeverity != null && { min_severity: minSeverity }),
        ...(minConfidence != null && { min_confidence: minConfidence }),
      },
      timeout: SECURITY_SCAN_TIMEOUT,
    },
  )
  return data
}

/**
 * Run Phase 2b SAST scan (jadx + mobsfscan) on an APK.
 *
 * Decompiles APK with jadx and runs mobsfscan for complex code pattern analysis.
 * Results are cached by APK SHA256. Pipeline budget is configurable (default 180s).
 */
export async function scanApkSast(
  projectId: string,
  firmwareId: string,
  apkPath: string,
  options?: {
    minSeverity?: string
    forceRescan?: boolean
    timeout?: number
  },
): Promise<SastScanResponse> {
  const { data } = await apiClient.post<SastScanResponse>(
    `${basePath(projectId, firmwareId)}/sast`,
    undefined,
    {
      params: {
        apk_path: apkPath,
        ...(options?.minSeverity != null && { min_severity: options.minSeverity }),
        ...(options?.forceRescan != null && { force_rescan: options.forceRescan }),
        ...(options?.timeout != null && { timeout: options.timeout }),
      },
      timeout: SECURITY_SCAN_TIMEOUT,
    },
  )
  return data
}

/**
 * Run all three scan phases on an APK concurrently.
 *
 * Returns results for manifest, bytecode, and SAST scans. Individual scan
 * failures are returned as errors in their respective response objects rather
 * than rejecting the entire promise.
 */
export async function scanApkAll(
  projectId: string,
  firmwareId: string,
  apkPath: string,
  options?: ApkScanOptions,
): Promise<ApkFullScanResult> {
  const [manifest, bytecode, sast] = await Promise.allSettled([
    scanApkManifest(projectId, firmwareId, apkPath, options?.persistFindings, options?.minSeverity),
    scanApkBytecode(projectId, firmwareId, apkPath, options?.minSeverity),
    scanApkSast(projectId, firmwareId, apkPath, {
      minSeverity: options?.minSeverity,
      forceRescan: options?.forceRescan,
      timeout: options?.timeout,
    }),
  ])

  return {
    manifest: manifest.status === 'fulfilled' ? manifest.value : null,
    bytecode: bytecode.status === 'fulfilled' ? bytecode.value : null,
    sast: sast.status === 'fulfilled' ? sast.value : null,
  }
}

// ---------------------------------------------------------------------------
// Decompiled source viewer
// ---------------------------------------------------------------------------

export interface SourceFileResponse {
  path: string
  source: string
  apk_path: string
  line_count: number
}

export interface SourceFileListResponse {
  apk_path: string
  files: string[]
  total: number
}

/**
 * List available decompiled source files for an APK.
 * Only available after a SAST scan has been run.
 */
export async function listDecompiledSources(
  projectId: string,
  firmwareId: string,
  apkPath: string,
): Promise<SourceFileListResponse> {
  const { data } = await apiClient.get<SourceFileListResponse>(
    `${basePath(projectId, firmwareId)}/source/list`,
    { params: { apk_path: apkPath } },
  )
  return data
}

/**
 * Get decompiled Java/Kotlin source for a specific file.
 */
export async function getDecompiledSource(
  projectId: string,
  firmwareId: string,
  apkPath: string,
  filePath: string,
): Promise<SourceFileResponse> {
  const { data } = await apiClient.get<SourceFileResponse>(
    `${basePath(projectId, firmwareId)}/source`,
    { params: { apk_path: apkPath, file_path: filePath } },
  )
  return data
}
