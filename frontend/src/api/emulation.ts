import apiClient, { appendApiKey } from './client'
import { apiUrl } from './config'
import type {
  EmulationSession,
  EmulationStartRequest,
  EmulationExecResponse,
  EmulationPreset,
  EmulationPresetCreate,
  EmulationPresetUpdate,
  FirmwareService,
  SystemEmulationStartRequest,
  SystemCommandResponse,
} from '@/types'

export async function startEmulation(
  projectId: string,
  request: EmulationStartRequest,
  firmwareId?: string | null,
): Promise<EmulationSession> {
  const { data } = await apiClient.post<EmulationSession>(
    `/projects/${projectId}/emulation/start`,
    request,
    { params: firmwareId ? { firmware_id: firmwareId } : undefined },
  )
  return data
}

export async function deleteSession(
  projectId: string,
  sessionId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/emulation/${sessionId}`)
}

export async function stopEmulation(
  projectId: string,
  sessionId: string,
): Promise<EmulationSession> {
  const { data } = await apiClient.post<EmulationSession>(
    `/projects/${projectId}/emulation/${sessionId}/stop`,
  )
  return data
}

export async function execInEmulation(
  projectId: string,
  sessionId: string,
  command: string,
  timeout = 30,
): Promise<EmulationExecResponse> {
  const { data } = await apiClient.post<EmulationExecResponse>(
    `/projects/${projectId}/emulation/${sessionId}/exec`,
    { command, timeout },
  )
  return data
}

export async function listSessions(
  projectId: string,
): Promise<EmulationSession[]> {
  const { data } = await apiClient.get<EmulationSession[]>(
    `/projects/${projectId}/emulation/sessions`,
  )
  return data
}

export async function getSessionStatus(
  projectId: string,
  sessionId: string,
): Promise<EmulationSession> {
  const { data } = await apiClient.get<EmulationSession>(
    `/projects/${projectId}/emulation/${sessionId}/status`,
  )
  return data
}

export async function getSessionLogs(
  projectId: string,
  sessionId: string,
): Promise<string> {
  const { data } = await apiClient.get<{ logs: string }>(
    `/projects/${projectId}/emulation/${sessionId}/logs`,
  )
  return data.logs
}

export function buildEmulationTerminalURL(
  projectId: string,
  sessionId: string,
): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return appendApiKey(
    `${proto}//${host}/api/v1/projects/${projectId}/emulation/${sessionId}/terminal`,
  )
}

// ── Emulation Presets ──

export async function listPresets(
  projectId: string,
): Promise<EmulationPreset[]> {
  const { data } = await apiClient.get<EmulationPreset[]>(
    `/projects/${projectId}/emulation/presets`,
  )
  return data
}

export async function createPreset(
  projectId: string,
  request: EmulationPresetCreate,
): Promise<EmulationPreset> {
  const { data } = await apiClient.post<EmulationPreset>(
    `/projects/${projectId}/emulation/presets`,
    request,
  )
  return data
}

export async function updatePreset(
  projectId: string,
  presetId: string,
  request: EmulationPresetUpdate,
): Promise<EmulationPreset> {
  const { data } = await apiClient.patch<EmulationPreset>(
    `/projects/${projectId}/emulation/presets/${presetId}`,
    request,
  )
  return data
}

export async function deletePreset(
  projectId: string,
  presetId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/emulation/presets/${presetId}`)
}

// ── System Emulation (FirmAE) ──

// `POST /emulation/system` does ~60 s of synchronous work (30 s
// `_wait_for_shim` + 30 s `httpx.post('/start')`) per
// `system_emulation_service.py:225+237`.  Per CLAUDE.md Rule #29
// (`frontend_ms ≥ backend_s × 1200`), 60 × 1200 = 72_000 ms minimum;
// 90_000 ms (×1.5) bakes in grace for cross-arch FirmAE bring-up on
// slower hosts.  Stop-gap pending the Rule #33 202+polling refactor
// (intake `audit-system-emulation-timeout-misalignment-2026-05-04.md`
// Path B) — once that ships the frontend can drop back to the
// default 30 s axios floor.
const SYSTEM_EMULATION_START_TIMEOUT = 90_000

export async function startSystemEmulation(
  projectId: string,
  firmwareId: string,
  request?: SystemEmulationStartRequest,
): Promise<EmulationSession> {
  const { data } = await apiClient.post<EmulationSession>(
    `/projects/${projectId}/emulation/system`,
    request ?? {},
    {
      params: { firmware_id: firmwareId },
      timeout: SYSTEM_EMULATION_START_TIMEOUT,
    },
  )
  return data
}

export async function getSystemEmulationStatus(
  projectId: string,
  sessionId: string,
): Promise<EmulationSession> {
  const { data } = await apiClient.get<EmulationSession>(
    `/projects/${projectId}/emulation/system/${sessionId}`,
  )
  return data
}

export async function getSystemEmulationServices(
  projectId: string,
  sessionId: string,
): Promise<FirmwareService[]> {
  const { data } = await apiClient.get<FirmwareService[]>(
    `/projects/${projectId}/emulation/system/${sessionId}/services`,
  )
  return data
}

export async function stopSystemEmulation(
  projectId: string,
  sessionId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/emulation/system/${sessionId}`)
}

export async function runCommandInFirmware(
  projectId: string,
  sessionId: string,
  command: string,
  timeout = 30,
): Promise<SystemCommandResponse> {
  const { data } = await apiClient.post<SystemCommandResponse>(
    `/projects/${projectId}/emulation/system/${sessionId}/command`,
    { command, timeout },
  )
  return data
}

export function buildSystemEmulationTerminalURL(
  projectId: string,
  sessionId: string,
  port: number,
): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return appendApiKey(
    `${proto}//${host}/api/v1/projects/${projectId}/emulation/system/${sessionId}/ws/${port}`,
  )
}

// ── Network Traffic Analysis ──

export interface NetworkCaptureResult {
  packet_count: number
  pcap_path: string
  size_bytes: number
  duration: number
}

export interface ProtocolBreakdown {
  protocol: string
  packet_count: number
  percentage: number
}

export interface NetworkConversation {
  src: string
  src_port: number
  dst: string
  dst_port: number
  protocol: string
  packet_count: number
  byte_count: number
}

export interface InsecureProtocolFinding {
  protocol: string
  port: number
  severity: string
  description: string
  evidence: string
  packet_count: number
}

export interface DnsQueryResult {
  domain: string
  query_type: string
  resolved_ips: string[]
}

export interface TlsInfoResult {
  server: string
  port: number
  version: string
  cipher_suites: string[]
}

export interface PcapAnalysis {
  total_packets: number
  protocol_breakdown: ProtocolBreakdown[]
  conversations: NetworkConversation[]
  insecure_findings: InsecureProtocolFinding[]
  dns_queries: DnsQueryResult[]
  tls_info: TlsInfoResult[]
}

// Network capture waits `duration` seconds of live traffic before
// responding; the default 10 s fits within the axios 30 s budget, but
// callers are free to pass higher values (60 s, 300 s) and the HTTP
// call will stall while the PCAP is still being written. PCAP
// analysis parses the full capture and can take minutes on a large
// dump. Both match the SECURITY_SCAN_TIMEOUT tier used by sibling
// files for backend-bound long-running operations.
const NETWORK_CAPTURE_TIMEOUT = 600_000

export async function captureNetworkTraffic(
  projectId: string,
  sessionId: string,
  duration = 10,
  iface = 'eth0',
): Promise<NetworkCaptureResult> {
  const { data } = await apiClient.post<NetworkCaptureResult>(
    `/projects/${projectId}/emulation/system/${sessionId}/capture`,
    { duration, interface: iface },
    { timeout: NETWORK_CAPTURE_TIMEOUT },
  )
  return data
}

export async function analyzeNetworkTraffic(
  projectId: string,
  sessionId: string,
): Promise<PcapAnalysis> {
  const { data } = await apiClient.get<PcapAnalysis>(
    `/projects/${projectId}/emulation/system/${sessionId}/network-analysis`,
    { timeout: NETWORK_CAPTURE_TIMEOUT },
  )
  return data
}

export function getPcapDownloadUrl(
  projectId: string,
  sessionId: string,
): string {
  return appendApiKey(
    apiUrl(`/api/v1/projects/${projectId}/emulation/system/${sessionId}/pcap`),
  )
}
