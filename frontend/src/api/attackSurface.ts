import apiClient from './client'
import { SECURITY_SCAN_TIMEOUT } from './timeouts'

// Backend ``list_attack_surface_entries`` now returns a Page envelope.
// ``getAttackSurface()`` still returns ``AttackSurfaceEntry[]`` for
// backward-compat; ``getAttackSurfacePage()`` exposes the full envelope.
interface PageEnvelope<T> {
  items: T[]
  total: number
  offset: number
  limit: number
}

function unwrap<T>(data: PageEnvelope<T> | T[]): T[] {
  return Array.isArray(data) ? data : (data?.items ?? [])
}

export interface AttackSurfaceEntry {
  id: string
  project_id: string
  firmware_id: string
  binary_path: string
  binary_name: string
  architecture: string | null
  file_size: number | null
  attack_surface_score: number
  score_breakdown: Record<string, unknown>
  is_setuid: boolean
  is_network_listener: boolean
  is_cgi_handler: boolean
  has_dangerous_imports: boolean
  dangerous_imports: string[]
  input_categories: string[]
  auto_findings_generated: boolean
  created_at: string
}

export interface AttackSurfaceSummary {
  total_binaries: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  top_categories: string[]
}

export interface AttackSurfaceScanResponse {
  entries: AttackSurfaceEntry[]
  summary: AttackSurfaceSummary
  cached: boolean
}

export async function getAttackSurface(
  projectId: string,
  params?: { min_score?: number; firmware_id?: string; limit?: number; offset?: number },
): Promise<AttackSurfaceEntry[]> {
  const { data } = await apiClient.get<PageEnvelope<AttackSurfaceEntry> | AttackSurfaceEntry[]>(
    `/projects/${projectId}/attack-surface`,
    { params },
  )
  return unwrap(data)
}

export async function getAttackSurfacePage(
  projectId: string,
  params?: { min_score?: number; firmware_id?: string; limit?: number; offset?: number },
): Promise<PageEnvelope<AttackSurfaceEntry>> {
  const { data } = await apiClient.get<PageEnvelope<AttackSurfaceEntry>>(
    `/projects/${projectId}/attack-surface`,
    { params },
  )
  return data
}

// Fetch ALL attack-surface entries by walking the Page envelope. The backend
// caps a single request at limit<=1000; without this the tab showed only the
// first 200 (server default) of up to ~1,600 entries per firmware.
const ATTACK_SURFACE_PAGE_LIMIT = 1000

export async function getAllAttackSurface(
  projectId: string,
  params?: { min_score?: number; firmware_id?: string },
): Promise<AttackSurfaceEntry[]> {
  const all: AttackSurfaceEntry[] = []
  let offset = 0
  for (let i = 0; i < 50; i++) {
    const page = await getAttackSurfacePage(projectId, {
      ...params,
      limit: ATTACK_SURFACE_PAGE_LIMIT,
      offset,
    })
    all.push(...page.items)
    if (all.length >= page.total || page.items.length < ATTACK_SURFACE_PAGE_LIMIT) break
    offset += ATTACK_SURFACE_PAGE_LIMIT
  }
  return all
}

export async function triggerAttackSurfaceScan(
  projectId: string,
  forceRescan = false,
): Promise<AttackSurfaceScanResponse> {
  const { data } = await apiClient.post<AttackSurfaceScanResponse>(
    `/projects/${projectId}/attack-surface/scan`,
    { force_rescan: forceRescan },
    { timeout: SECURITY_SCAN_TIMEOUT },
  )
  return data
}

export async function getAttackSurfaceEntry(
  projectId: string,
  entryId: string,
): Promise<AttackSurfaceEntry> {
  const { data } = await apiClient.get<AttackSurfaceEntry>(
    `/projects/${projectId}/attack-surface/${entryId}`,
  )
  return data
}
