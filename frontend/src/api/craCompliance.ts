import apiClient from './client'
import { SECURITY_SCAN_TIMEOUT } from './timeouts'

export interface CraRequirementResult {
  id: string
  assessment_id: string
  requirement_id: string
  requirement_title: string
  annex_part: number
  status: string
  auto_populated: boolean
  evidence_summary: string | null
  finding_ids: string[]
  tool_sources: string[]
  manual_notes: string | null
  manual_evidence: string | null
  related_cwes: string[]
  related_cves: string[]
  assessed_at: string | null
  updated_at: string
}

export interface CraAssessment {
  id: string
  project_id: string
  firmware_id: string | null
  assessor_name: string | null
  product_name: string | null
  product_version: string | null
  overall_status: string
  auto_pass_count: number
  auto_fail_count: number
  manual_count: number
  not_tested_count: number
  created_at: string
  updated_at: string
  requirement_results: CraRequirementResult[]
}

export type CraAssessmentSummary = Omit<CraAssessment, 'requirement_results'>

export async function createCraAssessment(projectId: string, body?: {
  product_name?: string; product_version?: string; assessor_name?: string; firmware_id?: string
}): Promise<CraAssessment> {
  const { data } = await apiClient.post<CraAssessment>(`/projects/${projectId}/cra/assessments`, body || {})
  return data
}

export async function listCraAssessments(projectId: string): Promise<CraAssessmentSummary[]> {
  const { data } = await apiClient.get<CraAssessmentSummary[]>(`/projects/${projectId}/cra/assessments`)
  return data
}

export async function getCraAssessment(projectId: string, assessmentId: string): Promise<CraAssessment> {
  const { data } = await apiClient.get<CraAssessment>(`/projects/${projectId}/cra/assessments/${assessmentId}`)
  return data
}

export async function autoPopulateCra(projectId: string, assessmentId: string): Promise<CraAssessment> {
  const { data } = await apiClient.post<CraAssessment>(
    `/projects/${projectId}/cra/assessments/${assessmentId}/auto-populate`,
    null,
    { timeout: SECURITY_SCAN_TIMEOUT },
  )
  return data
}

export async function updateCraRequirement(
  projectId: string, assessmentId: string, requirementId: string,
  body: { status?: string; manual_notes?: string; manual_evidence?: string }
): Promise<CraRequirementResult> {
  const { data } = await apiClient.patch<CraRequirementResult>(
    `/projects/${projectId}/cra/assessments/${assessmentId}/requirements/${requirementId}`, body
  )
  return data
}

export async function exportCraChecklist(projectId: string, assessmentId: string): Promise<Record<string, unknown>> {
  const { data } = await apiClient.get<Record<string, unknown>>(`/projects/${projectId}/cra/assessments/${assessmentId}/export`)
  return data
}

export async function exportArticle14(projectId: string, assessmentId: string, cveId: string): Promise<Record<string, unknown>> {
  const { data } = await apiClient.get<Record<string, unknown>>(`/projects/${projectId}/cra/assessments/${assessmentId}/article14/${cveId}`)
  return data
}
