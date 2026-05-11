import apiClient from './client'
import type {
  RenderResult,
  Report,
  ReportFinding,
  ReportSection,
  ReportSummary,
  ReportTemplate,
} from '@/types'

export async function listReports(projectId: string): Promise<ReportSummary[]> {
  const { data } = await apiClient.get<ReportSummary[]>(
    `/projects/${projectId}/reports`,
  )
  return data
}

export async function listReportTemplates(
  projectId: string,
): Promise<ReportTemplate[]> {
  const { data } = await apiClient.get<ReportTemplate[]>(
    `/projects/${projectId}/reports/templates`,
  )
  return data
}

export async function createReport(
  projectId: string,
  body: { template_id?: string; title?: string } = {},
): Promise<Report> {
  const { data } = await apiClient.post<Report>(
    `/projects/${projectId}/reports`,
    body,
  )
  return data
}

export async function getReport(
  projectId: string,
  reportId: string,
): Promise<Report> {
  const { data } = await apiClient.get<Report>(
    `/projects/${projectId}/reports/${reportId}`,
  )
  return data
}

export async function getReportTemplate(
  projectId: string,
  reportId: string,
): Promise<ReportTemplate> {
  const { data } = await apiClient.get<ReportTemplate>(
    `/projects/${projectId}/reports/${reportId}/template`,
  )
  return data
}

export async function upsertSection(
  projectId: string,
  reportId: string,
  slug: string,
  contentMd: string,
): Promise<ReportSection> {
  const { data } = await apiClient.put<ReportSection>(
    `/projects/${projectId}/reports/${reportId}/sections/${slug}`,
    { content_md: contentMd },
  )
  return data
}

export async function setFindingInclusion(
  projectId: string,
  reportId: string,
  findingId: string,
  included: boolean,
): Promise<ReportFinding> {
  const { data } = await apiClient.put<ReportFinding>(
    `/projects/${projectId}/reports/${reportId}/findings/${findingId}`,
    { included },
  )
  return data
}

export async function renameReport(
  projectId: string,
  reportId: string,
  title: string,
): Promise<Report> {
  const { data } = await apiClient.patch<Report>(
    `/projects/${projectId}/reports/${reportId}`,
    { title },
  )
  return data
}

export async function renderReport(
  projectId: string,
  reportId: string,
  format: 'pdf' = 'pdf',
): Promise<RenderResult> {
  const { data } = await apiClient.post<RenderResult>(
    `/projects/${projectId}/reports/${reportId}/render`,
    { format },
  )
  return data
}

export async function deleteReport(
  projectId: string,
  reportId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/reports/${reportId}`)
}

export function downloadRenderUrl(
  projectId: string,
  reportId: string,
  contentHash: string,
  format: 'pdf' = 'pdf',
): string {
  // Browser navigates to the absolute API URL; Vite proxies /api in dev.
  return `/api/v1/projects/${projectId}/reports/${reportId}/renders/${contentHash}?format=${format}`
}
