import apiClient, { appendApiKey } from './client'
import { apiUrl } from './config'
import type { GhidraResearchFile, GhidraScriptContent } from '@/types'

// .gzf archives can be hundreds of MB; scripts are small but use the same
// upload path. 600s matches the UPLOAD_TIMEOUT tier used by documents.ts.
const UPLOAD_TIMEOUT = 600_000

export async function listGhidraResearchFiles(
  projectId: string,
): Promise<GhidraResearchFile[]> {
  const { data } = await apiClient.get<GhidraResearchFile[]>(
    `/projects/${projectId}/ghidra-research`,
  )
  return data
}

export async function uploadGhidraResearchFile(
  projectId: string,
  file: File,
  description?: string,
  onProgress?: (percent: number) => void,
): Promise<GhidraResearchFile> {
  const form = new FormData()
  form.append('file', file)
  if (description) {
    form.append('description', description)
  }

  const { data } = await apiClient.post<GhidraResearchFile>(
    `/projects/${projectId}/ghidra-research`,
    form,
    {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: UPLOAD_TIMEOUT,
      onUploadProgress: (e) => {
        if (e.total && onProgress) {
          onProgress(Math.round((e.loaded * 100) / e.total))
        }
      },
    },
  )
  return data
}

export async function getGhidraResearchFile(
  projectId: string,
  fileId: string,
): Promise<GhidraResearchFile> {
  const { data } = await apiClient.get<GhidraResearchFile>(
    `/projects/${projectId}/ghidra-research/${fileId}`,
  )
  return data
}

export async function readGhidraScriptContent(
  projectId: string,
  fileId: string,
): Promise<GhidraScriptContent> {
  const { data } = await apiClient.get<GhidraScriptContent>(
    `/projects/${projectId}/ghidra-research/${fileId}/content`,
  )
  return data
}

export async function updateGhidraScriptContent(
  projectId: string,
  fileId: string,
  content: string,
): Promise<GhidraResearchFile> {
  const { data } = await apiClient.put<GhidraResearchFile>(
    `/projects/${projectId}/ghidra-research/${fileId}/content`,
    { content },
  )
  return data
}

export async function updateGhidraResearchFile(
  projectId: string,
  fileId: string,
  update: { description?: string | null },
): Promise<GhidraResearchFile> {
  const { data } = await apiClient.patch<GhidraResearchFile>(
    `/projects/${projectId}/ghidra-research/${fileId}`,
    update,
  )
  return data
}

export async function deleteGhidraResearchFile(
  projectId: string,
  fileId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/ghidra-research/${fileId}`)
}

export async function triggerGhidraArchiveImport(
  projectId: string,
  fileId: string,
): Promise<GhidraResearchFile> {
  // 202 ack is sub-second; default 30s axios floor is sufficient per Rule #33
  const { data } = await apiClient.post<GhidraResearchFile>(
    `/projects/${projectId}/ghidra-research/${fileId}/import`,
  )
  return data
}

export async function getGhidraArchiveImportStatus(
  projectId: string,
  fileId: string,
): Promise<GhidraResearchFile> {
  const { data } = await apiClient.get<GhidraResearchFile>(
    `/projects/${projectId}/ghidra-research/${fileId}/import-status`,
  )
  return data
}

export function getGhidraResearchDownloadUrl(
  projectId: string,
  fileId: string,
): string {
  // Must use appendApiKey — browser anchor clicks don't carry X-API-Key header (Rule #34b)
  return appendApiKey(
    apiUrl(`/api/v1/projects/${projectId}/ghidra-research/${fileId}/download`),
  )
}
