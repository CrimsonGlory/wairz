import { create } from 'zustand'
import type { FirmwareDetail, Project, ProjectDetail } from '@/types'
import { listProjects, getProject, createProject, deleteProject } from '@/api/projects'
import { uploadFirmware as apiFirmwareUpload, unpackFirmware as apiUnpackFirmware, listFirmware } from '@/api/firmware'
import { extractErrorMessage } from '@/utils/error'
import { resolveActiveFirmwareId } from '@/utils/firmware'

interface ProjectState {
  projects: Project[]
  currentProject: ProjectDetail | null
  /** Canonical selected firmware version for the open project. */
  selectedFirmwareId: string | null
  /**
   * Alias of selectedFirmwareId used by the version-picker surfaces that
   * landed from upstream (`FirmwareVersionPicker`, Sidebar kind gate, etc.).
   * Kept in lockstep so both naming conventions work after the merge.
   */
  activeFirmwareId: string | null
  loading: boolean
  creating: boolean
  uploading: boolean
  unpacking: boolean
  uploadProgress: number
  error: string | null
  // Shared firmware-list cache — accessed via useFirmwareList().  The
  // cache is keyed by projectId so a project switch invalidates
  // implicitly (consumers see an empty list until the new project's
  // list loads).  Upload / delete / rename paths call
  // invalidateFirmwareList() to force a refetch.
  firmwareList: FirmwareDetail[]
  firmwareListProjectId: string | null
  firmwareListLoading: boolean
  /**
   * Project id this store is currently hydrated for. `fetchProject` sets it
   * synchronously on entry and checks after every `await` before committing,
   * so a late `getProject(A)` response cannot overwrite a newer
   * `getProject(B)` during rapid /projects/A ↔ /projects/B navigation.
   * Cleared by `clearCurrentProject()` and by `ProjectRouteGuard` on route change.
   */
  currentProjectId: string | null
}

interface ProjectActions {
  fetchProjects: () => Promise<void>
  fetchProject: (id: string) => Promise<void>
  createProject: (name: string, description?: string) => Promise<ProjectDetail>
  removeProject: (id: string) => Promise<void>
  uploadFirmware: (projectId: string, file: File, versionLabel?: string) => Promise<void>
  unpackFirmware: (projectId: string, firmwareId: string) => Promise<void>
  setSelectedFirmware: (firmwareId: string | null) => void
  /** Alias of setSelectedFirmware for upstream version-picker consumers. */
  setActiveFirmware: (firmwareId: string | null) => void
  clearError: () => void
  clearCurrentProject: () => void
  loadFirmwareList: (projectId: string) => Promise<void>
  invalidateFirmwareList: () => void
}

function withActiveFirmware(
  selectedFirmwareId: string | null,
): Pick<ProjectState, 'selectedFirmwareId' | 'activeFirmwareId'> {
  return { selectedFirmwareId, activeFirmwareId: selectedFirmwareId }
}

export const useProjectStore = create<ProjectState & ProjectActions>((set, get) => ({
  projects: [],
  currentProject: null,
  selectedFirmwareId: null,
  activeFirmwareId: null,
  loading: false,
  creating: false,
  uploading: false,
  unpacking: false,
  uploadProgress: 0,
  error: null,
  firmwareList: [],
  firmwareListProjectId: null,
  firmwareListLoading: false,
  currentProjectId: null,

  fetchProjects: async () => {
    set({ loading: true, error: null })
    try {
      const projects = await listProjects()
      set({ projects, loading: false })
    } catch (e) {
      set({ loading: false, error: extractError(e) })
    }
  },

  fetchProject: async (id) => {
    // Only show loading spinner on initial fetch, not on polling refreshes
    const isRefresh = get().currentProject?.id === id
    if (!isRefresh) set({ loading: true, error: null, currentProjectId: id })
    else set({ currentProjectId: id })
    try {
      const project = await getProject(id)
      // Bail if user switched projects while we were fetching.
      if (get().currentProjectId !== id) return
      const prevActive = isRefresh ? get().selectedFirmwareId : null
      const selected = resolveActiveFirmwareId(prevActive, project.firmware)
      set({
        currentProject: project,
        loading: false,
        ...withActiveFirmware(selected),
      })
    } catch (e) {
      if (get().currentProjectId !== id) return
      if (!isRefresh) set({ loading: false, error: extractError(e) })
    }
  },

  createProject: async (name, description) => {
    set({ creating: true, error: null })
    try {
      const project = await createProject({ name, description })
      set((s) => ({ projects: [projectFromDetail(project), ...s.projects], creating: false }))
      return project
    } catch (e) {
      set({ creating: false, error: extractError(e) })
      throw e
    }
  },

  removeProject: async (id) => {
    try {
      await deleteProject(id)
      set((s) => {
        const clearing = s.currentProject?.id === id
        return {
          projects: s.projects.filter((p) => p.id !== id),
          currentProject: clearing ? null : s.currentProject,
          ...(clearing ? withActiveFirmware(null) : {}),
          // Drop cache if it belonged to the deleted project.
          firmwareList: s.firmwareListProjectId === id ? [] : s.firmwareList,
          firmwareListProjectId: s.firmwareListProjectId === id ? null : s.firmwareListProjectId,
        }
      })
    } catch (e) {
      set({ error: extractError(e) })
      throw e
    }
  },

  uploadFirmware: async (projectId, file, versionLabel) => {
    set({ uploading: true, uploadProgress: 0, error: null })
    try {
      await apiFirmwareUpload(projectId, file, versionLabel, (pct) => set({ uploadProgress: pct }))
      // Refresh project to get firmware info
      const project = await getProject(projectId)
      const selected = resolveActiveFirmwareId(get().selectedFirmwareId, project.firmware)
      set({
        uploading: false,
        uploadProgress: 100,
        currentProject: project,
        ...withActiveFirmware(selected),
      })
      // Sync into projects list
      syncProjectInList(set, get, project)
      // Invalidate firmware list cache — new upload must appear on
      // pages that already have the old list.
      set({ firmwareList: [], firmwareListProjectId: null })
    } catch (e) {
      set({ uploading: false, error: extractError(e) })
      throw e
    }
  },

  unpackFirmware: async (projectId, firmwareId) => {
    set({ unpacking: true, error: null })
    try {
      await apiUnpackFirmware(projectId, firmwareId)
      // Endpoint returns 202 immediately; refresh project to show "unpacking" status
      const project = await getProject(projectId)
      const selected = resolveActiveFirmwareId(get().selectedFirmwareId, project.firmware)
      set({
        unpacking: false,
        currentProject: project,
        ...withActiveFirmware(selected),
      })
      syncProjectInList(set, get, project)
    } catch (e) {
      set({ unpacking: false, error: extractError(e) })
      throw e
    }
  },

  setSelectedFirmware: (firmwareId) => set(withActiveFirmware(firmwareId)),
  setActiveFirmware: (firmwareId) => set(withActiveFirmware(firmwareId)),
  clearError: () => set({ error: null }),
  clearCurrentProject: () =>
    set({ currentProject: null, currentProjectId: null, ...withActiveFirmware(null) }),

  loadFirmwareList: async (projectId) => {
    // Cache hit — same project, list already populated.  Consumers
    // that need fresh data call invalidateFirmwareList() first.
    const state = get()
    if (
      state.firmwareListProjectId === projectId
      && state.firmwareList.length > 0
    ) {
      return
    }
    set({ firmwareListLoading: true })
    try {
      const list = await listFirmware(projectId)
      set({
        firmwareList: list,
        firmwareListProjectId: projectId,
        firmwareListLoading: false,
      })
    } catch {
      // Keep previous cached list on error; just stop the spinner.
      set({ firmwareListLoading: false })
    }
  },

  invalidateFirmwareList: () => {
    set({ firmwareList: [], firmwareListProjectId: null })
  },
}))

function projectFromDetail(d: ProjectDetail): Project {
  const { firmware: _, ...project } = d
  return project
}

function syncProjectInList(
  set: (fn: (s: ProjectState) => Partial<ProjectState>) => void,
  get: () => ProjectState,
  detail: ProjectDetail,
) {
  const base = projectFromDetail(detail)
  const existing = get().projects.find((p) => p.id === base.id)
  if (existing) {
    set((s) => ({ projects: s.projects.map((p) => (p.id === base.id ? base : p)) }))
  }
}

// Use the shared extractErrorMessage utility, aliased for backward compatibility
const extractError = (e: unknown) => extractErrorMessage(e, 'An unexpected error occurred')
