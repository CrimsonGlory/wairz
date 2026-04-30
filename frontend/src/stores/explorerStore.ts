import { create } from 'zustand'
import { listDirectory, readFile, getFileInfo } from '@/api/files'
import { useProjectStore } from '@/stores/projectStore'
import { listDocuments, readDocumentContent, createNote as apiCreateNote, updateDocumentContent } from '@/api/documents'
import type { FileContent, FileInfo, ProjectDocument } from '@/types'
import { extractErrorMessage } from '@/utils/error'

/** MIME types that indicate text content (even though some start with application/) */
const TEXT_MIME_PREFIXES = ['text/', 'application/json', 'application/xml', 'application/javascript']

function isBinaryMime(mime: string): boolean {
  return !TEXT_MIME_PREFIXES.some((prefix) => mime.startsWith(prefix))
}

export interface TreeNode {
  id: string
  name: string
  fileType: 'file' | 'directory' | 'symlink' | 'other'
  size: number
  permissions: string
  symlinkTarget: string | null
  children?: TreeNode[]
}

const PLACEHOLDER_ID = '__placeholder__'

function makePlaceholder(parentId: string): TreeNode {
  return {
    id: `${parentId}/${PLACEHOLDER_ID}`,
    name: 'Loading…',
    fileType: 'other',
    size: 0,
    permissions: '',
    symlinkTarget: null,
  }
}

export function isPlaceholder(node: TreeNode): boolean {
  return node.id.endsWith(`/${PLACEHOLDER_ID}`)
}

function updateNodeInTree(
  nodes: TreeNode[],
  targetId: string,
  updater: (node: TreeNode) => TreeNode,
): TreeNode[] {
  return nodes.map((node) => {
    if (node.id === targetId) return updater(node)
    if (node.children) {
      const updated = updateNodeInTree(node.children, targetId, updater)
      if (updated !== node.children) return { ...node, children: updated }
    }
    return node
  })
}

interface ExplorerState {
  treeData: TreeNode[]
  selectedPath: string | null
  selectedNode: TreeNode | null
  fileContent: FileContent | null
  fileInfo: FileInfo | null
  contentLoading: boolean
  infoLoading: boolean
  treeError: string | null
  /** Set after navigateToPath completes so FileTree can expand and scroll */
  pendingNavPath: string | null
  /** Line number to scroll to after file loads (from ?line= param) */
  pendingLine: number | null
  documents: ProjectDocument[]
  documentsLoading: boolean
  selectedDocumentId: string | null
  documentDirty: boolean
  documentContent: string | null
  /**
   * Project id the store is hydrated for. Async actions capture their
   * projectId at entry, set this, and check `get().currentProjectId === projectId`
   * after every `await` before committing. Prevents stale-project-data races
   * when a user navigates /projects/A → /projects/B while an A-scoped
   * listDirectory / readFile is still in flight. Cleared by `reset()` and
   * by `ProjectRouteGuard` on route change.
   */
  currentProjectId: string | null
}

interface ExplorerActions {
  loadRootDirectory: (projectId: string) => Promise<void>
  loadDirectory: (projectId: string, path: string) => Promise<void>
  selectFile: (projectId: string, node: TreeNode) => Promise<void>
  navigateToPath: (projectId: string, targetPath: string) => Promise<void>
  clearPendingNavPath: () => void
  setPendingLine: (line: number | null) => void
  clearPendingLine: () => void
  loadDocuments: (projectId: string) => Promise<void>
  selectDocument: (projectId: string, document: ProjectDocument) => Promise<void>
  setDocumentContent: (content: string) => void
  saveDocument: (projectId: string) => Promise<void>
  createNote: (projectId: string, title: string) => Promise<void>
  reset: () => void
}

const initialState: ExplorerState = {
  treeData: [],
  selectedPath: null,
  selectedNode: null,
  fileContent: null,
  fileInfo: null,
  contentLoading: false,
  infoLoading: false,
  treeError: null,
  pendingNavPath: null,
  pendingLine: null,
  documents: [],
  documentsLoading: false,
  selectedDocumentId: null,
  documentDirty: false,
  documentContent: null,
  currentProjectId: null,
}

export const useExplorerStore = create<ExplorerState & ExplorerActions>(
  (set, get) => ({
    ...initialState,

    loadRootDirectory: async (projectId) => {
      set({ treeError: null, currentProjectId: projectId })
      try {
        const fwId = useProjectStore.getState().selectedFirmwareId || undefined
        const listing = await listDirectory(projectId, '', fwId)
        if (get().currentProjectId !== projectId) return
        const nodes = listing.entries.map((entry) => {
          const id = `/${entry.name}`
          const node: TreeNode = {
            id,
            name: entry.name,
            fileType: entry.type,
            size: entry.size,
            permissions: entry.permissions,
            symlinkTarget: entry.symlink_target,
          }
          if (entry.type === 'directory') {
            node.children = [makePlaceholder(id)]
          }
          return node
        })
        // Sort: directories first, then alphabetical
        nodes.sort((a, b) => {
          if (a.fileType === 'directory' && b.fileType !== 'directory') return -1
          if (a.fileType !== 'directory' && b.fileType === 'directory') return 1
          return a.name.localeCompare(b.name)
        })
        if (get().currentProjectId === projectId) {
          set({ treeData: nodes })
        }
      } catch (e) {
        if (get().currentProjectId === projectId) {
          set({
            treeError: extractErrorMessage(e, 'Failed to load directory'),
          })
        }
      }
    },

    loadDirectory: async (projectId, path) => {
      if (get().currentProjectId === null) set({ currentProjectId: projectId })
      try {
        const fwId = useProjectStore.getState().selectedFirmwareId || undefined
        const listing = await listDirectory(projectId, path, fwId)
        if (get().currentProjectId !== projectId) return
        const children = listing.entries.map((entry) => {
          const id = `${path}/${entry.name}`
          const node: TreeNode = {
            id,
            name: entry.name,
            fileType: entry.type,
            size: entry.size,
            permissions: entry.permissions,
            symlinkTarget: entry.symlink_target,
          }
          if (entry.type === 'directory') {
            node.children = [makePlaceholder(id)]
          }
          return node
        })
        children.sort((a, b) => {
          if (a.fileType === 'directory' && b.fileType !== 'directory') return -1
          if (a.fileType !== 'directory' && b.fileType === 'directory') return 1
          return a.name.localeCompare(b.name)
        })
        if (get().currentProjectId !== projectId) return
        set((state) => ({
          treeData: updateNodeInTree(state.treeData, path, (node) => ({
            ...node,
            children,
          })),
        }))
      } catch {
        if (get().currentProjectId !== projectId) return
        // On error, remove placeholder so user can retry by collapsing/expanding
        set((state) => ({
          treeData: updateNodeInTree(state.treeData, path, (node) => ({
            ...node,
            children: [],
          })),
        }))
      }
    },

    selectFile: async (projectId, node) => {
      if (get().currentProjectId === null) set({ currentProjectId: projectId })
      set({
        selectedPath: node.id,
        selectedNode: node,
        fileContent: null,
        fileInfo: null,
        contentLoading: true,
        infoLoading: true,
        selectedDocumentId: null,
        documentDirty: false,
        documentContent: null,
      })

      const stillCurrent = () =>
        get().currentProjectId === projectId && get().selectedPath === node.id

      // Fetch file info first to determine if binary
      try {
        const fwId = useProjectStore.getState().selectedFirmwareId || undefined
        const info = await getFileInfo(projectId, node.id, fwId)
        if (!stillCurrent()) return
        set({ fileInfo: info, infoLoading: false })

        // If binary, skip content fetch — HexViewer manages its own data
        if (isBinaryMime(info.mime_type)) {
          set({ contentLoading: false })
          return
        }
      } catch {
        if (!stillCurrent()) return
        set({ infoLoading: false })
      }

      // Fetch text content
      try {
        const fwId = useProjectStore.getState().selectedFirmwareId || undefined
        const content = await readFile(projectId, node.id, undefined, undefined, undefined, fwId)
        if (stillCurrent()) {
          set({ fileContent: content, contentLoading: false })
        }
      } catch {
        if (stillCurrent()) {
          set({ contentLoading: false })
        }
      }
    },

    navigateToPath: async (projectId, targetPath) => {
      // Expand all parent directories and select the target file.
      // e.g. "/usr/bin/httpd" -> load "/", expand "/usr", expand "/usr/bin", select "httpd"
      const segments = targetPath.split('/').filter(Boolean)
      if (segments.length === 0) return

      // Ensure root is loaded
      if (get().treeData.length === 0) {
        await get().loadRootDirectory(projectId)
      }

      // Helper: find a node by path in the tree
      const findNodeByPath = (nodes: TreeNode[], path: string): TreeNode | null => {
        for (const n of nodes) {
          if (n.id === path) return n
          if (n.children) {
            const found = findNodeByPath(n.children, path)
            if (found) return found
          }
        }
        return null
      }

      // Helper: expand all parent directories for a given path
      const expandParents = async (segs: string[]) => {
        let cur = ''
        for (let i = 0; i < segs.length - 1; i++) {
          cur += '/' + segs[i]
          const dirNode = findNodeByPath(get().treeData, cur)
          if (dirNode?.children?.length === 1 && isPlaceholder(dirNode.children[0])) {
            await get().loadDirectory(projectId, cur)
          }
        }
      }

      // Expand each parent directory sequentially
      await expandParents(segments)

      let targetNode = findNodeByPath(get().treeData, targetPath)

      // If not found, the path may be rootfs-relative (e.g. /etc/main.conf from a
      // security finding) while the tree uses a virtual root prefix (e.g. /rootfs/).
      // Check if any root-level directory contains the first segment as a child.
      if (!targetNode) {
        const firstSeg = segments[0]
        for (const rootNode of get().treeData) {
          if (rootNode.fileType !== 'directory') continue
          const altPath = `${rootNode.id}${targetPath}`
          // Expand the root node if needed
          if (rootNode.children?.length === 1 && isPlaceholder(rootNode.children[0])) {
            await get().loadDirectory(projectId, rootNode.id)
          }
          // Check if this root contains our first segment
          const childMatch = findNodeByPath(get().treeData, `${rootNode.id}/${firstSeg}`)
          if (childMatch) {
            await expandParents(altPath.split('/').filter(Boolean))
            targetNode = findNodeByPath(get().treeData, altPath)
            if (targetNode) {
              targetPath = altPath
              break
            }
          }
        }
      }

      if (targetNode && targetNode.fileType !== 'directory') {
        await get().selectFile(projectId, targetNode)
      }

      // Signal the FileTree to visually expand parents and scroll to this node
      set({ pendingNavPath: targetPath })
    },

    clearPendingNavPath: () => set({ pendingNavPath: null }),
    setPendingLine: (line) => set({ pendingLine: line }),
    clearPendingLine: () => set({ pendingLine: null }),

    loadDocuments: async (projectId) => {
      if (get().currentProjectId === null) set({ currentProjectId: projectId })
      set({ documentsLoading: true })
      try {
        const docs = await listDocuments(projectId)
        if (get().currentProjectId === projectId) {
          set({ documents: docs, documentsLoading: false })
        }
      } catch {
        if (get().currentProjectId === projectId) {
          set({ documentsLoading: false })
        }
      }
    },

    selectDocument: async (projectId, document) => {
      if (get().currentProjectId === null) set({ currentProjectId: projectId })
      set({
        selectedDocumentId: document.id,
        selectedPath: null,
        selectedNode: null,
        fileContent: null,
        fileInfo: null,
        contentLoading: true,
        infoLoading: false,
        documentDirty: false,
        documentContent: null,
      })

      const stillCurrent = () =>
        get().currentProjectId === projectId && get().selectedDocumentId === document.id

      try {
        const result = await readDocumentContent(projectId, document.id)
        if (stillCurrent()) {
          set({
            fileContent: {
              content: result.content,
              is_binary: false,
              size: result.size,
              truncated: false,
            },
            contentLoading: false,
          })
        }
      } catch {
        if (stillCurrent()) {
          set({ contentLoading: false })
        }
      }
    },

    setDocumentContent: (content) => {
      set({ documentContent: content, documentDirty: true })
    },

    saveDocument: async (projectId) => {
      if (get().currentProjectId === null) set({ currentProjectId: projectId })
      const { selectedDocumentId, documentContent } = get()
      if (!selectedDocumentId || documentContent === null) return
      try {
        const updated = await updateDocumentContent(projectId, selectedDocumentId, documentContent)
        if (
          get().currentProjectId !== projectId
          || get().selectedDocumentId !== selectedDocumentId
        ) return
        set({
          documentDirty: false,
          fileContent: {
            content: documentContent,
            is_binary: false,
            size: updated.file_size,
            truncated: false,
          },
          // Update the document in the documents list with new metadata
          documents: get().documents.map((d) =>
            d.id === selectedDocumentId ? { ...d, file_size: updated.file_size, sha256: updated.sha256 } : d,
          ),
        })
      } catch {
        // Leave dirty state so user can retry
      }
    },

    createNote: async (projectId, title) => {
      if (get().currentProjectId === null) set({ currentProjectId: projectId })
      try {
        const doc = await apiCreateNote(projectId, title)
        if (get().currentProjectId !== projectId) return
        // Reload documents list then select the new note
        const docs = await listDocuments(projectId)
        if (get().currentProjectId !== projectId) return
        set({ documents: docs })
        // Select the new document
        get().selectDocument(projectId, doc)
      } catch {
        // Silently fail — could add error state later
      }
    },

    reset: () => set(initialState),
  }),
)
