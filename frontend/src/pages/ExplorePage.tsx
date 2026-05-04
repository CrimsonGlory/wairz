import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { FolderTree, PanelLeftClose, PanelLeftOpen, TerminalSquare, Cpu } from 'lucide-react'
import { useExplorerStore } from '@/stores/explorerStore'
import { useProjectStore } from '@/stores/projectStore'
import { useFirmwareList } from '@/hooks/useFirmwareList'
import FileTree from '@/components/explorer/FileTree'
import FileViewer from '@/components/explorer/FileViewer'
import UefiModules from '@/components/explorer/UefiModules'
import TerminalPanel from '@/components/explorer/TerminalPanel'
import FirmwareSelector from '@/components/projects/FirmwareSelector'

export default function ExplorePage() {
  const { projectId } = useParams<{ projectId: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const resetExplorer = useExplorerStore((s) => s.reset)
  const loadRootDirectory = useExplorerStore((s) => s.loadRootDirectory)
  const loadDocuments = useExplorerStore((s) => s.loadDocuments)
  const navigateToPath = useExplorerStore((s) => s.navigateToPath)
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const { firmwareList } = useFirmwareList(projectId)
  const [treeOpen, setTreeOpen] = useState(true)
  const [viewMode, setViewMode] = useState<'files' | 'uefi'>('files')
  const [terminalOpen, setTerminalOpen] = useState(false)
  const [terminalHeight, setTerminalHeight] = useState(250)
  const draggingRef = useRef(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (projectId) {
      loadDocuments(projectId)
    }
    return () => {
      resetExplorer()
    }
  }, [projectId, loadDocuments, resetExplorer])

  // Reload file tree when firmware version changes
  useEffect(() => {
    if (projectId && selectedFirmwareId) {
      loadRootDirectory(projectId)
    }
  }, [projectId, selectedFirmwareId, loadRootDirectory])

  // Handle ?path= and ?line= query parameters: expand tree, select file, scroll to line
  const setPendingLine = useExplorerStore((s) => s.setPendingLine)
  useEffect(() => {
    const pathParam = searchParams.get('path')
    const lineParam = searchParams.get('line')
    if (!projectId) return
    if (pathParam) {
      navigateToPath(projectId, pathParam)
      if (lineParam) {
        setPendingLine(parseInt(lineParam, 10) || null)
      }
      // Clear query params so they don't re-trigger on re-renders
      setSearchParams({}, { replace: true })
    }
  }, [projectId, searchParams, setSearchParams, navigateToPath, setPendingLine])

  // Vertical resize drag handler for terminal panel
  const handleDragStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    draggingRef.current = true

    const startY = e.clientY
    const startHeight = terminalHeight

    const onMouseMove = (moveEvent: MouseEvent) => {
      if (!draggingRef.current) return
      const delta = startY - moveEvent.clientY
      const newHeight = Math.min(600, Math.max(100, startHeight + delta))
      setTerminalHeight(newHeight)
    }

    const onMouseUp = () => {
      draggingRef.current = false
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }

    document.body.style.cursor = 'row-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [terminalHeight])

  return (
    <div className="-m-6 flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Left panel: file tree */}
      {treeOpen && (
        <div className="flex w-72 shrink-0 flex-col overflow-hidden border-r border-border">
          <div className="flex flex-col border-b border-border">
            <div className="flex min-w-0 items-center gap-2 px-4 py-2">
              <FolderTree className="h-4 w-4 shrink-0 text-muted-foreground" />
              <span className="shrink-0 text-sm font-medium">Files</span>
              <button
                onClick={() => setTreeOpen(false)}
                className="ml-auto shrink-0 rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                title="Collapse panel"
              >
                <PanelLeftClose className="h-4 w-4" />
              </button>
            </div>
            {projectId && firmwareList.filter((fw) => fw.extracted_path).length > 1 && (
              <div className="min-w-0 px-4 pb-2">
                <FirmwareSelector projectId={projectId} firmwareList={firmwareList} className="w-full" />
              </div>
            )}
          </div>
          <FileTree />
        </div>
      )}

      {/* Center panel: file viewer + terminal */}
      <div ref={containerRef} className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {/* Tabs row — docked toolbar with show-tree (when collapsed), view tabs, terminal toggle. No absolute overlays over data. */}
        <div className="flex shrink-0 items-center gap-1 border-b border-border px-2">
          {!treeOpen && (
            <button
              onClick={() => setTreeOpen(true)}
              className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              title="Show file tree"
            >
              <PanelLeftOpen className="h-4 w-4" />
            </button>
          )}
          <button
            onClick={() => setViewMode('files')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === 'files'
                ? 'border-b-2 border-primary text-foreground'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <FolderTree className="h-3.5 w-3.5" />
            Files
          </button>
          <button
            onClick={() => setViewMode('uefi')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === 'uefi'
                ? 'border-b-2 border-primary text-foreground'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            <Cpu className="h-3.5 w-3.5" />
            UEFI Modules
          </button>
          <button
            onClick={() => setTerminalOpen(!terminalOpen)}
            className={`ml-auto flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              terminalOpen
                ? 'border-b-2 border-primary text-foreground'
                : 'text-muted-foreground hover:text-foreground'
            }`}
            title={terminalOpen ? 'Close terminal' : 'Open terminal'}
          >
            <TerminalSquare className="h-3.5 w-3.5" />
            Terminal
          </button>
        </div>

        {/* Content area (takes remaining space) */}
        <div className="min-h-0 min-w-0 flex-1 overflow-hidden">
          {viewMode === 'files' ? (
            <FileViewer />
          ) : projectId ? (
            <UefiModules projectId={projectId} />
          ) : null}
        </div>

        {/* Drag handle + terminal panel — layout-participating, NOT an overlay over file content. */}
        {terminalOpen && (
          <>
            <div
              onMouseDown={handleDragStart}
              className="h-1 shrink-0 cursor-row-resize border-t border-border bg-background hover:bg-accent"
            />
            <div style={{ height: terminalHeight }} className="shrink-0 overflow-hidden">
              <TerminalPanel
                projectId={projectId}
                isOpen={terminalOpen}
                onClose={() => setTerminalOpen(false)}
              />
            </div>
          </>
        )}
      </div>
    </div>
  )
}
