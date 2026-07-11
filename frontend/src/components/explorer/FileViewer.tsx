import { useRef } from 'react'
import { Loader2, FileSearch, Save, Download } from 'lucide-react'
import Editor from '@monaco-editor/react'
import { useParams } from 'react-router-dom'
import { useExplorerStore } from '@/stores/explorerStore'
import { useProjectStore } from '@/stores/projectStore'
import { formatFileSize } from '@/utils/format'
import { getFileDownloadUrl } from '@/api/files'
import { getDocumentDownloadUrl } from '@/api/documents'
import BinaryTabs from './BinaryTabs'
import TextTabs from './TextTabs'

/** Map document filename extension to Monaco language */
function getDocumentLanguage(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase()
  switch (ext) {
    case 'md':
      return 'markdown'
    case 'json':
      return 'json'
    case 'xml':
    case 'html':
      return 'html'
    case 'csv':
    case 'txt':
    default:
      return 'plaintext'
  }
}

const EDITABLE_EXTENSIONS = new Set(['.md', '.txt', '.json', '.xml', '.html', '.csv'])

function isDocumentEditable(filename: string): boolean {
  const dot = filename.lastIndexOf('.')
  if (dot === -1) return false
  return EDITABLE_EXTENSIONS.has(filename.slice(dot).toLowerCase())
}

export default function FileViewer() {
  const { projectId } = useParams<{ projectId: string }>()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)
  const {
    selectedNode, selectedPath, selectedDocumentId, documents,
    fileContent, fileInfo, contentLoading, infoLoading,
    documentDirty, documentContent, setDocumentContent, saveDocument,
  } = useExplorerStore()

  const saveRef = useRef<(() => void) | null>(null)

  // Document view mode
  if (selectedDocumentId) {
    const doc = documents.find((d) => d.id === selectedDocumentId)
    const filename = doc?.original_filename ?? 'Document'
    const editable = isDocumentEditable(filename)
    const displayContent = documentContent !== null ? documentContent : (fileContent?.content ?? '')

    // Keep saveRef current for Ctrl+S keybinding
    saveRef.current = () => {
      if (projectId && documentDirty) saveDocument(projectId)
    }

    return (
      <div className="flex h-full flex-col">
        {/* Document header bar */}
        <div className="flex items-center gap-3 border-b border-border px-4 py-2">
          <span className="min-w-0 truncate font-mono text-sm">{filename}</span>
          {documentDirty && (
            <span className="h-2 w-2 shrink-0 rounded-full bg-blue-400" title="Unsaved changes" />
          )}
          <div className="ml-auto flex shrink-0 items-center gap-3 text-xs text-muted-foreground">
            {doc && (
              <>
                <span>{doc.content_type}</span>
                <span>{formatFileSize(doc.file_size)}</span>
              </>
            )}
            {projectId && selectedDocumentId && (
              <a
                href={getDocumentDownloadUrl(projectId, selectedDocumentId)}
                download
                className="flex items-center gap-1 rounded px-2 py-1 text-xs hover:bg-accent hover:text-accent-foreground"
                title="Download document"
              >
                <Download className="h-3.5 w-3.5" />
                Download
              </a>
            )}
            {editable && (
              <button
                onClick={() => projectId && saveDocument(projectId)}
                disabled={!documentDirty}
                className="flex items-center gap-1 rounded px-2 py-1 text-xs hover:bg-accent hover:text-accent-foreground disabled:opacity-40"
                title="Save (Ctrl+S)"
              >
                <Save className="h-3.5 w-3.5" />
                Save
              </button>
            )}
          </div>
        </div>

        {/* Document content */}
        {contentLoading ? (
          <div className="flex flex-1 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : fileContent ? (
          <div className="min-h-0 flex-1">
            <Editor
              language={getDocumentLanguage(filename)}
              value={displayContent}
              theme="vs-dark"
              onChange={(value) => {
                if (editable && value !== undefined) {
                  setDocumentContent(value)
                }
              }}
              onMount={(editor, monaco) => {
                if (editable) {
                  editor.addAction({
                    id: 'save-document',
                    label: 'Save Document',
                    keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS],
                    run: () => { saveRef.current?.() },
                  })
                }
              }}
              options={{
                readOnly: !editable,
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                fontSize: 13,
                lineNumbers: 'on',
                wordWrap: 'on',
                renderLineHighlight: editable ? 'line' : 'none',
                contextmenu: false,
                automaticLayout: true,
              }}
            />
          </div>
        ) : (
          <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
            Failed to load document content.
          </div>
        )}
      </div>
    )
  }

  if (!selectedPath) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        <div className="flex flex-col items-center gap-2">
          <FileSearch className="h-10 w-10" />
          <p className="text-sm">Select a file to view its contents</p>
        </div>
      </div>
    )
  }

  const isBinary = fileContent?.is_binary || (fileInfo && !contentLoading && !fileContent)
  const isElf = !!fileInfo?.elf_info
  const isLoading = contentLoading && !fileContent && !fileInfo

  return (
    <div className="flex h-full flex-col">
      {/* File header bar */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-2">
        <span className="min-w-0 truncate font-mono text-sm">{selectedPath}</span>
        <div className="ml-auto flex shrink-0 items-center gap-3 text-xs text-muted-foreground">
          {fileInfo && (
            <>
              <span>{fileInfo.mime_type}</span>
              <span>{formatFileSize(fileInfo.size)}</span>
              <span className="font-mono">{fileInfo.permissions}</span>
            </>
          )}
          {infoLoading && <Loader2 className="h-3 w-3 animate-spin" />}
          {projectId && selectedPath && (
            <a
              href={getFileDownloadUrl(projectId, selectedPath, selectedFirmwareId || undefined)}
              download
              className="flex items-center gap-1 rounded px-2 py-1 text-xs hover:bg-accent hover:text-accent-foreground"
              title="Download file"
            >
              <Download className="h-3.5 w-3.5" />
              Download
            </a>
          )}
        </div>
      </div>

      {/* Content area */}
      {isLoading ? (
        <div className="flex flex-1 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : isBinary && projectId && fileInfo ? (
        <BinaryTabs
          projectId={projectId}
          filePath={selectedPath}
          fileInfo={fileInfo}
          isElf={isElf}
          infoLoading={infoLoading}
        />
      ) : fileContent ? (
        <TextTabs
          selectedNode={selectedNode}
          selectedPath={selectedPath}
          fileContent={fileContent}
          fileInfo={fileInfo}
          infoLoading={infoLoading}
        />
      ) : (
        <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
          Failed to load file content.
        </div>
      )}
    </div>
  )
}
