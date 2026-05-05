import { useState, useEffect, useCallback } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { listFunctions, listImports, disassembleFunction, decompileFunction, fetchCleanedCode } from '@/api/analysis'
import { extractErrorMessage } from '@/utils/error'
import type { FunctionInfo, ImportInfo, FileInfo } from '@/types'
import HexViewer from './HexViewer'
import BinaryInfo from './BinaryInfo'
import FunctionListPanel from './FunctionListPanel'
import DisassemblyPanel from './DisassemblyPanel'
import DecompilationPanel from './DecompilationPanel'
import FileInfoPanel from './FileInfoPanel'

export default function BinaryTabs({
  projectId,
  filePath,
  fileInfo,
  isElf,
  infoLoading,
}: {
  projectId: string
  filePath: string
  fileInfo: FileInfo
  isElf: boolean
  infoLoading: boolean
}) {
  const [functions, setFunctions] = useState<FunctionInfo[]>([])
  const [imports, setImports] = useState<ImportInfo[]>([])
  const [functionsLoading, setFunctionsLoading] = useState(false)
  const [functionsLoaded, setFunctionsLoaded] = useState(false)
  const [functionsError, setFunctionsError] = useState<string | null>(null)
  const [selectedFunction, setSelectedFunction] = useState<string | null>(null)
  const [disasm, setDisasm] = useState<string | null>(null)
  const [disasmLoading, setDisasmLoading] = useState(false)
  const [decompilation, setDecompilation] = useState<string | null>(null)
  const [decompilationLoading, setDecompilationLoading] = useState(false)
  const [decompilationFunction, setDecompilationFunction] = useState<string | null>(null)
  const [cleanedCode, setCleanedCode] = useState<string | null>(null)
  const [cleanedCodeChecked, setCleanedCodeChecked] = useState(false)
  const [activeTab, setActiveTab] = useState('content')

  // Reset state when file changes
  useEffect(() => {
    setFunctions([])
    setImports([])
    setFunctionsLoaded(false)
    setFunctionsError(null)
    setSelectedFunction(null)
    setDisasm(null)
    setDecompilation(null)
    setDecompilationFunction(null)
    setCleanedCode(null)
    setCleanedCodeChecked(false)
    setActiveTab('content')
  }, [filePath])

  // Load functions when Functions tab is first selected; load decompilation when Decompile tab selected
  const handleTabChange = useCallback(
    (tab: string) => {
      setActiveTab(tab)
      if (tab === 'functions' && !functionsLoaded && !functionsLoading && isElf) {
        setFunctionsLoading(true)
        setFunctionsError(null)
        Promise.all([
          listFunctions(projectId, filePath),
          listImports(projectId, filePath).catch(() => ({ imports: [] as ImportInfo[] })),
        ])
          .then(([funcResp, impResp]) => {
            setFunctions(funcResp.functions)
            setImports(impResp.imports)
            setFunctionsLoaded(true)
          })
          .catch((err) => {
            const detail = err?.response?.data?.detail
            const status = err?.response?.status
            if (status === 504 || (typeof detail === 'string' && detail.toLowerCase().includes('timed out'))) {
              setFunctionsError('Analysis timed out — this binary may be too large. Try again or increase GHIDRA_TIMEOUT.')
            } else {
              setFunctionsError(extractErrorMessage(err, 'Failed to analyze binary.'))
            }
            setFunctions([])
          })
          .finally(() => setFunctionsLoading(false))
      }
      if (tab === 'decompile' && selectedFunction && decompilationFunction !== selectedFunction) {
        setDecompilation(null)
        setDecompilationFunction(selectedFunction)
        setDecompilationLoading(true)
        setCleanedCode(null)
        setCleanedCodeChecked(false)
        decompileFunction(projectId, filePath, selectedFunction)
          .then((resp) => setDecompilation(resp.decompiled_code))
          .catch(() => setDecompilation('Decompilation failed.'))
          .finally(() => setDecompilationLoading(false))
        fetchCleanedCode(projectId, filePath, selectedFunction)
          .then((resp) => {
            setCleanedCode(resp.available ? resp.cleaned_code : null)
            setCleanedCodeChecked(true)
          })
          .catch(() => setCleanedCodeChecked(true))
      }
    },
    [projectId, filePath, functionsLoaded, functionsLoading, isElf, selectedFunction, decompilationFunction],
  )

  // Load disassembly when a function is selected
  const handleSelectFunction = useCallback(
    (funcName: string) => {
      setSelectedFunction(funcName)
      setDisasm(null)
      setDisasmLoading(true)
      setActiveTab('disasm')
      disassembleFunction(projectId, filePath, funcName)
        .then((resp) => setDisasm(resp.disassembly))
        .catch(() => setDisasm('Failed to disassemble function.'))
        .finally(() => setDisasmLoading(false))
    },
    [projectId, filePath],
  )

  return (
    <Tabs value={activeTab} onValueChange={handleTabChange} className="flex flex-1 flex-col overflow-hidden">
      <TabsList className="mx-4 mt-2 w-fit">
        <TabsTrigger value="content">Hex</TabsTrigger>
        {isElf && <TabsTrigger value="functions">Functions</TabsTrigger>}
        {isElf && selectedFunction && <TabsTrigger value="disasm">Disassembly</TabsTrigger>}
        {isElf && selectedFunction && <TabsTrigger value="decompile">Decompile</TabsTrigger>}
        <TabsTrigger value="info">Info</TabsTrigger>
      </TabsList>

      <TabsContent value="content" className="flex flex-1 flex-col overflow-hidden mt-0 p-0">
        <div className="flex-1 overflow-hidden">
          <HexViewer projectId={projectId} filePath={filePath} fileSize={fileInfo.size} />
        </div>
        {fileInfo.elf_info && (
          <div className="border-t border-border p-4">
            <BinaryInfo fileInfo={fileInfo} />
          </div>
        )}
      </TabsContent>

      {isElf && (
        <TabsContent value="functions" className="flex-1 overflow-hidden mt-0 p-0">
          <FunctionListPanel
            functions={functions}
            imports={imports}
            loading={functionsLoading}
            error={functionsError}
            selectedFunction={selectedFunction}
            onSelectFunction={handleSelectFunction}
          />
        </TabsContent>
      )}

      {isElf && selectedFunction && (
        <TabsContent value="disasm" className="flex-1 overflow-hidden mt-0 p-0">
          <DisassemblyPanel
            functionName={selectedFunction}
            disassembly={disasm}
            loading={disasmLoading}
          />
        </TabsContent>
      )}

      {isElf && selectedFunction && (
        <TabsContent value="decompile" className="flex-1 overflow-hidden mt-0 p-0">
          <DecompilationPanel
            functionName={selectedFunction}
            binaryPath={filePath}
            decompilation={decompilation}
            loading={decompilationLoading}
            cleanedCode={cleanedCode}
            cleanedCodeChecked={cleanedCodeChecked}
          />
        </TabsContent>
      )}

      <TabsContent value="info" className="flex-1 overflow-auto mt-0 p-4">
        <FileInfoPanel fileInfo={fileInfo} infoLoading={infoLoading} />
      </TabsContent>
    </Tabs>
  )
}
