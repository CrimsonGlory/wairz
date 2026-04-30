import { useEffect, useState, useMemo } from 'react'
import { useParams } from 'react-router-dom'
import { Wrench, Search, Loader2 } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { listTools, runTool, type ToolInfo, type ToolRunResponse } from '@/api/tools'
import { useProjectStore } from '@/stores/projectStore'
import ToolCard from '@/components/tools/ToolCard'
import ToolForm from '@/components/tools/ToolForm'
import ToolOutput from '@/components/tools/ToolOutput'
import { formatToolName } from '@/components/tools/ToolCard'
import { extractErrorMessage } from '@/utils/error'

// ---------------------------------------------------------------------------
// Category classification
// ---------------------------------------------------------------------------

const CATEGORY_RULES: [string, (name: string) => boolean][] = [
  [
    'Binary Analysis',
    (n) =>
      /^(list_functions|disassemble_|decompile_|check_binary_|check_all_binary_|find_callers|xrefs_|get_binary_info|resolve_import|search_binary_|get_stack_|get_global_|trace_dataflow|cross_binary_|detect_capabilities|list_binary_|list_imports|list_exports|find_string_refs)/.test(n),
  ],
  [
    'SBOM & Vulnerabilities',
    (n) => /^(generate_sbom|export_sbom|get_sbom_|check_component_|run_vulnerability_|push_to_dependency|assess_vulnerabilities)/.test(n),
  ],
  [
    'Filesystem',
    (n) =>
      /^(list_directory|read_file|search_files|file_info|find_files_|get_component_map|get_firmware_metadata|extract_bootloader_)/.test(n),
  ],
  [
    'Strings',
    (n) => /^(extract_strings|search_strings|find_crypto_|find_hardcoded_)/.test(n),
  ],
  [
    'Comparison',
    (n) => /^(list_firmware_versions|diff_)/.test(n),
  ],
  [
    'Emulation',
    (n) =>
      /^(start_emulation|run_command_|stop_emulation|check_emulation_|get_emulation_|enumerate_emulation_|diagnose_emulation_|troubleshoot_|get_crash_|run_gdb_|save_emulation_|list_emulation_|start_emulation_from_)/.test(n),
  ],
  [
    'Fuzzing',
    (n) =>
      /^(analyze_fuzzing_|generate_fuzzing_|generate_seed_|generate_fuzzing_|start_fuzzing_|check_fuzzing_|stop_fuzzing_|triage_fuzzing_|diagnose_fuzzing_)/.test(n),
  ],
  [
    'Reporting',
    (n) =>
      /^(add_finding|list_findings|update_finding|read_project_|list_project_|generate_assessment_|run_full_assessment|save_code_)/.test(n),
  ],
  [
    'Security',
    (n) => /^(check_known_|analyze_config_|check_setuid_|analyze_init_|check_filesystem_|analyze_certificate|check_kernel_|scan_with_|vulhunt_)/.test(n),
  ],
]

function categorize(name: string): string {
  for (const [cat, test] of CATEGORY_RULES) {
    if (test(name)) return cat
  }
  return 'Other'
}

const ALL_CATEGORIES = [
  'all',
  'Security',
  'Binary Analysis',
  'SBOM & Vulnerabilities',
  'Filesystem',
  'Strings',
  'Comparison',
  'Emulation',
  'Fuzzing',
  'Reporting',
  'Other',
]

// ---------------------------------------------------------------------------
// Page component
// ---------------------------------------------------------------------------

export default function SecurityToolsPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const selectedFirmwareId = useProjectStore((s) => s.selectedFirmwareId)

  const [tools, setTools] = useState<ToolInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedTool, setSelectedTool] = useState<ToolInfo | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<string>('all')

  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<ToolRunResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [lastInput, setLastInput] = useState<Record<string, unknown>>({})

  // Fetch tools on mount
  useEffect(() => {
    if (!projectId) return
    setLoading(true)
    listTools(projectId)
      .then((resp) => {
        setTools(resp.tools)
      })
      .catch(() => {
        setTools([])
      })
      .finally(() => setLoading(false))
  }, [projectId])

  // Categorize tools
  const categorized = useMemo(() => {
    const map = new Map<string, string>()
    for (const t of tools) {
      map.set(t.name, categorize(t.name))
    }
    return map
  }, [tools])

  // Category counts (for showing badges)
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const cat of categorized.values()) {
      counts[cat] = (counts[cat] ?? 0) + 1
    }
    return counts
  }, [categorized])

  // Filter tools
  const filteredTools = useMemo(() => {
    let list = tools
    if (selectedCategory !== 'all') {
      list = list.filter((t) => categorized.get(t.name) === selectedCategory)
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      list = list.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          (t.description && t.description.toLowerCase().includes(q)),
      )
    }
    return list
  }, [tools, selectedCategory, searchQuery, categorized])

  // Run a tool
  const handleRun = async (input: Record<string, unknown>) => {
    if (!projectId || !selectedTool) return
    setRunning(true)
    setResult(null)
    setError(null)
    setLastInput(input)
    try {
      const resp = await runTool(
        projectId,
        selectedTool.name,
        input,
        selectedFirmwareId || undefined,
      )
      setResult(resp)
    } catch (err) {
      setError(extractErrorMessage(err, 'Tool execution failed'))
    } finally {
      setRunning(false)
    }
  }

  // Clear result when switching tools
  const handleSelectTool = (tool: ToolInfo) => {
    setSelectedTool(tool)
    setResult(null)
    setError(null)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 text-muted-foreground">
        <Loader2 className="h-6 w-6 animate-spin mr-2" />
        Loading tools...
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Wrench className="h-6 w-6 text-muted-foreground" />
        <div>
          <h1 className="text-lg font-semibold">Security Tools</h1>
          <p className="text-sm text-muted-foreground">
            Browse and run {tools.length} analysis tools directly from the browser
          </p>
        </div>
      </div>

      {/* Two-panel layout */}
      <div className="flex gap-0 rounded-lg border border-border overflow-hidden flex-col md:flex-row" style={{ height: 'calc(100vh - 10rem)' }}>
        {/* Left panel: tool list */}
        <div className="w-full md:w-80 shrink-0 border-b md:border-b-0 md:border-r border-border flex flex-col bg-background overflow-hidden">
          {/* Search */}
          <div className="p-3 border-b border-border space-y-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search tools..."
                className="pl-8 h-8 text-xs"
              />
            </div>
            {/* Category filter pills */}
            <div className="flex flex-wrap gap-1">
              {ALL_CATEGORIES.map((cat) => {
                const count = cat === 'all' ? tools.length : (categoryCounts[cat] ?? 0)
                if (cat !== 'all' && count === 0) return null
                return (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setSelectedCategory(cat)}
                    className={`text-[10px] px-2 py-0.5 rounded-full transition-colors ${
                      selectedCategory === cat
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted text-muted-foreground hover:bg-muted/80'
                    }`}
                  >
                    {cat === 'all' ? 'All' : cat}
                    <span className="ml-1 opacity-70">{count}</span>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Tool list */}
          <div className="flex-1 overflow-y-auto">
            <div className="p-2 space-y-0.5">
              {filteredTools.length === 0 ? (
                <p className="text-xs text-muted-foreground text-center py-4">
                  No tools match your search.
                </p>
              ) : (
                filteredTools.map((tool) => (
                  <ToolCard
                    key={tool.name}
                    tool={tool}
                    isSelected={selectedTool?.name === tool.name}
                    category={categorized.get(tool.name) ?? 'Other'}
                    onClick={() => handleSelectTool(tool)}
                  />
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right panel: form + output */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          {selectedTool ? (
            <>
              {/* Tool header */}
              <div className="p-4 border-b border-border">
                <h2 className="text-base font-semibold">
                  {formatToolName(selectedTool.name)}
                </h2>
                {selectedTool.description && (
                  <p className="text-sm text-muted-foreground mt-0.5">
                    {selectedTool.description}
                  </p>
                )}
              </div>

              {/* Form + Output scrollable area */}
              <div className="flex-1 overflow-y-auto p-4 space-y-6">
                <ToolForm
                  tool={selectedTool}
                  onSubmit={handleRun}
                  loading={running}
                />
                <div className="border-t border-border pt-4">
                  <ToolOutput result={result} loading={running} error={error} toolInput={lastInput} />
                </div>
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center flex-1 text-muted-foreground">
              <Wrench className="h-12 w-12 mb-3 opacity-20" />
              <p className="text-sm">Select a tool from the list to get started</p>
              <p className="text-xs mt-1">
                Browse by category or use the search box
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
