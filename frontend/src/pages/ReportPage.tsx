import { useEffect, useMemo, useRef, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import Editor from '@monaco-editor/react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  Circle,
  FileText,
  Loader2,
  Pencil,
  Plus,
  RotateCcw,
  Save,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  createReport,
  getReport,
  listReports,
  renameReport,
  renderReport,
  setFindingInclusion,
  upsertSection,
  downloadRenderUrl,
} from '@/api/reports'
import type {
  Report,
  ReportSummary,
  ReportTemplate,
  Severity,
  TemplateSection,
} from '@/types'
import { listReportTemplates } from '@/api/reports'

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_BADGE: Record<Severity, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
  info: 'bg-gray-100 text-gray-700',
}

interface SectionStatus {
  filled: boolean
  whitespaceOnly: boolean
  wordCount: number
}

function evaluateSection(content: string): SectionStatus {
  const trimmed = content.trim()
  return {
    filled: trimmed.length > 0,
    whitespaceOnly: content.length > 0 && trimmed.length === 0,
    wordCount: trimmed === '' ? 0 : trimmed.split(/\s+/).length,
  }
}

function formatRelativeTime(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  const sec = Math.floor(ms / 1000)
  if (sec < 60) return 'just now'
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}h ago`
  const day = Math.floor(hr / 24)
  if (day < 7) return `${day}d ago`
  return new Date(iso).toLocaleDateString()
}

function pickInitialReport(summaries: ReportSummary[]): ReportSummary | null {
  if (summaries.length === 0) return null
  // Reports with actual content win over empty ones, then most-recently-modified.
  const sorted = [...summaries].sort((a, b) => {
    const aHasContent = a.filled_section_count > 0
    const bHasContent = b.filled_section_count > 0
    if (aHasContent !== bHasContent) return aHasContent ? -1 : 1
    return (
      new Date(b.last_modified_at).getTime()
      - new Date(a.last_modified_at).getTime()
    )
  })
  return sorted[0]
}

export default function ReportPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()

  const [loading, setLoading] = useState(true)
  const [summaries, setSummaries] = useState<ReportSummary[]>([])
  const [templates, setTemplates] = useState<ReportTemplate[]>([])
  const [report, setReport] = useState<Report | null>(null)
  const [template, setTemplate] = useState<ReportTemplate | null>(null)
  const [activeSlug, setActiveSlug] = useState<string | null>(null)
  const [draftContent, setDraftContent] = useState('')
  const [saving, setSaving] = useState(false)
  const [savedAt, setSavedAt] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [renderResult, setRenderResult] = useState<{
    contentHash: string
    cached: boolean
    byteSize: number
  } | null>(null)
  const [rendering, setRendering] = useState(false)
  const [switching, setSwitching] = useState(false)
  const dirtyRef = useRef(false)

  async function loadReport(reportId: string, tpls: ReportTemplate[]) {
    if (!projectId) return
    const r = await getReport(projectId, reportId)
    const matched = tpls.find((tpl) => tpl.id === r.template_id) ?? null
    setReport(r)
    setTemplate(matched)
    if (matched) {
      const firstRequired = matched.sections.find((s) => s.required)
      const firstSlug = firstRequired?.slug ?? matched.sections[0]?.slug ?? null
      setActiveSlug(firstSlug)
      if (firstSlug) {
        const sec = r.sections.find((s) => s.slug === firstSlug)
        setDraftContent(sec?.content_md ?? '')
      }
    }
    dirtyRef.current = false
    setSavedAt(null)
    setRenderResult(null)
  }

  // Load the project's reports and pick the most-recently-modified one.
  useEffect(() => {
    let cancelled = false
    async function init() {
      if (!projectId) return
      setLoading(true)
      setError(null)
      try {
        const [list, tpls] = await Promise.all([
          listReports(projectId),
          listReportTemplates(projectId),
        ])
        if (cancelled) return
        setTemplates(tpls)
        let working = list
        let target = pickInitialReport(working)
        if (target === null) {
          const created = await createReport(projectId, {})
          working = await listReports(projectId)
          target = working.find((r) => r.id === created.id) ?? working[0] ?? null
        }
        setSummaries(working)
        if (target) await loadReport(target.id, tpls)
      } catch (err) {
        console.error('Failed to load report:', err)
        if (!cancelled) setError('Failed to load report. Check the backend logs.')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    init()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId])

  async function refreshSummaries() {
    if (!projectId) return
    const list = await listReports(projectId)
    setSummaries(list)
    return list
  }

  async function switchToReport(reportId: string) {
    if (!projectId || !templates.length) return
    if (report?.id === reportId) return
    if (dirtyRef.current && !window.confirm('Discard unsaved edits?')) return
    setSwitching(true)
    try {
      await loadReport(reportId, templates)
    } catch (err) {
      console.error('Switch failed:', err)
      setError('Failed to load that report.')
    } finally {
      setSwitching(false)
    }
  }

  async function handleNewDraft() {
    if (!projectId) return
    if (dirtyRef.current && !window.confirm('Discard unsaved edits?')) return
    setSwitching(true)
    try {
      const created = await createReport(projectId, {})
      await refreshSummaries()
      await loadReport(created.id, templates)
    } catch (err) {
      console.error('Create failed:', err)
      setError('Failed to create a new draft.')
    } finally {
      setSwitching(false)
    }
  }

  async function handleRenameCurrent() {
    if (!projectId || !report) return
    const next = window.prompt('Rename this report:', report.title)?.trim()
    if (!next || next === report.title) return
    try {
      const updated = await renameReport(projectId, report.id, next)
      setReport((prev) => (prev ? { ...prev, title: updated.title } : prev))
      void refreshSummaries()
      // Renames invalidate any cached PDF render (title is in the hash).
      setRenderResult(null)
    } catch (err) {
      console.error('Rename failed:', err)
      setError('Rename failed.')
    }
  }

  // Switch sections — confirm if there are unsaved edits.
  function selectSection(slug: string) {
    if (!report) return
    if (dirtyRef.current && !window.confirm('Discard unsaved edits?')) return
    setActiveSlug(slug)
    const sec = report.sections.find((s) => s.slug === slug)
    setDraftContent(sec?.content_md ?? '')
    dirtyRef.current = false
  }

  function handleEditorChange(value: string | undefined) {
    setDraftContent(value ?? '')
    dirtyRef.current = true
  }

  async function handleSave() {
    if (!projectId || !report || !activeSlug) return
    setSaving(true)
    setError(null)
    try {
      const updated = await upsertSection(
        projectId,
        report.id,
        activeSlug,
        draftContent,
      )
      setReport((prev) => {
        if (!prev) return prev
        const others = prev.sections.filter((s) => s.slug !== activeSlug)
        return { ...prev, sections: [...others, updated].sort((a, b) => a.order_index - b.order_index) }
      })
      setSavedAt(new Date().toLocaleTimeString())
      dirtyRef.current = false
      // Saving invalidates the cached render.
      setRenderResult(null)
      void refreshSummaries()
    } catch (err) {
      console.error('Save failed:', err)
      setError('Save failed. Check the backend logs for details.')
    } finally {
      setSaving(false)
    }
  }

  async function handleToggleFinding(findingId: string, included: boolean) {
    if (!projectId || !report) return
    try {
      const updated = await setFindingInclusion(projectId, report.id, findingId, included)
      setReport((prev) => {
        if (!prev) return prev
        return {
          ...prev,
          findings: prev.findings.map((rf) =>
            rf.finding.id === findingId ? updated : rf,
          ),
        }
      })
      setRenderResult(null)
    } catch (err) {
      console.error('Toggle failed:', err)
    }
  }

  async function handleRender() {
    if (!projectId || !report) return
    if (dirtyRef.current && !window.confirm('Render without saving current section?')) return
    setRendering(true)
    setError(null)
    try {
      const result = await renderReport(projectId, report.id, 'pdf')
      setRenderResult({
        contentHash: result.content_hash,
        cached: result.cached,
        byteSize: result.byte_size,
      })
      // Open the artifact in a new tab.
      const url = downloadRenderUrl(projectId, report.id, result.content_hash, 'pdf')
      window.open(url, '_blank')
      // Refresh the report so the new render appears in renders[].
      const refreshed = await getReport(projectId, report.id)
      setReport(refreshed)
    } catch (err) {
      console.error('Render failed:', err)
      setError('Render failed. Check the backend logs for details.')
    } finally {
      setRendering(false)
    }
  }

  const orderedSections: TemplateSection[] = useMemo(
    () => (template ? [...template.sections].sort((a, b) => a.order - b.order) : []),
    [template],
  )

  const sectionStatusBySlug = useMemo(() => {
    const out: Record<string, SectionStatus> = {}
    for (const ts of orderedSections) {
      const sec = report?.sections.find((s) => s.slug === ts.slug)
      out[ts.slug] = evaluateSection(sec?.content_md ?? '')
    }
    return out
  }, [orderedSections, report])

  const activeTemplateSection = useMemo(
    () => orderedSections.find((s) => s.slug === activeSlug) ?? null,
    [orderedSections, activeSlug],
  )

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-12 justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span>Loading report...</span>
      </div>
    )
  }

  if (error && !report) {
    return (
      <div className="flex flex-col items-center gap-3 py-12 text-muted-foreground">
        <AlertCircle className="h-6 w-6 text-destructive" />
        <p>{error}</p>
        <Button variant="outline" onClick={() => navigate(`/projects/${projectId}`)}>
          Back to project
        </Button>
      </div>
    )
  }

  if (!report || !template) return null

  const sortedFindings = [...report.findings].sort((a, b) => {
    const sa = SEVERITY_ORDER.indexOf(a.finding.severity)
    const sb = SEVERITY_ORDER.indexOf(b.finding.severity)
    return sa - sb || a.finding.title.localeCompare(b.finding.title)
  })

  const draftStatus = activeSlug ? evaluateSection(draftContent) : null

  return (
    <div className="-m-6 flex h-[calc(100vh-3.5rem)]">
      {/* Left: section list */}
      <div className="flex w-64 shrink-0 flex-col border-r border-border">
        <div className="flex items-center gap-2 border-b border-border px-4 py-2">
          <FileText className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Sections</span>
        </div>
        <div className="flex-1 overflow-y-auto p-2">
          {orderedSections.map((ts) => {
            const status = sectionStatusBySlug[ts.slug]
            const isActive = activeSlug === ts.slug
            const filled = status?.filled
            return (
              <button
                key={ts.slug}
                onClick={() => selectSection(ts.slug)}
                className={`mb-1 flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left text-xs transition-colors ${
                  isActive
                    ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                    : 'text-foreground/80 hover:bg-muted'
                }`}
              >
                {filled ? (
                  <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-green-600" />
                ) : (
                  <Circle className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${ts.required ? 'text-red-500' : 'text-muted-foreground'}`} />
                )}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1 truncate font-medium">
                    {ts.title}
                    {ts.required && !filled && (
                      <span className="text-[10px] font-normal text-red-500">required</span>
                    )}
                  </div>
                  {status?.wordCount !== undefined && (
                    <div className="text-[10px] text-muted-foreground">
                      {status.wordCount} word{status.wordCount === 1 ? '' : 's'}
                      {ts.max_words ? ` / ${ts.max_words} max` : ''}
                    </div>
                  )}
                </div>
              </button>
            )
          })}
          <div className="my-2 border-t border-border" />
          <div className="px-2 py-1 text-[10px] uppercase tracking-wide text-muted-foreground">
            Auto-rendered
          </div>
          <div className="px-2 py-1 text-xs text-muted-foreground">
            Findings ({sortedFindings.filter((f) => f.included).length} of{' '}
            {sortedFindings.length} included)
          </div>
        </div>
      </div>

      {/* Center: editor + preview */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Header */}
        <div className="flex items-center gap-3 border-b border-border px-4 py-2">
          <div className="min-w-0 flex-1">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  className="flex max-w-full items-center gap-1.5 rounded-md px-2 py-1 text-left text-sm font-medium hover:bg-muted disabled:opacity-50"
                  disabled={switching}
                >
                  <span className="truncate">{report.title}</span>
                  <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-80">
                <DropdownMenuLabel>Reports for this project</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {summaries.length === 0 ? (
                  <DropdownMenuItem disabled>No reports yet</DropdownMenuItem>
                ) : (
                  [...summaries]
                    .sort((a, b) =>
                      new Date(b.last_modified_at).getTime()
                        - new Date(a.last_modified_at).getTime(),
                    )
                    .map((s) => (
                      <DropdownMenuItem
                        key={s.id}
                        onSelect={() => switchToReport(s.id)}
                        className={`flex flex-col items-start gap-0.5 ${
                          s.id === report.id ? 'bg-muted/50' : ''
                        }`}
                      >
                        <div className="flex w-full items-center gap-2">
                          <span className="truncate text-sm font-medium">
                            {s.title}
                          </span>
                        </div>
                        <div className="text-[10px] text-muted-foreground">
                          {s.filled_section_count}/{s.total_section_count} sections
                          {' • '}
                          {formatRelativeTime(s.last_modified_at)}
                        </div>
                      </DropdownMenuItem>
                    ))
                )}
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={handleRenameCurrent}>
                  <Pencil className="mr-2 h-3.5 w-3.5" />
                  Rename current report…
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={handleNewDraft}>
                  <Plus className="mr-2 h-3.5 w-3.5" />
                  New draft
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <div className="px-2 text-xs text-muted-foreground">
              Template: {template.name}
            </div>
          </div>
          <Button size="sm" onClick={handleRender} disabled={rendering}>
            {rendering ? (
              <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
            ) : (
              <FileText className="mr-1 h-3.5 w-3.5" />
            )}
            Render PDF
          </Button>
        </div>

        {renderResult && (
          <div className="border-b border-emerald-200 bg-emerald-50 px-4 py-2 text-xs text-emerald-900">
            Rendered {(renderResult.byteSize / 1024).toFixed(1)} KB —
            hash {renderResult.contentHash.slice(0, 12)}…
            {renderResult.cached ? ' (cached)' : ' (fresh render)'}
          </div>
        )}
        {error && (
          <div className="border-b border-red-200 bg-red-50 px-4 py-2 text-xs text-red-900">
            {error}
          </div>
        )}

        {activeTemplateSection ? (
          <>
            {/* Section header + guidance */}
            <div className="border-b border-border bg-muted/30 px-4 py-2 text-xs">
              <div className="font-medium text-foreground">
                {activeTemplateSection.title}
              </div>
              {activeTemplateSection.guidance && (
                <div className="mt-1 text-muted-foreground">
                  {activeTemplateSection.guidance}
                </div>
              )}
              <div className="mt-1 flex items-center gap-3 text-[11px] text-muted-foreground">
                {activeTemplateSection.max_words && (
                  <span>Target ≤ {activeTemplateSection.max_words} words</span>
                )}
                {draftStatus && (
                  <span>{draftStatus.wordCount} words</span>
                )}
                {savedAt && <span>Saved at {savedAt}</span>}
              </div>
            </div>

            {/* Editor + preview */}
            <div className="grid min-h-0 flex-1 grid-cols-2">
              <div className="flex min-h-0 flex-col border-r border-border">
                <Editor
                  language="markdown"
                  value={draftContent}
                  theme="vs-dark"
                  onChange={handleEditorChange}
                  options={{
                    wordWrap: 'on',
                    minimap: { enabled: false },
                    fontSize: 13,
                    lineNumbers: 'off',
                    renderLineHighlight: 'none',
                    scrollBeyondLastLine: false,
                  }}
                />
                <div className="flex items-center justify-between border-t border-border px-3 py-1.5">
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => {
                      const sec = report.sections.find(
                        (s) => s.slug === activeSlug,
                      )
                      setDraftContent(sec?.content_md ?? '')
                      dirtyRef.current = false
                    }}
                  >
                    <RotateCcw className="mr-1 h-3.5 w-3.5" /> Revert
                  </Button>
                  <Button
                    size="sm"
                    onClick={handleSave}
                    disabled={saving}
                  >
                    {saving ? (
                      <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Save className="mr-1 h-3.5 w-3.5" />
                    )}
                    Save
                  </Button>
                </div>
              </div>
              <div className="report-preview min-h-0 overflow-y-auto bg-white p-4">
                {draftContent.trim() ? (
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {draftContent}
                  </ReactMarkdown>
                ) : (
                  <p className="placeholder">No content yet.</p>
                )}
              </div>
            </div>
          </>
        ) : (
          <div className="flex flex-1 items-center justify-center text-muted-foreground">
            Select a section to edit.
          </div>
        )}
      </div>

      {/* Right: findings inclusion */}
      <div className="flex w-80 shrink-0 flex-col border-l border-border">
        <div className="flex items-center gap-2 border-b border-border px-4 py-2">
          <span className="text-sm font-medium">Findings included</span>
        </div>
        <div className="flex-1 overflow-y-auto p-3">
          {sortedFindings.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No findings have been recorded for this project.
            </p>
          ) : (
            <ul className="space-y-2">
              {sortedFindings.map((rf) => (
                <li
                  key={rf.finding.id}
                  className="flex items-start gap-2 rounded-md border border-border bg-background px-2 py-1.5"
                >
                  <Checkbox
                    checked={rf.included}
                    onCheckedChange={(value) =>
                      handleToggleFinding(rf.finding.id, value === true)
                    }
                    className="mt-1"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded-full px-1.5 py-0.5 text-[10px] font-semibold uppercase ${SEVERITY_BADGE[rf.finding.severity]}`}
                      >
                        {rf.finding.severity}
                      </span>
                      <span className="truncate text-xs font-medium">
                        {rf.finding.title}
                      </span>
                    </div>
                    {rf.finding.file_path && (
                      <div className="truncate text-[10px] text-muted-foreground">
                        {rf.finding.file_path}
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}
