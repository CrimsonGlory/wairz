import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronDown, FileDown, FileText, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { exportFindings } from '@/api/findings'

interface ReportExportProps {
  projectId: string
}

export default function ReportExport({ projectId }: ReportExportProps) {
  const navigate = useNavigate()
  const [exporting, setExporting] = useState(false)

  const handleQuickExport = async (format: 'markdown' | 'pdf') => {
    setExporting(true)
    try {
      const blob = await exportFindings(projectId, format)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `security_report.${format === 'pdf' ? 'pdf' : 'md'}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Export failed:', err)
    } finally {
      setExporting(false)
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" disabled={exporting}>
          {exporting ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <FileText className="mr-2 h-4 w-4" />
          )}
          Report
          <ChevronDown className="ml-1 h-3 w-3" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel>Structured report</DropdownMenuLabel>
        <DropdownMenuItem onClick={() => navigate(`/projects/${projectId}/report`)}>
          <FileText className="mr-2 h-4 w-4" />
          Open report editor
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Quick export (findings only)</DropdownMenuLabel>
        <DropdownMenuItem onClick={() => handleQuickExport('markdown')}>
          <FileText className="mr-2 h-4 w-4" /> Markdown (.md)
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => handleQuickExport('pdf')}>
          <FileDown className="mr-2 h-4 w-4" /> PDF (.pdf)
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
