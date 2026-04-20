import {
  Square,
  AlertCircle,
  Clock,
  Zap,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { formatDate } from '@/utils/format'
import type { FuzzingCampaign, FuzzingStatus } from '@/types'

const STATUS_CONFIG: Record<FuzzingStatus, { label: string; className: string }> = {
  created: { label: 'Created', className: 'bg-gray-500 text-white' },
  queued: { label: 'Queued', className: 'bg-amber-500 text-white' },
  running: { label: 'Running', className: 'bg-green-500 text-white' },
  stopped: { label: 'Stopped', className: 'bg-zinc-600 text-white' },
  completed: { label: 'Completed', className: 'bg-blue-500 text-white' },
  error: { label: 'Error', className: 'bg-red-500 text-white' },
}

export interface CampaignCardProps {
  campaign: FuzzingCampaign
  isSelected: boolean
  onSelect: () => void
  onStop: () => void
}

export function CampaignCard({
  campaign,
  isSelected,
  onSelect,
  onStop,
}: CampaignCardProps) {
  const statusCfg = STATUS_CONFIG[campaign.status] || STATUS_CONFIG.created

  return (
    <div
      className={`cursor-pointer rounded-lg border p-3 transition-colors ${
        isSelected
          ? 'border-primary/50 bg-primary/5'
          : 'border-border hover:border-border/80'
      }`}
      onClick={onSelect}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Badge className={`text-[10px] ${statusCfg.className}`}>
            {statusCfg.label}
          </Badge>
          {campaign.crashes_count > 0 && (
            <Badge className="bg-red-500/10 text-red-500 text-[10px] border-red-500/30">
              {campaign.crashes_count} crash{campaign.crashes_count !== 1 ? 'es' : ''}
            </Badge>
          )}
        </div>
        {campaign.status === 'running' && (
          <Button
            variant="destructive"
            size="sm"
            className="h-6 text-[10px] px-2"
            onClick={(e) => {
              e.stopPropagation()
              onStop()
            }}
          >
            <Square className="mr-1 h-2.5 w-2.5" />
            Stop
          </Button>
        )}
      </div>

      <p className="mt-1 truncate text-xs text-muted-foreground font-mono">
        {campaign.binary_path}
      </p>

      <div className="mt-1 flex items-center gap-3 text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1">
          <Clock className="h-3 w-3" />
          {formatDate(campaign.created_at)}
        </span>
        {campaign.stats && (
          <span className="flex items-center gap-1">
            <Zap className="h-3 w-3" />
            {typeof campaign.stats.execs_per_sec === 'number'
              ? `${campaign.stats.execs_per_sec.toFixed(1)}/s`
              : '—'}
          </span>
        )}
      </div>

      {campaign.error_message && (
        <div className="mt-2 rounded-md bg-destructive/10 px-2 py-1 text-[10px] text-destructive">
          <AlertCircle className="mr-1 inline h-3 w-3" />
          {campaign.error_message.slice(0, 100)}
        </div>
      )}
    </div>
  )
}
