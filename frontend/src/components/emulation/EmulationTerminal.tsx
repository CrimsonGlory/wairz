import { useEffect, useRef } from 'react'
import { Square, TerminalSquare } from 'lucide-react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { Badge } from '@/components/ui/badge'
import { buildEmulationTerminalURL, getSessionLogs } from '@/api/emulation'
import type { EmulationSession, EmulationStatus } from '@/types'
import '@xterm/xterm/css/xterm.css'

const STATUS_CONFIG: Record<EmulationStatus, { label: string; className: string }> = {
  created: { label: 'Created', className: 'bg-gray-500 text-white' },
  pending: { label: 'Queued', className: 'bg-yellow-500 text-black' },
  starting: { label: 'Starting', className: 'bg-yellow-500 text-black' },
  booting: { label: 'Booting', className: 'bg-yellow-500 text-black' },
  running: { label: 'Running', className: 'bg-green-500 text-white' },
  ready: { label: 'Ready', className: 'bg-green-500 text-white' },
  stopping: { label: 'Stopping...', className: 'bg-orange-500 text-white' },
  stopped: { label: 'Stopped', className: 'bg-zinc-600 text-white' },
  error: { label: 'Error', className: 'bg-red-500 text-white' },
}

export interface EmulationTerminalProps {
  projectId: string
  session: EmulationSession
  onClose: () => void
}

export function EmulationTerminal({ projectId, session, onClose }: EmulationTerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectAttemptRef = useRef(0)
  const intentionalCloseRef = useRef(false)

  useEffect(() => {
    if (!containerRef.current || session.status !== 'running') return

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
      theme: {
        background: '#0a0a0b',
        foreground: '#e4e4e7',
        cursor: '#e4e4e7',
        selectionBackground: '#27272a',
        black: '#09090b',
        red: '#ef4444',
        green: '#22c55e',
        yellow: '#eab308',
        blue: '#3b82f6',
        magenta: '#a855f7',
        cyan: '#06b6d4',
        white: '#e4e4e7',
        brightBlack: '#52525b',
        brightRed: '#f87171',
        brightGreen: '#4ade80',
        brightYellow: '#facc15',
        brightBlue: '#60a5fa',
        brightMagenta: '#c084fc',
        brightCyan: '#22d3ee',
        brightWhite: '#fafafa',
      },
      scrollback: 5000,
      convertEol: true,
    })

    const fitAddon = new FitAddon()
    term.loadAddon(fitAddon)
    fitAddonRef.current = fitAddon
    termRef.current = term

    term.open(containerRef.current)
    requestAnimationFrame(() => fitAddon.fit())

    const MAX_RECONNECT_ATTEMPTS = 10
    const RECONNECT_BASE_DELAY = 1000

    function connectWebSocket() {
      const url = buildEmulationTerminalURL(projectId, session.id)
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        reconnectAttemptRef.current = 0
        ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
      }

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          if (msg.type === 'output' && msg.data) {
            term.write(msg.data)
          } else if (msg.type === 'error') {
            term.write(`\r\n\x1b[31mError: ${msg.data}\x1b[0m\r\n`)
          }
          // Ignore ping/pong messages (keepalive)
        } catch {
          term.write(event.data)
        }
      }

      ws.onclose = () => {
        if (intentionalCloseRef.current) return

        const attempt = reconnectAttemptRef.current
        if (attempt < MAX_RECONNECT_ATTEMPTS) {
          const delay = Math.min(RECONNECT_BASE_DELAY * Math.pow(1.5, attempt), 10000)
          term.write(`\r\n\x1b[90m[Disconnected — reconnecting in ${Math.round(delay / 1000)}s...]\x1b[0m\r\n`)
          reconnectAttemptRef.current = attempt + 1
          reconnectTimerRef.current = setTimeout(connectWebSocket, delay)
        } else {
          term.write('\r\n\x1b[90m[Session disconnected — max reconnect attempts reached]\x1b[0m\r\n')
          getSessionLogs(projectId, session.id)
            .then((logText) => {
              if (logText && logText !== '(no log available)') {
                term.write('\r\n\x1b[33m--- QEMU Startup Log ---\x1b[0m\r\n')
                term.write(logText.replace(/\n/g, '\r\n'))
                term.write('\r\n\x1b[33m--- End Log ---\x1b[0m\r\n')
              }
            })
            .catch(() => {})
        }
      }

      ws.onerror = () => {
        // onclose will fire after onerror, reconnect handled there
      }
    }

    connectWebSocket()

    const onData = term.onData((data: string) => {
      const ws = wsRef.current
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }))
      }
    })

    return () => {
      intentionalCloseRef.current = true
      onData.dispose()
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
      const ws = wsRef.current
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        ws.close()
      }
      wsRef.current = null
      termRef.current = null
      fitAddonRef.current = null
      term.dispose()
    }
  }, [projectId, session.id, session.status])

  // Resize observer
  useEffect(() => {
    if (!containerRef.current) return

    const observer = new ResizeObserver(() => {
      const fitAddon = fitAddonRef.current
      const term = termRef.current
      const ws = wsRef.current
      if (!fitAddon || !term) return
      try {
        fitAddon.fit()
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
        }
      } catch {
        // ignore
      }
    })
    observer.observe(containerRef.current)
    return () => observer.disconnect()
  }, [])

  return (
    <div className="flex h-full flex-col">
      {/* Terminal header */}
      <div className="flex items-center gap-2 border-b border-border bg-[#0a0a0b] px-3 py-1.5">
        <TerminalSquare className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-xs font-medium text-muted-foreground">
          Emulation Terminal — {session.mode} mode
          {session.architecture ? ` (${session.architecture})` : ''}
        </span>
        <Badge
          className={`ml-auto text-[10px] ${STATUS_CONFIG[session.status]?.className || ''}`}
        >
          {session.status}
        </Badge>
        <button
          onClick={onClose}
          className="rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          title="Close terminal"
        >
          <Square className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Terminal container */}
      <div ref={containerRef} className="flex-1 px-1 py-1" />
    </div>
  )
}
