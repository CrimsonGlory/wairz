import { useEffect, useRef, useCallback } from 'react'
import type { Terminal } from '@xterm/xterm'
import { buildTerminalWebSocketURL } from '@/api/terminal'

interface UseTerminalWebSocketOptions {
  projectId: string | undefined
  firmwareId?: string | null
  terminal: Terminal | null
  isOpen: boolean
}

export function useTerminalWebSocket({
  projectId,
  firmwareId,
  terminal,
  isOpen,
}: UseTerminalWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null)
  const connectedRef = useRef(false)

  const sendResize = useCallback((cols: number, rows: number) => {
    const ws = wsRef.current
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'resize', cols, rows }))
    }
  }, [])

  useEffect(() => {
    if (!isOpen || !projectId || !terminal) return

    let disposed = false
    let onData: { dispose: () => void } | null = null

    // The WS URL is built asynchronously (it awaits the auth token), so connect
    // inside a promise and guard against the effect being torn down meanwhile.
    void buildTerminalWebSocketURL(projectId, firmwareId ?? undefined).then((url) => {
      if (disposed) return
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        connectedRef.current = true
        sendResize(terminal.cols, terminal.rows)
      }

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          if (msg.type === 'output' && msg.data) {
            terminal.write(msg.data)
          } else if (msg.type === 'error') {
            terminal.write(`\r\n\x1b[31mError: ${msg.data}\x1b[0m\r\n`)
          }
        } catch {
          terminal.write(event.data)
        }
      }

      ws.onclose = () => {
        connectedRef.current = false
        terminal.write('\r\n\x1b[90m[Session ended]\x1b[0m\r\n')
      }

      ws.onerror = () => {
        connectedRef.current = false
      }

      onData = terminal.onData((data: string) => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'input', data }))
        }
      })
    })

    return () => {
      disposed = true
      onData?.dispose()
      connectedRef.current = false
      const ws = wsRef.current
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        ws.close()
      }
      wsRef.current = null
    }
  }, [isOpen, projectId, firmwareId, terminal, sendResize])

  return { sendResize }
}
