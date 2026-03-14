import { useEffect, useRef, useCallback } from 'react'

function resolveWsUrl() {
  const envUrl = import.meta.env.VITE_WS_URL

  // Ignore placeholder-like values such as "ws:<URL>/...".
  if (typeof envUrl === 'string') {
    const trimmed = envUrl.trim()
    if (trimmed && !trimmed.includes('<') && !trimmed.includes('>') && /^wss?:\/\//i.test(trimmed)) {
      return trimmed
    }
  }

  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
  return `${protocol}://${window.location.host}/ws/alerts`
}

export function useWebSocket(onMessage) {
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)
  const onMessageRef = useRef(onMessage)
  const shouldReconnectRef = useRef(true)
  const reconnectAttemptRef = useRef(0)

  useEffect(() => {
    onMessageRef.current = onMessage
  }, [onMessage])

  useEffect(() => {
    const clearSocketState = (ws) => {
      if (ws?._pingInterval) {
        clearInterval(ws._pingInterval)
        ws._pingInterval = null
      }
    }

    const scheduleReconnect = (connectFn) => {
      if (!shouldReconnectRef.current || reconnectTimer.current) return
      const attempt = reconnectAttemptRef.current
      const delay = Math.min(10000, 1500 + attempt * 1000)
      reconnectAttemptRef.current = Math.min(attempt + 1, 10)
      console.log(`🔌 WebSocket disconnected — reconnecting in ${Math.round(delay / 1000)}s`)
      reconnectTimer.current = setTimeout(() => {
        reconnectTimer.current = null
        connectFn()
      }, delay)
    }

    const connect = () => {
      if (!shouldReconnectRef.current) return

      let ws
      try {
        ws = new WebSocket(resolveWsUrl())
      } catch (e) {
        console.warn('WS connect error', e)
        scheduleReconnect(connect)
        return
      }

      wsRef.current = ws

      ws.onopen = () => {
        reconnectAttemptRef.current = 0
        if (reconnectTimer.current) {
          clearTimeout(reconnectTimer.current)
          reconnectTimer.current = null
        }
        console.log('🔌 WebSocket connected')
        ws._pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send('ping')
        }, 25000)
      }

      ws.onmessage = (event) => {
        try {
          if (event.data === 'pong') return
          const data = JSON.parse(event.data)
          if (data?.type === 'pong') return
          onMessageRef.current?.(data)
        } catch (e) {
          console.warn('WS parse error', e)
        }
      }

      ws.onerror = () => {
        // Avoid noisy logs for transient handshake failures.
      }

      ws.onclose = () => {
        clearSocketState(ws)
        if (wsRef.current === ws) wsRef.current = null
        // Reconnect only while hook instance is still mounted.
        if (shouldReconnectRef.current) {
          scheduleReconnect(connect)
        }
      }
    }

    shouldReconnectRef.current = true
    connect()

    return () => {
      shouldReconnectRef.current = false
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      if (wsRef.current) {
        clearSocketState(wsRef.current)
        if (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING) {
          wsRef.current.close()
        }
      }
    }
  }, [])

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(typeof data === 'string' ? data : JSON.stringify(data))
    }
  }, [])

  return { send }
}
