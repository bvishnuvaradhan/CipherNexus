import { useEffect, useRef, useCallback } from 'react'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/alerts'

export function useWebSocket(onMessage) {
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)
  const onMessageRef = useRef(onMessage)

  useEffect(() => {
    onMessageRef.current = onMessage
  }, [onMessage])

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws

      ws.onopen = () => {
        console.log('🔌 WebSocket connected')
        if (reconnectTimer.current) {
          clearTimeout(reconnectTimer.current)
          reconnectTimer.current = null
        }
        // Client-side ping keepalive to prevent silent disconnects
        ws._pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send('ping')
        }, 25000)
      }

      ws.onmessage = (event) => {
        try {
          // Ignore pong responses
          if (event.data === 'pong') return
          const data = JSON.parse(event.data)
          onMessageRef.current?.(data)
        } catch (e) {
          console.warn('WS parse error', e)
        }
      }

      ws.onclose = () => {
        console.log('🔌 WebSocket disconnected — reconnecting in 3s')
        if (ws._pingInterval) clearInterval(ws._pingInterval)
        reconnectTimer.current = setTimeout(connect, 3000)
      }

      ws.onerror = (err) => {
        console.warn('WS error', err)
        ws.close()
      }
    } catch (e) {
      console.warn('WS connect error', e)
      reconnectTimer.current = setTimeout(connect, 3000)
    }
  }, [])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(typeof data === 'string' ? data : JSON.stringify(data))
    }
  }, [])

  return { send }
}
