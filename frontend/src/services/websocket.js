import { useEffect, useRef, useCallback } from 'react'

const defaultWsUrl = () => {
  if (typeof window === 'undefined') return 'ws://localhost:8000/ws/alerts'
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.hostname}:8000/ws/alerts`
}

const WS_URL = import.meta.env.VITE_WS_URL || defaultWsUrl()

export function useWebSocket(onMessage) {
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)
  const pingTimer = useRef(null)
  const shouldReconnect = useRef(true)
  const onMessageRef = useRef(onMessage)

  useEffect(() => {
    onMessageRef.current = onMessage
  }, [onMessage])

  const connect = useCallback(() => {
    if (!shouldReconnect.current) return

    try {
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws

      ws.onopen = () => {
        console.log('🔌 WebSocket connected')
        if (reconnectTimer.current) {
          clearTimeout(reconnectTimer.current)
          reconnectTimer.current = null
        }
        if (pingTimer.current) {
          clearInterval(pingTimer.current)
          pingTimer.current = null
        }
        // Keep the socket active in intermediaries and align with backend ping handling.
        pingTimer.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping')
          }
        }, 15000)
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          onMessageRef.current?.(data)
        } catch (e) {
          console.warn('WS parse error', e)
        }
      }

      ws.onclose = () => {
        console.log('🔌 WebSocket disconnected — reconnecting in 3s')
        if (pingTimer.current) {
          clearInterval(pingTimer.current)
          pingTimer.current = null
        }
        if (shouldReconnect.current) {
          reconnectTimer.current = setTimeout(connect, 3000)
        }
      }

      ws.onerror = (err) => {
        console.warn('WS error', err)
      }
    } catch (e) {
      console.warn('WS connect error', e)
      if (shouldReconnect.current) {
        reconnectTimer.current = setTimeout(connect, 3000)
      }
    }
  }, [])

  useEffect(() => {
    shouldReconnect.current = true
    connect()
    return () => {
      shouldReconnect.current = false
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      if (pingTimer.current) clearInterval(pingTimer.current)
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
