import { useEffect, useRef } from 'react'
import { MessageSquare, ArrowRight } from 'lucide-react'
import { Timestamp } from './ui'

const AGENT_COLORS = {
  Sentry:    { text: 'text-cyan-400',   bg: 'bg-cyan-500/10 border-cyan-500/20' },
  Detective: { text: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/20' },
  Commander: { text: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
  System:    { text: 'text-slate-400',  bg: 'bg-slate-700/30 border-slate-700' },
}

const MSG_ICONS = {
  alert:    '🔴',
  query:    '❓',
  response: '✅',
  action:   '⚡',
}

function AgentTag({ name }) {
  const c = AGENT_COLORS[name] || AGENT_COLORS.System
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-mono font-semibold ${c.bg} ${c.text}`}>
      {name}
    </span>
  )
}

export function AgentFeedItem({ msg }) {
  const icon = MSG_ICONS[msg.message_type] || '📡'
  return (
    <div className="flex gap-3 py-2.5 px-3 border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors animate-slide-in">
      <span className="text-sm mt-0.5 shrink-0">{icon}</span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5 flex-wrap mb-1">
          <AgentTag name={msg.from_agent} />
          <ArrowRight className="w-3 h-3 text-slate-700 shrink-0" />
          <AgentTag name={msg.to_agent} />
          <span className="font-mono text-[11px] text-slate-600 ml-auto shrink-0">
            <Timestamp value={msg.timestamp} />
          </span>
        </div>
        <p className="font-mono text-xs text-slate-400 truncate">
          <span className="text-slate-500 mr-1">{msg.event}</span>
          {msg.ip && <span className="text-cyan-400/70">→ {msg.ip}</span>}
          {msg.severity && (
            <span className={`ml-2 text-[10px] uppercase font-semibold ${
              msg.severity === 'critical' ? 'text-rose-400' :
              msg.severity === 'high' ? 'text-orange-400' :
              msg.severity === 'medium' ? 'text-yellow-400' : 'text-slate-500'
            }`}>[{msg.severity}]</span>
          )}
        </p>
      </div>
    </div>
  )
}

export function AgentCommunicationFeed({ messages = [], maxHeight = 320, title = 'Agent Communication Feed' }) {
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  return (
    <div className="cyber-card overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800">
        <MessageSquare className="w-4 h-4 text-cyan-400" />
        <span className="font-mono text-sm font-semibold text-slate-300">{title}</span>
        <span className="ml-auto text-[11px] font-mono text-slate-600">{messages.length} messages</span>
      </div>
      <div className="overflow-y-auto" style={{ maxHeight }}>
        {messages.length === 0 ? (
          <div className="flex items-center justify-center py-10">
            <p className="font-mono text-xs text-slate-600">Waiting for agent communications...</p>
          </div>
        ) : (
          <>
            {messages.map((msg, i) => (
              <AgentFeedItem key={msg.id || i} msg={msg} />
            ))}
            <div ref={bottomRef} />
          </>
        )}
      </div>
    </div>
  )
}
