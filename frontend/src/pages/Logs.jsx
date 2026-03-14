import { useState, useEffect, useCallback } from 'react'
import { Terminal, RefreshCw, Filter, Download, ChevronDown } from 'lucide-react'
import { logsAPI } from '../services/api'
import { useWebSocket } from '../services/websocket'
import { SeverityBadge, PageHeader, Spinner, EmptyState, Timestamp } from '../components/ui'

const EVENT_TYPE_LABELS = {
  login_success: 'Login Success',
  login_failed: 'Login Failed',
  port_scan: 'Port Scan',
  traffic_spike: 'Traffic Spike',
  data_transfer: 'Data Transfer',
  firewall_block: 'Firewall Block',
  system_event: 'System Event',
  agent_action: 'Agent Action',
}

const AGENT_COLORS = {
  Sentry: 'text-cyan-400',
  Detective: 'text-purple-400',
  Commander: 'text-yellow-400',
}

export default function Logs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all') // all | critical | high | medium | low
  const [agentFilter, setAgentFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [liveMode, setLiveMode] = useState(true)
  const [expandedLogId, setExpandedLogId] = useState(null)

  const load = useCallback(async () => {
    try {
      const res = await logsAPI.list(200)
      setLogs(res.data.logs || [])
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    if (!liveMode) return
    const id = setInterval(load, 8000)
    return () => clearInterval(id)
  }, [load, liveMode])

  const handleWs = useCallback((msg) => {
    if (msg.type === 'log' && liveMode) {
      setLogs(p => [msg.data, ...p].slice(0, 200))
    }
  }, [liveMode])
  useWebSocket(handleWs)

  const filtered = logs.filter(log => {
    if (filter !== 'all' && log.severity !== filter) return false
    if (agentFilter !== 'all' && log.agent !== agentFilter) return false
    if (search && !log.message?.toLowerCase().includes(search.toLowerCase()) &&
        !log.source_ip?.includes(search)) return false
    return true
  })

  return (
    <div className="p-4 lg:p-6 space-y-5 animate-fade-in">
      <PageHeader
        title="Log Monitoring"
        subtitle="Real-time system & agent event logs"
        icon={Terminal}
      >
        <button onClick={load} className="btn-cyber text-xs px-3 py-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </PageHeader>

      {/* Filters */}
      <div className="cyber-card p-4">
        <div className="flex flex-wrap gap-3 items-center">
          <Filter className="w-4 h-4 text-slate-500 shrink-0" />

          {/* Severity filter */}
          <div className="flex gap-1.5 flex-wrap">
            {['all','critical','high','medium','low'].map(s => (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={`px-3 py-1 rounded text-[11px] font-mono font-semibold uppercase transition-all ${
                  filter === s
                    ? 'bg-cyan-500/20 border border-cyan-500/40 text-cyan-400'
                    : 'border border-slate-700 text-slate-500 hover:text-slate-300 hover:border-slate-600'
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="w-px h-4 bg-slate-700 hidden sm:block" />

          {/* Agent filter */}
          <div className="flex gap-1.5 flex-wrap">
            {['all','Sentry','Detective','Commander'].map(a => (
              <button
                key={a}
                onClick={() => setAgentFilter(a)}
                className={`px-3 py-1 rounded text-[11px] font-mono font-semibold transition-all ${
                  agentFilter === a
                    ? 'bg-cyan-500/20 border border-cyan-500/40 text-cyan-400'
                    : 'border border-slate-700 text-slate-500 hover:text-slate-300 hover:border-slate-600'
                }`}
              >
                {a}
              </button>
            ))}
          </div>

          {/* Search */}
          <div className="ml-auto">
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search logs..."
              className="w-48 px-3 py-1.5 rounded bg-slate-950 border border-slate-700 text-xs font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          {/* Live toggle */}
          <button
            onClick={() => setLiveMode(p => !p)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded border text-[11px] font-mono font-semibold transition-all ${
              liveMode
                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                : 'border-slate-700 text-slate-500'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full bg-current ${liveMode ? 'animate-pulse' : ''}`} />
            LIVE
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total', val: logs.length, color: 'text-slate-300' },
          { label: 'Critical', val: logs.filter(l => l.severity === 'critical').length, color: 'text-rose-400' },
          { label: 'High', val: logs.filter(l => l.severity === 'high').length, color: 'text-orange-400' },
          { label: 'Filtered', val: filtered.length, color: 'text-cyan-400' },
        ].map(s => (
          <div key={s.label} className="cyber-card px-4 py-3 text-center">
            <p className={`font-display font-bold text-xl ${s.color}`}>{s.val}</p>
            <p className="text-[11px] font-mono text-slate-600 uppercase">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Logs table */}
      <div className="cyber-card overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-12"><Spinner size="lg" /></div>
        ) : filtered.length === 0 ? (
          <EmptyState icon={Terminal} message="No logs match the current filters" />
        ) : (
          <div className="overflow-x-auto">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event Type</th>
                  <th>Agent</th>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th className="w-1/3">Message</th>
                </tr>
              </thead>
              <tbody>
                {filtered.flatMap((log, i) => {
                  const isForensics = log.agent === 'Forensics'
                  const rows = [
                    <tr 
                      key={`${log.id}-main`}
                      className={`animate-fade-in transition-colors ${isForensics ? 'hover:bg-slate-900/40 cursor-pointer' : ''}`}
                      onClick={() => isForensics && setExpandedLogId(expandedLogId === log.id ? null : log.id)}
                    >
                      <td>
                        <div className="flex items-center gap-2">
                          {isForensics && log.details && (
                            <ChevronDown 
                              className={`w-3.5 h-3.5 text-slate-500 transition-transform ${expandedLogId === log.id ? 'rotate-180' : ''}`}
                            />
                          )}
                          <Timestamp value={log.timestamp} />
                        </div>
                      </td>
                      <td className="text-slate-400">
                        {EVENT_TYPE_LABELS[log.event_type] || log.event_type}
                      </td>
                      <td>
                        <span className={`font-semibold ${AGENT_COLORS[log.agent] || 'text-slate-400'}`}>
                          {log.agent}
                        </span>
                      </td>
                      <td><SeverityBadge level={log.severity} /></td>
                      <td className="text-cyan-400/70">{log.source_ip || '—'}</td>
                      <td className="text-slate-400 max-w-xs">
                        <span className="block truncate" title={log.message}>{log.message}</span>
                      </td>
                    </tr>
                  ]
                  
                  if (isForensics && expandedLogId === log.id && log.details) {
                    rows.push(
                      <tr key={`${log.id}-details`} className="bg-slate-950/60 animate-fade-in">
                        <td colSpan="6" className="p-4">
                          <div className="space-y-3">
                            {log.details.summary && (
                              <div>
                                <p className="text-xs font-mono font-semibold text-cyan-400 uppercase mb-1">Summary</p>
                                <p className="text-sm text-slate-300 bg-slate-900/40 p-2 rounded border border-slate-800">
                                  {log.details.summary}
                                </p>
                              </div>
                            )}
                            {log.details.timeline && Array.isArray(log.details.timeline) && (
                              <div>
                                <p className="text-xs font-mono font-semibold text-cyan-400 uppercase mb-2">Timeline</p>
                                <div className="space-y-1.5 max-h-64 overflow-y-auto">
                                  {log.details.timeline.map((event, idx) => (
                                    <div 
                                      key={idx}
                                      className="flex gap-3 text-xs text-slate-400 bg-slate-900/30 p-2 rounded border-l-2 border-cyan-500/30"
                                    >
                                      <span className="text-cyan-500 font-semibold shrink-0">[{idx + 1}]</span>
                                      <span>{event}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  }
                  
                  return rows
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <p className="text-[11px] font-mono text-slate-700 text-right">
        Showing {filtered.length} of {logs.length} log entries
      </p>
    </div>
  )
}
