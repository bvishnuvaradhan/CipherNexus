import { useState, useEffect, useCallback } from 'react'
import { AlertTriangle, RefreshCw, Bell } from 'lucide-react'
import { alertsAPI } from '../services/api'
import { useWebSocket } from '../services/websocket'
import { SeverityBadge, StatusBadge, PageHeader, Spinner, EmptyState, Timestamp, StatCard } from '../components/ui'

export default function ThreatAlerts() {
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState('all')
  const [newCount, setNewCount] = useState(0)

  const load = useCallback(async () => {
    try {
      const [a, s] = await Promise.allSettled([alertsAPI.list(100), alertsAPI.stats()])
      if (a.status === 'fulfilled') setAlerts(a.value.data.alerts || [])
      if (s.status === 'fulfilled') setStats(s.value.data)
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => { const id = setInterval(load, 12000); return () => clearInterval(id) }, [load])

  const handleWs = useCallback((msg) => {
    if (msg.type === 'alert') {
      setAlerts(p => [msg.data, ...p].slice(0, 100))
      setNewCount(p => p + 1)
    }
  }, [])
  useWebSocket(handleWs)

  const filtered = severityFilter === 'all'
    ? alerts
    : alerts.filter(a => a.severity === severityFilter)

  return (
    <div className="p-4 lg:p-6 space-y-5 animate-fade-in">
      <PageHeader
        title="Threat Alerts"
        subtitle="Active and historical threat detections"
        icon={AlertTriangle}
      >
        {newCount > 0 && (
          <div className="flex items-center gap-1.5 px-3 py-1 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-mono">
            <Bell className="w-3 h-3" />
            {newCount} new
          </div>
        )}
        <button onClick={() => { load(); setNewCount(0) }} className="btn-cyber text-xs px-3 py-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </PageHeader>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Alerts" value={stats.total || 0} color="cyan" icon={AlertTriangle} />
        <StatCard label="Critical" value={stats.critical || 0} color="rose" icon={AlertTriangle} />
        <StatCard label="High" value={stats.high || 0} color="orange" icon={AlertTriangle} />
        <StatCard label="Active" value={stats.active || 0} color="yellow" icon={Bell} />
      </div>

      {/* Severity filter */}
      <div className="flex gap-2 flex-wrap">
        {['all','critical','high','medium','low'].map(s => (
          <button
            key={s}
            onClick={() => setSeverityFilter(s)}
            className={`px-4 py-1.5 rounded border text-[11px] font-mono font-semibold uppercase transition-all ${
              severityFilter === s
                ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-400'
                : 'border-slate-700 text-slate-500 hover:text-slate-300'
            }`}
          >
            {s} {s !== 'all' && stats[s] !== undefined ? `(${stats[s]})` : ''}
          </button>
        ))}
      </div>

      {/* Alerts table */}
      <div className="cyber-card overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-12"><Spinner /></div>
        ) : filtered.length === 0 ? (
          <EmptyState icon={AlertTriangle} message="No alerts match the selected filter" />
        ) : (
          <div className="overflow-x-auto">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Threat Type</th>
                  <th>Source IP</th>
                  <th>Severity</th>
                  <th>Agent</th>
                  <th>Status</th>
                  <th>Confidence</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a, i) => (
                  <tr key={a.id || i} className="animate-fade-in">
                    <td><Timestamp value={a.timestamp} /></td>
                    <td className="text-slate-300 font-semibold">{a.event}</td>
                    <td>
                      <span className="font-mono text-cyan-400/80 text-xs">{a.source_ip || '—'}</span>
                    </td>
                    <td><SeverityBadge level={a.severity} /></td>
                    <td>
                      <span className={`font-mono text-xs font-semibold ${
                        a.agent === 'Sentry' ? 'text-cyan-400' :
                        a.agent === 'Detective' ? 'text-purple-400' :
                        'text-yellow-400'
                      }`}>{a.agent}</span>
                    </td>
                    <td><StatusBadge status={a.status} /></td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1 rounded-full bg-slate-800 overflow-hidden">
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${Math.round((a.confidence || 0) * 100)}%`,
                              background: (a.confidence || 0) >= 0.8 ? '#f43f5e' : '#22d3ee',
                            }}
                          />
                        </div>
                        <span className="text-[11px] font-mono text-slate-400">
                          {Math.round((a.confidence || 0) * 100)}%
                        </span>
                      </div>
                    </td>
                    <td className="text-slate-500 max-w-[180px]">
                      <span className="block truncate text-[11px]" title={JSON.stringify(a.details)}>
                        {a.details ? Object.entries(a.details).slice(0, 2).map(([k, v]) => `${k}: ${v}`).join(' · ') : '—'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <p className="text-[11px] font-mono text-slate-700 text-right">
        Showing {filtered.length} of {alerts.length} alerts
      </p>
    </div>
  )
}
