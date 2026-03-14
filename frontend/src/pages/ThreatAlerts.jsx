import React, { useState, useEffect, useCallback } from 'react'
import { AlertTriangle, RefreshCw, Bell, ChevronDown, ChevronUp, FileText, Brain, Shield, Clock, Loader } from 'lucide-react'
import { alertsAPI, logsAPI } from '../services/api'
import { useWebSocket } from '../services/websocket'
import { SeverityBadge, StatusBadge, PageHeader, Spinner, EmptyState, Timestamp, StatCard, ConfidenceBar } from '../components/ui'

const ATTACK_TYPE_META = {
  brute_force:      { label: 'Brute Force',      color: 'text-rose-400',   bg: 'bg-rose-500/10 border-rose-500/20' },
  port_scan:        { label: 'Port Scan',         color: 'text-cyan-400',   bg: 'bg-cyan-500/10 border-cyan-500/20' },
  suspicious_login: { label: 'Suspicious Login',  color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/20' },
  data_exfiltration:{ label: 'Data Exfiltration', color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
  traffic_spike:    { label: 'Traffic Spike',     color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
  malware:          { label: 'Malware',            color: 'text-red-400',    bg: 'bg-red-500/10 border-red-500/20' },
  ddos:             { label: 'DDoS',               color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
  sql_injection:    { label: 'SQL Injection',      color: 'text-rose-400',   bg: 'bg-rose-500/10 border-rose-500/20' },
  xss:              { label: 'XSS',                color: 'text-pink-400',   bg: 'bg-pink-500/10 border-pink-500/20' },
  ransomware:       { label: 'Ransomware',          color: 'text-red-400',   bg: 'bg-red-600/10 border-red-600/20' },
  mitm:             { label: 'MITM',               color: 'text-violet-400', bg: 'bg-violet-500/10 border-violet-500/20' },
  dns_spoofing:     { label: 'DNS Spoofing',       color: 'text-emerald-400',bg: 'bg-emerald-500/10 border-emerald-500/20' },
  command_control:  { label: 'C2 Beacon',          color: 'text-amber-400',  bg: 'bg-amber-500/10 border-amber-500/20' },
}

// Helper to parse UTC timestamps correctly (backend sends without Z suffix)
function parseUtcTimestamp(value) {
  if (!value) return null
  let ts = value
  if (typeof ts === 'string' && !ts.endsWith('Z') && !ts.includes('+') && !ts.includes('-', 10)) {
    ts = ts + 'Z'
  }
  return new Date(ts)
}

function AttackTypeBadge({ type }) {
  const meta = ATTACK_TYPE_META[type] || { label: type?.replace(/_/g, ' ')?.toUpperCase() || '—', color: 'text-slate-400', bg: 'bg-slate-800 border-slate-700' }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border font-mono text-[10px] font-bold uppercase tracking-wide ${meta.color} ${meta.bg}`}>
      {meta.label}
    </span>
  )
}

function AlertDetailPanel({ detail, loading, alert, logs = [] }) {
  if (loading) {
    return (
      <div className="p-8 flex items-center justify-center gap-3 bg-slate-900/50 border-t border-slate-800">
        <Loader className="w-5 h-5 text-cyan-400 animate-spin" />
        <span className="font-mono text-xs text-slate-400">Loading threat analysis...</span>
      </div>
    )
  }

  const resp = detail?.commander_response
  const recs = detail?.recommendations || []
  const details = alert?.details || detail?.alert?.details || {}

  const detectionTime = parseUtcTimestamp(alert?.timestamp)
  const responseTime = parseUtcTimestamp(resp?.timestamp)
  const deltaMs = detectionTime && responseTime ? responseTime - detectionTime : null

  return (
    <div className="border-t border-slate-800 bg-slate-900/60 p-5 space-y-4 animate-fade-in">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Attack Details */}
        <div className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span className="font-mono text-xs font-bold text-slate-300 uppercase tracking-wider">Attack Details</span>
          </div>
          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {Object.entries(details).length === 0 ? (
              <p className="font-mono text-xs text-slate-600">No additional details available</p>
            ) : (
              Object.entries(details).map(([k, v]) => (
                <div key={k} className="flex gap-3 font-mono text-xs">
                  <span className="text-slate-600 min-w-[130px] shrink-0">{k.replace(/_/g, ' ')}:</span>
                  <span className="text-slate-300 break-all">
                    {Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v)}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Commander Analysis */}
        <div className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800">
            <Brain className="w-4 h-4 text-yellow-400" />
            <span className="font-mono text-xs font-bold text-slate-300 uppercase tracking-wider">Commander Analysis</span>
          </div>
          {resp ? (
            <div className="space-y-3">
              <div>
                <p className="text-[10px] font-mono text-slate-600 uppercase mb-1">XAI Reasoning Chain</p>
                <p className="font-mono text-xs text-slate-300 leading-relaxed">{resp.reasoning}</p>
              </div>
              {resp.signals?.length > 0 && (
                <div>
                  <p className="text-[10px] font-mono text-slate-600 uppercase mb-1">Signals</p>
                  {resp.signals.map((s, i) => (
                    <p key={i} className="font-mono text-[11px] text-slate-400">{s}</p>
                  ))}
                </div>
              )}
              <div className="flex items-center gap-4 pt-2">
                <StatusBadge status={resp.status} />
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] text-slate-600">Confidence:</span>
                  <ConfidenceBar value={resp.confidence} />
                </div>
              </div>
            </div>
          ) : (
            <p className="font-mono text-xs text-slate-600">Awaiting commander analysis...</p>
          )}
        </div>

        {/* Recommendations */}
        <div className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span className="font-mono text-xs font-bold text-slate-300 uppercase tracking-wider">Recommended Actions</span>
          </div>
          {recs.length === 0 ? (
            <p className="font-mono text-xs text-slate-600">No recommendations available</p>
          ) : (
            <ol className="space-y-2">
              {recs.slice(0, 5).map((rec, i) => (
                <li key={i} className="flex gap-2 font-mono text-xs">
                  <span className="text-cyan-400 font-bold shrink-0">{i + 1}.</span>
                  <span className={i === 0 && rec.startsWith('CRITICAL') ? 'text-rose-400 font-semibold' : 'text-slate-300'}>
                    {rec}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </div>

        {/* Timeline */}
        <div className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800">
            <Clock className="w-4 h-4 text-purple-400" />
            <span className="font-mono text-xs font-bold text-slate-300 uppercase tracking-wider">Timeline</span>
          </div>
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-rose-500" />
              <div>
                <p className="font-mono text-[10px] text-slate-600 uppercase">Detected</p>
                <p className="font-mono text-xs text-slate-300">{detectionTime?.toLocaleString() || '—'}</p>
              </div>
            </div>
            {resp && (
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-cyan-500" />
                <div>
                  <p className="font-mono text-[10px] text-slate-600 uppercase">Response Generated</p>
                  <p className="font-mono text-xs text-slate-300">{responseTime?.toLocaleString() || '—'}</p>
                </div>
              </div>
            )}
            {deltaMs !== null && (
              <div className="pt-2 border-t border-slate-800">
                <p className="font-mono text-[10px] text-slate-600 uppercase">Time to Respond</p>
                <p className="font-mono text-sm text-emerald-400 font-bold">{deltaMs < 1000 ? `${deltaMs}ms` : `${(deltaMs / 1000).toFixed(2)}s`}</p>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="cyber-card p-4">
        <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800">
          <FileText className="w-4 h-4 text-cyan-400" />
          <span className="font-mono text-xs font-bold text-slate-300 uppercase tracking-wider">Related Logs</span>
          <span className="ml-auto text-[10px] font-mono text-slate-600">{logs.length} entries</span>
        </div>
        {logs.length === 0 ? (
          <p className="font-mono text-xs text-slate-600">No contextual logs found for this alert</p>
        ) : (
          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {logs.map((log, i) => (
              <div key={`${log.id || 'log'}-${i}`} className="rounded border border-slate-800 bg-slate-950/50 px-3 py-2">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-[10px] text-slate-600 uppercase">{log.event_type || 'event'}</span>
                  <span className="ml-auto"><Timestamp value={log.timestamp} /></span>
                </div>
                <p className="font-mono text-xs text-slate-300 leading-relaxed">{log.message || '—'}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default function ThreatAlerts() {
  const PAGE_SIZE = 10

  const formatLocalDateTime = (date) => {
    const d = new Date(date)
    const y = d.getFullYear()
    const m = String(d.getMonth() + 1).padStart(2, '0')
    const day = String(d.getDate()).padStart(2, '0')
    const h = String(d.getHours()).padStart(2, '0')
    const min = String(d.getMinutes()).padStart(2, '0')
    return `${y}-${m}-${day}T${h}:${min}`
  }

  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState('all')
  const [page, setPage] = useState(1)
  const [newCount, setNewCount] = useState(0)
  const [expandedId, setExpandedId] = useState(null)
  const [alertDetail, setAlertDetail] = useState(null)
  const [alertLogs, setAlertLogs] = useState([])
  const [detailLoading, setDetailLoading] = useState(false)
  const [reportFrom, setReportFrom] = useState(() => formatLocalDateTime(Date.now() - 24 * 60 * 60 * 1000))
  const [reportTo, setReportTo] = useState(() => formatLocalDateTime(Date.now()))
  const [reportCategories, setReportCategories] = useState([])
  const [downloadingReport, setDownloadingReport] = useState(false)

  const load = useCallback(async () => {
    try {
      const [a, s] = await Promise.allSettled([alertsAPI.list(100), alertsAPI.stats()])
      if (a.status === 'fulfilled') setAlerts((a.value.data.alerts || []).slice(0, 100))
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

  const handleRowClick = useCallback(async (alert) => {
    if (expandedId === alert.id) {
      setExpandedId(null)
      setAlertDetail(null)
      setAlertLogs([])
      return
    }
    setExpandedId(alert.id)
    setDetailLoading(true)
    setAlertDetail(null)
    setAlertLogs([])
    try {
      const [detailRes, logsRes] = await Promise.allSettled([
        alertsAPI.detail(alert.id),
        logsAPI.forAlert(alert.id, 100),
      ])

      if (detailRes.status === 'fulfilled') {
        setAlertDetail(detailRes.value.data)
      } else {
        setAlertDetail({ alert, commander_response: null, recommendations: [] })
      }

      if (logsRes.status === 'fulfilled') {
        setAlertLogs(logsRes.value.data.logs || [])
      }
    } catch {
      setAlertDetail({ alert, commander_response: null, recommendations: [] })
    } finally {
      setDetailLoading(false)
    }
  }, [expandedId])

  const filtered = severityFilter === 'all'
    ? alerts
    : alerts.filter(a => a.severity === severityFilter)

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const currentPage = Math.min(page, totalPages)
  const pagedAlerts = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE)

  useEffect(() => {
    setPage(1)
  }, [severityFilter])

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages)
    }
  }, [page, totalPages])

  const toggleReportCategory = useCallback((type) => {
    setReportCategories((prev) => (
      prev.includes(type) ? prev.filter((item) => item !== type) : [...prev, type]
    ))
  }, [])

  const downloadReport = useCallback(async () => {
    if (!reportFrom || !reportTo) return
    setDownloadingReport(true)
    try {
      const startIso = new Date(reportFrom).toISOString().replace('Z', '')
      const endIso = new Date(reportTo).toISOString().replace('Z', '')
      const response = await alertsAPI.reportCsv(startIso, endIso, severityFilter, reportCategories)
      const blobUrl = URL.createObjectURL(new Blob([response.data], { type: 'text/csv;charset=utf-8;' }))
      const link = document.createElement('a')
      const safeFrom = reportFrom.replace(/[:T]/g, '-').slice(0, 16)
      const safeTo = reportTo.replace(/[:T]/g, '-').slice(0, 16)
      const categorySuffix = reportCategories.length > 0 ? `-${reportCategories.length}-cats` : '-all-cats'
      link.href = blobUrl
      link.setAttribute('download', `threat-alerts-report-${safeFrom}-to-${safeTo}${categorySuffix}.csv`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(blobUrl)
    } finally {
      setDownloadingReport(false)
    }
  }, [reportFrom, reportTo, severityFilter, reportCategories])

  return (
    <div className="p-4 lg:p-6 space-y-5 animate-fade-in">
      <PageHeader
        title="Threat Alerts"
        subtitle="Active and historical threat detections — click a row for details"
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
            onClick={() => {
              setSeverityFilter(s)
              setExpandedId(null)
              setAlertDetail(null)
              setAlertLogs([])
            }}
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

      {/* Report download */}
      <div className="cyber-card p-4">
        <div className="flex flex-col lg:flex-row lg:items-end gap-3">
          <div className="flex-1 min-w-[200px]">
            <p className="text-[10px] font-mono text-slate-600 uppercase mb-1">Report From</p>
            <input
              type="datetime-local"
              value={reportFrom}
              onChange={(e) => setReportFrom(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-slate-300"
            />
          </div>
          <div className="flex-1 min-w-[200px]">
            <p className="text-[10px] font-mono text-slate-600 uppercase mb-1">Report To</p>
            <input
              type="datetime-local"
              value={reportTo}
              onChange={(e) => setReportTo(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-slate-300"
            />
          </div>
          <div className="lg:pb-0.5">
            <button
              onClick={downloadReport}
              disabled={downloadingReport || !reportFrom || !reportTo}
              className="btn-cyber text-xs px-3 py-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {downloadingReport ? (
                <><Loader className="w-3.5 h-3.5 animate-spin" /> Generating Report...</>
              ) : (
                <><FileText className="w-3.5 h-3.5" /> Download CSV Report</>
              )}
            </button>
          </div>
        </div>
        <div className="mt-3">
          <div className="flex items-center justify-between gap-3 mb-2">
            <p className="text-[10px] font-mono text-slate-600 uppercase">Categories (Threat Types)</p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setReportCategories(Object.keys(ATTACK_TYPE_META))}
                className="px-2 py-1 rounded border border-slate-700 text-[10px] font-mono text-slate-400 hover:text-slate-200"
              >
                Select All
              </button>
              <button
                type="button"
                onClick={() => setReportCategories([])}
                className="px-2 py-1 rounded border border-slate-700 text-[10px] font-mono text-slate-400 hover:text-slate-200"
              >
                Clear
              </button>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {Object.entries(ATTACK_TYPE_META).map(([type, meta]) => {
              const selected = reportCategories.includes(type)
              return (
                <button
                  key={type}
                  type="button"
                  onClick={() => toggleReportCategory(type)}
                  className={`px-2.5 py-1 rounded border text-[10px] font-mono font-semibold uppercase tracking-wide transition-all ${selected ? `${meta.bg} ${meta.color}` : 'border-slate-700 text-slate-500 hover:text-slate-300'}`}
                >
                  {meta.label}
                </button>
              )
            })}
          </div>
        </div>
        <p className="mt-2 text-[11px] font-mono text-slate-600">
          Exports alert records and commander analysis for the selected period and chosen categories.
        </p>
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
                  <th className="w-8"></th>
                  <th>Time</th>
                  <th>Attack Type</th>
                  <th>Event</th>
                  <th>Source IP</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {pagedAlerts.map((a, i) => (
                  <React.Fragment key={`${a.id || 'alert'}-${i}`}>
                    <tr
                      className="animate-fade-in cursor-pointer hover:bg-slate-800/40 transition-colors"
                      onClick={() => handleRowClick(a)}
                    >
                      <td className="text-center">
                        {expandedId === a.id ? (
                          <ChevronUp className="w-4 h-4 text-cyan-400 inline" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-slate-600 inline" />
                        )}
                      </td>
                      <td><Timestamp value={a.timestamp} /></td>
                      <td><AttackTypeBadge type={a.threat_type} /></td>
                      <td className="text-slate-300 font-semibold max-w-[160px]">
                        <span className="block truncate text-xs" title={a.event}>{a.event}</span>
                      </td>
                      <td>
                        <span className="font-mono text-cyan-400/80 text-xs">{a.source_ip || '—'}</span>
                      </td>
                      <td><SeverityBadge level={a.severity} /></td>
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
                    </tr>
                    {expandedId === a.id && (
                      <tr key={`${a.id || 'alert'}-${i}-detail`}>
                        <td colSpan={8} className="p-0">
                          <AlertDetailPanel detail={alertDetail} loading={detailLoading} alert={a} logs={alertLogs} />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {filtered.length > 0 && (
        <div className="flex items-center justify-between gap-3">
          <p className="text-[11px] font-mono text-slate-700">
            Page {currentPage} of {totalPages}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((prev) => Math.max(1, prev - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1.5 rounded border border-slate-700 text-[11px] font-mono text-slate-400 disabled:opacity-40 disabled:cursor-not-allowed hover:text-slate-200"
            >
              Prev
            </button>
            <button
              onClick={() => setPage((prev) => Math.min(totalPages, prev + 1))}
              disabled={currentPage === totalPages}
              className="px-3 py-1.5 rounded border border-slate-700 text-[11px] font-mono text-slate-400 disabled:opacity-40 disabled:cursor-not-allowed hover:text-slate-200"
            >
              Next
            </button>
          </div>
        </div>
      )}

      <p className="text-[11px] font-mono text-slate-700 text-right">
        Showing {pagedAlerts.length} of {filtered.length} alerts on this page • {alerts.length} total loaded • Click a row to view detailed analysis
      </p>
    </div>
  )
}
