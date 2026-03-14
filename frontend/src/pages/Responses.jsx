import { Fragment, useState, useEffect, useCallback } from 'react'
import { Database, RefreshCw, Shield, Brain, ChevronDown, ChevronRight } from 'lucide-react'
import { responsesAPI } from '../services/api'
import { useWebSocket } from '../services/websocket'
import { StatusBadge, PageHeader, Spinner, EmptyState, Timestamp, StatCard, ConfidenceBar } from '../components/ui'

function normalizeResponses(rows = []) {
  const list = [...rows]

  // If an incident is resolved, hide older monitoring rows for the same incident.
  const resolvedAlertIds = new Set(
    list
      .filter((r) => r?.status === 'resolved' && r?.related_alert_id)
      .map((r) => r.related_alert_id)
  )

  const filtered = list.filter((r) => {
    if (r?.status !== 'monitoring') return true
    if (!r?.related_alert_id) return true
    return !resolvedAlertIds.has(r.related_alert_id)
  })

  return filtered.sort((a, b) => String(b?.timestamp || '').localeCompare(String(a?.timestamp || '')))
}

function buildStatsFromResponses(rows = []) {
  const stats = { total: rows.length, blocked: 0, monitoring: 0, resolved: 0 }
  for (const r of rows) {
    const status = String(r?.status || '').toLowerCase()
    if (status === 'blocked') stats.blocked += 1
    if (status === 'monitoring') stats.monitoring += 1
    if (status === 'resolved') stats.resolved += 1
  }
  return stats
}

// ── XAI Reasoning Expander ────────────────────────────────────────────
function ReasoningPanel({ reasoning, signals = [] }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen(p => !p)}
        className="flex items-center gap-1.5 text-[11px] font-mono text-cyan-400/70 hover:text-cyan-400 transition-colors"
      >
        {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        <Brain className="w-3 h-3" />
        XAI Reasoning
      </button>
      {open && (
        <div className="mt-2 p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2 animate-fade-in">
          {/* Signal chain */}
          {signals.length > 0 && (
            <div className="space-y-1">
              {signals.map((s, i) => (
                <div key={i} className="flex items-start gap-2 text-[11px] font-mono">
                  <span className="text-slate-700 shrink-0 mt-0.5">{i + 1}.</span>
                  <span className={`shrink-0 font-semibold ${
                    s.startsWith('[Sentry]') ? 'text-cyan-400' :
                    s.startsWith('[Detective]') ? 'text-purple-400' :
                    s.startsWith('[Commander]') ? 'text-yellow-400' :
                    'text-slate-400'
                  }`}>
                    {s.match(/^\[.*?\]/)?.[0]}
                  </span>
                  <span className="text-slate-500">{s.replace(/^\[.*?\]\s*/, '')}</span>
                </div>
              ))}
            </div>
          )}
          {/* Full reasoning string */}
          <p className="text-[11px] font-mono text-slate-500 leading-relaxed pt-2 border-t border-slate-800">
            {reasoning}
          </p>
        </div>
      )}
    </div>
  )
}

// ── Response Row (expanded card on mobile, table row on desktop) ──────
function ResponseCard({ resp }) {
  const statusGlow = {
    blocked:    'shadow-glow-rose',
    monitoring: '',
    resolved:   'shadow-glow-emerald',
  }

  return (
    <div className={`cyber-card p-4 ${statusGlow[resp.status] || ''} animate-fade-in`}>
      <div className="flex flex-wrap items-start gap-3 mb-3">
        <div className="flex-1 min-w-0">
          <p className="font-mono text-sm font-semibold text-slate-200 truncate">{resp.action}</p>
          <p className="text-[11px] font-mono text-slate-600 mt-0.5">
            Target: <span className="text-cyan-400">{resp.target}</span>
            {' · '}Agent: <span className={`font-semibold ${
              resp.agent === 'Sentry' ? 'text-cyan-400' :
              resp.agent === 'Detective' ? 'text-purple-400' :
              'text-yellow-400'
            }`}>{resp.agent}</span>
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <StatusBadge status={resp.status} />
          <Timestamp value={resp.timestamp} />
        </div>
      </div>

      <div className="mb-2">
        <p className="text-[11px] font-mono text-slate-600 mb-1">Confidence Score</p>
        <ConfidenceBar value={resp.confidence} />
      </div>

      <ReasoningPanel reasoning={resp.reasoning} signals={resp.signals || []} />
    </div>
  )
}

// ── Table view for larger screens ─────────────────────────────────────
function ResponseTable({ responses }) {
  const [expanded, setExpanded] = useState(null)

  return (
    <div className="cyber-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="cyber-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Target</th>
              <th>Agent</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>XAI</th>
            </tr>
          </thead>
          <tbody>
            {responses.map((r, i) => (
              <Fragment key={r.id || `row-${i}`}>
                <tr className="cursor-pointer" onClick={() => setExpanded(expanded === i ? null : i)}>
                  <td><Timestamp value={r.timestamp} /></td>
                  <td className="text-slate-300 font-semibold max-w-[200px]">
                    <span className="block truncate">{r.action}</span>
                  </td>
                  <td className="text-cyan-400/80">{r.target}</td>
                  <td>
                    <span className={`font-semibold ${
                      r.agent === 'Sentry' ? 'text-cyan-400' :
                      r.agent === 'Detective' ? 'text-purple-400' :
                      'text-yellow-400'
                    }`}>{r.agent}</span>
                  </td>
                  <td style={{ minWidth: 140 }}>
                    <ConfidenceBar value={r.confidence} />
                  </td>
                  <td><StatusBadge status={r.status} /></td>
                  <td>
                    <button
                      className="flex items-center gap-1 text-[11px] font-mono text-cyan-400/60 hover:text-cyan-400 transition-colors"
                      onClick={e => { e.stopPropagation(); setExpanded(expanded === i ? null : i) }}
                    >
                      <ChevronDown className={`w-3 h-3 transition-transform ${expanded === i ? 'rotate-180' : ''}`} />
                      {expanded === i ? 'hide' : 'view'}
                    </button>
                  </td>
                </tr>
                {expanded === i && (
                  <tr className="bg-slate-900/80 border-t-2 border-cyan-500/20">
                    <td colSpan={7} className="px-4 py-4">
                      <div className="space-y-3 animate-fade-in">
                        {(r.signals || []).length > 0 && (
                          <div className="space-y-2">
                            <p className="text-[10px] font-mono font-semibold text-cyan-400 uppercase tracking-wider">Signal Chain</p>
                            {r.signals.map((s, si) => (
                              <div key={si} className="flex items-start gap-2 text-[11px] font-mono bg-slate-950/40 p-2 rounded border-l-2 border-cyan-500/30">
                                <span className="text-slate-600 shrink-0 font-semibold">{si + 1}.</span>
                                <span className={`shrink-0 font-bold ${
                                  s.startsWith('[Sentry]') ? 'text-cyan-400' :
                                  s.startsWith('[Detective]') ? 'text-purple-400' :
                                  s.startsWith('[Commander]') ? 'text-yellow-400' : 'text-slate-400'
                                }`}>{s.match(/^\[.*?\]/)?.[0]}</span>
                                <span className="text-slate-300">{s.replace(/^\[.*?\]\s*/, '')}</span>
                              </div>
                            ))}
                          </div>
                        )}
                        {r.reasoning && (
                          <div className="bg-slate-950/40 border border-slate-800 rounded p-3 space-y-1">
                            <p className="text-[10px] font-mono font-semibold text-cyan-400 uppercase tracking-wider">XAI Reasoning</p>
                            <p className="text-[11px] font-mono text-slate-300 leading-relaxed">
                              {r.reasoning}
                            </p>
                          </div>
                        )}
                        {(!r.reasoning && (!r.signals || r.signals.length === 0)) && (
                          <p className="text-[11px] font-mono text-slate-600 italic">No reasoning data available</p>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────
export default function Responses() {
  const [responses, setResponses] = useState([])
  const [stats, setStats] = useState({})
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState('all')
  const [viewMode, setViewMode] = useState('table') // table | cards

  const load = useCallback(async () => {
    try {
      const [r, s] = await Promise.allSettled([
        responsesAPI.list(100),
        responsesAPI.stats(),
      ])
      if (r.status === 'fulfilled') {
        const normalized = normalizeResponses(r.value.data.responses || [])
        setResponses(normalized)
        setStats(buildStatsFromResponses(normalized))
      } else if (s.status === 'fulfilled') {
        setStats(s.value.data)
      }
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => { const id = setInterval(load, 10000); return () => clearInterval(id) }, [load])

  const handleWs = useCallback((msg) => {
    if (msg.type === 'response') {
      setResponses((p) => {
        const normalized = normalizeResponses([msg.data, ...p]).slice(0, 100)
        setStats(buildStatsFromResponses(normalized))
        return normalized
      })
    }
  }, [])
  useWebSocket(handleWs)

  const filtered = statusFilter === 'all'
    ? responses
    : responses.filter(r => r.status === statusFilter)

  return (
    <div className="p-4 lg:p-6 space-y-5 animate-fade-in">
      <PageHeader
        title="Automated Responses"
        subtitle="Commander-issued actions with Explainable AI (XAI) reasoning"
        icon={Database}
      >
        <div className="flex gap-1 p-1 rounded-lg border border-slate-700">
          <button
            onClick={() => setViewMode('table')}
            className={`px-3 py-1 rounded text-[11px] font-mono transition-all ${
              viewMode === 'table' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-600 hover:text-slate-400'
            }`}
          >Table</button>
          <button
            onClick={() => setViewMode('cards')}
            className={`px-3 py-1 rounded text-[11px] font-mono transition-all ${
              viewMode === 'cards' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-600 hover:text-slate-400'
            }`}
          >Cards</button>
        </div>
        <button onClick={load} className="btn-cyber text-xs px-3 py-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </PageHeader>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Responses" value={stats.total || 0} icon={Database} color="cyan" />
        <StatCard label="IPs Blocked" value={stats.blocked || 0} icon={Shield} color="rose" sub="Glowing red ●" />
        <StatCard label="Monitoring" value={stats.monitoring || 0} icon={Database} color="yellow" sub="Yellow pulse ●" />
        <StatCard label="Resolved" value={stats.resolved || 0} icon={Shield} color="emerald" sub="Green ●" />
      </div>

      {/* XAI info banner */}
      <div className="flex items-start gap-3 p-4 rounded-lg bg-cyan-500/5 border border-cyan-500/15">
        <Brain className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs font-mono text-slate-400">
          <span className="text-cyan-400 font-semibold">EXPLAINABLE AI (XAI) — </span>
          Every automated response includes a reasoning path built from multi-agent signal correlation.
          Click <span className="text-cyan-400">view</span> on any row or expand a card to see the full
          Sentry → Detective → Commander reasoning chain and confidence score.
        </div>
      </div>

      {/* Status filter */}
      <div className="flex gap-2 flex-wrap">
        {['all', 'blocked', 'monitoring', 'resolved'].map(s => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={`px-4 py-1.5 rounded border text-[11px] font-mono font-semibold uppercase transition-all ${
              statusFilter === s
                ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-400'
                : 'border-slate-700 text-slate-500 hover:text-slate-300'
            }`}
          >
            {s} {s !== 'all' && stats[s] !== undefined ? `(${stats[s]})` : ''}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-12"><Spinner size="lg" /></div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={Shield}
          message="No responses yet — run a simulation from the Attack Simulator to generate automated responses"
        />
      ) : viewMode === 'table' ? (
        <ResponseTable responses={filtered} />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filtered.map((r, i) => <ResponseCard key={r.id || i} resp={r} />)}
        </div>
      )}

      <p className="text-[11px] font-mono text-slate-700 text-right">
        Showing {filtered.length} of {responses.length} responses
      </p>
    </div>
  )
}
