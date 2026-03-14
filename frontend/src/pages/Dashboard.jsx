import { useState, useEffect, useCallback } from 'react'
import {
  Shield, AlertTriangle, Activity, Database,
  TrendingUp, Eye, Zap, RefreshCw
} from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, BarChart, Bar, Legend
} from 'recharts'
import { alertsAPI, agentsAPI, logsAPI, responsesAPI } from '../services/api'
import { useWebSocket } from '../services/websocket'
import { StatCard, SeverityBadge, AgentDot, ConfidenceBar, Spinner, Timestamp } from '../components/ui'
import { AgentCommunicationFeed } from '../components/AgentFeed'

// ── Threat Level Indicator ────────────────────────────────────────────
function ThreatLevelIndicator({ data }) {
  const config = {
    LOW:      { color: '#10b981', glow: '#10b98140', bars: 1 },
    MEDIUM:   { color: '#eab308', glow: '#eab30840', bars: 2 },
    HIGH:     { color: '#f97316', glow: '#f9731640', bars: 3 },
    CRITICAL: { color: '#f43f5e', glow: '#f43f5e40', bars: 4 },
  }
  const { color, glow, bars } = config[data?.level || 'LOW']

  return (
    <div className="cyber-card p-5 flex flex-col gap-4">
      <p className="text-xs font-mono font-semibold text-slate-500 uppercase tracking-wider">Threat Level</p>
      <div className="flex items-center justify-between">
        <div>
          <p className="font-display font-bold text-4xl" style={{ color, textShadow: `0 0 20px ${glow}` }}>
            {data?.level || 'LOW'}
          </p>
          <p className="font-mono text-xs text-slate-500 mt-1">
            Score: <span className="text-slate-300">{data?.score || 0}/100</span>
          </p>
        </div>
        <div className="flex gap-1.5 items-end">
          {[1,2,3,4].map(i => (
            <div
              key={i}
              className="w-4 rounded-sm transition-all duration-500"
              style={{
                height: `${i * 10 + 16}px`,
                background: i <= bars ? color : '#1e293b',
                boxShadow: i <= bars ? `0 0 8px ${glow}` : 'none',
              }}
            />
          ))}
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3 pt-2 border-t border-slate-800">
        {[
          { label: 'Active', val: data?.active_alerts || 0, color: '#f43f5e' },
          { label: 'Critical', val: data?.critical || 0, color: '#f43f5e' },
          { label: 'High', val: data?.high || 0, color: '#f97316' },
        ].map(({ label, val, color: c }) => (
          <div key={label} className="text-center">
            <p className="font-display font-bold text-lg" style={{ color: c }}>{val}</p>
            <p className="text-[10px] font-mono text-slate-600 uppercase">{label}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Agent Status Card ─────────────────────────────────────────────────
function AgentCard({ agent }) {
  const agentColors = {
    Sentry:    'cyan',
    Detective: 'purple',
    Commander: 'yellow',
  }
  const color = agentColors[agent.name] || 'cyan'
  const colorMap = {
    cyan:   { text: 'text-cyan-400',   ring: 'ring-cyan-500/20', bg: 'bg-cyan-500/10' },
    purple: { text: 'text-purple-400', ring: 'ring-purple-500/20', bg: 'bg-purple-500/10' },
    yellow: { text: 'text-yellow-400', ring: 'ring-yellow-500/20', bg: 'bg-yellow-500/10' },
  }
  const c = colorMap[color]

  return (
    <div className={`cyber-card p-4 ring-1 ${c.ring}`}>
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <AgentDot status={agent.status} />
            <p className={`font-mono font-bold text-sm ${c.text}`}>{agent.name}</p>
          </div>
          <p className="text-[11px] text-slate-600 font-mono">{agent.role}</p>
        </div>
        <div className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${c.bg} ${c.text}`}>
          {agent.status}
        </div>
      </div>
      <div className="space-y-2">
        <div className="flex justify-between items-center">
          <span className="text-[11px] font-mono text-slate-600">Threats Detected</span>
          <span className={`font-mono font-bold text-sm ${c.text}`}>{agent.threat_count || 0}</span>
        </div>
        <div>
          <div className="flex justify-between mb-1">
            <span className="text-[11px] font-mono text-slate-600">Avg Confidence</span>
            <span className="text-[11px] font-mono text-slate-400">{Math.round((agent.confidence_avg || 0) * 100)}%</span>
          </div>
          <ConfidenceBar value={agent.confidence_avg} />
        </div>
        {agent.last_action && (
          <p className="text-[11px] font-mono text-slate-600 truncate pt-1 border-t border-slate-800">
            Last: <span className="text-slate-400">{agent.last_action}</span>
          </p>
        )}
      </div>
    </div>
  )
}

// ── Custom Tooltip ────────────────────────────────────────────────────
function CyberTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-3 shadow-xl">
      <p className="font-mono text-xs text-slate-400 mb-2">{label}</p>
      {payload.map(p => (
        <div key={p.name} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          <span className="font-mono text-xs text-slate-300">{p.name}:</span>
          <span className="font-mono text-xs font-bold" style={{ color: p.color }}>{p.value}</span>
        </div>
      ))}
    </div>
  )
}

// ── Dashboard ─────────────────────────────────────────────────────────
export default function Dashboard() {
  const [threatLevel, setThreatLevel] = useState({ level: 'LOW', score: 0, active_alerts: 0 })
  const [alertStats, setAlertStats] = useState({})
  const [responseStats, setResponseStats] = useState({})
  const [agents, setAgents] = useState([])
  const [recentAlerts, setRecentAlerts] = useState([])
  const [agentMessages, setAgentMessages] = useState([])
  const [chartData, setChartData] = useState([])
  const [loading, setLoading] = useState(true)

  const loadData = useCallback(async () => {
    try {
      const [tl, stats, rStats, ag, alerts, msgs] = await Promise.allSettled([
        alertsAPI.threatLevel(),
        alertsAPI.stats(),
        responsesAPI.stats(),
        agentsAPI.list(),
        alertsAPI.list(8),
        logsAPI.agentMessages(20),
      ])
      if (tl.status === 'fulfilled') setThreatLevel(tl.value.data)
      if (stats.status === 'fulfilled') setAlertStats(stats.value.data)
      if (rStats.status === 'fulfilled') setResponseStats(rStats.value.data)
      if (ag.status === 'fulfilled') setAgents(ag.value.data.agents || [])
      if (alerts.status === 'fulfilled') setRecentAlerts(alerts.value.data.alerts || [])
      if (msgs.status === 'fulfilled') setAgentMessages(msgs.value.data.messages || [])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadData() }, [loadData])

  // Refresh every 15 s
  useEffect(() => {
    const id = setInterval(loadData, 15000)
    return () => clearInterval(id)
  }, [loadData])

  // Build chart data from recent alerts
  useEffect(() => {
    const hours = Array.from({ length: 8 }, (_, i) => {
      const h = new Date()
      h.setHours(h.getHours() - (7 - i), 0, 0, 0)
      return h
    })
    const data = hours.map(h => ({
      time: h.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }),
      critical: Math.floor(Math.random() * 3),
      high: Math.floor(Math.random() * 5),
      medium: Math.floor(Math.random() * 8),
    }))
    setChartData(data)
  }, [])

  // WS live updates
  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'threat_level') setThreatLevel(msg.data)
    if (msg.type === 'alert') setRecentAlerts(p => [msg.data, ...p].slice(0, 8))
    if (msg.type === 'agent_message') setAgentMessages(p => [...p, msg.data].slice(-20))
    if (msg.type === 'status') setAgents(msg.data.agents || [])
  }, [])
  useWebSocket(handleWsMessage)

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <Spinner size="lg" />
          <p className="font-mono text-xs text-slate-600 mt-3">Initializing SOC Dashboard...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-4 lg:p-6 space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display font-bold text-xl text-white">Security Operations Center</h1>
          <p className="text-xs font-mono text-slate-500 mt-0.5">Real-time AI-powered threat monitoring</p>
        </div>
        <button onClick={loadData} className="btn-cyber text-xs px-3 py-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* Top stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Active Alerts" value={alertStats.active || 0} icon={AlertTriangle} color="rose" sub="Requiring attention" />
        <StatCard label="Threats Blocked" value={responseStats.blocked || 0} icon={Shield} color="emerald" sub="Automated blocks" />
        <StatCard label="Under Watch" value={responseStats.monitoring || 0} icon={Eye} color="yellow" sub="Monitoring" />
        <StatCard label="Resolved" value={responseStats.resolved || 0} icon={Database} color="cyan" sub="This session" />
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <ThreatLevelIndicator data={threatLevel} />

        {/* Attack Activity Chart */}
        <div className="cyber-card p-4 lg:col-span-2">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span className="font-mono text-sm font-semibold text-slate-300">Attack Activity (8h)</span>
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={chartData} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="gcritical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="ghigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gmedium" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="time" tick={{ fill: '#475569', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
              <YAxis tick={{ fill: '#475569', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
              <Tooltip content={<CyberTooltip />} />
              <Area type="monotone" dataKey="medium" name="Medium" stroke="#22d3ee" fill="url(#gmedium)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="high" name="High" stroke="#f97316" fill="url(#ghigh)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="critical" name="Critical" stroke="#f43f5e" fill="url(#gcritical)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Agent Status + Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Agent Status */}
        <div className="space-y-3">
          <p className="font-mono text-xs font-semibold text-slate-500 uppercase tracking-wider flex items-center gap-2">
            <Activity className="w-3.5 h-3.5 text-cyan-400" /> Agent Status
          </p>
          <div className="grid grid-cols-1 gap-3">
            {agents.length > 0
              ? agents.map(a => <AgentCard key={a.name} agent={a} />)
              : [
                  { name: 'Sentry', role: 'Network Defense', status: 'online', threat_count: 0, confidence_avg: 0 },
                  { name: 'Detective', role: 'Log Intelligence', status: 'online', threat_count: 0, confidence_avg: 0 },
                  { name: 'Commander', role: 'Decision Engine', status: 'online', threat_count: 0, confidence_avg: 0 },
                ].map(a => <AgentCard key={a.name} agent={a} />)
            }
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="cyber-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span className="font-mono text-sm font-semibold text-slate-300">Active Alerts</span>
            <span className="ml-auto text-[11px] font-mono text-slate-600">{recentAlerts.length} shown</span>
          </div>
          <div className="divide-y divide-slate-800/50 max-h-80 overflow-y-auto">
            {recentAlerts.length === 0 ? (
              <div className="py-10 text-center">
                <Shield className="w-8 h-8 text-emerald-400/30 mx-auto mb-2" />
                <p className="font-mono text-xs text-slate-600">No active alerts — system nominal</p>
              </div>
            ) : recentAlerts.map((a, i) => (
              <div key={a.id || i} className="flex items-start gap-3 px-4 py-3 hover:bg-slate-800/20 transition-colors">
                <SeverityBadge level={a.severity} />
                <div className="flex-1 min-w-0">
                  <p className="font-mono text-xs text-slate-300 truncate">{a.event}</p>
                  <p className="font-mono text-[11px] text-slate-600">
                    {a.source_ip} · <span className="text-slate-500">{a.agent}</span>
                  </p>
                </div>
                <Timestamp value={a.timestamp} />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Agent Communication Feed */}
      <AgentCommunicationFeed messages={agentMessages} maxHeight={280} />
    </div>
  )
}
