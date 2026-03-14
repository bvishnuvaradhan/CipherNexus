import { useState, useEffect, useCallback } from 'react'
import { Activity, Shield, Search, Cpu, Clock, Target, TrendingUp } from 'lucide-react'
import { agentsAPI, logsAPI } from '../services/api'
import { useWebSocket } from '../services/websocket'
import { AgentDot, ConfidenceBar, PageHeader, Spinner, Timestamp } from '../components/ui'
import { AgentCommunicationFeed } from '../components/AgentFeed'

const AGENT_META = {
  Sentry: {
    color: 'cyan',
    icon: Shield,
    desc: 'Monitors inbound/outbound network traffic. Detects spikes, port scans, and suspicious IPs in real time.',
    bg: 'from-cyan-500/5 to-transparent',
    border: 'border-cyan-500/20',
    textColor: 'text-cyan-400',
    ring: 'ring-cyan-500/10',
  },
  Detective: {
    color: 'purple',
    icon: Search,
    desc: 'Analyzes authentication logs, detects brute force patterns, flags abnormal login locations and credential attacks.',
    bg: 'from-purple-500/5 to-transparent',
    border: 'border-purple-500/20',
    textColor: 'text-purple-400',
    ring: 'ring-purple-500/10',
  },
  Commander: {
    color: 'yellow',
    icon: Cpu,
    desc: 'Central decision engine. Correlates signals from Sentry and Detective, computes XAI reasoning, and executes responses.',
    bg: 'from-yellow-500/5 to-transparent',
    border: 'border-yellow-500/20',
    textColor: 'text-yellow-400',
    ring: 'ring-yellow-500/10',
  },
  'Threat Intelligence': {
    color: 'rose',
    icon: Target,
    desc: 'Correlates IOC feeds, reputation data, and known malicious infrastructure to improve confidence and reduce false positives.',
    bg: 'from-rose-500/5 to-transparent',
    border: 'border-rose-500/20',
    textColor: 'text-rose-400',
    ring: 'ring-rose-500/10',
  },
  'Anomaly Detection': {
    color: 'emerald',
    icon: TrendingUp,
    desc: 'Runs behavioral anomaly analysis and ML scoring to identify unusual patterns and unknown attack activity.',
    bg: 'from-emerald-500/5 to-transparent',
    border: 'border-emerald-500/20',
    textColor: 'text-emerald-400',
    ring: 'ring-emerald-500/10',
  },
  'Response Automation': {
    color: 'orange',
    icon: Shield,
    desc: 'Executes defensive actions such as IP blocking, target isolation, and administrator notifications once threats are confirmed.',
    bg: 'from-orange-500/5 to-transparent',
    border: 'border-orange-500/20',
    textColor: 'text-orange-400',
    ring: 'ring-orange-500/10',
  },
  Forensics: {
    color: 'indigo',
    icon: Clock,
    desc: 'Reconstructs attack timelines, summarizes incident evidence, and generates investigation-ready forensic context.',
    bg: 'from-indigo-500/5 to-transparent',
    border: 'border-indigo-500/20',
    textColor: 'text-indigo-400',
    ring: 'ring-indigo-500/10',
  },
}

const DEFAULT_AGENTS = [
  { name: 'Sentry', role: 'Network Defense', status: 'offline', threat_count: 0, total_threats_detected: 0, confidence_avg: 0, responsibilities: ['Monitor network traffic','Detect traffic spikes','Identify port scans','Flag suspicious IPs'], uptime_seconds: 0, has_live_status: false },
  { name: 'Detective', role: 'Log Intelligence', status: 'offline', threat_count: 0, total_threats_detected: 0, confidence_avg: 0, responsibilities: ['Analyze login attempts','Detect brute force attacks','Flag abnormal login locations','Analyze system logs'], uptime_seconds: 0, has_live_status: false },
  { name: 'Commander', role: 'Decision Engine', status: 'offline', threat_count: 0, total_threats_detected: 0, confidence_avg: 0, responsibilities: ['Correlate signals from Sentry & Detective','Determine threat severity','Initiate mitigation actions','Generate XAI reasoning paths'], uptime_seconds: 0, has_live_status: false },
  { name: 'Threat Intelligence', role: 'Threat Intelligence', status: 'offline', threat_count: 0, total_threats_detected: 0, confidence_avg: 0, responsibilities: ['Monitor IOC and reputation feeds','Correlate IPs with malicious infrastructure','Track CVE and reputation context','Reduce false positives with external intel'], uptime_seconds: 0, has_live_status: false },
  { name: 'Anomaly Detection', role: 'Behavioral Analytics', status: 'offline', threat_count: 0, total_threats_detected: 0, confidence_avg: 0, responsibilities: ['Detect behavioral anomalies','Score suspicious events with ML','Identify unknown attack patterns','Provide anomaly confidence'], uptime_seconds: 0, has_live_status: false },
  { name: 'Response Automation', role: 'Defensive Execution', status: 'offline', threat_count: 0, total_threats_detected: 0, confidence_avg: 0, responsibilities: ['Execute containment actions','Block malicious IPs','Trigger notifications','Track execution outcomes'], uptime_seconds: 0, has_live_status: false },
  { name: 'Forensics', role: 'Incident Investigation', status: 'offline', threat_count: 0, total_threats_detected: 0, confidence_avg: 0, responsibilities: ['Reconstruct attack timelines','Summarize incident evidence','Generate forensic notes','Support future tuning'], uptime_seconds: 0, has_live_status: false },
]

function mergeAgentsWithDefaults(liveAgents = [], prevAgents = []) {
  const byName = new Map((liveAgents || []).map((a) => [a.name, a]))
  const prevByName = new Map((prevAgents || []).map((a) => [a.name, a]))
  const receivedAtMs = Date.now()

  return DEFAULT_AGENTS.map((base) => {
    const prev = prevByName.get(base.name) || {}
    const live = byName.get(base.name) || {}
    const hasLive = byName.has(base.name)

    const threatCount = hasLive
      ? Number(live.threat_count ?? prev.threat_count ?? base.threat_count ?? 0)
      : Number(prev.threat_count ?? base.threat_count ?? 0)
    const totalThreatsDetected = Math.max(
      Number(base.total_threats_detected || 0),
      Number(prev.total_threats_detected || 0),
      Number(live.total_threats_detected ?? live.threat_count ?? 0)
    )
    const confidenceAvg = Math.max(
      Number(base.confidence_avg || 0),
      Number(prev.confidence_avg || 0),
      Number(live.confidence_avg || 0)
    )
    const uptimeSeconds = Math.max(
      Number(base.uptime_seconds || 0),
      Number(prev.uptime_seconds || 0),
      Number(live.uptime_seconds || 0)
    )

    return {
      ...base,
      ...prev,
      ...live,
      threat_count: threatCount,
      total_threats_detected: totalThreatsDetected,
      confidence_avg: confidenceAvg,
      uptime_seconds: uptimeSeconds,
      _receivedAtMs: hasLive ? receivedAtMs : Number(prev._receivedAtMs || receivedAtMs),
    }
  })
}

function AgentDetailCard({ agent, nowMs }) {
  const meta = AGENT_META[agent.name] || AGENT_META.Sentry
  const Icon = meta.icon
  const baseUptime = Number(agent.uptime_seconds || 0)
  const receivedAtMs = Number(agent._receivedAtMs || nowMs)
  const elapsedSeconds = Math.max(0, Math.floor((nowMs - receivedAtMs) / 1000))
  const isActiveRuntime = Boolean(agent.has_live_status) || agent.status === 'online' || agent.status === 'busy'
  const uptimeSeconds = isActiveRuntime ? baseUptime + elapsedSeconds : baseUptime
  const uptimeLabel = uptimeSeconds < 60 ? `${uptimeSeconds}s` : `${Math.floor(uptimeSeconds / 60)}m`

  return (
    <div className={`cyber-card ring-1 ${meta.ring} overflow-hidden`}>
      {/* Header */}
      <div className={`bg-gradient-to-r ${meta.bg} px-5 py-4 border-b ${meta.border}`}>
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl bg-slate-900 border ${meta.border} flex items-center justify-center`}>
              <Icon className={`w-5 h-5 ${meta.textColor}`} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <AgentDot status={agent.status} />
                <h3 className={`font-display font-bold text-lg ${meta.textColor}`}>{agent.name}</h3>
              </div>
              <p className="text-xs font-mono text-slate-500">{agent.role}</p>
            </div>
          </div>
          <span className={`px-2 py-1 rounded border text-[11px] font-mono font-semibold uppercase ${
            agent.status === 'online' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
            agent.status === 'busy'   ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400' :
            'bg-slate-700/30 border-slate-700 text-slate-500'
          }`}>
            {agent.status}
          </span>
        </div>
        <p className="text-xs font-mono text-slate-500 mt-3 leading-relaxed">{meta.desc}</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 p-5">
        <div>
          <p className="text-[11px] font-mono text-slate-600 uppercase tracking-wider mb-1">Threats Detected</p>
          <p className={`font-display font-bold text-2xl ${meta.textColor}`}>{agent.total_threats_detected || agent.threat_count || 0}</p>
        </div>
        <div>
          <p className="text-[11px] font-mono text-slate-600 uppercase tracking-wider mb-1">Uptime</p>
          <p className="font-display font-bold text-2xl text-slate-300">{uptimeLabel}</p>
        </div>
        <div className="col-span-2">
          <p className="text-[11px] font-mono text-slate-600 uppercase tracking-wider mb-2">Avg Confidence</p>
          <ConfidenceBar value={agent.confidence_avg} />
        </div>
      </div>

      {/* Responsibilities */}
      <div className="px-5 pb-4">
        <p className="text-[11px] font-mono text-slate-600 uppercase tracking-wider mb-2">Responsibilities</p>
        <ul className="space-y-1.5">
          {(agent.responsibilities || []).map((r, i) => (
            <li key={i} className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <span className={`w-1 h-1 rounded-full ${meta.textColor} bg-current`} />
              {r}
            </li>
          ))}
        </ul>
      </div>

      {/* Last action */}
      {agent.last_action && (
        <div className={`px-5 py-3 border-t ${meta.border} bg-slate-950/50`}>
          <p className="text-[11px] font-mono text-slate-600 uppercase tracking-wider mb-1">Last Action</p>
          <p className="text-xs font-mono text-slate-400 truncate">{agent.last_action}</p>
          {agent.last_action_time && (
            <div className="mt-1">
              <Timestamp value={agent.last_action_time} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── A2A Protocol Diagram ──────────────────────────────────────────────
function A2AProtocolDiagram() {
  return (
    <div className="cyber-card p-5">
      <div className="flex items-center gap-2 mb-4">
        <Activity className="w-4 h-4 text-cyan-400" />
        <span className="font-mono text-sm font-semibold text-slate-300">A2A Communication Protocol</span>
      </div>
      <div className="relative">
        {/* Flow */}
        <div className="flex flex-col gap-3">
          {[
            { from: 'Sentry', arrow: '→', to: 'Commander', msg: 'traffic_spike detected from 192.168.1.x', color: 'text-cyan-400' },
            { from: 'Commander', arrow: '→', to: 'Detective', msg: 'verify_ip: check login logs for 192.168.1.x', color: 'text-yellow-400' },
            { from: 'Detective', arrow: '→', to: 'Commander', msg: '5 failed root logins confirmed (confidence: 0.87)', color: 'text-purple-400' },
            { from: 'Commander', arrow: '→', to: 'System', msg: 'Block IP — confidence: 0.92 — XAI reasoning generated', color: 'text-emerald-400' },
          ].map((step, i) => (
            <div key={i} className="flex items-center gap-2 font-mono text-xs p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/50">
              <span className="text-[10px] text-slate-700 w-4 shrink-0">{i + 1}.</span>
              <span className={`font-semibold ${step.color} shrink-0`}>[{step.from}]</span>
              <span className="text-slate-700 shrink-0">{step.arrow}</span>
              <span className="text-slate-500 shrink-0">[{step.to}]</span>
              <span className="text-slate-600 truncate ml-1">{step.msg}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function Agents() {
  const [agents, setAgents] = useState(() => mergeAgentsWithDefaults([], []))
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(true)
  const [nowMs, setNowMs] = useState(Date.now())

  const load = useCallback(async () => {
    try {
      const [ag, msgs] = await Promise.allSettled([
        agentsAPI.list(),
        logsAPI.agentMessages(30),
      ])
      if (ag.status === 'fulfilled') {
        setAgents((prev) => mergeAgentsWithDefaults(ag.value.data.agents || [], prev))
      }
      if (msgs.status === 'fulfilled') setMessages(msgs.value.data.messages || [])
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => { const id = setInterval(load, 10000); return () => clearInterval(id) }, [load])
  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  const handleWs = useCallback((msg) => {
    if (msg.type === 'status') {
      setAgents((prev) => mergeAgentsWithDefaults(msg.data.agents || [], prev))
    }
    if (msg.type === 'agent_message') setMessages(p => [...p, msg.data].slice(-30))
  }, [])
  useWebSocket(handleWs)

  return (
    <div className="p-4 lg:p-6 space-y-6 animate-fade-in">
      <PageHeader
        title="Agent Operations"
        subtitle="Multi-agent AI architecture — real-time monitoring & coordination"
        icon={Activity}
      />

      {loading ? (
        <div className="flex justify-center py-12"><Spinner size="lg" /></div>
      ) : (
        <>
          <div className="cyber-card p-3">
            <div className="flex items-center justify-between mb-3 px-1">
              <p className="font-mono text-xs font-semibold text-slate-500 uppercase tracking-wider">Agent Operations</p>
              <p className="font-mono text-[11px] text-slate-600">Scroll horizontally</p>
            </div>
            <div className="overflow-x-auto pb-2">
              <div className="flex gap-4 min-w-max">
                {agents.map(a => (
                  <div key={a.name} className="w-[360px] shrink-0">
                    <AgentDetailCard agent={a} nowMs={nowMs} />
                  </div>
                ))}
              </div>
            </div>
          </div>

          <A2AProtocolDiagram />

          <AgentCommunicationFeed messages={messages} maxHeight={360} />
        </>
      )}
    </div>
  )
}
