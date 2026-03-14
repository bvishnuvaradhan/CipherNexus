import { useState, useCallback } from 'react'
import { Zap, Play, Shield, Terminal, Activity, AlertTriangle, Wifi, Target } from 'lucide-react'
import { simulatorAPI } from '../services/api'
import { useWebSocket } from '../services/websocket'
import { PageHeader, SeverityBadge, ConfidenceBar, Timestamp } from '../components/ui'

const ATTACK_CONFIGS = [
  {
    type: 'brute_force',
    label: 'Brute Force Attack',
    icon: Terminal,
    color: 'rose',
    desc: 'Simulates repeated failed login attempts against SSH/admin accounts. Triggers Detective agent analysis.',
    agent: 'Detective',
    expectedSeverity: 'high',
    details: ['Multiple failed SSH logins', 'Root account targeted', 'Sliding window detection'],
  },
  {
    type: 'port_scan',
    label: 'Port Scan',
    icon: Wifi,
    color: 'cyan',
    desc: 'Simulates sequential port probing across the network range. Triggers Sentry network monitoring.',
    agent: 'Sentry',
    expectedSeverity: 'medium',
    details: ['50–500 ports probed', 'Sequential scan pattern', 'Network anomaly flagged'],
  },
  {
    type: 'suspicious_login',
    label: 'Suspicious Login',
    icon: Shield,
    color: 'purple',
    desc: 'Simulates login from a flagged geographic location (TOR, hostile nation). Triggers Detective geolocation check.',
    agent: 'Detective',
    expectedSeverity: 'medium',
    details: ['TOR exit node detected', 'Geo-anomaly flagged', 'Credential validation bypass'],
  },
  {
    type: 'data_exfiltration',
    label: 'Data Exfiltration',
    icon: Activity,
    color: 'yellow',
    desc: 'Simulates abnormally large outbound data transfer. Triggers Detective data-transfer analysis.',
    agent: 'Detective',
    expectedSeverity: 'critical',
    details: ['80–400 MB outbound', 'Unusual destination', 'Off-hours transfer'],
  },
]

const INTENSITIES = [
  { value: 'low',    label: 'LOW',    color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20' },
  { value: 'medium', label: 'MED',    color: 'text-yellow-400',  bg: 'bg-yellow-500/10 border-yellow-500/20' },
  { value: 'high',   label: 'HIGH',   color: 'text-rose-400',    bg: 'bg-rose-500/10 border-rose-500/20' },
]

const COLOR_MAP = {
  rose:   { card: 'border-rose-500/20 ring-rose-500/5',   icon: 'bg-rose-500/10 text-rose-400',   btn: 'border-rose-500/40 bg-rose-500/10 text-rose-400 hover:bg-rose-500/20', label: 'text-rose-400' },
  cyan:   { card: 'border-cyan-500/20 ring-cyan-500/5',   icon: 'bg-cyan-500/10 text-cyan-400',   btn: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20', label: 'text-cyan-400' },
  purple: { card: 'border-purple-500/20 ring-purple-500/5', icon: 'bg-purple-500/10 text-purple-400', btn: 'border-purple-500/40 bg-purple-500/10 text-purple-400 hover:bg-purple-500/20', label: 'text-purple-400' },
  yellow: { card: 'border-yellow-500/20 ring-yellow-500/5', icon: 'bg-yellow-500/10 text-yellow-400', btn: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20', label: 'text-yellow-400' },
}

// ── Terminal-style live event log ─────────────────────────────────────
function SimTerminal({ events }) {
  return (
    <div className="cyber-card overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 bg-slate-950/50">
        <div className="flex gap-1.5">
          <span className="w-3 h-3 rounded-full bg-rose-500/60" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/60" />
          <span className="w-3 h-3 rounded-full bg-emerald-500/60" />
        </div>
        <span className="font-mono text-xs text-slate-500 ml-2">simulation_terminal — live output</span>
      </div>
      <div className="p-4 font-mono text-xs space-y-1.5 max-h-64 overflow-y-auto bg-slate-950/30">
        {events.length === 0 ? (
          <p className="text-slate-700 cursor-blink">Awaiting simulation command</p>
        ) : (
          events.map((ev, i) => (
            <div key={i} className="flex gap-3 animate-slide-in">
              <span className="text-slate-700 shrink-0">[{ev.time}]</span>
              <span className={`shrink-0 font-semibold ${
                ev.type === 'error' ? 'text-rose-400' :
                ev.type === 'success' ? 'text-emerald-400' :
                ev.type === 'warn' ? 'text-yellow-400' :
                ev.type === 'agent' ? 'text-cyan-400' :
                'text-slate-400'
              }`}>
                {ev.tag}
              </span>
              <span className="text-slate-400">{ev.msg}</span>
            </div>
          ))
        )}
        {events.length > 0 && (
          <p className="text-slate-700 cursor-blink mt-1"> </p>
        )}
      </div>
    </div>
  )
}

// ── Result Panel ──────────────────────────────────────────────────────
function SimResult({ result }) {
  if (!result) return null
  const { attack, agent_result } = result
  const alert = agent_result?.alert

  return (
    <div className="cyber-card p-5 border-emerald-500/20 ring-1 ring-emerald-500/5 animate-fade-in">
      <div className="flex items-center gap-2 mb-4">
        <div className="w-6 h-6 rounded-full bg-emerald-500/20 flex items-center justify-center">
          <span className="text-emerald-400 text-xs">✓</span>
        </div>
        <span className="font-mono text-sm font-semibold text-emerald-400">Simulation Complete</span>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <p className="text-[11px] font-mono text-slate-600 uppercase mb-1">Attack Type</p>
          <p className="font-mono text-sm text-slate-300">{attack?.attack_type?.replace('_', ' ').toUpperCase()}</p>
        </div>
        <div>
          <p className="text-[11px] font-mono text-slate-600 uppercase mb-1">Source IP</p>
          <p className="font-mono text-sm text-cyan-400">{attack?.source_ip}</p>
        </div>
        <div>
          <p className="text-[11px] font-mono text-slate-600 uppercase mb-1">Agent Triggered</p>
          <p className="font-mono text-sm text-purple-400">{agent_result?.triggered}</p>
        </div>
        <div>
          <p className="text-[11px] font-mono text-slate-600 uppercase mb-1">Mitigated</p>
          <p className={`font-mono text-sm font-bold ${attack?.mitigated ? 'text-emerald-400' : 'text-rose-400'}`}>
            {attack?.mitigated ? 'YES' : 'PENDING'}
          </p>
        </div>
      </div>

      {alert && (
        <div className="pt-4 border-t border-slate-800">
          <p className="text-[11px] font-mono text-slate-600 uppercase mb-3">Generated Alert</p>
          <div className="flex items-center gap-3 flex-wrap">
            <SeverityBadge level={alert.severity} />
            <span className="font-mono text-xs text-slate-400">{alert.event}</span>
            <span className="ml-auto">
              <ConfidenceBar value={alert.confidence} />
            </span>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Attack Card ───────────────────────────────────────────────────────
function AttackCard({ config, intensity, running, onLaunch }) {
  const c = COLOR_MAP[config.color]
  const Icon = config.icon
  const isRunning = running === config.type

  return (
    <div className={`cyber-card ring-1 ${c.card} p-5 flex flex-col gap-4`}>
      <div className="flex items-start gap-3">
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${c.icon}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div className="flex-1">
          <p className={`font-display font-bold text-base ${c.label}`}>{config.label}</p>
          <p className="text-[11px] font-mono text-slate-600 mt-0.5">
            → <span className="text-slate-500">{config.agent} Agent</span>
          </p>
        </div>
        <SeverityBadge level={config.expectedSeverity} />
      </div>

      <p className="text-xs font-mono text-slate-500 leading-relaxed">{config.desc}</p>

      <ul className="space-y-1">
        {config.details.map((d, i) => (
          <li key={i} className="flex items-center gap-2 text-[11px] font-mono text-slate-600">
            <span className={`w-1 h-1 rounded-full bg-current ${c.label}`} />
            {d}
          </li>
        ))}
      </ul>

      <button
        onClick={() => onLaunch(config.type)}
        disabled={!!running}
        className={`
          flex items-center justify-center gap-2 w-full py-2.5 rounded border font-mono text-sm font-semibold
          transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed
          ${c.btn} active:scale-95
        `}
      >
        {isRunning ? (
          <>
            <span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin" />
            SIMULATING...
          </>
        ) : (
          <>
            <Play className="w-3.5 h-3.5" />
            Launch Attack
          </>
        )}
      </button>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────
export default function Simulator() {
  const [intensity, setIntensity] = useState('medium')
  const [running, setRunning] = useState(null)
  const [termEvents, setTermEvents] = useState([])
  const [lastResult, setLastResult] = useState(null)
  const [wsEvents, setWsEvents] = useState([])

  const addTermEvent = useCallback((type, tag, msg) => {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false })
    setTermEvents(p => [...p, { type, tag, msg, time }].slice(-40))
  }, [])

  const handleWs = useCallback((msg) => {
    if (msg.type === 'simulation_started') {
      addTermEvent('agent', '[WS]', `Simulation broadcast received — attack in progress`)
    }
    if (msg.type === 'alert') {
      addTermEvent('warn', '[ALERT]', `${msg.data.event} from ${msg.data.source_ip} [${msg.data.severity?.toUpperCase()}]`)
    }
    if (msg.type === 'agent_message') {
      addTermEvent('agent', `[${msg.data.from_agent}→${msg.data.to_agent}]`, msg.data.event)
    }
    if (msg.type === 'response') {
      addTermEvent('success', '[RESPONSE]', `${msg.data.action} — confidence: ${Math.round((msg.data.confidence || 0) * 100)}%`)
    }
  }, [addTermEvent])
  useWebSocket(handleWs)

  const launchAttack = useCallback(async (attackType) => {
    setRunning(attackType)
    setTermEvents([])
    setLastResult(null)

    const label = ATTACK_CONFIGS.find(c => c.type === attackType)?.label
    addTermEvent('warn', '[INIT]', `Launching ${label} simulation — intensity: ${intensity.toUpperCase()}`)
    addTermEvent('agent', '[SYS]', `Assigning attack vector to agent pipeline...`)

    try {
      await new Promise(r => setTimeout(r, 600))
      addTermEvent('agent', '[DISPATCH]', `Attack packet routed — agents notified`)

      const res = await simulatorAPI.trigger(attackType, null, intensity)
      addTermEvent('success', '[DONE]', `Simulation executed — checking agent responses...`)

      const data = res.data
      setLastResult(data)

      if (data.agent_result?.alert) {
        const a = data.agent_result.alert
        addTermEvent('warn', '[ALERT]', `${a.event} — severity: ${a.severity?.toUpperCase()} — confidence: ${Math.round((a.confidence || 0) * 100)}%`)
      }
      addTermEvent('success', '[MITIGATION]', `Commander initiating automated response...`)
    } catch (err) {
      addTermEvent('error', '[ERROR]', err.response?.data?.detail || 'Simulation failed — backend unreachable')
    } finally {
      setRunning(null)
    }
  }, [intensity, addTermEvent])

  return (
    <div className="p-4 lg:p-6 space-y-6 animate-fade-in">
      <PageHeader
        title="Attack Simulator"
        subtitle="Inject synthetic threats to test multi-agent detection pipeline"
        icon={Zap}
      >
        {/* Intensity selector */}
        <div className="flex items-center gap-2 border border-slate-700 rounded-lg p-1">
          {INTENSITIES.map(({ value, label, color, bg }) => (
            <button
              key={value}
              onClick={() => setIntensity(value)}
              className={`px-3 py-1 rounded text-[11px] font-mono font-bold uppercase transition-all ${
                intensity === value ? `${bg} ${color} border border-current/30` : 'text-slate-600 hover:text-slate-400'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </PageHeader>

      {/* Warning banner */}
      <div className="flex items-start gap-3 p-4 rounded-lg bg-yellow-500/5 border border-yellow-500/20">
        <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
        <div className="text-xs font-mono text-slate-400">
          <span className="text-yellow-400 font-semibold">SIMULATION MODE — </span>
          All attacks are synthetic and contained within the platform. Triggers real agent pipelines, generates real alerts and automated responses with XAI reasoning.
        </div>
      </div>

      {/* Attack cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {ATTACK_CONFIGS.map(config => (
          <AttackCard
            key={config.type}
            config={config}
            intensity={intensity}
            running={running}
            onLaunch={launchAttack}
          />
        ))}
      </div>

      {/* Terminal + result */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SimTerminal events={termEvents} />
        {lastResult ? (
          <SimResult result={lastResult} />
        ) : (
          <div className="cyber-card p-6 flex flex-col items-center justify-center text-center gap-3">
            <Target className="w-10 h-10 text-slate-700" />
            <p className="font-mono text-xs text-slate-600">Launch a simulation to see results here</p>
            <p className="text-[11px] font-mono text-slate-700">Alerts, agent responses, and XAI reasoning will appear after execution</p>
          </div>
        )}
      </div>
    </div>
  )
}
