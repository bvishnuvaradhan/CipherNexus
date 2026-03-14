import { TrendingUp, TrendingDown, Minus } from 'lucide-react'

// ── Severity Badge ────────────────────────────────────────────────────
export function SeverityBadge({ level }) {
  const map = {
    critical: 'badge-critical',
    high:     'badge-high',
    medium:   'badge-medium',
    low:      'badge-low',
    safe:     'badge-safe',
  }
  return (
    <span className={map[level?.toLowerCase()] || 'badge-low'}>
      <span className="w-1.5 h-1.5 rounded-full bg-current inline-block" />
      {level?.toUpperCase()}
    </span>
  )
}

// ── Status Badge ──────────────────────────────────────────────────────
export function StatusBadge({ status }) {
  const map = {
    blocked:    'badge-blocked',
    monitoring: 'badge-monitoring',
    resolved:   'badge-resolved',
    active:     'badge-high',
    pending:    'badge-medium',
  }
  const dotAnim = {
    monitoring: 'animate-pulse',
    blocked: '',
    resolved: '',
  }
  return (
    <span className={map[status?.toLowerCase()] || 'badge-medium'}>
      <span className={`w-1.5 h-1.5 rounded-full bg-current inline-block ${dotAnim[status?.toLowerCase()] || ''}`} />
      {status?.toUpperCase()}
    </span>
  )
}

// ── Agent Status Dot ─────────────────────────────────────────────────
export function AgentDot({ status }) {
  const map = {
    online:  'agent-dot-online',
    busy:    'agent-dot-busy',
    offline: 'agent-dot-offline',
    alert:   'agent-dot-alert',
  }
  return <span className={map[status] || 'agent-dot-offline'} />
}

// ── Stat Card ─────────────────────────────────────────────────────────
export function StatCard({ label, value, sub, icon: Icon, color = 'cyan', trend }) {
  const colors = {
    cyan:    'text-cyan-400',
    rose:    'text-rose-400',
    emerald: 'text-emerald-400',
    yellow:  'text-yellow-400',
    orange:  'text-orange-400',
    purple:  'text-purple-400',
  }
  const bgs = {
    cyan:    'bg-cyan-500/10 border-cyan-500/20',
    rose:    'bg-rose-500/10 border-rose-500/20',
    emerald: 'bg-emerald-500/10 border-emerald-500/20',
    yellow:  'bg-yellow-500/10 border-yellow-500/20',
    orange:  'bg-orange-500/10 border-orange-500/20',
    purple:  'bg-purple-500/10 border-purple-500/20',
  }

  return (
    <div className="cyber-card p-4 animate-fade-in">
      <div className="flex items-start justify-between mb-3">
        <p className="text-xs font-mono font-semibold text-slate-500 uppercase tracking-wider">{label}</p>
        {Icon && (
          <div className={`w-8 h-8 rounded-lg border flex items-center justify-center ${bgs[color]}`}>
            <Icon className={`w-4 h-4 ${colors[color]}`} />
          </div>
        )}
      </div>
      <p className={`font-display font-bold text-3xl ${colors[color]} mb-1`}>{value}</p>
      {sub && <p className="text-xs font-mono text-slate-600">{sub}</p>}
      {trend !== undefined && (
        <div className="flex items-center gap-1 mt-2">
          {trend > 0 ? (
            <TrendingUp className="w-3 h-3 text-rose-400" />
          ) : trend < 0 ? (
            <TrendingDown className="w-3 h-3 text-emerald-400" />
          ) : (
            <Minus className="w-3 h-3 text-slate-600" />
          )}
          <span className={`text-[11px] font-mono ${trend > 0 ? 'text-rose-400' : trend < 0 ? 'text-emerald-400' : 'text-slate-600'}`}>
            {trend > 0 ? `+${trend}` : trend} from last hour
          </span>
        </div>
      )}
    </div>
  )
}

// ── Confidence Bar ────────────────────────────────────────────────────
export function ConfidenceBar({ value }) {
  const pct = Math.round((value || 0) * 100)
  const color = pct >= 85 ? '#f43f5e' : pct >= 65 ? '#eab308' : '#22d3ee'
  return (
    <div className="flex items-center gap-2">
      <div className="confidence-bar flex-1" style={{ minWidth: 60 }}>
        <div
          className="confidence-fill"
          style={{ width: `${pct}%`, background: color, boxShadow: `0 0 6px ${color}80` }}
        />
      </div>
      <span className="font-mono text-xs font-semibold" style={{ color }}>{pct}%</span>
    </div>
  )
}

// ── Page Header ───────────────────────────────────────────────────────
export function PageHeader({ title, subtitle, icon: Icon, children }) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div className="flex items-center gap-3">
        {Icon && (
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
            <Icon className="w-5 h-5 text-cyan-400" />
          </div>
        )}
        <div>
          <h1 className="font-display font-bold text-xl text-white">{title}</h1>
          {subtitle && <p className="text-xs font-mono text-slate-500 mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </div>
  )
}

// ── Loading Spinner ───────────────────────────────────────────────────
export function Spinner({ size = 'md' }) {
  const s = { sm: 'w-4 h-4', md: 'w-6 h-6', lg: 'w-8 h-8' }
  return (
    <div className={`${s[size]} border-2 border-cyan-500/20 border-t-cyan-400 rounded-full animate-spin`} />
  )
}

// ── Empty State ───────────────────────────────────────────────────────
export function EmptyState({ message = 'No data available', icon: Icon }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      {Icon && <Icon className="w-10 h-10 text-slate-700 mb-3" />}
      <p className="font-mono text-sm text-slate-600">{message}</p>
    </div>
  )
}

// ── Timestamp ─────────────────────────────────────────────────────────
export function Timestamp({ value }) {
  if (!value) return <span className="text-slate-600">—</span>
  // Backend sends UTC times without 'Z' suffix — append it if missing
  let ts = value
  if (typeof ts === 'string' && !ts.endsWith('Z') && !ts.includes('+') && !ts.includes('-', 10)) {
    ts = ts + 'Z'
  }
  const d = new Date(ts)
  // Use local time formatting
  const time = d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  const date = d.toLocaleDateString('en-US', { month: 'short', day: '2-digit' })
  return (
    <span className="font-mono text-xs text-slate-500">
      <span className="text-slate-400">{time}</span>
      <span className="text-slate-700 ml-1">{date}</span>
    </span>
  )
}
