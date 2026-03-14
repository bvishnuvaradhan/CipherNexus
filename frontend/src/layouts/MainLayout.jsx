import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { useState, useEffect, useCallback } from 'react'
import {
  Shield, Activity, Terminal, AlertTriangle,
  Zap, Database, LogOut, Wifi, WifiOff, ChevronRight,
  Menu, X, FlaskConical
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { alertsAPI } from '../services/api'
import { useWebSocket } from '../services/websocket'

const NAV_ITEMS = [
  { to: '/',          label: 'Dashboard',     Icon: Shield },
  { to: '/agents',    label: 'Agents',        Icon: Activity },
  { to: '/logs',      label: 'Logs',          Icon: Terminal },
  { to: '/alerts',    label: 'Threat Alerts', Icon: AlertTriangle },
  { to: '/simulator', label: 'Simulator',     Icon: Zap },
  { to: '/responses', label: 'Responses',     Icon: Database },
  { to: '/labs',      label: 'Labs',          Icon: FlaskConical },
]

const LEVEL_COLORS = {
  LOW:      'text-emerald-400',
  MEDIUM:   'text-yellow-400',
  HIGH:     'text-orange-400',
  CRITICAL: 'text-rose-400',
}
const LEVEL_BG = {
  LOW:      'bg-emerald-500/10 border-emerald-500/30',
  MEDIUM:   'bg-yellow-500/10 border-yellow-500/30',
  HIGH:     'bg-orange-500/10 border-orange-500/30',
  CRITICAL: 'bg-rose-500/10 border-rose-500/30 animate-pulse',
}

export default function MainLayout() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const [threatLevel, setThreatLevel] = useState({ level: 'LOW', score: 0, active_alerts: 0 })
  const [wsConnected, setWsConnected] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [liveAlerts, setLiveAlerts] = useState(0)

  useEffect(() => {
    alertsAPI.threatLevel().then(r => setThreatLevel(r.data)).catch(() => {})
  }, [])

  const handleWsMessage = useCallback((msg) => {
    setWsConnected(true)
    if (msg.type === 'threat_level') {
      setThreatLevel(msg.data)
    }
    if (msg.type === 'alert') {
      setLiveAlerts(p => p + 1)
    }
  }, [])

  useWebSocket(handleWsMessage)

  useEffect(() => {
    // Mark WS as trying to connect after mount
    const t = setTimeout(() => setWsConnected(true), 500)
    return () => clearTimeout(t)
  }, [])

  return (
    <div className="flex h-screen bg-cyber-bg cyber-grid overflow-hidden">
      {/* Scan line */}
      <div className="scan-line" />

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* ── Sidebar ──────────────────────────────────────────── */}
      <aside
        className={`
          fixed lg:static inset-y-0 left-0 z-40
          w-64 flex flex-col bg-slate-950 border-r border-slate-800
          transition-transform duration-300
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        `}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-800">
          <div className="relative">
            <Shield className="w-8 h-8 text-cyan-400" />
            <div className="absolute inset-0 blur-sm opacity-40">
              <Shield className="w-8 h-8 text-cyan-400" />
            </div>
          </div>
          <div>
            <p className="font-display font-bold text-sm text-white tracking-wide">AI CYBER</p>
            <p className="font-mono text-[10px] text-cyan-400 tracking-[0.2em]">DEFENSE v2.0</p>
          </div>
          <button
            className="ml-auto lg:hidden text-slate-500 hover:text-white"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map(({ to, label, Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) => `
                flex items-center gap-3 px-3 py-2.5 rounded-lg
                font-mono text-sm transition-all duration-150 group
                ${isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                  : 'text-slate-500 hover:text-slate-200 hover:bg-slate-800/60'
                }
              `}
            >
              {({ isActive }) => (
                <>
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-600 group-hover:text-slate-400'}`} />
                  <span>{label}</span>
                  {isActive && <ChevronRight className="w-3 h-3 ml-auto text-cyan-500/50" />}
                  {label === 'Threat Alerts' && liveAlerts > 0 && (
                    <span className="ml-auto bg-rose-500 text-white text-[10px] font-bold rounded-full w-4 h-4 flex items-center justify-center">
                      {liveAlerts > 9 ? '9+' : liveAlerts}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* User footer */}
        <div className="px-3 py-3 border-t border-slate-800 space-y-2">
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900">
            <div className="w-7 h-7 rounded-full bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center">
              <span className="text-cyan-400 text-xs font-mono font-bold uppercase">
                {user?.username?.[0] || 'A'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-mono text-slate-300 truncate">{user?.username}</p>
              <p className="text-[10px] text-slate-600">SOC Analyst</p>
            </div>
            <button
              onClick={logout}
              className="text-slate-600 hover:text-rose-400 transition-colors"
              title="Logout"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main ─────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <header className="flex items-center gap-4 px-4 lg:px-6 py-3 bg-slate-950/80 backdrop-blur border-b border-slate-800 shrink-0">
          <button
            className="lg:hidden text-slate-500 hover:text-white"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400 opacity-60" />
            <span className="font-display font-semibold text-sm text-slate-300 hidden sm:block">
              AI Cyber Defense Platform
            </span>
          </div>

          <div className="flex items-center gap-2 ml-auto">
            {/* WS Status */}
            <div className={`flex items-center gap-1.5 px-2 py-1 rounded border text-[11px] font-mono ${
              wsConnected
                ? 'border-emerald-500/20 text-emerald-400 bg-emerald-500/5'
                : 'border-slate-700 text-slate-500'
            }`}>
              {wsConnected
                ? <Wifi className="w-3 h-3" />
                : <WifiOff className="w-3 h-3" />
              }
              <span className="hidden sm:inline">{wsConnected ? 'LIVE' : 'OFFLINE'}</span>
            </div>

            {/* Threat Level */}
            <div className={`flex items-center gap-2 px-3 py-1 rounded border text-xs font-mono font-semibold ${LEVEL_BG[threatLevel.level] || LEVEL_BG.LOW}`}>
              <span className={`text-[10px] text-slate-500 hidden sm:inline`}>THREAT</span>
              <span className={LEVEL_COLORS[threatLevel.level] || 'text-emerald-400'}>
                {threatLevel.level}
              </span>
              {threatLevel.active_alerts > 0 && (
                <span className="text-slate-500 hidden sm:inline">
                  · {threatLevel.active_alerts} active
                </span>
              )}
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
