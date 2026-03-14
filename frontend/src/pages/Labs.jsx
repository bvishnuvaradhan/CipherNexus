import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  FlaskConical, Plus, Trash2, ExternalLink, Skull, Activity,
  AlertCircle, Loader, Shield, Clock, Hash
} from 'lucide-react'
import { useLab } from '../context/LabContext'
import { PageHeader, Spinner } from '../components/ui'

function formatElapsed(isoStr) {
  if (!isoStr) return '—'
  const diff = Math.floor((Date.now() - new Date(isoStr).getTime()) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}

// ── Active lab card ─────────────────────────────────────────────────────────
function ActiveLabCard({ lab, onDestroy, destroying }) {
  return (
    <div className="cyber-card overflow-hidden">
      {/* Status bar */}
      <div className="flex items-center gap-2 px-5 py-3 border-b border-slate-800"
        style={{ background: 'rgba(16,185,129,0.04)' }}
      >
        <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        <span className="font-mono text-xs font-bold text-emerald-400 uppercase tracking-wider">
          LAB INSTANCE ACTIVE
        </span>
        <span className="ml-auto font-mono text-[10px] text-slate-600">
          ID: {lab.id.slice(0, 8)}…
        </span>
      </div>

      <div className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-6">
        {/* Lab info */}
        <div className="space-y-4">
          <div>
            <p className="font-mono text-[10px] text-slate-600 uppercase tracking-wider mb-1">Instance Name</p>
            <p className="font-mono font-bold text-lg text-white">{lab.name}</p>
          </div>
          {lab.description && (
            <div>
              <p className="font-mono text-[10px] text-slate-600 uppercase tracking-wider mb-1">Description</p>
              <p className="font-mono text-sm text-slate-400">{lab.description}</p>
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <p className="font-mono text-[10px] text-slate-600 uppercase tracking-wider mb-1">Created</p>
              <div className="flex items-center gap-1.5">
                <Clock className="w-3 h-3 text-slate-600" />
                <p className="font-mono text-xs text-slate-400">{formatElapsed(lab.created_at)}</p>
              </div>
            </div>
            <div>
              <p className="font-mono text-[10px] text-slate-600 uppercase tracking-wider mb-1">Attacks Run</p>
              <div className="flex items-center gap-1.5">
                <Hash className="w-3 h-3 text-slate-600" />
                <p className="font-mono text-xs text-slate-400">{lab.attack_count || 0}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex flex-col gap-3 justify-center">
          {/* Launch hacker console */}
          <a
            href="/hacker/login"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-center gap-2.5 px-4 py-3 rounded-xl font-mono font-bold text-sm uppercase tracking-wider transition-all duration-200 group"
            style={{
              background: 'rgba(239,68,68,0.12)',
              border: '1px solid rgba(239,68,68,0.35)',
              color: '#ef4444',
              boxShadow: '0 0 20px rgba(239,68,68,0.08)',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.background = 'rgba(239,68,68,0.2)'
              e.currentTarget.style.boxShadow = '0 0 30px rgba(239,68,68,0.15)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = 'rgba(239,68,68,0.12)'
              e.currentTarget.style.boxShadow = '0 0 20px rgba(239,68,68,0.08)'
            }}
          >
            <Skull className="w-4 h-4" />
            Launch Hacker Console
            <ExternalLink className="w-3.5 h-3.5 opacity-60 group-hover:opacity-100 transition-opacity" />
          </a>

          {/* Session token */}
          <div className="px-3 py-2 rounded-lg font-mono text-[10px] flex items-center gap-2"
            style={{ background: 'rgba(34,211,238,0.04)', border: '1px solid rgba(34,211,238,0.1)' }}
          >
            <Shield className="w-3 h-3 text-cyan-500/50 shrink-0" />
            <span className="text-slate-600">Session token:</span>
            <span className="text-cyan-600/60 truncate">{lab.token}</span>
          </div>

          {/* Destroy */}
          <button
            onClick={() => onDestroy(lab.id)}
            disabled={destroying}
            className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl font-mono text-xs font-semibold uppercase tracking-wider transition-all duration-200"
            style={{
              background: 'transparent',
              border: '1px solid rgba(100,116,139,0.25)',
              color: '#64748b',
              opacity: destroying ? 0.5 : 1,
              cursor: destroying ? 'not-allowed' : 'pointer',
            }}
            onMouseEnter={e => !destroying && (e.currentTarget.style.color = '#ef4444') && (e.currentTarget.style.borderColor = 'rgba(239,68,68,0.3)')}
            onMouseLeave={e => (e.currentTarget.style.color = '#64748b') && (e.currentTarget.style.borderColor = 'rgba(100,116,139,0.25)')}
          >
            {destroying ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
            Destroy Instance
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Create form ─────────────────────────────────────────────────────────────
function CreateLabForm({ onCreate, creating }) {
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!name.trim()) { setError('Instance name is required.'); return }
    setError('')
    try {
      await onCreate(name.trim(), desc.trim() || undefined)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create lab instance.')
    }
  }

  return (
    <div className="cyber-card p-6">
      <div className="flex items-center gap-2.5 mb-6 pb-4 border-b border-slate-800">
        <FlaskConical className="w-5 h-5 text-cyan-400" />
        <h3 className="font-mono font-bold text-sm text-slate-200">Create Lab Instance</h3>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block font-mono text-xs text-slate-500 uppercase tracking-wider mb-2">
            Instance Name <span className="text-rose-500">*</span>
          </label>
          <input
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="e.g. Pentest Lab Alpha"
            className="w-full px-4 py-2.5 rounded-lg bg-slate-950 border border-slate-700 font-mono text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 transition-colors"
          />
        </div>
        <div>
          <label className="block font-mono text-xs text-slate-500 uppercase tracking-wider mb-2">
            Description <span className="text-slate-700">(optional)</span>
          </label>
          <input
            type="text"
            value={desc}
            onChange={e => setDesc(e.target.value)}
            placeholder="Attack simulation test environment"
            className="w-full px-4 py-2.5 rounded-lg bg-slate-950 border border-slate-700 font-mono text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 transition-colors"
          />
        </div>

        {error && (
          <div className="flex items-center gap-2 p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 font-mono text-xs text-rose-400">
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={creating}
          className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg font-mono font-semibold text-sm transition-all duration-200 btn-cyber disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {creating
            ? <><Loader className="w-4 h-4 animate-spin" /> Initializing...</>
            : <><Plus className="w-4 h-4" /> Create Lab Instance</>
          }
        </button>
      </form>
    </div>
  )
}

// ── Info panel ──────────────────────────────────────────────────────────────
function LabInfoPanel() {
  return (
    <div className="cyber-card p-5 space-y-4">
      <h3 className="font-mono font-bold text-xs text-slate-500 uppercase tracking-wider flex items-center gap-2">
        <Activity className="w-3.5 h-3.5 text-cyan-400" />
        How Labs Work
      </h3>
      <ul className="space-y-3">
        {[
          { icon: '01', text: 'Create a lab instance to enable the Hacker Console attack simulator.' },
          { icon: '02', text: 'Once active, click "Launch Hacker Console" to open the attack portal in a new tab.' },
          { icon: '03', text: 'All attacks from the hacker console are detected by the AI defense agents in real-time.' },
          { icon: '04', text: 'Monitor detections on the Dashboard and Threat Alerts pages.' },
          { icon: '05', text: 'Destroy the lab instance when done to disable the Hacker Console access.' },
        ].map(({ icon, text }) => (
          <li key={icon} className="flex gap-3 items-start">
            <span className="font-mono text-[10px] text-cyan-600 font-bold shrink-0 mt-0.5">{icon}</span>
            <p className="font-mono text-xs text-slate-500 leading-relaxed">{text}</p>
          </li>
        ))}
      </ul>
    </div>
  )
}

// ── Main page ───────────────────────────────────────────────────────────────
export default function Labs() {
  const { activeLab, loading, createLab, destroyLab } = useLab()
  const [creating, setCreating] = useState(false)
  const [destroying, setDestroying] = useState(false)

  const handleCreate = async (name, description) => {
    setCreating(true)
    try {
      await createLab(name, description)
    } finally {
      setCreating(false)
    }
  }

  const handleDestroy = async (labId) => {
    setDestroying(true)
    try {
      await destroyLab(labId)
    } finally {
      setDestroying(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <Spinner size="lg" />
          <p className="font-mono text-xs text-slate-600 mt-3">Loading lab instances...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-4 lg:p-6 space-y-6 animate-fade-in">
      <PageHeader
        title="Attack Labs"
        subtitle="Manage isolated simulation environments for the Hacker Console"
        icon={FlaskConical}
      />

      {/* Status banner */}
      <div className={`flex items-center gap-3 p-4 rounded-xl border font-mono text-sm ${
        activeLab
          ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-400'
          : 'bg-slate-800/30 border-slate-700/50 text-slate-500'
      }`}>
        <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${
          activeLab ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'
        }`} />
        {activeLab
          ? <>Lab instance <span className="font-bold text-white mx-1">"{activeLab.name}"</span> is running — Hacker Console is accessible.</>
          : <>No active lab instance — <span className="text-slate-400 ml-1">Hacker Console access is disabled until a lab is created.</span></>
        }
        {!activeLab && (
          <div className="ml-auto flex items-center gap-1.5">
            <Skull className="w-3.5 h-3.5 text-slate-700" />
            <span className="text-[11px] text-slate-700">Hacker Console locked</span>
          </div>
        )}
        {activeLab && (
          <a
            href="/hacker/login"
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto flex items-center gap-1.5 text-[11px] font-bold hover:underline"
            style={{ color: '#ef4444' }}
          >
            <Skull className="w-3.5 h-3.5" />
            Open Hacker Console
            <ExternalLink className="w-3 h-3" />
          </a>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main content */}
        <div className="lg:col-span-2 space-y-4">
          {activeLab ? (
            <ActiveLabCard
              lab={activeLab}
              onDestroy={handleDestroy}
              destroying={destroying}
            />
          ) : (
            <CreateLabForm onCreate={handleCreate} creating={creating} />
          )}
        </div>

        {/* Info sidebar */}
        <LabInfoPanel />
      </div>
    </div>
  )
}
