import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Skull, Lock, User, Eye, EyeOff, AlertCircle, Loader, Terminal, ShieldOff } from 'lucide-react'
import { useHackerAuth } from '../context/HackerAuthContext'
import { useLab } from '../context/LabContext'

export default function HackerLogin() {
  const { hackerLogin } = useHackerAuth()
  const { activeLab, loading: labLoading } = useLab()
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', password: '' })
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!activeLab) { setError('No active lab instance. Access locked.'); return }
    if (!form.username || !form.password) {
      setError('Credentials required.')
      return
    }
    setLoading(true)
    setError('')
    try {
      await hackerLogin(form.username, form.password)
      navigate('/hacker/console')
    } catch (err) {
      setError(err.response?.data?.detail || 'Access denied — invalid operator credentials.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4"
      style={{ background: '#0a0505', backgroundImage: 'radial-gradient(ellipse at center, #1a0505 0%, #0a0505 70%)' }}
    >
      {/* Scanline overlay */}
      <div className="fixed inset-0 pointer-events-none"
        style={{ background: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,0,0,0.015) 2px, rgba(255,0,0,0.015) 4px)' }}
      />
      {/* Corner decorations */}
      <div className="fixed top-0 left-0 w-32 h-32 border-l-2 border-t-2 border-rose-500/20" />
      <div className="fixed top-0 right-0 w-32 h-32 border-r-2 border-t-2 border-rose-500/20" />
      <div className="fixed bottom-0 left-0 w-32 h-32 border-l-2 border-b-2 border-rose-500/20" />
      <div className="fixed bottom-0 right-0 w-32 h-32 border-r-2 border-b-2 border-rose-500/20" />

      {/* Background glows */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 rounded-full blur-3xl"
          style={{ background: 'rgba(239,68,68,0.04)' }} />
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 rounded-full blur-3xl"
          style={{ background: 'rgba(239,68,68,0.03)' }} />
      </div>

      <div className="relative w-full max-w-md" style={{ animation: 'fadeIn 0.5s ease' }}>
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl border mb-4 relative"
            style={{ background: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.25)' }}
          >
            <Skull className="w-10 h-10" style={{ color: '#ef4444' }} />
            <div className="absolute inset-0 rounded-2xl animate-pulse"
              style={{ background: 'rgba(239,68,68,0.05)' }} />
          </div>
          <h1 className="font-mono font-bold text-2xl mb-1 tracking-widest uppercase"
            style={{ color: '#ef4444', textShadow: '0 0 30px rgba(239,68,68,0.5)' }}>
            HACKER CONSOLE
          </h1>
          <p className="font-mono text-xs tracking-widest" style={{ color: '#6b2020' }}>
            RESTRICTED ACCESS — AUTHORIZED OPERATORS ONLY
          </p>
          <div className="flex items-center justify-center gap-2 mt-3">
            {[...Array(3)].map((_, i) => (
              <span key={i} className="w-1.5 h-1.5 rounded-full animate-pulse"
                style={{ background: '#ef4444', animationDelay: `${i * 0.3}s` }} />
            ))}
          </div>
        </div>

        {/* Card */}
        <div className="rounded-xl p-8 border"
          style={{ background: 'rgba(15,5,5,0.9)', borderColor: 'rgba(239,68,68,0.2)', boxShadow: '0 0 60px rgba(239,68,68,0.08), inset 0 0 60px rgba(0,0,0,0.3)' }}
        >
        {/* No active lab — access locked */}
          {!labLoading && !activeLab && (
            <div className="flex flex-col items-center gap-3 p-5 rounded-lg mb-6 border text-center"
              style={{ background: 'rgba(100,116,139,0.06)', borderColor: 'rgba(100,116,139,0.2)' }}
            >
              <ShieldOff className="w-8 h-8" style={{ color: '#64748b' }} />
              <div className="font-mono text-xs" style={{ color: '#64748b' }}>
                <p className="font-bold uppercase tracking-wider mb-1.5" style={{ color: '#94a3b8' }}>ACCESS LOCKED</p>
                <p>No active lab instance found.</p>
                <p className="mt-1">A SOC analyst must create a lab instance</p>
                <p>before the Hacker Console is accessible.</p>
              </div>
            </div>
          )}

          {/* Credentials hint (only when lab is active) */}
          {activeLab && (
            <div className="flex items-start gap-2 p-3 rounded-lg mb-6 border"
              style={{ background: 'rgba(239,68,68,0.05)', borderColor: 'rgba(239,68,68,0.15)' }}
            >
              <Terminal className="w-4 h-4 shrink-0 mt-0.5" style={{ color: '#ef4444' }} />
              <div className="font-mono text-xs" style={{ color: '#94a3b8' }}>
                <p className="font-semibold mb-1" style={{ color: '#ef4444' }}>OPERATOR CREDENTIALS</p>
                <p>phantom / h4ck3r2026 &nbsp;·&nbsp; shadow / darkweb99</p>
                <p>ghost / r00t4cc3ss &nbsp;·&nbsp; zero / zd4y_2026</p>
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username */}
            <div>
              <label className="block font-mono text-xs font-semibold uppercase tracking-wider mb-2"
                style={{ color: '#6b2020' }}>
                Operator Handle
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: '#6b2020' }} />
                <input
                  type="text"
                  value={form.username}
                  onChange={e => setForm(p => ({ ...p, username: e.target.value }))}
                  placeholder="Enter handle"
                  className="w-full pl-10 pr-4 py-3 rounded-lg font-mono text-sm outline-none transition-all"
                  style={{
                    background: '#0f0505', border: '1px solid rgba(239,68,68,0.2)',
                    color: '#f1f5f9', '::placeholder': { color: '#4a1515' },
                  }}
                  onFocus={e => e.target.style.borderColor = 'rgba(239,68,68,0.5)'}
                  onBlur={e => e.target.style.borderColor = 'rgba(239,68,68,0.2)'}
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block font-mono text-xs font-semibold uppercase tracking-wider mb-2"
                style={{ color: '#6b2020' }}>
                Auth Key
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: '#6b2020' }} />
                <input
                  type={showPass ? 'text' : 'password'}
                  value={form.password}
                  onChange={e => setForm(p => ({ ...p, password: e.target.value }))}
                  placeholder="Enter auth key"
                  className="w-full pl-10 pr-10 py-3 rounded-lg font-mono text-sm outline-none transition-all"
                  style={{ background: '#0f0505', border: '1px solid rgba(239,68,68,0.2)', color: '#f1f5f9' }}
                  onFocus={e => e.target.style.borderColor = 'rgba(239,68,68,0.5)'}
                  onBlur={e => e.target.style.borderColor = 'rgba(239,68,68,0.2)'}
                />
                <button type="button" onClick={() => setShowPass(p => !p)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                  style={{ color: '#6b2020' }}
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 p-3 rounded-lg font-mono text-xs border"
                style={{ background: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.25)', color: '#ef4444' }}
              >
                <AlertCircle className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || !activeLab}
              className="w-full py-3 rounded-lg font-mono font-bold text-sm uppercase tracking-wider transition-all duration-200 flex items-center justify-center gap-2"
              style={{
                background: (loading || !activeLab) ? 'rgba(239,68,68,0.05)' : 'rgba(239,68,68,0.12)',
                border: '1px solid rgba(239,68,68,0.35)',
                color: !activeLab ? '#6b2020' : '#ef4444',
                boxShadow: '0 0 20px rgba(239,68,68,0.1)',
                opacity: (loading || !activeLab) ? 0.5 : 1,
                cursor: (loading || !activeLab) ? 'not-allowed' : 'pointer',
              }}
              onMouseEnter={e => !loading && activeLab && (e.target.style.background = 'rgba(239,68,68,0.2)')}
              onMouseLeave={e => !loading && activeLab && (e.target.style.background = 'rgba(239,68,68,0.12)')}
            >
              {loading ? (
                <><Loader className="w-4 h-4 animate-spin" /> AUTHENTICATING...</>
              ) : (
                <><Skull className="w-4 h-4" /> BREACH SYSTEM</>
              )}
            </button>
          </form>
        </div>

        <p className="text-center font-mono text-xs mt-4" style={{ color: '#3d0f0f' }}>
          ALL ACTIVITY IS MONITORED AND LOGGED BY THE AI DEFENSE SYSTEM
        </p>
      </div>
    </div>
  )
}
