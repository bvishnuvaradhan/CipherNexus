import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Lock, User, Eye, EyeOff, AlertCircle, Loader } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', password: '' })
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.username || !form.password) {
      setError('Please enter your credentials.')
      return
    }
    setLoading(true)
    setError('')
    try {
      await login(form.username, form.password)
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed. Check credentials.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-cyber-bg cyber-grid flex items-center justify-center p-4">
      <div className="scan-line" />

      {/* Background glow */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-purple-500/5 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-md animate-fade-in">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 mb-4 relative">
            <Shield className="w-8 h-8 text-cyan-400" />
            <div className="absolute inset-0 rounded-2xl bg-cyan-400/5 animate-pulse" />
          </div>
          <h1 className="font-display font-bold text-2xl text-white mb-1 text-glow-cyan">
            AI CYBER DEFENSE
          </h1>
          <p className="font-mono text-xs text-slate-500 tracking-widest">
            SECURE ACCESS PORTAL v2.0
          </p>
        </div>

        {/* Card */}
        <div className="cyber-card gradient-border p-8">
          {/* Demo hint */}
          <div className="flex items-start gap-2 p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/15 mb-6">
            <AlertCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div className="text-xs font-mono text-slate-400">
              <p className="text-cyan-400 font-semibold mb-1">DEMO CREDENTIALS</p>
              <p>Username: <span className="text-white">admin</span> / Password: <span className="text-white">cyber2026</span></p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username */}
            <div>
              <label className="block text-xs font-mono font-semibold text-slate-500 uppercase tracking-wider mb-2">
                Operator ID
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                <input
                  type="text"
                  value={form.username}
                  onChange={e => setForm(p => ({ ...p, username: e.target.value }))}
                  placeholder="Enter username"
                  className="w-full pl-10 pr-4 py-3 rounded-lg bg-slate-950 border border-slate-700 text-white font-mono text-sm placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:bg-slate-900 transition-colors"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-xs font-mono font-semibold text-slate-500 uppercase tracking-wider mb-2">
                Auth Code
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                <input
                  type={showPass ? 'text' : 'password'}
                  value={form.password}
                  onChange={e => setForm(p => ({ ...p, password: e.target.value }))}
                  placeholder="Enter password"
                  className="w-full pl-10 pr-10 py-3 rounded-lg bg-slate-950 border border-slate-700 text-white font-mono text-sm placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:bg-slate-900 transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(p => !p)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400"
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-mono">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 rounded-lg bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 font-mono font-semibold text-sm hover:bg-cyan-500/25 hover:border-cyan-400/50 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              style={{ boxShadow: '0 0 20px rgba(34,211,238,0.1)' }}
            >
              {loading ? (
                <>
                  <Loader className="w-4 h-4 animate-spin" />
                  AUTHENTICATING...
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  ACCESS SYSTEM
                </>
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-xs font-mono text-slate-700 mt-6">
          CLASSIFIED // SOC INTERNAL SYSTEM // AUTHORIZED PERSONNEL ONLY
        </p>
      </div>
    </div>
  )
}
