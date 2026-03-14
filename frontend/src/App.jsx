import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import { HackerAuthProvider, useHackerAuth } from './context/HackerAuthContext'
import { LabProvider, useLab } from './context/LabContext'
import MainLayout from './layouts/MainLayout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Agents from './pages/Agents'
import Logs from './pages/Logs'
import ThreatAlerts from './pages/ThreatAlerts'
import Simulator from './pages/Simulator'
import Responses from './pages/Responses'
import Labs from './pages/Labs'
import ReportsEmail from './pages/ReportsEmail'
import HackerLogin from './pages/HackerLogin'
import HackerConsole from './pages/HackerConsole'

function ProtectedRoute({ children }) {
  const { isAuthenticated } = useAuth()
  return isAuthenticated ? children : <Navigate to="/login" replace />
}

function HackerProtectedRoute({ children }) {
  const { isAuthenticated } = useHackerAuth()
  const { activeLab, loading } = useLab()

  if (loading) return null
  if (!isAuthenticated) return <Navigate to="/hacker/login" replace />
  if (!activeLab) return <Navigate to="/hacker/login" replace />
  return children
}

function AppRoutes() {
  const { isAuthenticated } = useAuth()
  const { isAuthenticated: hackerAuth } = useHackerAuth()
  const { activeLab, loading: labLoading } = useLab()

  return (
    <Routes>
      {/* ── SOC Analyst routes ──────────────────────────────────── */}
      <Route
        path="/login"
        element={isAuthenticated ? <Navigate to="/" replace /> : <Login />}
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <MainLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="agents" element={<Agents />} />
        <Route path="logs" element={<Logs />} />
        <Route path="alerts" element={<ThreatAlerts />} />
        <Route path="simulator" element={<Simulator />} />
        <Route path="responses" element={<Responses />} />
        <Route path="labs" element={<Labs />} />
        <Route path="reports-email" element={<ReportsEmail />} />
      </Route>

      {/* ── Hacker Console routes (separate, standalone) ─────────── */}
      <Route
        path="/hacker/login"
        element={hackerAuth && activeLab && !labLoading ? <Navigate to="/hacker/console" replace /> : <HackerLogin />}
      />
      <Route
        path="/hacker/console"
        element={
          <HackerProtectedRoute>
            <HackerConsole />
          </HackerProtectedRoute>
        }
      />

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <HackerAuthProvider>
        <LabProvider>
          <BrowserRouter>
            <AppRoutes />
          </BrowserRouter>
        </LabProvider>
      </HackerAuthProvider>
    </AuthProvider>
  )
}
