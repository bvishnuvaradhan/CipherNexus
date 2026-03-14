import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || '/api'

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 10000,
})

// Request interceptor — attach auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor — handle 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('username')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// ── Auth ──────────────────────────────────────────────────────────────
export const authAPI = {
  login: (credentials) => api.post('/auth/login', credentials),
  logout: () => api.post('/auth/logout'),
}

// ── Alerts ────────────────────────────────────────────────────────────
export const alertsAPI = {
  list: (limit = 50, severity = null) =>
    api.get('/alerts', { params: { limit, ...(severity && { severity }) } }),
  threatLevel: () => api.get('/alerts/threat-level'),
  stats: () => api.get('/alerts/stats'),
}

// ── Logs ──────────────────────────────────────────────────────────────
export const logsAPI = {
  list: (limit = 100) => api.get('/logs', { params: { limit } }),
  agentMessages: (limit = 50) => api.get('/logs/agent-messages', { params: { limit } }),
}

// ── Agents ────────────────────────────────────────────────────────────
export const agentsAPI = {
  list: () => api.get('/agents'),
  get: (name) => api.get(`/agents/${name}`),
}

// ── Responses ─────────────────────────────────────────────────────────
export const responsesAPI = {
  list: (limit = 50) => api.get('/responses', { params: { limit } }),
  stats: () => api.get('/responses/stats'),
}

// ── Simulator ─────────────────────────────────────────────────────────
export const simulatorAPI = {
  trigger: (attackType, sourceIp = null, intensity = 'medium') =>
    api.post('/simulate-attack', {
      attack_type: attackType,
      source_ip: sourceIp,
      intensity,
    }),
  attackTypes: () => api.get('/simulate-attack/attack-types'),
}

export default api
