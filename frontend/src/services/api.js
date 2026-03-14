import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || '/api'

// ── SOC analyst API (uses localStorage token) ─────────────────────────────
const api = axios.create({ baseURL: BASE_URL, timeout: 15000 })

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token')
    if (token) config.headers.Authorization = `Bearer ${token}`
    return config
  },
  (error) => Promise.reject(error)
)

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

// ── Hacker console API (uses sessionStorage token) ────────────────────────
const hackerAxios = axios.create({ baseURL: BASE_URL, timeout: 30000 })

hackerAxios.interceptors.request.use(
  (config) => {
    const token = sessionStorage.getItem('hacker_token')
    if (token) config.headers.Authorization = `Bearer ${token}`
    return config
  },
  (error) => Promise.reject(error)
)

hackerAxios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      sessionStorage.removeItem('hacker_token')
      sessionStorage.removeItem('hacker_username')
      window.location.href = '/hacker/login'
    }
    return Promise.reject(error)
  }
)

// ── Auth ──────────────────────────────────────────────────────────────────
export const authAPI = {
  login:  (credentials) => api.post('/auth/login', credentials),
  logout: () => api.post('/auth/logout'),
}

// ── Alerts ────────────────────────────────────────────────────────────────
export const alertsAPI = {
  list:        (limit = 50, severity = null) =>
    api.get('/alerts', { params: { limit, ...(severity && { severity }) } }),
  detail:      (alertId) => api.get(`/alerts/${alertId}`),
  threatLevel: () => api.get('/alerts/threat-level'),
  stats:       () => api.get('/alerts/stats'),
  reportCsv:   (startTime, endTime, severity = null, threatTypes = []) =>
    api.get('/alerts/report.csv', {
      params: {
        start_time: startTime,
        end_time: endTime,
        ...(severity && severity !== 'all' ? { severity } : {}),
        ...(Array.isArray(threatTypes) && threatTypes.length > 0 ? { threat_types: threatTypes.join(',') } : {}),
      },
      responseType: 'blob',
    }),
}

// ── Logs ──────────────────────────────────────────────────────────────────
export const logsAPI = {
  list:          (limit = 100) => api.get('/logs', { params: { limit } }),
  agentMessages: (limit = 50)  => api.get('/logs/agent-messages', { params: { limit } }),
  forAlert:      (alertId, limit = 100) => api.get(`/logs/for-alert/${alertId}`, { params: { limit } }),
}

// ── Agents ────────────────────────────────────────────────────────────────
export const agentsAPI = {
  list: ()     => api.get('/agents'),
  get:  (name) => api.get(`/agents/${name}`),
}

// ── Responses ─────────────────────────────────────────────────────────────
export const responsesAPI = {
  list:  (limit = 50) => api.get('/responses', { params: { limit } }),
  stats: () => api.get('/responses/stats'),
}

// ── Simulator (SOC side — legacy) ─────────────────────────────────────────
export const simulatorAPI = {
  trigger: (attackType, sourceIp = null, intensity = 'medium') =>
    api.post('/simulate-attack', { attack_type: attackType, source_ip: sourceIp, intensity }),
  attackTypes: () => api.get('/simulate-attack/attack-types'),
}

// ── Labs ──────────────────────────────────────────────────────────────────
export const labsAPI = {
  list:      () => api.get('/labs'),
  getActive: () => api.get('/labs/active'),
  create:    (data) => api.post('/labs', data),
  destroy:   (id) => api.delete(`/labs/${id}`),
}

// ── Hacker Console API (full parameter support) ───────────────────────────
export const hackerAPI = {
  /**
   * Launch an attack with full parameter set.
   * @param {Object} payload
   * @param {string} payload.attack_type
   * @param {string} [payload.source_ip]
   * @param {string} [payload.target_ip]
   * @param {string} [payload.intensity]
   * @param {string} [payload.username]
   * @param {number} [payload.attempt_count]
   * @param {number} [payload.port_range_start]
   * @param {number} [payload.port_range_end]
   * @param {number} [payload.payload_size_mb]
   * @param {number} [payload.packet_rate]
   * @param {string} [payload.injection_type]
   * @param {string} [payload.xss_type]
   * @param {number} [payload.beacon_interval]
   * @param {string} [payload.target_domain]
   * @param {string} [payload.target_protocol]
   * @param {string} [payload.spread_rate]
   * @param {number} [payload.duration_seconds]
   */
  launchAttack: (payload) => hackerAxios.post('/simulate-attack', payload),
  attackTypes:  () => hackerAxios.get('/simulate-attack/attack-types'),
}

// ── Machine Learning ──────────────────────────────────────────────────────
export const mlAPI = {
  status:   () => api.get('/ml/status'),
  getConfig: () => api.get('/ml/config'),
  setConfig: (anomalyThreshold) => api.post('/ml/config', { anomaly_threshold: anomalyThreshold }),
}

export default api
