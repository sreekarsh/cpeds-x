/**
 * CPEDS-X API client
 * Connects to FastAPI backend. Base URL from VITE_API_BASE_URL env,
 * defaults to local dev server.
 */
import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
export const TOKEN_KEY = 'cpeds_token'

const api = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  timeout: 20000,
})

// Attach the JWT (if present) to every request.
api.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// If a token expires or is rejected mid-session, clear it and let the app
// fall back to the login screen (AuthContext listens for this event).
api.interceptors.response.use(
  (res) => res,
  (error) => {
    const status = error?.response?.status
    const url = error?.config?.url || ''
    // Don't bounce on the auth endpoints themselves — those 401s are expected
    // (e.g. wrong password) and are handled inline by the forms.
    const isAuthCall = url.includes('/auth/')
    if (status === 401 && !isAuthCall) {
      localStorage.removeItem(TOKEN_KEY)
      window.dispatchEvent(new Event('cpeds-unauthorized'))
    }
    return Promise.reject(error)
  }
)

// ---- Detection / dashboard endpoints (require auth) ----
export const checkHealth = () => api.get('/health')
export const getMetrics = () => api.get('/metrics')
// Retrain + hot-swap the model. mode = 'synthetic' | 'real'. For real mode,
// pass the labeled dataset text (datasetContent) and its filename. Training can
// take a few seconds, so this call overrides the default axios timeout.
export const reloadTraining = ({ mode = 'synthetic', datasetContent = null, datasetFilename = '', labelKey = null } = {}) =>
  api.post('/train/reload', {
    mode,
    dataset_content: datasetContent,
    dataset_filename: datasetFilename,
    label_key: labelKey,
  }, { timeout: 120000 })
export const simulateLog = (threat_class) => api.post('/simulate', { threat_class })
export const predict = (audit_log) => api.post('/predict', { audit_log })
export const explain = (scaled_features, predicted_class) =>
  api.post('/explain', { scaled_features, predicted_class })
export const mitigate = (principal, predicted_class, confidence, instance_id) =>
  api.post('/mitigate', { principal, predicted_class, confidence, instance_id })

// ---- Log analysis (upload real CloudTrail / JSON / CSV) ----
export const analyzeLogs = (content, format = 'auto', filename = '') =>
  api.post('/analyze', { content, format, filename })
export const getSampleLogs = () => api.get('/analyze/sample')

// ---- Attack Scenario Runner (purple-team loop) ----
export const getScenarios = () => api.get('/scenarios')
export const runScenario = (scenario_id) => api.post('/scenario/run', { scenario_id })

// ---- Live AWS containment (real sandbox account, human-approved) ----
export const getLiveStatus = () => api.get('/live/status')
export const pollLive = (minutes = 60) => api.post('/live/poll', { minutes })
export const containLive = (principal, predicted_class, confidence, raw_log) =>
  api.post('/live/contain', { principal, predicted_class, confidence, raw_log })
export const undoLive = (incident_id) => api.post('/live/undo', { incident_id })

// ---- Incident history (per-operator) ----
export const getIncidents = (limit = 200) => api.get('/incidents', { params: { limit } })
export const getIncident = (id) => api.get(`/incidents/${id}`)
export const clearIncidents = () => api.delete('/incidents')

// ---- Authentication endpoints (public) ----
export const apiSignup = (full_name, email, password) =>
  api.post('/auth/signup', { full_name, email, password })
export const apiLogin = (email, password) =>
  api.post('/auth/login', { email, password })
export const apiMe = () => api.get('/auth/me')
export const apiForgotPassword = (email) =>
  api.post('/auth/forgot-password', { email })
export const apiResetPassword = (token, new_password) =>
  api.post('/auth/reset-password', { token, new_password })

/** Extract a human-readable message from an axios error. */
export const errMessage = (error, fallback = 'Something went wrong. Please try again.') => {
  const d = error?.response?.data?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d) && d[0]?.msg) return d[0].msg
  if (error?.code === 'ERR_NETWORK') return 'Cannot reach the server. Is the backend running?'
  return fallback
}

export default api
