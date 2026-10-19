const BASE = '/api'

async function get(path) {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

async function put(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

async function del(path) {
  const res = await fetch(`${BASE}${path}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

// Sessions
export const fetchSessions = (params = {}) => {
  const qs = new URLSearchParams(params).toString()
  return get(`/sessions${qs ? '?' + qs : ''}`)
}
export const fetchChainState = (sessionId) =>
  get(`/sessions/${sessionId}/chain-state`)

// Events
export const fetchEvents = (params = {}) => {
  const qs = new URLSearchParams(params).toString()
  return get(`/events${qs ? '?' + qs : ''}`)
}
export const fetchStats = () => get('/events/stats')

// Routing
export const fetchRoutingTable = () => get('/routing-table')

// Toxic Flow
export const fetchToxicFlow = () => get('/toxic-flow')

// Rules
export const fetchRules = () => get('/rules')
export const createRule = (rule) => post('/rules', rule)
export const updateRule = (id, rule) => put(`/rules/${id}`, rule)
export const deleteRule = (id) => del(`/rules/${id}`)

// Backends
export const fetchBackends = () => get('/backends')
export const addBackend = (data) => post('/backends', data)
export const deleteBackend = (name) => del(`/backends/${name}`)
export const triggerRescan = () => post('/rescan')
export const resetRuntimeState = () => post('/backends/reset-runtime')

// Label overrides
export const setLabelOverride = (toolName, labels) => put(`/overrides/${toolName}`, { labels })
export const clearLabelOverride = (toolName) => del(`/overrides/${toolName}`)

// Anomaly config
export const fetchAnomalyConfig = () => get('/anomaly-config')
export const updateAnomalyConfig = (cfg) => put('/anomaly-config', cfg)

// Scenarios
export const fetchScenarios = () => get('/scenarios')
export const runScenario = (id) => post(`/scenarios/${id}/run`)

// Tool changes
export const fetchToolChanges = (limit) => get(`/tool-changes${limit ? '?limit=' + limit : ''}`)
