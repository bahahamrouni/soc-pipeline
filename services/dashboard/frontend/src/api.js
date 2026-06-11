import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

export const getHealth        = () => api.get('/health')
export const getSummary       = () => api.get('/stats/summary')
export const getTimeline      = (period) => api.get(`/stats/timeline?period=${period}`)
export const getTopHosts      = () => api.get('/stats/top-hosts?limit=8')
export const getTopRules      = () => api.get('/stats/top-rules?limit=6')
export const getConfidence    = () => api.get('/stats/confidence-distribution')
export const getRecentIncidents = (limit=10) => api.get(`/incidents/recent?limit=${limit}`)
export const getIncidents     = (params) => api.get('/incidents', { params })
export const getIncident      = (id) => api.get(`/incidents/${id}`)
export const updateIncident   = (id, data) => api.patch(`/incidents/${id}`, data)

export default api