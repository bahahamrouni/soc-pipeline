export const SEVERITY_LABELS = { 0: 'Info', 1: 'Moyen', 2: 'Élevé', 3: 'Critique' }
export const SEVERITY_COLORS = { 0: '#3b82f6', 1: '#eab308', 2: '#f97316', 3: '#ef4444' }
export const SEVERITY_BADGE  = { 0: 'badge-info', 1: 'badge-medium', 2: 'badge-high', 3: 'badge-critical' }
export const STATUS_BADGE    = { open: 'badge-open', closed: 'badge-closed', investigating: 'badge-investigating' }
export const STATUS_LABELS   = { open: 'Ouvert', closed: 'Fermé', investigating: 'En cours' }

export const ATTACK_LABELS = {
  brute_force:           'Force Brute',
  privilege_escalation:  'Escalade de Privilèges',
  lateral_movement:      'Mouvement Latéral',
  alert_storm:           'Tempête d\'Alertes',
  reconnaissance:        'Reconnaissance',
  data_exfiltration:     'Exfiltration de Données',
  malware_activity:      'Activité Malware',
  normal_activity:       'Activité Normale',
}

export function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('fr-FR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  })
}

export function formatConfidence(v) {
  if (v == null) return '—'
  return `${(v * 100).toFixed(1)}%`
}

export function severityBadge(sev) {
  return SEVERITY_BADGE[sev] || 'badge-info'
}