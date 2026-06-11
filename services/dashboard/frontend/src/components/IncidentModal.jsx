import { useEffect, useState } from 'react'
import { X, Shield, Clock, Target, Cpu } from 'lucide-react'
import { getIncident, updateIncident } from '../api'
import { SEVERITY_LABELS, SEVERITY_COLORS, STATUS_LABELS, ATTACK_LABELS, formatDate, formatConfidence } from '../utils'

export default function IncidentModal({ id, onClose }) {
  const [incident, setIncident] = useState(null)
  const [loading, setLoading]   = useState(true)
  const [status, setStatus]     = useState('')
  const [notes, setNotes]       = useState('')
  const [saving, setSaving]     = useState(false)

  useEffect(() => {
    getIncident(id).then(r => {
      setIncident(r.data)
      setStatus(r.data.status || 'open')
      setNotes(r.data.analyst_notes || '')
      setLoading(false)
    })
  }, [id])

  const save = async () => {
    setSaving(true)
    await updateIncident(id, { status, analyst_notes: notes })
    setSaving(false)
    onClose()
  }

  const ai = incident?.raw_incident?.ai_inference || {}
  const rule = incident?.raw_incident?.correlation_rule || {}
  const sev = incident?.severity ?? 0

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-soc-panel border border-soc-border rounded-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-soc-border">
          <div className="flex items-center gap-3">
            <Shield size={20} style={{ color: SEVERITY_COLORS[sev] }} />
            <div>
              <div className="font-semibold text-white">
                {ATTACK_LABELS[ai.attack_class] || ai.attack_class || 'Incident'}
              </div>
              <div className="text-xs text-soc-muted font-mono">{id}</div>
            </div>
          </div>
          <button onClick={onClose} className="text-soc-muted hover:text-white">
            <X size={20} />
          </button>
        </div>

        {loading ? (
          <div className="p-8 text-center text-soc-muted">Chargement...</div>
        ) : (
          <div className="p-6 space-y-6">

            {/* KPIs row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { label: 'Sévérité',    value: SEVERITY_LABELS[sev], color: SEVERITY_COLORS[sev] },
                { label: 'Confiance',   value: formatConfidence(incident.confidence) },
                { label: 'Nb. Alertes', value: incident.event_count },
                { label: 'Statut',      value: STATUS_LABELS[incident.status] || incident.status },
              ].map(({ label, value, color }) => (
                <div key={label} className="bg-soc-bg rounded-lg p-3">
                  <div className="text-xs text-soc-muted mb-1">{label}</div>
                  <div className="font-semibold" style={{ color: color || '#f1f5f9' }}>{value}</div>
                </div>
              ))}
            </div>

            {/* Correlation rule */}
            <div className="bg-soc-bg rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3 text-sm font-semibold text-white">
                <Clock size={14} /> Règle de Corrélation
              </div>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div><span className="text-soc-muted">ID : </span>{rule.id}</div>
                <div><span className="text-soc-muted">Nom : </span>{rule.name}</div>
                <div><span className="text-soc-muted">Fenêtre : </span>{rule.window_sec}s</div>
                <div><span className="text-soc-muted">Seuil : </span>{rule.threshold} événements</div>
              </div>
            </div>

            {/* AI Inference */}
            <div className="bg-soc-bg rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3 text-sm font-semibold text-white">
                <Cpu size={14} /> Inférence IA (XGBoost)
              </div>
              <div className="grid grid-cols-2 gap-2 text-sm mb-3">
                <div><span className="text-soc-muted">Classe : </span>{ATTACK_LABELS[ai.attack_class] || ai.attack_class}</div>
                <div><span className="text-soc-muted">Confiance : </span>{formatConfidence(ai.confidence)}</div>
                <div><span className="text-soc-muted">Vrai positif : </span>{ai.is_true_positive ? '✅ Oui' : '❌ Non'}</div>
                <div><span className="text-soc-muted">Modèle : </span>{ai.model}</div>
              </div>
              {/* Probability bars */}
              {ai.all_probabilities && (
                <div className="space-y-1.5">
                  {Object.entries(ai.all_probabilities)
                    .sort(([,a],[,b]) => b - a)
                    .slice(0, 5)
                    .map(([cls, prob]) => (
                      <div key={cls} className="flex items-center gap-2">
                        <div className="w-32 text-xs text-soc-muted truncate">{ATTACK_LABELS[cls] || cls}</div>
                        <div className="flex-1 bg-soc-border rounded-full h-1.5">
                          <div className="bg-soc-accent h-1.5 rounded-full" style={{ width: `${prob * 100}%` }} />
                        </div>
                        <div className="text-xs text-soc-muted w-10 text-right">{(prob * 100).toFixed(1)}%</div>
                      </div>
                    ))
                  }
                </div>
              )}
            </div>

            {/* Hosts */}
            {incident.target_hosts?.length > 0 && (
              <div className="bg-soc-bg rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2 text-sm font-semibold text-white">
                  <Target size={14} /> Hôtes Ciblés
                </div>
                <div className="flex flex-wrap gap-2">
                  {incident.target_hosts.map(h => (
                    <span key={h} className="px-2 py-0.5 bg-soc-border rounded text-xs text-white font-mono">{h}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Timestamps */}
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="bg-soc-bg rounded-lg p-3">
                <div className="text-xs text-soc-muted mb-1">Première détection</div>
                <div className="text-white">{formatDate(incident.first_seen)}</div>
              </div>
              <div className="bg-soc-bg rounded-lg p-3">
                <div className="text-xs text-soc-muted mb-1">Dernière activité</div>
                <div className="text-white">{formatDate(incident.last_seen)}</div>
              </div>
            </div>

            {/* Analyst actions */}
            <div className="bg-soc-bg rounded-lg p-4 space-y-3">
              <div className="text-sm font-semibold text-white">Actions Analyste</div>
              <div>
                <label className="text-xs text-soc-muted block mb-1">Statut</label>
                <select
                  value={status}
                  onChange={e => setStatus(e.target.value)}
                  className="bg-soc-panel border border-soc-border rounded px-3 py-1.5 text-sm text-white w-full"
                >
                  <option value="open">Ouvert</option>
                  <option value="investigating">En cours d'investigation</option>
                  <option value="closed">Fermé</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-soc-muted block mb-1">Notes analyste</label>
                <textarea
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  rows={3}
                  placeholder="Ajouter des notes..."
                  className="bg-soc-panel border border-soc-border rounded px-3 py-1.5 text-sm text-white w-full resize-none"
                />
              </div>
              <button
                onClick={save}
                disabled={saving}
                className="bg-soc-accent hover:bg-blue-600 text-white text-sm px-4 py-2 rounded-lg disabled:opacity-50"
              >
                {saving ? 'Enregistrement...' : 'Enregistrer'}
              </button>
            </div>

          </div>
        )}
      </div>
    </div>
  )
}