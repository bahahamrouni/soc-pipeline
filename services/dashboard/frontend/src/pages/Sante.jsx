import { useEffect, useState } from 'react'
import { CheckCircle, XCircle, Clock } from 'lucide-react'
import { getHealth, getSummary } from '../api'

const PIPELINE_STAGES = [
  { id: 1, name: 'Ingestion',      desc: 'Lecture des alertes Wazuh → wazuh-alerts-raw',   topic: 'wazuh-alerts-raw'  },
  { id: 2, name: 'Traitement',     desc: 'Normalisation ECS + CMDB → alerts-enriched',      topic: 'alerts-enriched'   },
  { id: 3, name: 'Corrélation',    desc: 'Fenêtres glissantes Redis → incidents',            topic: 'incidents'         },
  { id: 4, name: 'Inférence IA',   desc: 'Classification XGBoost → ai-results',             topic: 'ai-results'        },
  { id: 5, name: 'Stockage',       desc: 'PostgreSQL + OpenSearch ← ai-results',            topic: null                },
  { id: 6, name: 'Dashboard',      desc: 'FastAPI + React (vous êtes ici)',                  topic: null                },
  { id: 7, name: 'Résumé IA',      desc: 'FLAN-T5 — résumés en langage naturel',            topic: null                },
]

export default function Sante() {
  const [health,  setHealth]  = useState(null)
  const [summary, setSummary] = useState(null)
  const [lastUpdate, setLastUpdate] = useState(null)

  const load = async () => {
    try {
      const [h, s] = await Promise.all([getHealth(), getSummary()])
      setHealth(h.data)
      setSummary(s.data)
      setLastUpdate(new Date().toLocaleTimeString('fr-FR'))
    } catch(e) { console.error(e) }
  }

  useEffect(() => { load() }, [])
  useEffect(() => { const t = setInterval(load, 15000); return () => clearInterval(t) }, [])

  const pgOk = health?.services?.postgresql?.status === 'up'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Santé du Système</h1>
          <p className="text-sm text-soc-muted">Statut en temps réel du pipeline SOC</p>
        </div>
        <div className="text-xs text-soc-muted">MàJ : {lastUpdate || '—'} · Auto 15s</div>
      </div>

      {/* Global status */}
      <div className={`rounded-xl border p-4 flex items-center gap-3 ${
        pgOk ? 'border-green-800 bg-green-900/20' : 'border-red-800 bg-red-900/20'
      }`}>
        {pgOk
          ? <CheckCircle size={20} className="text-green-400" />
          : <XCircle    size={20} className="text-red-400" />
        }
        <div>
          <div className={`font-semibold ${pgOk ? 'text-green-400' : 'text-red-400'}`}>
            {pgOk ? 'Système Opérationnel' : 'Dégradé — Vérifier les Services'}
          </div>
          <div className="text-xs text-soc-muted">{health?.timestamp}</div>
        </div>
      </div>

      {/* Storage stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Incidents PostgreSQL', value: health?.services?.postgresql?.incidents, color: '#22c55e' },
          { label: 'Incidents Ouverts',    value: summary?.open,     color: '#f97316' },
          { label: 'Vrais Positifs IA',    value: summary?.true_positives, color: '#3b82f6' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-soc-panel border border-soc-border rounded-xl p-4">
            <div className="text-2xl font-bold" style={{ color }}>{value ?? '—'}</div>
            <div className="text-sm text-soc-muted mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Pipeline stages */}
      <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
        <div className="text-sm font-semibold text-white mb-4">Étapes du Pipeline</div>
        <div className="space-y-3">
          {PIPELINE_STAGES.map((stage, i) => (
            <div key={stage.id}>
              <div className="flex items-center gap-3">
                {/* Phase number */}
                <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${
                  stage.id <= 6 ? 'bg-green-900 text-green-400' : 'bg-soc-border text-soc-muted'
                }`}>
                  {stage.id}
                </div>

                {/* Info */}
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-white">{stage.name}</span>
                    {stage.id <= 6
                      ? <CheckCircle size={12} className="text-green-400" />
                      : <Clock       size={12} className="text-soc-muted"  />
                    }
                  </div>
                  <div className="text-xs text-soc-muted">{stage.desc}</div>
                </div>

                {/* Topic badge */}
                {stage.topic && (
                  <span className="text-xs font-mono bg-soc-bg border border-soc-border px-2 py-0.5 rounded text-soc-accent">
                    {stage.topic}
                  </span>
                )}

                {/* Status badge */}
                <span className={`text-xs px-2 py-0.5 rounded ${
                  stage.id <= 6 ? 'bg-green-900 text-green-400' : 'bg-soc-border text-soc-muted'
                }`}>
                  {stage.id <= 6 ? 'Actif' : 'À venir'}
                </span>
              </div>

              {/* Connector line */}
              {i < PIPELINE_STAGES.length - 1 && (
                <div className="ml-3.5 w-px h-3 bg-soc-border mt-1" />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Severity breakdown */}
      {summary && (
        <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
          <div className="text-sm font-semibold text-white mb-4">Répartition par Sévérité</div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {summary.by_severity.map(s => (
              <div key={s.name} className="bg-soc-bg rounded-lg p-3 text-center">
                <div className="text-2xl font-bold" style={{ color: s.color }}>{s.value}</div>
                <div className="text-xs text-soc-muted mt-1">{s.name}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}   