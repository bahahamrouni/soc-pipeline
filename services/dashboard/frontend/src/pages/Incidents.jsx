import { useEffect, useState } from 'react'
import { Search, Filter, ChevronLeft, ChevronRight } from 'lucide-react'
import IncidentModal from '../components/IncidentModal'
import { getIncidents } from '../api'
import { SEVERITY_LABELS, SEVERITY_COLORS, SEVERITY_BADGE, STATUS_LABELS, ATTACK_LABELS, formatDate, formatConfidence } from '../utils'

const SEV_OPTIONS = [
  { value: '', label: 'Toutes sévérités' },
  { value: 3,  label: 'Critique' },
  { value: 2,  label: 'Élevé' },
  { value: 1,  label: 'Moyen' },
  { value: 0,  label: 'Info' },
]
const STATUS_OPTIONS = [
  { value: '',             label: 'Tous statuts' },
  { value: 'open',        label: 'Ouvert' },
  { value: 'investigating', label: 'En cours' },
  { value: 'closed',      label: 'Fermé' },
]

export default function Incidents() {
  const [data,     setData]     = useState({ items: [], total: 0, pages: 1 })
  const [page,     setPage]     = useState(1)
  const [search,   setSearch]   = useState('')
  const [severity, setSeverity] = useState('')
  const [status,   setStatus]   = useState('')
  const [selected, setSelected] = useState(null)
  const [loading,  setLoading]  = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const params = { page, per_page: 25 }
      if (search)   params.search   = search
      if (severity !== '') params.severity = severity
      if (status)   params.status   = status
      const r = await getIncidents(params)
      setData(r.data)
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [page, severity, status])
  useEffect(() => {
    const t = setTimeout(load, 400)
    return () => clearTimeout(t)
  }, [search])

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white">Incidents</h1>
        <p className="text-sm text-soc-muted">{data.total} incident(s) au total</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-48">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-soc-muted" />
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1) }}
            placeholder="Rechercher (hôte, IP, catégorie...)"
            className="w-full bg-soc-panel border border-soc-border rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-soc-muted"
          />
        </div>
        <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1) }}
          className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-white">
          {SEV_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <select value={status} onChange={e => { setStatus(e.target.value); setPage(1) }}
          className="bg-soc-panel border border-soc-border rounded-lg px-3 py-2 text-sm text-white">
          {STATUS_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="bg-soc-panel border border-soc-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-soc-border text-soc-muted text-xs uppercase tracking-wide">
                <th className="text-left px-4 py-3">Sévérité</th>
                <th className="text-left px-4 py-3">Catégorie / Classe IA</th>
                <th className="text-left px-4 py-3">Règle</th>
                <th className="text-left px-4 py-3">Hôtes Ciblés</th>
                <th className="text-left px-4 py-3">Confiance</th>
                <th className="text-left px-4 py-3">Statut</th>
                <th className="text-left px-4 py-3">Détecté le</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} className="text-center py-8 text-soc-muted">Chargement...</td></tr>
              ) : data.items.length === 0 ? (
                <tr><td colSpan={7} className="text-center py-8 text-soc-muted">Aucun incident trouvé</td></tr>
              ) : data.items.map(inc => (
                <tr key={inc.id}
                  onClick={() => setSelected(inc.id)}
                  className="border-b border-soc-border hover:bg-soc-border/30 cursor-pointer transition-colors">
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-1 rounded font-medium ${SEVERITY_BADGE[inc.severity]}`}>
                      {SEVERITY_LABELS[inc.severity]}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-white">{ATTACK_LABELS[inc.attack_class] || inc.category}</div>
                    <div className="text-xs text-soc-muted font-mono">{inc.attack_class}</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-xs font-mono text-soc-accent">{inc.rule_id}</div>
                    <div className="text-xs text-soc-muted">{inc.rule_name}</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {(inc.target_hosts || []).slice(0, 2).map(h => (
                        <span key={h} className="text-xs font-mono bg-soc-border px-1.5 py-0.5 rounded">{h}</span>
                      ))}
                      {(inc.target_hosts || []).length > 2 && (
                        <span className="text-xs text-soc-muted">+{inc.target_hosts.length - 2}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-soc-border rounded-full h-1.5 w-16">
                        <div className="h-1.5 rounded-full bg-soc-accent"
                             style={{ width: `${(inc.confidence || 0) * 100}%` }} />
                      </div>
                      <span className="text-xs text-soc-muted">{formatConfidence(inc.confidence)}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-1 rounded ${
                      inc.status === 'open' ? 'badge-open' :
                      inc.status === 'investigating' ? 'badge-investigating' : 'badge-closed'
                    }`}>
                      {STATUS_LABELS[inc.status] || inc.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-soc-muted whitespace-nowrap">
                    {formatDate(inc.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-soc-border">
          <div className="text-xs text-soc-muted">
            Page {page} sur {data.pages} · {data.total} résultats
          </div>
          <div className="flex gap-2">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="p-1.5 rounded hover:bg-soc-border disabled:opacity-30 text-soc-muted hover:text-white">
              <ChevronLeft size={16} />
            </button>
            <button onClick={() => setPage(p => Math.min(data.pages, p + 1))} disabled={page >= data.pages}
              className="p-1.5 rounded hover:bg-soc-border disabled:opacity-30 text-soc-muted hover:text-white">
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>

      {selected && <IncidentModal id={selected} onClose={() => { setSelected(null); load() }} />}
    </div>
  )
}