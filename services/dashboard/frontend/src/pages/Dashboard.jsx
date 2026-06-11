import { useEffect, useState } from 'react'
import { ShieldAlert, ShieldX, Activity, CheckCircle, AlertTriangle, Zap } from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import KpiCard from '../components/KpiCard'
import IncidentModal from '../components/IncidentModal'
import { getSummary, getTimeline, getTopHosts, getTopRules, getRecentIncidents } from '../api'
import { SEVERITY_LABELS, SEVERITY_COLORS, SEVERITY_BADGE, STATUS_LABELS, ATTACK_LABELS, formatDate, formatConfidence } from '../utils'

const PERIOD_LABELS = { '24h': '24 Heures', '7d': '7 Jours', '30d': '30 Jours' }

export default function Dashboard() {
  const [summary,  setSummary]  = useState(null)
  const [timeline, setTimeline] = useState([])
  const [hosts,    setHosts]    = useState([])
  const [rules,    setRules]    = useState([])
  const [recent,   setRecent]   = useState([])
  const [period,   setPeriod]   = useState('24h')
  const [selected, setSelected] = useState(null)
  const [lastUpdate, setLastUpdate] = useState(null)

  const load = async () => {
    try {
      const [s, t, h, r, rec] = await Promise.all([
        getSummary(), getTimeline(period), getTopHosts(), getTopRules(), getRecentIncidents(10)
      ])
      setSummary(s.data)
      setTimeline(t.data)
      setHosts(h.data)
      setRules(r.data)
      setRecent(rec.data)
      setLastUpdate(new Date().toLocaleTimeString('fr-FR'))
    } catch (e) { console.error(e) }
  }

  useEffect(() => { load() }, [period])
  useEffect(() => { const t = setInterval(load, 30000); return () => clearInterval(t) }, [period])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Tableau de Bord</h1>
          <p className="text-sm text-soc-muted">Centre des Opérations de Sécurité — HACO S.A.</p>
        </div>
        <div className="text-xs text-soc-muted">
          Dernière MàJ : {lastUpdate || '—'} • Auto-actualisation 30s
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <KpiCard title="Total Incidents"   value={summary?.total}         icon={ShieldAlert}  color="#3b82f6" />
        <KpiCard title="Incidents Ouverts" value={summary?.open}          icon={Activity}     color="#f97316" />
        <KpiCard title="Critiques"         value={summary?.critical}      icon={ShieldX}      color="#ef4444" />
        <KpiCard title="Élevés"            value={summary?.high}          icon={AlertTriangle} color="#f97316" />
        <KpiCard title="Vrais Positifs"    value={summary?.true_positives} icon={CheckCircle}  color="#22c55e" />
        <KpiCard title="Moyens"            value={summary?.medium}        icon={Zap}          color="#eab308" />
      </div>

      {/* Timeline + Severity donut */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Timeline */}
        <div className="lg:col-span-2 bg-soc-panel border border-soc-border rounded-xl p-4">
          <div className="flex items-center justify-between mb-4">
            <div className="text-sm font-semibold text-white">Évolution des Incidents</div>
            <div className="flex gap-1">
              {Object.entries(PERIOD_LABELS).map(([k, v]) => (
                <button key={k} onClick={() => setPeriod(k)}
                  className={`px-2 py-1 text-xs rounded ${period === k ? 'bg-soc-accent text-white' : 'text-soc-muted hover:text-white'}`}>
                  {v}
                </button>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="label" stroke="#6b7280" tick={{ fontSize: 11 }} />
              <YAxis stroke="#6b7280" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px' }} />
              <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#colorCritical)" name="Critique" />
              <Area type="monotone" dataKey="high"     stroke="#f97316" fill="url(#colorHigh)"     name="Élevé" />
              <Area type="monotone" dataKey="medium"   stroke="#eab308" fill="none" strokeDasharray="4 2" name="Moyen" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity donut */}
        <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
          <div className="text-sm font-semibold text-white mb-4">Répartition par Sévérité</div>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={summary?.by_severity || []} cx="50%" cy="50%" innerRadius={45} outerRadius={70}
                   dataKey="value" nameKey="name">
                {(summary?.by_severity || []).map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px' }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-1.5 mt-2">
            {(summary?.by_severity || []).map(s => (
              <div key={s.name} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full" style={{ background: s.color }} />
                  <span className="text-soc-muted">{s.name}</span>
                </div>
                <span className="text-white font-medium">{s.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Attack classes + Top hosts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Attack class bar chart */}
        <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
          <div className="text-sm font-semibold text-white mb-4">Classes d'Attaque</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={(summary?.by_category || []).map(c => ({
              name: ATTACK_LABELS[c.category] || c.category,
              count: c.cnt
            }))} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
              <XAxis type="number" stroke="#6b7280" tick={{ fontSize: 11 }} />
              <YAxis type="category" dataKey="name" stroke="#6b7280" tick={{ fontSize: 10 }} width={120} />
              <Tooltip contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px' }} />
              <Bar dataKey="count" fill="#3b82f6" radius={[0,4,4,0]} name="Incidents" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top hosts */}
        <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
          <div className="text-sm font-semibold text-white mb-4">Hôtes les Plus Ciblés</div>
          <div className="space-y-2">
            {hosts.slice(0, 8).map((h, i) => (
              <div key={h.host} className="flex items-center gap-3">
                <div className="text-xs text-soc-muted w-4">{i + 1}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-xs text-white font-mono truncate">{h.host}</span>
                    <span className="text-xs text-soc-muted ml-2">{h.incident_count}</span>
                  </div>
                  <div className="bg-soc-border rounded-full h-1">
                    <div className="h-1 rounded-full" style={{
                      width: `${(h.incident_count / (hosts[0]?.incident_count || 1)) * 100}%`,
                      background: SEVERITY_COLORS[h.max_severity] || '#3b82f6'
                    }} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top rules + Recent incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top rules */}
        <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
          <div className="text-sm font-semibold text-white mb-4">Règles de Corrélation les Plus Actives</div>
          <div className="space-y-2">
            {rules.map(r => (
              <div key={r.rule_id} className="flex items-center justify-between py-2 border-b border-soc-border last:border-0">
                <div>
                  <div className="text-xs font-mono text-soc-accent">{r.rule_id}</div>
                  <div className="text-sm text-white">{r.rule_name}</div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-white">{r.fired_count}</div>
                  <div className="text-xs text-soc-muted">déclenchements</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent incidents feed */}
        <div className="bg-soc-panel border border-soc-border rounded-xl p-4">
          <div className="text-sm font-semibold text-white mb-4">Flux d'Incidents Récents</div>
          <div className="space-y-2">
            {recent.map(inc => (
              <div key={inc.id}
                onClick={() => setSelected(inc.id)}
                className="flex items-center gap-3 py-2 border-b border-soc-border last:border-0 cursor-pointer hover:bg-soc-border/30 rounded px-2 -mx-2 transition-colors">
                <div className="w-2 h-2 rounded-full flex-shrink-0"
                     style={{ background: SEVERITY_COLORS[inc.severity] }} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs text-white truncate">
                    {ATTACK_LABELS[inc.attack_class] || inc.attack_class || inc.category}
                  </div>
                  <div className="text-xs text-soc-muted">
                    {inc.target_hosts?.[0] || '—'} · {formatDate(inc.created_at)}
                  </div>
                </div>
                <span className={`text-xs px-1.5 py-0.5 rounded ${SEVERITY_BADGE[inc.severity]}`}>
                  {SEVERITY_LABELS[inc.severity]}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {selected && <IncidentModal id={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}