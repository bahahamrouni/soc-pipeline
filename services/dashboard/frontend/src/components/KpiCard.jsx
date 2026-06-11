export default function KpiCard({ title, value, sub, color, icon: Icon }) {
  return (
    <div className="bg-soc-panel border border-soc-border rounded-xl p-4 flex items-center gap-4">
      {Icon && (
        <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
             style={{ backgroundColor: color + '22', color }}>
          <Icon size={20} />
        </div>
      )}
      <div>
        <div className="text-2xl font-bold text-white">{value ?? '—'}</div>
        <div className="text-sm text-soc-muted">{title}</div>
        {sub && <div className="text-xs mt-0.5" style={{ color }}>{sub}</div>}
      </div>
    </div>
  )
}