import { NavLink } from 'react-router-dom'
import { LayoutDashboard, ShieldAlert, Activity, Server } from 'lucide-react'

const links = [
  { to: '/',          icon: LayoutDashboard, label: 'Tableau de Bord' },
  { to: '/incidents', icon: ShieldAlert,     label: 'Incidents'        },
  { to: '/sante',     icon: Activity,        label: 'Santé Système'    },
]

export default function Sidebar() {
  return (
    <aside className="w-56 min-h-screen bg-soc-panel border-r border-soc-border flex flex-col">
      {/* Logo */}
      <div className="px-4 py-5 border-b border-soc-border">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-soc-accent rounded flex items-center justify-center">
            <Server size={16} className="text-white" />
          </div>
          <div>
            <div className="text-sm font-bold text-white">HACO SOC</div>
            <div className="text-xs text-soc-muted">v1.0</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-4 space-y-1">
        {links.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-soc-accent text-white'
                  : 'text-soc-muted hover:text-white hover:bg-soc-border'
              }`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-soc-border text-xs text-soc-muted">
        HACO S.A. — El Haouaria
      </div>
    </aside>
  )
}