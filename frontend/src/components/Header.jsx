import { Shield, Circle, LogOut } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Header({ status }) {
  const { user, logout } = useAuth()

  const statusConfig = {
    active: { color: 'text-green-400', bg: 'bg-green-400', label: 'ACTIVE' },
    offline: { color: 'text-red-400', bg: 'bg-red-400', label: 'OFFLINE' },
    checking: { color: 'text-yellow-400', bg: 'bg-yellow-400', label: 'CONNECTING' },
  }
  const cfg = statusConfig[status] || statusConfig.checking

  // Initials for the user avatar chip.
  const initials = (user?.full_name || user?.email || '?')
    .split(/\s+/)
    .map((p) => p[0])
    .slice(0, 2)
    .join('')
    .toUpperCase()

  return (
    <header className="bg-cyber-panel border-b border-cyber-border">
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyber-accent/10 rounded-lg">
            <Shield className="text-cyber-accent" size={28} />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">
              CPEDS-X: Cloud Privilege Escalation Defense
            </h1>
            <p className="text-xs text-gray-400">
              Real-Time ML Threat Detection & Automated Containment
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 bg-cyber-bg rounded-full border border-cyber-border">
            <Circle className={`${cfg.color} ${cfg.bg} rounded-full animate-pulse`} size={8} fill="currentColor" />
            <span className={`text-xs font-semibold ${cfg.color}`}>{cfg.label}</span>
          </div>

          {user && (
            <>
              <div className="flex items-center gap-2.5 pl-1">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyber-accent/15 text-xs font-semibold text-cyber-accent">
                  {initials}
                </div>
                <div className="hidden md:block leading-tight">
                  <div className="text-sm font-medium text-gray-100">{user.full_name}</div>
                  <div className="text-[11px] text-gray-500">{user.email}</div>
                </div>
              </div>
              <button
                onClick={logout}
                className="flex items-center gap-1.5 rounded-lg border border-cyber-border px-3 py-1.5 text-sm text-gray-300 transition-colors hover:border-red-500/50 hover:text-red-300 focus:outline-none focus:ring-2 focus:ring-red-500/30"
                title="Sign out"
              >
                <LogOut size={15} />
                <span className="hidden sm:inline">Sign out</span>
              </button>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
