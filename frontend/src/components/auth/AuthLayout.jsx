/**
 * AuthLayout — split-screen shell for the auth screens.
 *
 * Left: the KillChainBrand signature panel (hidden on small screens).
 * Right: the active form (login / signup / forgot / reset), passed as children.
 *
 * The whole thing is centered in a single full-height viewport so the auth
 * experience feels like a dedicated secure gate, not a page within the app.
 */
import KillChainBrand from './KillChainBrand'
import { ShieldCheck } from 'lucide-react'

export default function AuthLayout({ title, subtitle, children, serverStatus }) {
  const statusText = {
    active: 'Backend online',
    offline: 'Backend offline',
    checking: 'Connecting…',
  }[serverStatus] || 'Connecting…'
  const statusDot = {
    active: 'bg-green-400',
    offline: 'bg-red-400',
    checking: 'bg-yellow-400',
  }[serverStatus] || 'bg-yellow-400'

  return (
    <div className="flex min-h-screen items-stretch bg-cyber-bg text-gray-100">
      <div className="mx-auto grid w-full max-w-5xl grid-cols-1 lg:grid-cols-2">
        {/* Brand panel */}
        <div className="relative hidden border-r border-cyber-border bg-cyber-panel p-10 lg:block">
          <KillChainBrand />
        </div>

        {/* Form panel */}
        <div className="flex flex-col justify-center px-6 py-12 sm:px-12">
          <div className="mx-auto w-full max-w-sm animate-fade-rise">
            {/* Compact brand for mobile (brand panel is hidden there) */}
            <div className="mb-8 flex items-center gap-2 lg:hidden">
              <div className="rounded-lg bg-cyber-accent/10 p-1.5">
                <ShieldCheck className="text-cyber-accent" size={20} />
              </div>
              <span className="font-mono-soc text-sm tracking-[0.3em] uppercase text-cyber-accent">
                CPEDS-X
              </span>
            </div>

            <h1 className="text-2xl font-bold text-white">{title}</h1>
            {subtitle && <p className="mt-1.5 text-sm text-gray-400">{subtitle}</p>}

            <div className="mt-8">{children}</div>

            <div className="mt-8 flex items-center gap-2 border-t border-cyber-border pt-4">
              <span className={`h-1.5 w-1.5 rounded-full ${statusDot} animate-pulse`} />
              <span className="font-mono-soc text-[11px] uppercase tracking-widest text-gray-500">
                {statusText}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
