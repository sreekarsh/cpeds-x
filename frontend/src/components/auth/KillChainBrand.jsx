/**
 * KillChainBrand — the signature element of the auth screen.
 *
 * An animated privilege-escalation kill chain: External Actor -> IAM Identity
 * -> Assumed Role -> Compute Host -> Data Store. It's the exact attack path
 * CPEDS-X exists to detect, so the login screen opens with the product's thesis
 * rather than a generic logo. Pure SVG + CSS; no dependencies.
 */
import { Globe, KeyRound, UserCog, Server, Database } from 'lucide-react'

const STAGES = [
  { icon: Globe,   label: 'External Actor', tag: 'ingress' },
  { icon: KeyRound, label: 'IAM Identity',  tag: 'credential' },
  { icon: UserCog, label: 'Assumed Role',   tag: 'escalation' },
  { icon: Server,  label: 'Compute Host',   tag: 'lateral' },
  { icon: Database, label: 'Data Store',    tag: 'exfiltration' },
]

export default function KillChainBrand() {
  return (
    <div className="relative flex flex-col justify-between h-full overflow-hidden">
      {/* drifting grid backdrop */}
      <div
        className="kc-grid pointer-events-none absolute inset-0 opacity-[0.15]"
        style={{
          backgroundImage:
            'linear-gradient(#22d3ee22 1px, transparent 1px), linear-gradient(90deg, #22d3ee22 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />
      {/* soft radial glow */}
      <div
        className="pointer-events-none absolute -top-24 -left-24 h-96 w-96 rounded-full opacity-30 blur-3xl"
        style={{ background: 'radial-gradient(circle, #22d3ee55, transparent 70%)' }}
      />

      {/* Top: wordmark */}
      <div className="relative z-10">
        <div className="flex items-center gap-2 text-cyber-accent">
          <span className="font-mono-soc text-sm tracking-[0.3em] uppercase">CPEDS-X</span>
        </div>
        <p className="mt-1 font-mono-soc text-[11px] tracking-widest text-gray-500 uppercase">
          Secure Operations Console
        </p>
      </div>

      {/* Middle: the kill chain */}
      <div className="relative z-10 py-6">
        <p className="mb-6 max-w-xs text-lg font-semibold leading-snug text-gray-200">
          We watch the path attackers take —
          <span className="text-cyber-accent"> from a stolen key to your data.</span>
        </p>

        <ol className="space-y-0">
          {STAGES.map((stage, i) => {
            const Icon = stage.icon
            const last = i === STAGES.length - 1
            return (
              <li key={stage.label} className="relative flex items-center gap-4">
                <div className="flex flex-col items-center">
                  <span
                    className="kc-node flex h-11 w-11 items-center justify-center rounded-lg border border-cyber-accent/40 bg-cyber-accent/5 text-cyber-accent"
                    style={{ animationDelay: `${i * 0.35}s` }}
                  >
                    <Icon size={18} />
                  </span>
                  {!last && (
                    <svg width="2" height="34" className="my-0.5" aria-hidden="true">
                      <line
                        x1="1" y1="0" x2="1" y2="34"
                        className="kc-link"
                        stroke="#22d3ee"
                        strokeWidth="2"
                        style={{ animationDelay: `${i * 0.2}s` }}
                      />
                    </svg>
                  )}
                </div>
                <div className={last ? '' : 'pb-1'}>
                  <div className="text-sm font-medium text-gray-100">{stage.label}</div>
                  <div className="font-mono-soc text-[10px] uppercase tracking-widest text-gray-500">
                    {String(i + 1).padStart(2, '0')} · {stage.tag}
                  </div>
                </div>
              </li>
            )
          })}
        </ol>
      </div>

      {/* Bottom: honest footnote */}
      <div className="relative z-10 font-mono-soc text-[11px] leading-relaxed text-gray-600">
        <div className="mb-1 h-px w-12 bg-cyber-border" />
        LightGBM ensemble · SHAP explainability · automated containment
      </div>
    </div>
  )
}
