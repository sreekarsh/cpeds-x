import { useMemo } from 'react'
import { Network, User, Key, ShieldAlert, Server, Database, Globe } from 'lucide-react'

/**
 * Node Graph Attack Map
 * Visualizes the cloud privilege-escalation kill-chain as a node graph.
 * Nodes and edges light up based on the selected incident's threat class,
 * mapping each class (C1-C4) to the attack stages it activates.
 */

// Kill-chain nodes laid out left-to-right
const NODES = [
  { id: 'attacker', label: 'External Actor', icon: Globe, x: 80, y: 160 },
  { id: 'iam',      label: 'IAM Identity',   icon: User, x: 260, y: 160 },
  { id: 'role',     label: 'Assumed Role',   icon: Key, x: 440, y: 80 },
  { id: 'priv',     label: 'Privilege Grant', icon: ShieldAlert, x: 440, y: 240 },
  { id: 'host',     label: 'EC2 / Host',     icon: Server, x: 620, y: 160 },
  { id: 'data',     label: 'S3 / Secrets',   icon: Database, x: 800, y: 160 },
]

const EDGES = [
  { from: 'attacker', to: 'iam' },
  { from: 'iam', to: 'role' },
  { from: 'iam', to: 'priv' },
  { from: 'role', to: 'host' },
  { from: 'priv', to: 'host' },
  { from: 'host', to: 'data' },
]

// Which nodes/edges each threat class activates
const CLASS_PATHS = {
  0: { nodes: ['attacker', 'iam'], label: 'C0 Benign — normal identity activity', color: '#22c55e' },
  1: { nodes: ['attacker', 'iam', 'role'], label: 'C1 Horizontal — lateral role assumption', color: '#eab308' },
  2: { nodes: ['attacker', 'iam', 'priv', 'host'], label: 'C2 Vertical — privilege grant escalation', color: '#ef4444' },
  3: { nodes: ['attacker', 'iam', 'role', 'host', 'data'], label: 'C3 Exfiltration — data access & extraction', color: '#a855f7' },
  4: { nodes: ['attacker', 'iam', 'role', 'priv', 'host', 'data'], label: 'C4 Lateral — full cross-account movement', color: '#f97316' },
}

function nodeById(id) {
  return NODES.find(n => n.id === id)
}

export default function AttackMap({ incident }) {
  const activeClass = incident?.predictedClass ?? null
  const path = activeClass !== null ? CLASS_PATHS[activeClass] : null
  const activeNodes = useMemo(() => new Set(path?.nodes || []), [path])

  // An edge is active if BOTH its endpoints are in the active path
  const isEdgeActive = (e) => activeNodes.has(e.from) && activeNodes.has(e.to)

  return (
    <div className="space-y-6">
      <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
        <div className="flex items-center justify-between flex-wrap gap-3 mb-2">
          <div className="flex items-center gap-2">
            <Network className="text-cyber-accent" size={20} />
            <h2 className="text-lg font-semibold">Node Graph Attack Map</h2>
          </div>
          {path && (
            <span
              className="px-3 py-1 rounded-full text-xs font-semibold border"
              style={{ color: path.color, borderColor: `${path.color}66`, background: `${path.color}1a` }}
            >
              {path.label}
            </span>
          )}
        </div>

        {!incident && (
          <p className="text-sm text-gray-500 mb-4">
            No incident selected. Run a simulation in the Attack Simulator tab and
            click a row — the attack path will light up here.
          </p>
        )}

        {/* SVG graph */}
        <div className="w-full overflow-x-auto">
          <svg viewBox="0 0 880 320" className="w-full min-w-[700px]" style={{ height: 320 }}>
            {/* Edges */}
            {EDGES.map((e, i) => {
              const a = nodeById(e.from)
              const b = nodeById(e.to)
              const active = isEdgeActive(e)
              return (
                <g key={i}>
                  <line
                    x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                    stroke={active ? (path?.color || '#22d3ee') : '#1f2937'}
                    strokeWidth={active ? 3 : 1.5}
                    strokeDasharray={active ? '0' : '4 4'}
                  />
                  {active && (
                    <circle r="4" fill={path?.color || '#22d3ee'}>
                      <animateMotion
                        dur="1.8s"
                        repeatCount="indefinite"
                        path={`M ${a.x} ${a.y} L ${b.x} ${b.y}`}
                      />
                    </circle>
                  )}
                </g>
              )
            })}

            {/* Nodes */}
            {NODES.map((n) => {
              const active = activeNodes.has(n.id)
              const color = active ? (path?.color || '#22d3ee') : '#374151'
              return (
                <g key={n.id}>
                  <circle
                    cx={n.x} cy={n.y} r={26}
                    fill="#0a0e1a"
                    stroke={color}
                    strokeWidth={active ? 3 : 1.5}
                    style={active ? { filter: `drop-shadow(0 0 6px ${color})` } : {}}
                  />
                  <text
                    x={n.x} y={n.y + 46}
                    textAnchor="middle"
                    fontSize="12"
                    fill={active ? '#e5e7eb' : '#6b7280'}
                    fontWeight={active ? 600 : 400}
                  >
                    {n.label}
                  </text>
                </g>
              )
            })}
          </svg>
        </div>

        {/* Icon legend row (lucide icons under the SVG, since SVG can't embed them directly) */}
        <div className="flex flex-wrap gap-4 mt-2 text-xs text-gray-400">
          {NODES.map(n => {
            const Icon = n.icon
            const active = activeNodes.has(n.id)
            return (
              <span key={n.id} className={`flex items-center gap-1.5 ${active ? 'text-gray-200' : ''}`}>
                <Icon size={14} style={active ? { color: path?.color } : {}} />
                {n.label}
              </span>
            )
          })}
        </div>
      </div>

      {/* Stage explanation */}
      {incident && (
        <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
          <h3 className="font-semibold mb-3">Attack Progression</h3>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            {path.nodes.map((nid, i) => (
              <span key={nid} className="flex items-center gap-2">
                <span
                  className="px-3 py-1.5 rounded-lg border font-medium"
                  style={{ color: path.color, borderColor: `${path.color}66`, background: `${path.color}1a` }}
                >
                  {nodeById(nid).label}
                </span>
                {i < path.nodes.length - 1 && <span className="text-gray-600">→</span>}
              </span>
            ))}
          </div>
          <p className="text-xs text-gray-500 mt-4">
            Detected threat <span className="font-mono">{incident.classLabel}</span> at{' '}
            {(incident.confidence * 100).toFixed(1)}% confidence.
            {incident.actionStatus === 'CONTAINED' && ' Path severed by automated containment.'}
          </p>
        </div>
      )}
    </div>
  )
}
