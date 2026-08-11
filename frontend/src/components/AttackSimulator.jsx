import { useState } from 'react'
import { Zap, ShieldAlert, Database, Play } from 'lucide-react'
import { simulateLog, predict } from '../api'

// Threat class -> badge styling
const CLASS_STYLES = {
  0: { label: 'C0 Benign', cls: 'bg-green-500/20 text-green-400 border-green-500/40' },
  1: { label: 'C1 Horizontal', cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40' },
  2: { label: 'C2 Vertical', cls: 'bg-red-500/20 text-red-400 border-red-500/40' },
  3: { label: 'C3 Exfiltration', cls: 'bg-purple-500/20 text-purple-400 border-purple-500/40' },
  4: { label: 'C4 Lateral', cls: 'bg-orange-500/20 text-orange-400 border-orange-500/40' },
}

const SIM_BUTTONS = [
  { cls: 0, label: 'Simulate Normal (C0)', icon: Play, color: 'bg-green-600 hover:bg-green-500' },
  { cls: 2, label: 'Simulate Vertical Escalation (C2)', icon: ShieldAlert, color: 'bg-red-600 hover:bg-red-500' },
  { cls: 3, label: 'Simulate Data Exfiltration (C3)', icon: Database, color: 'bg-purple-600 hover:bg-purple-500' },
]

export default function AttackSimulator({ onIncidentSelect }) {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const runSimulation = async (threatClass) => {
    setLoading(true)
    setError(null)
    try {
      // 1. Generate synthetic audit log for the class
      const simRes = await simulateLog(threatClass)
      const auditLog = simRes.data.audit_log

      // 2. Run full detection pipeline
      const predRes = await predict(auditLog)
      const data = predRes.data

      const incident = {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        user: auditLog.userIdentity?.userName || 'unknown',
        principal: auditLog.userIdentity?.arn || 'n/a',
        predictedClass: data.prediction.predicted_class,
        classLabel: data.prediction.class_label,
        confidence: data.prediction.confidence,
        latency: data.prediction.execution_latency_ms,
        actionStatus: data.threshold_exceeded ? 'CONTAINED' : 'MONITORED',
        xai: data.xai,
        summary: data.soc_summary,
        mitigation: data.mitigation,
        probabilities: data.prediction.probabilities,
      }

      setLogs(prev => [incident, ...prev].slice(0, 20))
    } catch (e) {
      setError('Backend unreachable. Is FastAPI running on :8000?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Simulator controls */}
      <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
        <div className="flex items-center gap-2 mb-4">
          <Zap className="text-cyber-accent" size={20} />
          <h2 className="text-lg font-semibold">Live Telemetry Stream & Attack Simulator</h2>
        </div>
        <div className="flex flex-wrap gap-3">
          {SIM_BUTTONS.map(btn => {
            const Icon = btn.icon
            return (
              <button
                key={btn.cls}
                onClick={() => runSimulation(btn.cls)}
                disabled={loading}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-white font-medium
                            transition-colors disabled:opacity-50 ${btn.color}`}
              >
                <Icon size={16} />
                {btn.label}
              </button>
            )
          })}
        </div>
        {loading && <p className="text-sm text-cyber-accent mt-3 animate-pulse">Running inference pipeline...</p>}
        {error && <p className="text-sm text-red-400 mt-3">{error}</p>}
      </div>

      {/* Live log stream table */}
      <div className="bg-cyber-panel border border-cyber-border rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-border">
          <h3 className="font-semibold">Live Event Stream</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-cyber-bg text-gray-400 text-xs uppercase">
              <tr>
                <th className="text-left px-6 py-3">Timestamp</th>
                <th className="text-left px-6 py-3">User</th>
                <th className="text-left px-6 py-3">Principal</th>
                <th className="text-left px-6 py-3">Threat Class</th>
                <th className="text-left px-6 py-3">Confidence</th>
                <th className="text-left px-6 py-3">Action</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-10 text-center text-gray-500">
                    No events yet. Trigger a simulation above.
                  </td>
                </tr>
              )}
              {logs.map(log => {
                const style = CLASS_STYLES[log.predictedClass]
                return (
                  <tr
                    key={log.id}
                    onClick={() => onIncidentSelect(log)}
                    className="border-t border-cyber-border hover:bg-cyber-bg/50 cursor-pointer"
                  >
                    <td className="px-6 py-3 font-mono text-xs text-gray-400">{log.timestamp}</td>
                    <td className="px-6 py-3">{log.user}</td>
                    <td className="px-6 py-3 font-mono text-xs text-gray-400 max-w-[180px] truncate">{log.principal}</td>
                    <td className="px-6 py-3">
                      <span className={`px-2 py-1 rounded text-xs font-semibold border ${style.cls}`}>
                        {style.label}
                      </span>
                    </td>
                    <td className="px-6 py-3 font-mono">{(log.confidence * 100).toFixed(1)}%</td>
                    <td className="px-6 py-3">
                      <span className={`text-xs font-semibold ${
                        log.actionStatus === 'CONTAINED' ? 'text-red-400' : 'text-gray-400'
                      }`}>
                        {log.actionStatus}
                      </span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
      <p className="text-xs text-gray-500">Click any row to inspect its XAI breakdown →</p>
    </div>
  )
}
