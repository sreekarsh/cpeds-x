import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { Brain, FileText, ShieldCheck, Clock } from 'lucide-react'

export default function XAIView({ incident }) {
  if (!incident) {
    return (
      <div className="bg-cyber-panel border border-cyber-border rounded-xl p-12 text-center text-gray-500">
        <Brain size={40} className="mx-auto mb-3 opacity-40" />
        No incident selected. Run a simulation and click a row to view its SHAP breakdown.
      </div>
    )
  }

  // Prepare SHAP data for horizontal bar chart
  const shapData = (incident.xai?.top_features || []).map(f => ({
    feature: f.feature,
    value: f.shap_value,
    contribution: f.contribution,
    increases: f.direction === 'increases_risk',
  }))

  return (
    <div className="space-y-6">
      {/* Incident header */}
      <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <h2 className="text-lg font-semibold">{incident.classLabel}</h2>
            <p className="text-sm text-gray-400 font-mono">{incident.principal}</p>
          </div>
          <div className="flex gap-6 text-sm">
            <div>
              <p className="text-gray-500 text-xs">CONFIDENCE</p>
              <p className="font-mono text-lg text-cyber-accent">{(incident.confidence * 100).toFixed(1)}%</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs">LATENCY</p>
              <p className="font-mono text-lg">{incident.latency} ms</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SHAP bar chart */}
        <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <Brain className="text-cyber-accent" size={18} />
            <h3 className="font-semibold">Top-5 SHAP Feature Contributions</h3>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={shapData} layout="vertical" margin={{ left: 20, right: 20 }}>
              <XAxis type="number" stroke="#6b7280" fontSize={11} />
              <YAxis dataKey="feature" type="category" width={140} stroke="#9ca3af" fontSize={11} />
              <Tooltip
                contentStyle={{ background: '#0a0e1a', border: '1px solid #1f2937', borderRadius: 8 }}
                labelStyle={{ color: '#e5e7eb' }}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {shapData.map((d, i) => (
                  <Cell key={i} fill={d.increases ? '#ef4444' : '#22c55e'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="flex gap-4 text-xs mt-2">
            <span className="flex items-center gap-1"><span className="w-3 h-3 bg-red-500 rounded-sm inline-block" /> Increases risk</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 bg-green-500 rounded-sm inline-block" /> Decreases risk</span>
          </div>
        </div>

        {/* GenAI summary + mitigation */}
        <div className="space-y-6">
          <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
            <div className="flex items-center gap-2 mb-3">
              <FileText className="text-cyber-accent" size={18} />
              <h3 className="font-semibold">GenAI Co-Pilot Summary</h3>
            </div>
            <p className="text-sm leading-relaxed text-gray-300 bg-cyber-bg p-4 rounded-lg border border-cyber-border">
              {incident.summary}
            </p>
          </div>

          <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
            <div className="flex items-center gap-2 mb-3">
              <ShieldCheck className="text-cyber-accent" size={18} />
              <h3 className="font-semibold">Automated Mitigation</h3>
            </div>
            {incident.mitigation ? (
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-sm">
                  <Clock size={14} className="text-gray-400" />
                  <span>MTTC:</span>
                  <span className="font-mono text-green-400">{incident.mitigation.mttc_seconds}s</span>
                  {incident.mitigation.mttc_target_met &&
                    <span className="text-xs text-green-400">(&lt; 30s target met)</span>}
                </div>
                {incident.mitigation.actions.map((a, i) => (
                  <div key={i} className="text-xs bg-cyber-bg p-3 rounded-lg border border-cyber-border">
                    <span className="font-semibold text-cyber-accent">{a.action}</span>
                    <span className={`ml-2 ${a.status === 'success' ? 'text-green-400' : 'text-red-400'}`}>
                      [{a.status}] ({a.mode})
                    </span>
                    {a.detail && <p className="text-gray-400 mt-1">{a.detail}</p>}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500">
                No mitigation triggered (benign or below 0.75 threshold).
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
