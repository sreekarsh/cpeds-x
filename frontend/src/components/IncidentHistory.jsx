import { useState, useEffect, useCallback } from 'react'
import {
  History, RefreshCw, Trash2, Loader2, ShieldAlert, ShieldCheck,
  AlertTriangle, ChevronRight, Activity, Swords, UploadCloud, FileDown, Radio,
} from 'lucide-react'
import { getIncidents, predict, clearIncidents, errMessage } from '../api'
import { generateSocReport } from '../utils/socReport'
import { useAuth } from '../context/AuthContext'

// Threat class -> badge styling (shared palette across every tab).
const CLASS_STYLES = {
  0: { label: 'C0 Benign', cls: 'bg-green-500/15 text-green-400 border-green-500/40' },
  1: { label: 'C1 Horizontal', cls: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40' },
  2: { label: 'C2 Vertical', cls: 'bg-red-500/15 text-red-400 border-red-500/40' },
  3: { label: 'C3 Exfiltration', cls: 'bg-purple-500/15 text-purple-400 border-purple-500/40' },
  4: { label: 'C4 Lateral', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/40' },
}

// Where a saved detection came from -> small labelled chip.
const SOURCE_META = {
  live: { label: 'Live sim', icon: Activity },
  'live-aws': { label: 'Live AWS', icon: Radio },
  scenario: { label: 'Scenario', icon: Swords },
  analyze: { label: 'Upload', icon: UploadCloud },
}

function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return d.toLocaleString([], {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
  })
}

function StatCard({ icon: Icon, label, value, tone = 'text-gray-100', sub }) {
  return (
    <div className="rounded-xl border border-cyber-border bg-cyber-panel px-4 py-3">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-gray-500">
        <Icon size={14} /> {label}
      </div>
      <div className={`mt-1 text-2xl font-semibold ${tone}`}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-gray-500">{sub}</div>}
    </div>
  )
}

export default function IncidentHistory({ onIncidentSelect }) {
  const { user } = useAuth()
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [rowLoading, setRowLoading] = useState(null)
  const [clearing, setClearing] = useState(false)
  const [confirmClear, setConfirmClear] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const res = await getIncidents(500)
      setIncidents(res.data.incidents || [])
    } catch (e) {
      setError(errMessage(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Re-run the full pipeline (with SHAP) on the stored raw log and hand the
  // incident to the XAI tab — same contract the other producers use.
  const inspectRow = async (inc) => {
    if (!inc.raw_log) return
    setRowLoading(inc.id)
    setError('')
    try {
      const { data: d } = await predict(inc.raw_log)
      onIncidentSelect({
        id: `hist-${inc.id}`,
        timestamp: fmtTime(inc.created_at),
        user: inc.raw_log?.userIdentity?.userName || inc.principal || 'unknown',
        principal: inc.principal || 'n/a',
        predictedClass: d.prediction.predicted_class,
        classLabel: d.prediction.class_label,
        confidence: d.prediction.confidence,
        latency: d.prediction.execution_latency_ms,
        actionStatus: d.threshold_exceeded ? 'CONTAINED' : 'MONITORED',
        xai: d.xai,
        summary: d.soc_summary,
        mitigation: d.mitigation,
        probabilities: d.prediction.probabilities,
      })
    } catch (e) {
      setError(errMessage(e))
    } finally {
      setRowLoading(null)
    }
  }

  const doClear = async () => {
    setClearing(true)
    setError('')
    try {
      await clearIncidents()
      setIncidents([])
      setConfirmClear(false)
    } catch (e) {
      setError(errMessage(e))
    } finally {
      setClearing(false)
    }
  }

  const downloadReport = () => {
    if (!incidents.length) return
    try {
      generateSocReport(incidents, {
        analystName: user?.full_name,
        analystEmail: user?.email,
      })
    } catch (e) {
      setError('Could not open the report for printing. Check that pop-ups/printing are allowed.')
    }
  }

  const total = incidents.length
  const threats = incidents.filter((i) => i.predicted_class !== 0).length
  const contained = incidents.filter((i) => i.action_status === 'CONTAINED').length
  const lastSeen = total ? fmtTime(incidents[0].created_at) : '—'

  return (
    <div className="space-y-6">
      {/* ---------------- Header + toolbar ---------------- */}
      <div className="rounded-xl border border-cyber-border bg-cyber-panel p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="mb-2 flex items-center gap-2">
              <History className="text-cyber-accent" size={20} />
              <h2 className="text-lg font-semibold">Incident History</h2>
            </div>
            <p className="max-w-2xl text-sm text-gray-400">
              Every detection you trigger — from the live simulator, a purple-team
              scenario, or an uploaded log — is saved to your own private case file.
              Click any incident to re-open its full XAI breakdown.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={downloadReport}
              disabled={!total}
              className="flex items-center gap-2 rounded-lg border border-cyber-accent/40 bg-cyber-accent/10 px-3 py-2 text-sm font-medium text-cyber-accent transition-colors hover:bg-cyber-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
              title="Generate a printable SOC report (Save as PDF)"
            >
              <FileDown size={15} /> Download report
            </button>
            <button
              onClick={load}
              disabled={loading}
              className="flex items-center gap-2 rounded-lg border border-cyber-border px-3 py-2 text-sm font-medium text-gray-300 transition-colors hover:border-cyber-accent/50 hover:text-cyber-accent disabled:opacity-50"
            >
              {loading ? <Loader2 size={15} className="animate-spin" /> : <RefreshCw size={15} />}
              Refresh
            </button>
            {confirmClear ? (
              <div className="flex items-center gap-2">
                <button
                  onClick={doClear}
                  disabled={clearing}
                  className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm font-medium text-red-300 transition-colors hover:bg-red-500/20 disabled:opacity-50"
                >
                  {clearing ? <Loader2 size={15} className="animate-spin" /> : <Trash2 size={15} />}
                  Confirm clear
                </button>
                <button
                  onClick={() => setConfirmClear(false)}
                  className="rounded-lg px-2 py-2 text-sm text-gray-500 hover:text-gray-300"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirmClear(true)}
                disabled={!total}
                className="flex items-center gap-2 rounded-lg border border-cyber-border px-3 py-2 text-sm font-medium text-gray-400 transition-colors hover:border-red-500/50 hover:text-red-300 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <Trash2 size={15} /> Clear history
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-sm text-red-300">
            <AlertTriangle size={16} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* ---------------- Stat cards ---------------- */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard icon={History} label="Saved incidents" value={total} sub="your case file" />
        <StatCard icon={ShieldAlert} label="Threats" value={threats}
          tone={threats ? 'text-red-400' : 'text-green-400'} sub="non-benign verdicts" />
        <StatCard icon={ShieldCheck} label="Auto-contained" value={contained}
          tone={contained ? 'text-cyber-accent' : 'text-gray-100'} sub="≥ 75% confidence" />
        <StatCard icon={Activity} label="Most recent" value={lastSeen} sub="local time" />
      </div>

      {/* ---------------- Incident table ---------------- */}
      <div className="overflow-hidden rounded-xl border border-cyber-border bg-cyber-panel">
        <div className="border-b border-cyber-border px-6 py-4">
          <h3 className="font-semibold">Detections — newest first</h3>
          <p className="mt-0.5 text-xs text-gray-500">Click any row to open its XAI breakdown →</p>
        </div>

        {loading ? (
          <div className="flex items-center gap-2 px-6 py-10 text-sm text-gray-500">
            <Loader2 size={16} className="animate-spin" /> Loading incident history…
          </div>
        ) : total === 0 ? (
          <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
            <History className="mb-3 text-gray-600" size={30} />
            <p className="text-sm text-gray-400">No incidents saved yet.</p>
            <p className="mt-1 max-w-md text-xs text-gray-500">
              Run the Attack Simulator or launch a Scenario, and every detection will
              land here automatically for later review.
            </p>
          </div>
        ) : (
          <div className="max-h-[560px] overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-cyber-bg text-xs uppercase text-gray-400">
                <tr>
                  <th className="px-4 py-3 text-left">Time</th>
                  <th className="px-4 py-3 text-left">Source</th>
                  <th className="px-4 py-3 text-left">Event</th>
                  <th className="px-4 py-3 text-left">Principal</th>
                  <th className="px-4 py-3 text-left">Threat Class</th>
                  <th className="px-4 py-3 text-left">Confidence</th>
                  <th className="px-4 py-3 text-left">Action</th>
                  <th className="px-4 py-3 text-left"></th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => {
                  const style = CLASS_STYLES[inc.predicted_class] || CLASS_STYLES[0]
                  const isThreat = inc.predicted_class !== 0
                  const src = SOURCE_META[inc.source] || { label: inc.source || '—', icon: Activity }
                  const SrcIcon = src.icon
                  const drillable = !!inc.raw_log
                  return (
                    <tr
                      key={inc.id}
                      onClick={() => inspectRow(inc)}
                      className={`border-t border-cyber-border ${drillable ? 'cursor-pointer hover:bg-cyber-bg/50' : 'opacity-70'}`}
                    >
                      <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-gray-400">{fmtTime(inc.created_at)}</td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center gap-1.5 rounded bg-cyber-bg px-2 py-1 text-[11px] text-gray-400">
                          <SrcIcon size={12} /> {src.label}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-gray-200">{inc.event_name || '—'}</div>
                        <div className="font-mono text-[11px] text-gray-500">{inc.source_ip || ''}</div>
                      </td>
                      <td className="max-w-[200px] truncate px-4 py-3 font-mono text-xs text-gray-400">{inc.principal}</td>
                      <td className="px-4 py-3">
                        <span className={`rounded border px-2 py-1 text-xs font-semibold ${style.cls}`}>{style.label}</span>
                      </td>
                      <td className="px-4 py-3 font-mono">{(inc.confidence * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-semibold ${inc.action_status === 'CONTAINED' ? 'text-red-400' : 'text-gray-400'}`}>
                          {inc.action_status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        {rowLoading === inc.id
                          ? <Loader2 size={15} className="animate-spin text-cyber-accent" />
                          : drillable
                            ? <ChevronRight size={15} className={isThreat ? 'text-cyber-accent' : 'text-gray-600'} />
                            : <span className="text-[10px] text-gray-600">no log</span>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
