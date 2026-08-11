import { useState, useRef, useCallback } from 'react'
import {
  UploadCloud, FileJson, Play, Loader2, ShieldCheck, ShieldAlert,
  AlertTriangle, Download, FileText, X, ChevronRight, Activity,
} from 'lucide-react'
import { analyzeLogs, getSampleLogs, predict, errMessage } from '../api'

// Threat class -> badge styling (matches the Attack Simulator palette).
const CLASS_STYLES = {
  0: { label: 'C0 Benign', cls: 'bg-green-500/15 text-green-400 border-green-500/40' },
  1: { label: 'C1 Horizontal', cls: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40' },
  2: { label: 'C2 Vertical', cls: 'bg-red-500/15 text-red-400 border-red-500/40' },
  3: { label: 'C3 Exfiltration', cls: 'bg-purple-500/15 text-purple-400 border-purple-500/40' },
  4: { label: 'C4 Lateral', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/40' },
}

const MAX_BYTES = 8 * 1024 * 1024 // 8 MB upload guard

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

export default function LogAnalysis({ onIncidentSelect }) {
  const [fileName, setFileName] = useState('')
  const [content, setContent] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const [loading, setLoading] = useState(false)
  const [loadingSample, setLoadingSample] = useState(false)
  const [rowLoading, setRowLoading] = useState(null)
  const [error, setError] = useState('')
  const [data, setData] = useState(null)
  const fileInput = useRef(null)

  const readFile = useCallback((file) => {
    setError('')
    if (!file) return
    if (file.size > MAX_BYTES) {
      setError(`File is too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Limit is 8 MB.`)
      return
    }
    const reader = new FileReader()
    reader.onload = (e) => {
      setContent(e.target.result || '')
      setFileName(file.name)
      setData(null)
    }
    reader.onerror = () => setError('Could not read that file.')
    reader.readAsText(file)
  }, [])

  const onDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    readFile(e.dataTransfer.files?.[0])
  }

  const loadSample = async () => {
    setError('')
    setLoadingSample(true)
    try {
      const res = await getSampleLogs()
      setContent(res.data.content)
      setFileName(res.data.filename || 'cloudtrail_events_sample.json')
      setData(null)
    } catch (e) {
      setError(errMessage(e))
    } finally {
      setLoadingSample(false)
    }
  }

  const runAnalysis = async () => {
    if (!content.trim()) {
      setError('Load a file or the sample export first.')
      return
    }
    setLoading(true)
    setError('')
    try {
      const res = await analyzeLogs(content, 'auto', fileName)
      setData(res.data)
    } catch (e) {
      setError(errMessage(e))
    } finally {
      setLoading(false)
    }
  }

  const clearFile = () => {
    setContent('')
    setFileName('')
    setData(null)
    setError('')
    if (fileInput.current) fileInput.current.value = ''
  }

  // Click a result row -> re-run the full pipeline (with SHAP) and hand the
  // incident to the XAI tab, exactly like the Attack Simulator does.
  const inspectRow = async (r) => {
    if (r.error) return
    setRowLoading(r.row)
    try {
      const predRes = await predict(r.raw_log)
      const d = predRes.data
      const incident = {
        id: `${Date.now()}-${r.row}`,
        timestamp: r.timestamp || new Date().toLocaleTimeString(),
        user: r.raw_log?.userIdentity?.userName || r.principal || 'unknown',
        principal: r.principal || 'n/a',
        predictedClass: d.prediction.predicted_class,
        classLabel: d.prediction.class_label,
        confidence: d.prediction.confidence,
        latency: d.prediction.execution_latency_ms,
        actionStatus: d.threshold_exceeded ? 'CONTAINED' : 'MONITORED',
        xai: d.xai,
        summary: d.soc_summary,
        mitigation: d.mitigation,
        probabilities: d.prediction.probabilities,
      }
      onIncidentSelect(incident)
    } catch (e) {
      setError(errMessage(e))
    } finally {
      setRowLoading(null)
    }
  }

  const exportCsv = () => {
    if (!data?.results?.length) return
    const header = ['row', 'timestamp', 'event_name', 'principal', 'source_ip', 'class_label', 'confidence', 'action']
    const lines = [header.join(',')]
    for (const r of data.results) {
      if (r.error) continue
      const row = [
        r.row,
        r.timestamp || '',
        r.event_name || '',
        (r.principal || '').replace(/,/g, ' '),
        r.source_ip || '',
        r.class_label || '',
        (r.confidence * 100).toFixed(1) + '%',
        r.action || '',
      ]
      lines.push(row.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(','))
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'cpeds-x_analysis.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const s = data?.summary

  return (
    <div className="space-y-6">
      {/* ---------------- Upload panel ---------------- */}
      <div className="rounded-xl border border-cyber-border bg-cyber-panel p-6">
        <div className="mb-4 flex items-center gap-2">
          <UploadCloud className="text-cyber-accent" size={20} />
          <h2 className="text-lg font-semibold">Log Analysis — Ingest &amp; Triage</h2>
        </div>
        <p className="mb-4 text-sm text-gray-400">
          Upload an AWS CloudTrail export or any JSON / JSON&nbsp;Lines / CSV log file.
          Every event is scored by the trained model, with auto-containment applied to
          high-confidence threats. No file? Load a realistic sample export to see it work.
        </p>

        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => fileInput.current?.click()}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-8 text-center transition-colors
            ${dragOver ? 'border-cyber-accent bg-cyber-accent/5' : 'border-cyber-border hover:border-cyber-accent/50'}`}
        >
          <input
            ref={fileInput}
            type="file"
            accept=".json,.jsonl,.ndjson,.csv,.txt,application/json,text/csv"
            className="hidden"
            onChange={(e) => readFile(e.target.files?.[0])}
          />
          <UploadCloud className="mb-2 text-gray-500" size={28} />
          <p className="text-sm text-gray-300">
            <span className="font-medium text-cyber-accent">Click to browse</span> or drag a log file here
          </p>
          <p className="mt-1 text-xs text-gray-500">CloudTrail JSON · JSON array · .jsonl · .csv — up to 8&nbsp;MB</p>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button
            onClick={runAnalysis}
            disabled={loading || !content.trim()}
            className="flex items-center gap-2 rounded-lg bg-cyber-accent px-4 py-2.5 text-sm font-semibold text-cyber-bg transition-colors hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
            {loading ? 'Analyzing…' : 'Analyze logs'}
          </button>

          <button
            onClick={loadSample}
            disabled={loadingSample}
            className="flex items-center gap-2 rounded-lg border border-cyber-border px-4 py-2.5 text-sm font-medium text-gray-300 transition-colors hover:border-cyber-accent/50 hover:text-cyber-accent disabled:opacity-50"
          >
            {loadingSample ? <Loader2 size={16} className="animate-spin" /> : <FileJson size={16} />}
            Load sample export
          </button>

          {fileName && (
            <span className="flex items-center gap-2 rounded-lg bg-cyber-bg px-3 py-2 text-xs text-gray-400">
              <FileText size={14} className="text-cyber-accent" />
              {fileName}
              <button onClick={clearFile} className="text-gray-500 hover:text-red-400" title="Clear">
                <X size={14} />
              </button>
            </span>
          )}
        </div>

        {error && (
          <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-sm text-red-300">
            <AlertTriangle size={16} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* ---------------- Results ---------------- */}
      {s && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard icon={Activity} label="Events analyzed" value={s.analyzed}
              sub={s.truncated ? `capped at ${s.max_rows} of ${s.total_received}` : `${s.total_received} received`} />
            <StatCard icon={ShieldAlert} label="Threats detected" value={s.threats_detected}
              tone={s.threats_detected ? 'text-red-400' : 'text-green-400'}
              sub={`${s.benign} benign`} />
            <StatCard icon={ShieldCheck} label="Auto-contained" value={s.auto_contained}
              tone={s.auto_contained ? 'text-cyber-accent' : 'text-gray-100'}
              sub={`≥ 75% confidence`} />
            <StatCard icon={Activity} label="Processing" value={`${s.processing_ms} ms`}
              sub={`avg conf ${(s.avg_confidence * 100).toFixed(1)}%`} />
          </div>

          {/* threat distribution bar */}
          <div className="rounded-xl border border-cyber-border bg-cyber-panel p-5">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="font-semibold">Threat Distribution</h3>
              <button
                onClick={exportCsv}
                className="flex items-center gap-1.5 rounded-lg border border-cyber-border px-3 py-1.5 text-xs font-medium text-gray-300 transition-colors hover:border-cyber-accent/50 hover:text-cyber-accent"
              >
                <Download size={13} /> Export CSV
              </button>
            </div>
            <div className="space-y-2">
              {Object.entries(s.class_counts).map(([label, count]) => {
                const clsNum = Number(label[1])
                const pct = s.analyzed ? (count / s.analyzed) * 100 : 0
                const style = CLASS_STYLES[clsNum] || CLASS_STYLES[0]
                return (
                  <div key={label} className="flex items-center gap-3">
                    <span className={`w-28 shrink-0 rounded border px-2 py-0.5 text-center text-xs font-semibold ${style.cls}`}>
                      {style.label}
                    </span>
                    <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-cyber-bg">
                      <div className="h-full rounded-full bg-cyber-accent/70" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="w-14 text-right font-mono text-xs text-gray-400">{count}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* results table */}
          <div className="overflow-hidden rounded-xl border border-cyber-border bg-cyber-panel">
            <div className="border-b border-cyber-border px-6 py-4">
              <h3 className="font-semibold">Analyzed Events</h3>
              <p className="mt-0.5 text-xs text-gray-500">Click any row to open its XAI breakdown →</p>
            </div>
            <div className="max-h-[520px] overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-cyber-bg text-xs uppercase text-gray-400">
                  <tr>
                    <th className="px-4 py-3 text-left">#</th>
                    <th className="px-4 py-3 text-left">Event</th>
                    <th className="px-4 py-3 text-left">Principal</th>
                    <th className="px-4 py-3 text-left">Threat Class</th>
                    <th className="px-4 py-3 text-left">Confidence</th>
                    <th className="px-4 py-3 text-left">Action</th>
                    <th className="px-4 py-3 text-left"></th>
                  </tr>
                </thead>
                <tbody>
                  {data.results.map((r) => {
                    if (r.error) {
                      return (
                        <tr key={r.row} className="border-t border-cyber-border">
                          <td className="px-4 py-3 font-mono text-xs text-gray-500">{r.row}</td>
                          <td colSpan={6} className="px-4 py-3 text-xs text-red-400">{r.error}</td>
                        </tr>
                      )
                    }
                    const style = CLASS_STYLES[r.predicted_class] || CLASS_STYLES[0]
                    const isThreat = r.predicted_class !== 0
                    return (
                      <tr
                        key={r.row}
                        onClick={() => inspectRow(r)}
                        className="cursor-pointer border-t border-cyber-border hover:bg-cyber-bg/50"
                      >
                        <td className="px-4 py-3 font-mono text-xs text-gray-500">{r.row}</td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-gray-200">{r.event_name || '—'}</div>
                          <div className="font-mono text-[11px] text-gray-500">{r.source_ip}</div>
                        </td>
                        <td className="max-w-[200px] truncate px-4 py-3 font-mono text-xs text-gray-400">{r.principal}</td>
                        <td className="px-4 py-3">
                          <span className={`rounded border px-2 py-1 text-xs font-semibold ${style.cls}`}>{style.label}</span>
                        </td>
                        <td className="px-4 py-3 font-mono">{(r.confidence * 100).toFixed(1)}%</td>
                        <td className="px-4 py-3">
                          <span className={`text-xs font-semibold ${r.action === 'CONTAINED' ? 'text-red-400' : 'text-gray-400'}`}>
                            {r.action}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right">
                          {rowLoading === r.row
                            ? <Loader2 size={15} className="animate-spin text-cyber-accent" />
                            : <ChevronRight size={15} className={isThreat ? 'text-cyber-accent' : 'text-gray-600'} />}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
