import { useState, useEffect, useCallback } from 'react'
import {
  Radio, ShieldAlert, ShieldCheck, ShieldOff, Loader2, RefreshCw,
  AlertTriangle, CheckCircle2, Ban, Undo2, Cloud, KeyRound, Lock,
  ChevronRight, Activity, Eye, Server, Copy, Check, Trash2,
} from 'lucide-react'
import {
  getLiveStatus, pollLive, containLive, undoLive, predict, errMessage,
} from '../api'

// Threat class -> badge styling (shared palette across every tab).
const CLASS_STYLES = {
  0: { label: 'C0 Benign', cls: 'bg-green-500/15 text-green-400 border-green-500/40' },
  1: { label: 'C1 Horizontal', cls: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40' },
  2: { label: 'C2 Vertical', cls: 'bg-red-500/15 text-red-400 border-red-500/40' },
  3: { label: 'C3 Exfiltration', cls: 'bg-purple-500/15 text-purple-400 border-purple-500/40' },
  4: { label: 'C4 Lateral', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/40' },
}

// The poll verdicts live only in component state, so a browser refresh would
// wipe them. Persist the last poll (plus in-progress review states) to
// localStorage and rehydrate on mount. Same store the auth token already uses —
// this is the real app, not a sandboxed artifact.
const POLL_CACHE_KEY = 'cpeds_live_poll'

function readPollCache() {
  try {
    const raw = localStorage.getItem(POLL_CACHE_KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

// On reload, roll any in-flight spinner state back to its resting state so a
// row is never stuck mid-action (the network call didn't survive the refresh).
function sanitizeRows(rows) {
  return (rows || []).map((r) => {
    if (r._state === 'containing') return { ...r, _state: 'armed' }
    if (r._state === 'undoing') return { ...r, _state: 'contained' }
    return r
  })
}

// One-word status for a row, used by the copy-to-clipboard export.
function decisionLabel(row) {
  if (row._state === 'contained') return 'CONTAINED'
  if (row._state === 'reversed') return 'REVERSED'
  const s = row.decision?.status
  if (s === 'pending') return 'PENDING'
  if (s === 'blocked') return 'GUARDED'
  return 'MONITORED'
}

// Render the verdicts as plain text for the clipboard.
function buildLogText(poll, rows) {
  const lines = ['CPEDS-X — Live AWS Containment · CloudTrail verdicts']
  if (poll) {
    const pending = rows.filter((r) => r.decision?.status === 'pending'
      && r._state !== 'contained' && r._state !== 'reversed').length
    lines.push(`${poll.events_seen ?? rows.length} events · ${pending} pending · ${poll.polled_minutes ?? '?'} min look-back`)
    if (poll.identity?.account) lines.push(`account ${poll.identity.account}`)
  }
  lines.push('')
  rows.forEach((r) => {
    const cls = (CLASS_STYLES[r.predicted_class] || CLASS_STYLES[0]).label
    lines.push(`${r.event_name || '—'}  [${cls}]  ${decisionLabel(r)}`)
    lines.push(`    ${r.principal} · ${r.source_ip || 'no-ip'} · ${(r.confidence * 100).toFixed(1)}% conf`)
    if (r.decision?.reason) lines.push(`    ${r.decision.reason}`)
  })
  return lines.join('\n')
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

export default function LiveContainment({ onIncidentSelect }) {
  const [status, setStatus] = useState(null)
  const [loadingStatus, setLoadingStatus] = useState(true)
  const [minutes, setMinutes] = useState(() => readPollCache()?.minutes ?? 60)
  const [polling, setPolling] = useState(false)
  // Rehydrate the last poll from localStorage so a refresh doesn't wipe the log.
  const [poll, setPoll] = useState(() => readPollCache()?.poll ?? null)
  const [rows, setRows] = useState(() => sanitizeRows(readPollCache()?.rows))
  const [error, setError] = useState('')
  const [inspecting, setInspecting] = useState(null)
  const [copied, setCopied] = useState(false)

  const loadStatus = useCallback(async () => {
    setLoadingStatus(true)
    try {
      const { data } = await getLiveStatus()
      setStatus(data)
    } catch (e) {
      setError(errMessage(e))
    } finally {
      setLoadingStatus(false)
    }
  }, [])

  useEffect(() => { loadStatus() }, [loadStatus])

  // Persist the poll + row states (incl. contained/reversed) on every change so
  // a refresh restores exactly what the operator was looking at.
  useEffect(() => {
    try {
      if (poll) {
        localStorage.setItem(POLL_CACHE_KEY, JSON.stringify({ poll, rows, minutes }))
      } else {
        localStorage.removeItem(POLL_CACHE_KEY)
      }
    } catch {
      /* quota / private-mode — non-fatal, the log just won't survive a refresh */
    }
  }, [poll, rows, minutes])

  const clearLog = () => {
    setPoll(null)
    setRows([])
    setError('')
    try { localStorage.removeItem(POLL_CACHE_KEY) } catch { /* ignore */ }
  }

  const copyLog = async () => {
    const text = buildLogText(poll, rows)
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      // Fallback for older browsers / non-secure contexts.
      const ta = document.createElement('textarea')
      ta.value = text
      document.body.appendChild(ta)
      ta.select()
      try { document.execCommand('copy') } catch { /* ignore */ }
      document.body.removeChild(ta)
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 1800)
  }

  const doPoll = async () => {
    setPolling(true)
    setError('')
    try {
      const { data } = await pollLive(minutes)
      setPoll(data)
      setRows((data.verdicts || []).map((v, i) => ({ ...v, _rid: i, _state: 'idle' })))
    } catch (e) {
      setError(errMessage(e))
    } finally {
      setPolling(false)
    }
  }

  const patchRow = (rid, patch) =>
    setRows((rs) => rs.map((r) => (r._rid === rid ? { ...r, ...patch } : r)))

  // Two-click human approval: arm -> confirm. Nothing hits AWS until confirm.
  const arm = (rid) => patchRow(rid, { _state: 'armed', _error: '' })
  const cancel = (rid) => patchRow(rid, { _state: 'idle', _error: '' })

  const confirm = async (row) => {
    patchRow(row._rid, { _state: 'containing', _error: '' })
    try {
      const { data } = await containLive(
        row.principal, row.predicted_class, row.confidence, row.raw_log)
      patchRow(row._rid, {
        _state: 'contained',
        _incidentId: data.incident_id,
        _containment: data.containment,
      })
      // Refresh the blast-room counter from the authoritative response.
      if (data.containment?.blast_room != null) {
        setPoll((p) => (p ? { ...p, blast_room: data.containment.blast_room } : p))
      }
    } catch (e) {
      patchRow(row._rid, { _state: 'armed', _error: errMessage(e) })
    }
  }

  const undo = async (row) => {
    patchRow(row._rid, { _state: 'undoing', _error: '' })
    try {
      await undoLive(row._incidentId)
      patchRow(row._rid, { _state: 'reversed' })
    } catch (e) {
      patchRow(row._rid, { _state: 'contained', _error: errMessage(e) })
    }
  }

  // Re-run the full pipeline (with SHAP) on the event and hand it to the XAI tab.
  const inspect = async (row) => {
    if (!row.raw_log) return
    setInspecting(row._rid)
    setError('')
    try {
      const { data: d } = await predict(row.raw_log)
      onIncidentSelect?.({
        id: `live-${row._rid}`,
        timestamp: row.event_time || new Date().toLocaleTimeString(),
        user: row.raw_log?.userIdentity?.userName || row.principal,
        principal: row.principal,
        predictedClass: d.prediction.predicted_class,
        classLabel: d.prediction.class_label,
        confidence: d.prediction.confidence,
        latency: d.prediction.execution_latency_ms,
        actionStatus: row._state === 'contained' ? 'CONTAINED' : 'MONITORED',
        xai: d.xai,
        summary: d.soc_summary,
        mitigation: d.mitigation,
        probabilities: d.prediction.probabilities,
      })
    } catch (e) {
      setError(errMessage(e))
    } finally {
      setInspecting(null)
    }
  }

  const ready = status?.ready
  const pendingCount = rows.filter((r) => r.decision?.status === 'pending'
    && r._state !== 'contained' && r._state !== 'reversed').length

  return (
    <div className="space-y-6">
      {/* ---------------- Header + safety banner ---------------- */}
      <div className="rounded-xl border border-cyber-border bg-cyber-panel p-6">
        <div className="mb-3 flex items-center gap-2">
          <Radio className="text-cyber-accent" size={20} />
          <h2 className="text-lg font-semibold">Live AWS Containment</h2>
          <ModeChip status={status} loading={loadingStatus} />
        </div>
        <p className="max-w-3xl text-sm text-gray-400">
          The real detection-to-containment loop: CPEDS-X polls a genuine AWS
          account's CloudTrail, scores every event with the same model as every
          other tab, and stages high-confidence threats for your approval. Model
          confidence alone never fires — a real IAM revoke happens only when you
          click <span className="text-gray-200">Confirm</span>, and every action
          is reversible.
        </p>

        {/* Sandbox-only warning — always visible in this tab. */}
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2.5 text-xs text-amber-200/90">
          <Lock size={15} className="mt-0.5 shrink-0" />
          <span>
            <span className="font-semibold">Sandbox accounts only.</span> Live
            mode issues real, destructive IAM changes. Guardrails scope it to{' '}
            <code className="rounded bg-cyber-bg px-1">cpeds-*</code> test users,
            skip protected principals, cap the blast radius, and keep a rollback
            token for every action. The Attack Simulator and Scenario Runner stay
            on mock — this is the only tab that touches a live account.
          </span>
        </div>
      </div>

      {/* ---------------- Arming status ---------------- */}
      {loadingStatus ? (
        <div className="flex items-center gap-2 rounded-xl border border-cyber-border bg-cyber-panel px-6 py-5 text-sm text-gray-500">
          <Loader2 size={16} className="animate-spin" /> Checking live-mode status…
        </div>
      ) : ready ? (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard icon={ShieldCheck} label="Live mode" value="Armed"
            tone="text-green-400" sub={status.mode} />
          <StatCard icon={Server} label="AWS account"
            value={status.identity?.account || '—'}
            sub={status.identity?.arn ? shortArn(status.identity.arn) : 'responder identity'} />
          <StatCard icon={ShieldAlert} label="Blast room"
            value={`${poll?.blast_room ?? status.blast_room}/${status.blast_cap}`}
            tone={(poll?.blast_room ?? status.blast_room) > 0 ? 'text-cyber-accent' : 'text-red-400'}
            sub={`per ${Math.round(status.blast_window_seconds / 60)} min`} />
          <StatCard icon={KeyRound} label="Auto-fire gate"
            value={`≥ ${Math.round(status.threshold * 100)}%`} sub="+ analyst confirm" />
        </div>
      ) : (
        <NotArmed status={status} onRetry={loadStatus} />
      )}

      {/* ---------------- Poll controls ---------------- */}
      <div className="rounded-xl border border-cyber-border bg-cyber-panel p-6">
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={doPoll}
            disabled={polling}
            className="flex items-center gap-2 rounded-lg bg-cyber-accent px-4 py-2.5 text-sm font-semibold text-cyber-bg transition-colors hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {polling ? <Loader2 size={16} className="animate-spin" /> : <Cloud size={16} />}
            {polling ? 'Polling CloudTrail…' : 'Poll live account'}
          </button>

          <label className="flex items-center gap-2 text-xs text-gray-400">
            Look-back
            <select
              value={minutes}
              onChange={(e) => setMinutes(Number(e.target.value))}
              className="rounded-lg border border-cyber-border bg-cyber-bg px-2 py-1.5 text-gray-200 focus:border-cyber-accent focus:outline-none"
            >
              <option value={15}>15 min</option>
              <option value={60}>1 hour</option>
              <option value={360}>6 hours</option>
              <option value={1440}>24 hours</option>
            </select>
          </label>

          <button
            onClick={loadStatus}
            className="flex items-center gap-2 rounded-lg border border-cyber-border px-3 py-2 text-xs font-medium text-gray-400 transition-colors hover:border-cyber-accent/50 hover:text-cyber-accent"
          >
            <RefreshCw size={14} /> Re-check status
          </button>

          {poll && (
            <span className="ml-auto flex items-center gap-4 text-xs text-gray-500">
              <span>{poll.events_seen} events</span>
              <span className={pendingCount ? 'text-red-400' : 'text-green-400'}>
                {pendingCount} pending
              </span>
            </span>
          )}
        </div>

        <p className="mt-3 text-xs text-gray-600">
          CloudTrail LookupEvents is honest about latency — expect a ~5–15 minute
          delay before an attack API call shows up here.
        </p>

        {error && (
          <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-sm text-red-300">
            <AlertTriangle size={16} className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* ---------------- Verdicts ---------------- */}
      {poll && (
        <div className="overflow-hidden rounded-xl border border-cyber-border bg-cyber-panel">
          <div className="flex items-start justify-between gap-3 border-b border-cyber-border px-6 py-4">
            <div className="min-w-0">
              <h3 className="font-semibold">CloudTrail verdicts</h3>
              <p className="mt-0.5 text-xs text-gray-500">
                {poll.ready
                  ? 'Confirm a pending threat to issue a real, reversible IAM revoke.'
                  : poll.status_reason}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button
                onClick={copyLog}
                disabled={rows.length === 0}
                title="Copy all verdicts to clipboard"
                className="flex items-center gap-1.5 rounded-lg border border-cyber-border px-3 py-1.5 text-xs font-medium text-gray-300 transition-colors hover:border-cyber-accent/50 hover:text-cyber-accent disabled:cursor-not-allowed disabled:opacity-40"
              >
                {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
                {copied ? 'Copied' : 'Copy logs'}
              </button>
              <button
                onClick={clearLog}
                title="Clear the saved log from this browser"
                className="flex items-center gap-1.5 rounded-lg border border-cyber-border px-3 py-1.5 text-xs font-medium text-gray-400 transition-colors hover:border-red-500/50 hover:text-red-300"
              >
                <Trash2 size={14} /> Clear
              </button>
            </div>
          </div>

          {rows.length === 0 ? (
            <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
              <Radio className="mb-3 text-gray-600" size={30} />
              <p className="text-sm text-gray-400">
                No events in the look-back window.
              </p>
              <p className="mt-1 max-w-md text-xs text-gray-500">
                Run a privilege-escalation call against the sandbox (or Stratus
                Red Team), wait for CloudTrail, then poll again.
              </p>
            </div>
          ) : (
            <ul className="divide-y divide-cyber-border">
              {rows.map((row) => (
                <VerdictRow
                  key={row._rid}
                  row={row}
                  inspecting={inspecting === row._rid}
                  onArm={() => arm(row._rid)}
                  onCancel={() => cancel(row._rid)}
                  onConfirm={() => confirm(row)}
                  onUndo={() => undo(row)}
                  onInspect={() => inspect(row)}
                />
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}

// ------------------------------------------------------------------
// Sub-components
// ------------------------------------------------------------------
function ModeChip({ status, loading }) {
  if (loading) return null
  const armed = status?.ready
  return (
    <span className={`ml-1 inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide
      ${armed
        ? 'border-green-500/40 bg-green-500/10 text-green-400'
        : 'border-gray-600 bg-cyber-bg text-gray-400'}`}>
      {armed ? <ShieldCheck size={12} /> : <ShieldOff size={12} />}
      {armed ? 'Live armed' : (status?.mode || 'mock')}
    </span>
  )
}

function NotArmed({ status, onRetry }) {
  return (
    <div className="rounded-xl border border-cyber-border bg-cyber-panel p-6">
      <div className="flex items-start gap-3">
        <ShieldOff className="mt-0.5 shrink-0 text-gray-500" size={20} />
        <div className="min-w-0">
          <h3 className="font-semibold text-gray-200">
            Live mode is not armed <span className="text-gray-500">({status?.mode || 'mock'})</span>
          </h3>
          <p className="mt-1 text-sm text-gray-400">{status?.reason}</p>
          <div className="mt-4 rounded-lg border border-cyber-border bg-cyber-bg p-4 text-xs text-gray-400">
            <p className="mb-2 font-semibold text-gray-300">To arm it on your operational host:</p>
            <ol className="list-decimal space-y-1 pl-4">
              <li>Set <code className="rounded bg-cyber-panel px-1 text-cyber-accent">CONTAINMENT_MODE=live</code> in the backend environment.</li>
              <li>Provide the least-privilege <code className="rounded bg-cyber-panel px-1 text-cyber-accent">cpeds-responder</code> credentials (via <code className="rounded bg-cyber-panel px-1">AWS_PROFILE</code> or the default chain).</li>
              <li>Point it at a throwaway sandbox account — never production.</li>
            </ol>
            <p className="mt-3 text-gray-500">
              Demo deployments intentionally omit these credentials, so live mode
              can't fire there. Polling still works below and will report status.
            </p>
          </div>
          <button
            onClick={onRetry}
            className="mt-4 flex items-center gap-2 rounded-lg border border-cyber-border px-3 py-2 text-xs font-medium text-gray-300 transition-colors hover:border-cyber-accent/50 hover:text-cyber-accent"
          >
            <RefreshCw size={14} /> Re-check
          </button>
        </div>
      </div>
    </div>
  )
}

function VerdictRow({ row, inspecting, onArm, onCancel, onConfirm, onUndo, onInspect }) {
  const style = CLASS_STYLES[row.predicted_class] || CLASS_STYLES[0]
  const d = row.decision || {}
  const isThreat = row.predicted_class !== 0

  return (
    <li className="px-6 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-gray-100">{row.event_name || '—'}</span>
            <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${style.cls}`}>{style.label}</span>
            <StateBadge state={row._state} decision={d} />
          </div>
          <p className="mt-1 truncate font-mono text-xs text-gray-500">
            {row.principal} · {row.source_ip || 'no-ip'} · {(row.confidence * 100).toFixed(1)}% conf
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onInspect}
            disabled={inspecting}
            className="flex items-center gap-1 text-xs font-medium text-cyber-accent transition-colors hover:text-cyan-300 disabled:opacity-50"
          >
            {inspecting ? <Loader2 size={13} className="animate-spin" /> : <Eye size={13} />} XAI
          </button>

          {/* Action zone depends on the gate decision + local state. */}
          {row._state === 'contained' ? (
            <button
              onClick={onUndo}
              className="flex items-center gap-1.5 rounded-lg border border-cyber-border px-3 py-1.5 text-xs font-semibold text-gray-300 transition-colors hover:border-cyber-accent/60 hover:text-cyber-accent"
            >
              <Undo2 size={14} /> Undo
            </button>
          ) : row._state === 'undoing' ? (
            <span className="flex items-center gap-1.5 text-xs text-gray-400">
              <Loader2 size={14} className="animate-spin" /> Reversing…
            </span>
          ) : row._state === 'reversed' ? (
            <span className="flex items-center gap-1.5 text-xs font-semibold text-green-400">
              <CheckCircle2 size={14} /> Reversed
            </span>
          ) : d.status === 'pending' ? (
            row._state === 'containing' ? (
              <span className="flex items-center gap-1.5 text-xs text-red-300">
                <Loader2 size={14} className="animate-spin" /> Revoking…
              </span>
            ) : row._state === 'armed' ? (
              <div className="flex items-center gap-2">
                <button
                  onClick={onConfirm}
                  className="flex items-center gap-1.5 rounded-lg bg-red-500/90 px-3 py-1.5 text-xs font-bold text-white transition-colors hover:bg-red-500"
                >
                  <ShieldAlert size={14} /> Confirm real revoke
                </button>
                <button onClick={onCancel} className="px-2 py-1 text-xs text-gray-500 hover:text-gray-300">
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={onArm}
                className="flex items-center gap-1.5 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-300 transition-colors hover:bg-red-500/20"
              >
                <ShieldAlert size={14} /> Review &amp; contain
              </button>
            )
          ) : d.status === 'blocked' ? (
            <span className="flex items-center gap-1.5 rounded-lg border border-cyber-border px-3 py-1.5 text-xs font-medium text-amber-300/80">
              <Ban size={14} /> Guarded
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-xs text-gray-500">
              <CheckCircle2 size={14} className={isThreat ? 'text-gray-500' : 'text-green-500'} /> Monitored
            </span>
          )}
        </div>
      </div>

      {/* Preview shown once armed: exactly what the confirm will do. */}
      {row._state === 'armed' && (
        <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-200/90">
          <p className="font-semibold text-red-300">Preview — on confirm, CPEDS-X will:</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-4 text-red-200/80">
            <li>Set every access key on <span className="font-mono">{shortName(row.principal)}</span> to <span className="font-mono">Inactive</span>.</li>
            <li>Attach a deny-all <span className="font-mono">CPEDS-Quarantine</span> inline policy.</li>
          </ul>
          <p className="mt-1.5 text-red-200/70">This is reversible with Undo. A rollback token is saved to the incident.</p>
        </div>
      )}

      {/* Decision / guardrail reason line. */}
      {d.reason && row._state !== 'armed' && (
        <p className="mt-2 flex items-center gap-1.5 text-[11px] text-gray-500">
          <ChevronRight size={11} /> {d.reason}
        </p>
      )}

      {row._containment && row._state === 'contained' && (
        <p className="mt-2 flex items-center gap-1.5 text-[11px] text-red-300/80">
          <ShieldAlert size={11} /> Contained on live AWS ({row._containment.actions?.length || 0} actions) · incident #{row._incidentId}
        </p>
      )}

      {row._error && (
        <p className="mt-2 flex items-center gap-1.5 text-[11px] text-red-400">
          <AlertTriangle size={11} /> {row._error}
        </p>
      )}
    </li>
  )
}

function StateBadge({ state, decision }) {
  if (state === 'contained')
    return <Tag cls="border-red-500/50 bg-red-500/15 text-red-300" icon={ShieldAlert} text="Contained" />
  if (state === 'reversed')
    return <Tag cls="border-green-500/40 bg-green-500/10 text-green-400" icon={CheckCircle2} text="Reversed" />
  if (decision?.status === 'pending')
    return <Tag cls="border-amber-500/40 bg-amber-500/10 text-amber-300" icon={Activity} text="Pending" />
  if (decision?.status === 'blocked')
    return <Tag cls="border-cyber-border bg-cyber-bg text-gray-400" icon={Ban} text="Guarded" />
  return null
}

function Tag({ cls, icon: Icon, text }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${cls}`}>
      <Icon size={11} /> {text}
    </span>
  )
}

function shortArn(arn) {
  if (!arn) return ''
  return arn.length > 42 ? '…' + arn.slice(-40) : arn
}
function shortName(principal) {
  if (!principal) return 'principal'
  return principal.split('/').pop()
}
