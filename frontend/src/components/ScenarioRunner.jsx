import { useState, useEffect, useRef } from 'react'
import {
  Swords, Play, Loader2, ShieldCheck, ShieldAlert, Crosshair,
  ChevronRight, Target, Clock, Radar, AlertTriangle, CheckCircle2,
  Check, X,
} from 'lucide-react'
import { getScenarios, runScenario, getSimAvailability, errMessage } from '../api'
import SourceToggle from './SourceToggle'

// Threat class -> badge styling (shared palette with the other tabs).
const CLASS_STYLES = {
  0: { label: 'C0 Benign', cls: 'bg-green-500/15 text-green-400 border-green-500/40' },
  1: { label: 'C1 Horizontal', cls: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40' },
  2: { label: 'C2 Vertical', cls: 'bg-red-500/15 text-red-400 border-red-500/40' },
  3: { label: 'C3 Exfiltration', cls: 'bg-purple-500/15 text-purple-400 border-purple-500/40' },
  4: { label: 'C4 Lateral', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/40' },
}

// Map a completed scenario step into the incident shape XAIView expects.
function stepToIncident(step, run) {
  return {
    id: `scenario-${run.scenario_id}-${step.step}`,
    timestamp: new Date().toLocaleTimeString(),
    user: run.attacker_principal,
    principal: run.attacker_principal,
    predictedClass: step.predicted_class,
    classLabel: step.class_label,
    confidence: step.confidence,
    latency: step.execution_latency_ms,
    actionStatus: step.action_status,
    xai: step.xai,
    summary: step.soc_summary,
    mitigation: step.mitigation,
    probabilities: step.probabilities,
    groundTruthLabel: step.ground_truth_label ?? null,
    correct: step.ground_truth_label != null ? step.correct : null,
  }
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

export default function ScenarioRunner({ onIncidentSelect }) {
  const [scenarios, setScenarios] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [loadingList, setLoadingList] = useState(true)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const [run, setRun] = useState(null)
  const [revealed, setRevealed] = useState(0) // steps shown so far (live feel)
  const [source, setSource] = useState('synthetic')
  const [availability, setAvailability] = useState(null)
  const timers = useRef([])

  useEffect(() => {
    getScenarios()
      .then((res) => {
        setScenarios(res.data.scenarios || [])
        if (res.data.scenarios?.length) setSelectedId(res.data.scenarios[0].id)
      })
      .catch((e) => setError(errMessage(e)))
      .finally(() => setLoadingList(false))
    // Whether Real mode can replay labeled events (and per-class counts).
    getSimAvailability()
      .then((res) => setAvailability(res.data))
      .catch(() => setAvailability({ available: false, note: 'Could not reach the server.' }))
    // Clear any pending reveal timers on unmount.
    return () => timers.current.forEach(clearTimeout)
  }, [])

  const launch = async () => {
    if (!selectedId) return
    setRunning(true)
    setError('')
    setRun(null)
    setRevealed(0)
    timers.current.forEach(clearTimeout)
    timers.current = []
    try {
      const res = await runScenario(selectedId, source)
      setRun(res.data)
      // Stagger the reveal so the timeline plays out like a live engagement.
      const total = res.data.steps.length
      for (let i = 1; i <= total; i++) {
        timers.current.push(setTimeout(() => setRevealed(i), i * 550))
      }
    } catch (e) {
      setError(errMessage(e))
    } finally {
      setRunning(false)
    }
  }

  const selected = scenarios.find((s) => s.id === selectedId)
  const playing = run && revealed < run.steps.length

  return (
    <div className="space-y-6">
      {/* ---------------- Intro + scenario picker ---------------- */}
      <div className="rounded-xl border border-cyber-border bg-cyber-panel p-6">
        <div className="mb-4 flex items-center gap-2">
          <Swords className="text-cyber-accent" size={20} />
          <h2 className="text-lg font-semibold">Attack Scenario Runner — Purple Team</h2>
        </div>
        <p className="mb-5 text-sm text-gray-400">
          Emulate a real attacker's kill-chain step by step and watch CPEDS-X classify each
          action live. Every step maps to a{' '}
          <span className="text-gray-200">MITRE ATT&amp;CK</span> technique and is scored by the
          same model as the live simulator, with auto-containment firing on high-confidence
          threats. Early recon reads benign by design — that honest mix is what a real
          engagement looks like.
        </p>

        {loadingList ? (
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <Loader2 size={16} className="animate-spin" /> Loading scenarios…
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-3">
            {scenarios.map((sc) => {
              const active = sc.id === selectedId
              return (
                <button
                  key={sc.id}
                  onClick={() => setSelectedId(sc.id)}
                  className={`rounded-lg border p-4 text-left transition-colors
                    ${active
                      ? 'border-cyber-accent bg-cyber-accent/5'
                      : 'border-cyber-border hover:border-cyber-accent/50'}`}
                >
                  <div className="mb-1 flex items-center gap-2">
                    <Crosshair size={15} className={active ? 'text-cyber-accent' : 'text-gray-500'} />
                    <span className="font-semibold text-gray-100">{sc.name}</span>
                  </div>
                  <div className="mb-2 inline-block rounded bg-cyber-bg px-2 py-0.5 text-[11px] uppercase tracking-wide text-gray-400">
                    {sc.tactic}
                  </div>
                  <p className="text-xs leading-relaxed text-gray-500">{sc.summary}</p>
                  <div className="mt-3 flex items-center gap-2 text-[11px] text-gray-500">
                    <Target size={12} /> {sc.step_count} steps · {sc.techniques.length} techniques
                  </div>
                </button>
              )
            })}
          </div>
        )}

        <div className="mt-5">
          <SourceToggle
            source={source}
            onChange={setSource}
            availability={availability}
            disabled={running}
          />
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button
            onClick={launch}
            disabled={running || !selectedId}
            className="flex items-center gap-2 rounded-lg bg-cyber-accent px-4 py-2.5 text-sm font-semibold text-cyber-bg transition-colors hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {running ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
            {running ? 'Launching campaign…' : `Launch attack${selected ? `: ${selected.name}` : ''}`}
          </button>
          {playing && (
            <span className="flex items-center gap-2 text-xs text-cyber-accent">
              <Radar size={14} className="animate-pulse" /> Detonating step {revealed + 1} of {run.steps.length}…
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

      {/* ---------------- Run summary + timeline ---------------- */}
      {run && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard icon={Target} label="Steps executed"
              value={`${Math.min(revealed, run.steps_total)}/${run.steps_total}`}
              sub={run.tactic} />
            <StatCard icon={ShieldAlert} label="Threats detected" value={run.threats_detected}
              tone={run.threats_detected ? 'text-red-400' : 'text-green-400'}
              sub="non-benign verdicts" />
            <StatCard icon={ShieldCheck} label="Auto-contained" value={run.auto_contained}
              tone={run.auto_contained ? 'text-cyber-accent' : 'text-gray-100'}
              sub="≥ 75% confidence" />
            <StatCard icon={Clock} label="Detection time" value={`${run.duration_ms} ms`}
              sub="full campaign" />
          </div>

          <div className="rounded-xl border border-cyber-border bg-cyber-panel">
            <div className="border-b border-cyber-border px-6 py-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="font-semibold">Attack Timeline — {run.scenario_name}</h3>
                {run.source === 'real' && (() => {
                  const scored = run.steps.filter((s) => s.ground_truth_label != null)
                  const hits = scored.filter((s) => s.correct).length
                  return scored.length ? (
                    <span className="rounded border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 font-mono text-xs text-cyan-300">
                      real replay · model {hits}/{scored.length} correct
                    </span>
                  ) : null
                })()}
              </div>
              <p className="mt-0.5 font-mono text-xs text-gray-500">
                attacker: {run.attacker_principal} · origin: {run.source_ip}
              </p>
            </div>
            <ol className="relative px-6 py-5">
              {run.steps.slice(0, revealed).map((step, i) => (
                <TimelineStep
                  key={step.step}
                  step={step}
                  isLast={i === run.steps.length - 1}
                  onInspect={() => onIncidentSelect(stepToIncident(step, run))}
                />
              ))}
            </ol>
          </div>

          {!playing && (
            <p className="px-1 text-xs text-gray-500">{run.note}</p>
          )}
        </>
      )}
    </div>
  )
}

function TimelineStep({ step, isLast, onInspect }) {
  const isThreat = step.predicted_class !== 0
  const contained = step.action_status === 'CONTAINED'
  const style = CLASS_STYLES[step.predicted_class] || CLASS_STYLES[0]
  const ls = step.localstack
  const hasTruth = step.ground_truth_label != null
  const truthStyle = hasTruth ? (CLASS_STYLES[step.ground_truth_label] || CLASS_STYLES[0]) : null

  return (
    <li className="relative flex gap-4 pb-6 last:pb-0">
      {/* vertical rail + node */}
      {!isLast && <span className="absolute left-[11px] top-7 h-full w-px bg-cyber-border" />}
      <div className={`z-10 mt-1 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[10px]
        ${isThreat ? 'border-red-500/50 bg-red-500/15 text-red-400' : 'border-green-500/50 bg-green-500/10 text-green-400'}`}>
        {isThreat ? <ShieldAlert size={13} /> : <CheckCircle2 size={13} />}
      </div>

      <div className="min-w-0 flex-1 rounded-lg border border-cyber-border bg-cyber-bg/60 p-4">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <div className="flex items-center gap-2">
              <span className="font-medium text-gray-100">{step.name}</span>
              <span className="rounded bg-cyber-panel px-1.5 py-0.5 font-mono text-[10px] text-gray-500">
                {step.event_name}
              </span>
              {step.step_source === 'real' && (
                <span className="rounded bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[10px] text-cyan-400">
                  real event
                </span>
              )}
            </div>
            <p className="mt-1 text-xs text-gray-500">{step.description}</p>
          </div>
          <div className="flex flex-col items-end gap-1">
            {hasTruth && (
              <span className={`rounded border px-2 py-0.5 text-[10px] font-semibold ${truthStyle.cls}`}>
                truth: {truthStyle.label}
              </span>
            )}
            <span className={`rounded border px-2 py-1 text-xs font-semibold ${style.cls}`}>
              {hasTruth ? 'pred: ' : ''}{style.label}
            </span>
          </div>
        </div>

        {/* MITRE ATT&CK tag + verdict line */}
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
          <span className="rounded bg-purple-500/10 px-2 py-0.5 font-mono text-purple-300">
            {step.technique_id}
          </span>
          <span className="text-gray-400">{step.technique}</span>
          <span className="text-gray-600">·</span>
          <span className="text-gray-400">tactic: {step.tactic}</span>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1.5">
          <span className="font-mono text-sm text-cyber-accent">
            {(step.confidence * 100).toFixed(1)}% conf
          </span>
          <span className="font-mono text-xs text-gray-500">{step.execution_latency_ms} ms</span>
          {hasTruth && (
            step.correct ? (
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-green-400">
                <Check size={13} /> model hit
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-400">
                <X size={13} /> model miss
              </span>
            )
          )}
          <span className={contained ? 'font-semibold text-red-400' : 'font-medium text-gray-500'}>
            {contained ? '⚑ AUTO-CONTAINED' : 'MONITORED'}
          </span>
          {ls && (
            <span className="flex items-center gap-1 font-mono text-[11px] text-cyan-500/80">
              <Radar size={11} />
              {ls.status === 'executed' ? `${ls.call} (LocalStack)` : ls.status}
            </span>
          )}
          <button
            onClick={onInspect}
            className="ml-auto flex items-center gap-1 text-xs font-medium text-cyber-accent transition-colors hover:text-cyan-300"
          >
            XAI <ChevronRight size={13} />
          </button>
        </div>
      </div>
    </li>
  )
}
