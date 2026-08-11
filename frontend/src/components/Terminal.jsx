import { useState, useRef, useEffect, useCallback } from 'react'
import { TerminalSquare, Cpu } from 'lucide-react'
import {
  simulateLog, predict, analyzeLogs, getMetrics,
  getLiveStatus, pollLive, errMessage,
} from '../api'

/*
 * In-app Terminal — a real console inside the dashboard, so you can drive the
 * whole detection engine by typing (like the `cpeds` CLI, but in the browser).
 * It talks to the SAME backend endpoints every other tab uses, with your login
 * token, so it works identically in local dev and on the deployed app.
 *
 * The palette, monospace voice, and kill-chain accent are inherited from the
 * SOC theme (cyber-* tokens + .font-mono-soc) so this reads as one product.
 */

const CLASS_LABEL = {
  0: 'C0 Benign', 1: 'C1 Horizontal', 2: 'C2 Vertical',
  3: 'C3 Exfiltration', 4: 'C4 Lateral',
}
// Per-class output colour, matching the badges elsewhere in the app.
const CLASS_COLOR = {
  0: 'text-green-400', 1: 'text-yellow-400', 2: 'text-red-400',
  3: 'text-fuchsia-400', 4: 'text-orange-400',
}

const BANNER = [
  '  ____ ____  _____ ____  ____        __  __',
  ' / ___|  _ \\| ____|  _ \\/ ___|      \\ \\/ /',
  '| |   | |_) |  _| | | | \\___ \\ _____ \\  / ',
  '| |___|  __/| |___| |_| |___) |_____|/  \\ ',
  ' \\____|_|   |_____|____/|____/      /_/\\_\\',
]

// The command reference, also used to render `help`.
const HELP = [
  ['simulate <0-4>', 'generate a synthetic attack of that class and score it'],
  ['predict {json}', 'score one CloudTrail event pasted as JSON'],
  ['analyze {json}', 'batch-score a CloudTrail export / JSON array'],
  ['metrics', "this session's measured model accuracy"],
  ['live status', 'is real-AWS containment armed? which account?'],
  ['live poll [mins]', 'score real CloudTrail, stage pending threats (default 60)'],
  ['help', 'show this reference'],
  ['clear', 'clear the screen'],
  ['history', 'list previous commands'],
]

const PROMPT = 'cpeds ❯'

let LINE_SEQ = 0
const nextId = () => `${Date.now()}-${LINE_SEQ++}`

export default function Terminal({ onIncidentSelect, active = true, embedded = false }) {
  // Each line: { id, kind: 'cmd'|'out'|'err'|'info'|'node', text?, node? }
  const [lines, setLines] = useState(() => bootLines())
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [history, setHistory] = useState([])
  const [histIdx, setHistIdx] = useState(-1) // -1 = editing a fresh line

  const scrollRef = useRef(null)
  const inputRef = useRef(null)

  const scrollToBottom = () => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }

  // Keep the newest output in view.
  useEffect(() => { scrollToBottom() }, [lines, busy])

  const focusInput = () => inputRef.current?.focus()

  // Focus on first mount only if this console is the visible one (so the deck
  // mounting hidden tabs doesn't steal focus).
  useEffect(() => { if (active) focusInput() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // When this console becomes the active tab, focus it and snap to the newest
  // output — its scroll position isn't updated while hidden (display:none).
  useEffect(() => {
    if (active) { focusInput(); scrollToBottom() }
  }, [active])

  const push = useCallback((line) => {
    setLines((prev) => [...prev, { id: nextId(), ...line }])
  }, [])
  const pushText = useCallback((text, kind = 'out') => {
    // Support multi-line strings by splitting so each row aligns cleanly.
    const rows = String(text).split('\n')
    setLines((prev) => [
      ...prev,
      ...rows.map((t) => ({ id: nextId(), kind, text: t })),
    ])
  }, [])

  // ---- command handlers -------------------------------------------------
  const runSimulate = async (arg) => {
    const cls = Number(arg)
    if (!Number.isInteger(cls) || cls < 0 || cls > 4) {
      pushText('usage: simulate <0-4>   (0 benign · 1 horizontal · 2 vertical · 3 exfil · 4 lateral)', 'err')
      return
    }
    const { data: sim } = await simulateLog(cls)
    const auditLog = sim.audit_log
    const { data } = await predict(auditLog)
    const p = data.prediction
    emitVerdict({
      predicted_class: p.predicted_class,
      class_label: p.class_label,
      confidence: p.confidence,
      event_name: auditLog.eventName,
      principal: auditLog.userIdentity?.arn || auditLog.userIdentity?.userName,
      latency: p.execution_latency_ms,
      contained: data.threshold_exceeded,
    })
    // Make the verdict clickable → opens the XAI tab, same handoff as other tabs.
    push({
      kind: 'node',
      node: (
        <OpenXai
          onClick={() => onIncidentSelect?.({
            id: Date.now(),
            timestamp: new Date().toLocaleTimeString(),
            user: auditLog.userIdentity?.userName || 'unknown',
            principal: auditLog.userIdentity?.arn || 'n/a',
            predictedClass: p.predicted_class,
            classLabel: p.class_label,
            confidence: p.confidence,
            latency: p.execution_latency_ms,
            actionStatus: data.threshold_exceeded ? 'CONTAINED' : 'MONITORED',
            xai: data.xai,
            summary: data.soc_summary,
            mitigation: data.mitigation,
            probabilities: p.probabilities,
          })}
        />
      ),
    })
  }

  const runPredict = async (payload) => {
    const log = parseJsonArg(payload)
    if (log === undefined) {
      pushText('usage: predict {"eventName":"CreateUser", ...}   — paste a CloudTrail event as JSON', 'err')
      return
    }
    const { data } = await predict(log)
    const p = data.prediction
    emitVerdict({
      predicted_class: p.predicted_class,
      class_label: p.class_label,
      confidence: p.confidence,
      event_name: log.eventName,
      principal: log.userIdentity?.arn || log.userIdentity?.userName,
      latency: p.execution_latency_ms,
      contained: data.threshold_exceeded,
    })
  }

  const runAnalyze = async (payload) => {
    const raw = (payload || '').trim()
    if (!raw) {
      pushText('usage: analyze {"Records":[ ... ]}   — paste a CloudTrail export or JSON array', 'err')
      return
    }
    const { data } = await analyzeLogs(raw, 'auto', 'terminal.json')
    const s = data.summary
    pushText(
      `analyzed ${s.analyzed}/${s.total_received} events · ` +
      `${s.threats_detected} threat(s) · ${s.benign} benign · ` +
      `${s.auto_contained} auto-contained · avg conf ${(s.avg_confidence * 100).toFixed(1)}%`,
      'info',
    )
    for (const r of (data.results || []).slice(0, 50)) {
      const c = CLASS_COLOR[r.predicted_class] || 'text-gray-300'
      const mark = r.predicted_class !== 0 ? '⚠' : '·'
      push({
        kind: 'out',
        node: (
          <span className="font-mono-soc">
            <span className={r.predicted_class !== 0 ? 'text-red-400' : 'text-green-500'}>{` ${mark} `}</span>
            <span className="text-gray-400">{(r.event_name || '—').padEnd(22).slice(0, 22)}</span>
            {'  '}
            <span className={c}>{(CLASS_LABEL[r.predicted_class] || '?').padEnd(15)}</span>
            {'  '}
            <span className="text-gray-300">{(r.confidence * 100).toFixed(1).padStart(5)}%</span>
            {'  '}
            <span className={r.action === 'CONTAINED' ? 'text-red-400' : 'text-gray-500'}>{r.action}</span>
          </span>
        ),
      })
    }
    if ((data.results || []).length > 50) {
      pushText(`… and ${data.results.length - 50} more (showing first 50)`, 'info')
    }
  }

  const runMetrics = async () => {
    const { data } = await getMetrics()
    const m = data.measured || {}
    if (!Object.keys(m).length) {
      pushText('no measured metrics available yet', 'info')
      return
    }
    pushText('model — measured metrics (this session\'s training run)', 'info')
    const fmt = (v) => (typeof v === 'number' ? (v <= 1 ? (v * 100).toFixed(2) + '%' : v.toFixed(4)) : v)
    for (const [k, label] of [
      ['accuracy', 'accuracy'], ['macro_f1', 'macro F1'],
      ['weighted_f1', 'weighted F1'], ['roc_auc', 'ROC-AUC'],
    ]) {
      if (m[k] !== undefined) pushText(`  ${label.padEnd(13)} ${fmt(m[k])}`, 'out')
    }
  }

  const runLive = async (rest) => {
    const [sub, arg] = rest
    if (sub === 'status' || !sub) {
      const { data } = await getLiveStatus()
      if (data.ready) {
        pushText(`live containment: ARMED`, 'info')
        pushText(`  account   ${data.identity?.account || '—'}`, 'out')
        pushText(`  identity  ${data.identity?.arn || '—'}`, 'out')
        pushText(`  blast     ${data.blast_room}/${data.blast_cap} in ${data.blast_window_seconds}s`, 'out')
      } else {
        pushText(`live containment: ${String(data.mode || 'mock').toUpperCase()} (not armed)`, 'info')
        pushText(`  ${data.reason || 'set CONTAINMENT_MODE=live with sandbox creds'}`, 'out')
      }
      return
    }
    if (sub === 'poll') {
      const minutes = Number(arg) || 60
      const { data } = await pollLive(minutes)
      const verdicts = data.verdicts || []
      pushText(
        `CloudTrail — ${data.events_seen ?? verdicts.length} events, ` +
        `${data.pending_count ?? 0} pending (${data.polled_minutes ?? minutes} min look-back)`,
        'info',
      )
      if (!data.ready) pushText(`  ${data.status_reason || 'live mode not armed'}`, 'out')
      if (!verdicts.length) { pushText('  no events in the look-back window.', 'out'); return }
      for (const v of verdicts) {
        const status = (v.decision?.status) || 'monitor'
        const tag = status === 'pending' ? 'text-red-400'
          : status === 'blocked' ? 'text-yellow-400' : 'text-gray-500'
        const label = status === 'pending' ? 'PENDING'
          : status === 'blocked' ? 'GUARDED' : 'monitored'
        push({
          kind: 'out',
          node: (
            <span className="font-mono-soc">
              <span className="text-gray-400">{(v.event_name || '—').padEnd(20).slice(0, 20)}</span>{'  '}
              <span className={CLASS_COLOR[v.predicted_class] || 'text-gray-300'}>
                {(CLASS_LABEL[v.predicted_class] || '?').padEnd(15)}
              </span>{'  '}
              <span className="text-gray-300">{((v.confidence || 0) * 100).toFixed(1).padStart(5)}%</span>{'  '}
              <span className={tag}>{label}</span>
            </span>
          ),
        })
        pushText(`      ${v.principal || '—'} · ${v.source_ip || 'no-ip'}`, 'dim')
      }
      pushText('contain a pending threat from the Live Containment tab (two-click approval).', 'dim')
      return
    }
    pushText(`unknown live command: ${sub}. try: live status · live poll [minutes]`, 'err')
  }

  // ---- dispatch ---------------------------------------------------------
  const emitVerdict = ({ predicted_class, class_label, confidence, event_name, principal, latency, contained }) => {
    push({
      kind: 'out',
      node: (
        <span className="font-mono-soc">
          <span className="text-gray-500">verdict  </span>
          <span className={`font-semibold ${CLASS_COLOR[predicted_class] || 'text-gray-200'}`}>
            {class_label || CLASS_LABEL[predicted_class]}
          </span>
          <span className="text-gray-300">{'  '}{(confidence * 100).toFixed(1)}%</span>
          {contained
            ? <span className="text-red-400">{'  '}▸ CONTAINED</span>
            : <span className="text-gray-500">{'  '}▸ monitored</span>}
        </span>
      ),
    })
    if (event_name) pushText(`  event      ${event_name}`, 'dim')
    if (principal) pushText(`  principal  ${principal}`, 'dim')
    if (latency !== undefined) pushText(`  latency    ${latency} ms`, 'dim')
  }

  const execute = async (raw) => {
    const cmd = raw.trim()
    if (!cmd) return
    push({ kind: 'cmd', text: cmd })
    setHistory((h) => [...h, cmd])

    // Split only the first token(s); keep JSON payloads intact.
    const [name, ...rest] = cmd.split(/\s+/)
    const lower = name.toLowerCase()

    if (lower === 'clear') { setLines([]); return }
    if (lower === 'help' || lower === '?') { printHelp(pushText); return }
    if (lower === 'history') {
      if (!history.length) pushText('(no history yet)', 'dim')
      history.forEach((h, i) => pushText(`  ${String(i + 1).padStart(3)}  ${h}`, 'dim'))
      return
    }

    setBusy(true)
    try {
      if (lower === 'simulate' || lower === 'sim') await runSimulate(rest[0])
      else if (lower === 'predict') await runPredict(cmd.slice(name.length).trim())
      else if (lower === 'analyze') await runAnalyze(cmd.slice(name.length).trim())
      else if (lower === 'metrics') await runMetrics()
      else if (lower === 'live') await runLive(rest.map((r) => r.toLowerCase()))
      else pushText(`command not found: ${name}. type 'help' for the list.`, 'err')
    } catch (e) {
      pushText(errMessage(e), 'err')
    } finally {
      setBusy(false)
      focusInput()
    }
  }

  const onSubmit = (e) => {
    e.preventDefault()
    if (busy) return
    const cmd = input
    setInput('')
    setHistIdx(-1)
    execute(cmd)
  }

  // Up/down arrows walk the command history, like a real shell.
  const onKeyDown = (e) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (!history.length) return
      const idx = histIdx === -1 ? history.length - 1 : Math.max(0, histIdx - 1)
      setHistIdx(idx)
      setInput(history[idx])
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (histIdx === -1) return
      const idx = histIdx + 1
      if (idx >= history.length) { setHistIdx(-1); setInput('') }
      else { setHistIdx(idx); setInput(history[idx]) }
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault()
      setLines([])
    }
  }

  // The console body (scrollback + input) — shared by the standalone layout and
  // the embedded (tabbed deck) layout.
  const consoleBody = (
    <div
      ref={scrollRef}
      onClick={focusInput}
      className="h-[460px] overflow-y-auto px-4 py-3 font-mono-soc text-[13px] leading-relaxed"
    >
      {lines.map((l) => (
        <div key={l.id} className="whitespace-pre-wrap break-words">
          {l.kind === 'cmd' ? (
            <span>
              <span className="text-cyber-accent">{PROMPT} </span>
              <span className="text-gray-100">{l.text}</span>
            </span>
          ) : l.node ? (
            l.node
          ) : (
            <span className={lineClass(l.kind)}>{l.text}</span>
          )}
        </div>
      ))}
      {busy && (
        <div className="text-gray-500">
          <span className="inline-block animate-pulse">▍ running…</span>
        </div>
      )}

      {/* Input line lives inside the scrollback so it feels like one surface */}
      <form onSubmit={onSubmit} className="mt-1 flex items-center gap-2">
        <span className="text-cyber-accent">{PROMPT}</span>
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
          disabled={busy}
          className="flex-1 border-none bg-transparent text-gray-100 caret-cyber-accent outline-none placeholder:text-gray-600 disabled:opacity-50"
          placeholder={busy ? '' : "try: simulate 2"}
          aria-label="terminal command input"
        />
      </form>
    </div>
  )

  // Embedded mode: TerminalDeck supplies the header, the card, and the tabbed
  // title bar — we render only the console body.
  if (embedded) return consoleBody

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="mb-1 flex items-center gap-2">
            <TerminalSquare className="text-cyber-accent" size={20} />
            <h2 className="text-lg font-semibold">Terminal</h2>
          </div>
          <p className="max-w-2xl text-sm text-gray-400">
            Drive the detection engine by typing — the same commands as the
            <span className="font-mono-soc text-gray-300"> cpeds </span>
            CLI, running against your live backend. Type
            <button onClick={() => { setInput('help'); focusInput() }}
              className="mx-1 font-mono-soc text-cyber-accent hover:underline">help</button>
            to start.
          </p>
        </div>
        <div className="hidden items-center gap-2 rounded-lg border border-cyber-border bg-cyber-panel px-3 py-2 text-xs text-gray-400 sm:flex">
          <Cpu size={14} className="text-cyber-accent" />
          in-process model · your session
        </div>
      </div>

      {/* Console */}
      <div className="overflow-hidden rounded-xl border border-cyber-border bg-[#070b14] shadow-inner">
        {/* Title bar */}
        <div className="flex items-center gap-2 border-b border-cyber-border bg-cyber-panel px-4 py-2">
          <span className="h-3 w-3 rounded-full bg-red-500/70" />
          <span className="h-3 w-3 rounded-full bg-yellow-500/70" />
          <span className="h-3 w-3 rounded-full bg-green-500/70" />
          <span className="ml-2 font-mono-soc text-xs text-gray-500">cpeds — detection console</span>
        </div>

        {consoleBody}
      </div>

      <p className="text-xs text-gray-500">
        ↑/↓ recall commands · Ctrl+L clears · click a verdict to open its XAI breakdown →
      </p>
    </div>
  )
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------
function lineClass(kind) {
  switch (kind) {
    case 'err': return 'text-red-400'
    case 'info': return 'text-cyber-accent'
    case 'dim': return 'text-gray-500'
    default: return 'text-gray-300'
  }
}

function OpenXai({ onClick }) {
  return (
    <button
      onClick={onClick}
      className="text-gray-500 underline decoration-dotted underline-offset-2 transition-colors hover:text-cyber-accent"
    >
      → open XAI breakdown
    </button>
  )
}

// Parse a JSON argument; returns undefined on empty/invalid so callers can
// print a usage hint rather than throwing.
function parseJsonArg(payload) {
  const raw = (payload || '').trim()
  if (!raw) return undefined
  try {
    const obj = JSON.parse(raw)
    return obj && typeof obj === 'object' ? obj : undefined
  } catch {
    return undefined
  }
}

function printHelp(pushText) {
  pushText('commands:', 'info')
  for (const [cmd, desc] of HELP) {
    pushText(`  ${cmd.padEnd(16)} ${desc}`, 'out')
  }
  pushText('flags & tips:', 'info')
  pushText('  ↑/↓ recall previous commands · Ctrl+L clears the screen', 'out')
  pushText('  simulate classes: 0 benign · 1 horizontal · 2 vertical · 3 exfil · 4 lateral', 'out')
}

function bootLines() {
  const out = []
  const add = (kind, text) => out.push({ id: nextId(), kind, text })
  for (const b of BANNER) add('accent', b)
  add('dim', '  Cloud Privilege Escalation Detection System · detection console')
  add('out', '')
  add('info', "type 'help' for commands, or 'simulate 2' to catch a vertical-escalation attack.")
  add('out', '')
  return out.map((l) => (
    l.kind === 'accent'
      ? { ...l, node: <span className="text-cyber-accent">{l.text}</span> }
      : l
  ))
}
