import { useState, useRef } from 'react'
import { TerminalSquare, Cpu, Plus, X } from 'lucide-react'
import Terminal from './Terminal'

/*
 * TerminalDeck — run several `cpeds` consoles at once, like the "New Terminal"
 * tabs in an IDE. Each session is an independent <Terminal> with its own
 * scrollback, command history, and in-flight commands.
 *
 * Persistence model (by design): every session stays MOUNTED the whole time the
 * app is open — inactive ones are just hidden with `hidden` (display:none), not
 * unmounted. So switching between terminal tabs, or leaving the Terminal
 * dashboard tab and coming back, preserves everything (including a command that
 * is still running in a background console). A full browser refresh starts
 * fresh, which is the behaviour we chose.
 *
 * Chrome (header, card, traffic lights, tab strip) lives here once; each
 * <Terminal embedded> renders only its console body so the frame never doubles.
 */

const MAX_TERMINALS = 8

export default function TerminalDeck({ onIncidentSelect, active = true }) {
  // Sessions are ordered; `id` is stable, `name` shows on the tab chip.
  const [sessions, setSessions] = useState([{ id: 1, name: 'cpeds' }])
  const [activeId, setActiveId] = useState(1)
  const seq = useRef(1) // last id handed out; next is ++seq

  // Handlers read the current sessions/activeId from the render closure and keep
  // the setSessions updater pure — so React StrictMode's double-invoke in dev
  // can't double-increment the id counter or fire setActiveId twice.
  const addSession = () => {
    if (sessions.length >= MAX_TERMINALS) return
    const id = seq.current + 1
    seq.current = id
    setSessions((prev) => [...prev, { id, name: `cpeds ${id}` }])
    setActiveId(id)
  }

  const closeSession = (id) => {
    if (sessions.length <= 1) return // always keep one console open
    const idx = sessions.findIndex((s) => s.id === id)
    const next = sessions.filter((s) => s.id !== id)
    setSessions(next)
    // If we closed the active tab, fall back to its left neighbour.
    if (id === activeId) {
      const fallback = next[Math.max(0, idx - 1)]
      if (fallback) setActiveId(fallback.id)
    }
  }

  const atMax = sessions.length >= MAX_TERMINALS

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
            CLI, running against your live backend. Open several consoles with
            <span className="mx-1 inline-flex items-center gap-1 font-mono-soc text-cyber-accent">
              <Plus size={12} className="inline" />new terminal
            </span>
            to run attacks side by side.
          </p>
        </div>
        <div className="hidden items-center gap-2 rounded-lg border border-cyber-border bg-cyber-panel px-3 py-2 text-xs text-gray-400 sm:flex">
          <Cpu size={14} className="text-cyber-accent" />
          in-process model · {sessions.length} session{sessions.length > 1 ? 's' : ''}
        </div>
      </div>

      {/* Console */}
      <div className="overflow-hidden rounded-xl border border-cyber-border bg-[#070b14] shadow-inner">
        {/* Title bar — traffic lights + a tab strip of open sessions */}
        <div className="flex items-center gap-3 border-b border-cyber-border bg-cyber-panel px-4 py-2">
          <div className="flex shrink-0 items-center gap-2">
            <span className="h-3 w-3 rounded-full bg-red-500/70" />
            <span className="h-3 w-3 rounded-full bg-yellow-500/70" />
            <span className="h-3 w-3 rounded-full bg-green-500/70" />
          </div>

          {/* Tab chips */}
          <div className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto">
            {sessions.map((s) => {
              const isActive = s.id === activeId
              return (
                <div
                  key={s.id}
                  onClick={() => setActiveId(s.id)}
                  className={`group flex shrink-0 cursor-pointer items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono-soc text-xs transition-colors ${
                    isActive
                      ? 'border-cyber-accent/40 bg-cyber-accent/10 text-cyber-accent'
                      : 'border-transparent text-gray-500 hover:bg-white/5 hover:text-gray-300'
                  }`}
                  title={s.name}
                >
                  <TerminalSquare size={12} className="shrink-0" />
                  <span className="max-w-[120px] truncate">{s.name}</span>
                  {sessions.length > 1 && (
                    <button
                      onClick={(e) => { e.stopPropagation(); closeSession(s.id) }}
                      className={`ml-0.5 rounded p-0.5 transition-colors hover:bg-white/10 hover:text-red-400 ${
                        isActive ? 'text-cyber-accent/70' : 'text-gray-600 opacity-0 group-hover:opacity-100'
                      }`}
                      aria-label={`close ${s.name}`}
                    >
                      <X size={12} />
                    </button>
                  )}
                </div>
              )
            })}

            {/* New terminal */}
            <button
              onClick={addSession}
              disabled={atMax}
              className="ml-1 flex shrink-0 items-center gap-1 rounded-md px-2 py-1 font-mono-soc text-xs text-gray-500 transition-colors hover:bg-white/5 hover:text-cyber-accent disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-gray-500"
              title={atMax ? `max ${MAX_TERMINALS} terminals` : 'new terminal'}
              aria-label="new terminal"
            >
              <Plus size={13} />
              new
            </button>
          </div>
        </div>

        {/* Session bodies — all mounted, only the active one visible, so state
            and running commands survive tab switches. */}
        {sessions.map((s) => (
          <div key={s.id} className={s.id === activeId ? '' : 'hidden'}>
            <Terminal
              embedded
              active={active && s.id === activeId}
              onIncidentSelect={onIncidentSelect}
            />
          </div>
        ))}
      </div>

      <p className="text-xs text-gray-500">
        ↑/↓ recall commands · Ctrl+L clears · click
        <span className="mx-1 inline-flex items-center gap-1 font-mono-soc text-gray-400">
          <Plus size={11} className="inline" />new
        </span>
        for another console · click a verdict to open its XAI breakdown →
      </p>
    </div>
  )
}
