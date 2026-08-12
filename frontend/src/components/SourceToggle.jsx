import { FlaskConical, Database, Info } from 'lucide-react'

/**
 * Synthetic / Real event-source switch, shared by the Attack Simulator and the
 * Scenario Runner. This is INDEPENDENT of how the model was trained — it only
 * chooses what kind of event gets fed to the (already-loaded) model:
 *   - synthetic: fabricate a CloudTrail event from a class template
 *   - real:      replay a labeled CloudTrail event sampled from the dataset
 *
 * Props:
 *   source       'synthetic' | 'real'
 *   onChange     (next) => void
 *   availability null while loading, else { available, dataset, total, per_class, note }
 *   disabled     bool — lock the switch while a run is in flight
 */
export default function SourceToggle({ source, onChange, availability, disabled }) {
  const realReady = !!availability?.available
  const total = availability?.total ?? 0

  return (
    <div className="rounded-lg border border-cyber-border bg-cyber-bg/40 p-3">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-xs uppercase tracking-wide text-gray-500">Event source</span>
        <div className="inline-flex overflow-hidden rounded-lg border border-cyber-border">
          <button
            type="button"
            onClick={() => onChange('synthetic')}
            disabled={disabled}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium transition-colors disabled:opacity-50
              ${source === 'synthetic'
                ? 'bg-cyber-accent text-cyber-bg'
                : 'bg-transparent text-gray-400 hover:text-gray-200'}`}
          >
            <FlaskConical size={14} /> Synthetic
          </button>
          <button
            type="button"
            onClick={() => realReady && onChange('real')}
            disabled={disabled || !realReady}
            title={realReady ? '' : 'No labeled dataset available'}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40
              ${source === 'real'
                ? 'bg-cyber-accent text-cyber-bg'
                : 'bg-transparent text-gray-400 hover:text-gray-200'}`}
          >
            <Database size={14} /> Real
          </button>
        </div>
        {source === 'real' && realReady && (
          <span className="font-mono text-xs text-gray-500">
            {availability.dataset} · {total} events
          </span>
        )}
      </div>

      <div className="mt-2 flex items-start gap-1.5 text-xs text-gray-500">
        <Info size={13} className="mt-0.5 shrink-0" />
        {realReady ? (
          source === 'real' ? (
            <span>
              Real mode replays labeled CloudTrail events and shows the model's
              prediction against the dataset's ground-truth label (a genuine
              hit/miss). Per class: {formatPerClass(availability.per_class)}.
            </span>
          ) : (
            <span>
              Synthetic mode fabricates events from class templates. Switch to
              Real to replay actual labeled CloudTrail events.
            </span>
          )
        ) : (
          <span>{availability?.note || 'Checking for a labeled dataset…'}</span>
        )}
      </div>
    </div>
  )
}

const CLASS_SHORT = { 0: 'C0', 1: 'C1', 2: 'C2', 3: 'C3', 4: 'C4' }

function formatPerClass(perClass) {
  if (!perClass) return 'n/a'
  return Object.entries(perClass)
    .map(([c, n]) => `${CLASS_SHORT[c] ?? c}:${n}`)
    .join('  ')
}
