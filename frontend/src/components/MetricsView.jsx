import { useState, useEffect, useRef, useCallback } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import {
  Target, Award, Activity, Timer, Info, Database, FlaskConical,
  UploadCloud, RefreshCw, Loader2, AlertTriangle, CheckCircle2, X,
} from 'lucide-react'
import { getMetrics, reloadTraining, getTrainStatus, errMessage } from '../api'

const CLASS_SHORT = ['C0', 'C1', 'C2', 'C3', 'C4']

const MAX_DATASET_BYTES = 8 * 1024 * 1024 // mirrors the backend cap

// Fallback reference confusion matrix (used only until live metrics load or if
// the backend build predates per-class reporting).
const CONFUSION_FALLBACK = [
  [0.98, 0.01, 0.00, 0.01, 0.00],
  [0.02, 0.95, 0.02, 0.00, 0.01],
  [0.01, 0.02, 0.96, 0.01, 0.00],
  [0.00, 0.01, 0.01, 0.97, 0.01],
  [0.01, 0.02, 0.01, 0.02, 0.94],
]

export default function MetricsView() {
  const [metrics, setMetrics] = useState(null)
  const [error, setError] = useState(null)

  // ---- Training-source controls ----
  const [mode, setMode] = useState('synthetic')   // 'synthetic' | 'real'
  const [datasetText, setDatasetText] = useState('')
  const [datasetName, setDatasetName] = useState('')
  const [retraining, setRetraining] = useState(false)
  const [retrainStage, setRetrainStage] = useState('')      // live progress stage
  const [retrainElapsed, setRetrainElapsed] = useState(0)   // seconds, from server
  const [retrainError, setRetrainError] = useState('')
  const [retrainOk, setRetrainOk] = useState('')
  const fileInput = useRef(null)
  const pollTimer = useRef(null)      // setTimeout handle for the status poller

  const loadMetrics = useCallback(() => {
    return getMetrics()
      .then(r => {
        setMetrics(r.data)
        // Reflect the server's actual training mode in the toggle.
        const eff = r.data?.training?.effective_mode
        if (eff === 'synthetic' || eff === 'real') setMode(eff)
      })
      .catch(() => setError('Could not load metrics from backend.'))
  }, [])

  // Poll the background retrain job until it leaves the "running" state. Called
  // both right after kicking a retrain off AND on mount (so a job already in
  // flight — e.g. after a page refresh — resumes its progress display and keeps
  // the button correctly disabled instead of looking stuck or throwing a 409).
  const pollTrainStatus = useCallback(() => {
    getTrainStatus()
      .then(r => {
        const s = r.data || {}
        setRetrainElapsed(Math.round((s.elapsed_ms || 0) / 1000))
        if (s.state === 'running') {
          setRetraining(true)
          setRetrainStage(s.stage || 'Working…')
          pollTimer.current = setTimeout(pollTrainStatus, 1500)
          return
        }
        // Terminal states: stop polling and settle the UI.
        setRetraining(false)
        setRetrainStage('')
        if (s.state === 'done') {
          const acc = s.result?.measured?.lightgbm_accuracy
          const eff = s.result?.training?.effective_mode
          setRetrainError('')
          setRetrainOk(
            `Retrained on ${eff === 'real' ? 'your real dataset' : 'synthetic data'}` +
            (acc != null ? ` — LightGBM accuracy ${(acc * 100).toFixed(1)}%.` : '.')
          )
          loadMetrics()   // refresh charts (CV macro-F1 strip appears when present)
        } else if (s.state === 'error') {
          setRetrainOk('')
          setRetrainError(s.error || 'Retrain failed.')
          loadMetrics()   // model was left intact; re-sync the active-mode badge
        }
      })
      .catch(() => {
        // A transient status-poll failure shouldn't wedge the button; stop and
        // let the user retry. (A real in-flight job will still finish server-side.)
        setRetraining(false)
        setRetrainStage('')
      })
  }, [loadMetrics])

  useEffect(() => {
    loadMetrics()
    pollTrainStatus()  // resume any retrain already running (survives refresh)
    return () => { if (pollTimer.current) clearTimeout(pollTimer.current) }
  }, [loadMetrics, pollTrainStatus])

  const readDataset = (file) => {
    setRetrainError(''); setRetrainOk('')
    if (!file) return
    if (file.size > MAX_DATASET_BYTES) {
      setRetrainError(`Dataset is too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Limit is 8 MB.`)
      return
    }
    const reader = new FileReader()
    reader.onload = (e) => { setDatasetText(e.target.result || ''); setDatasetName(file.name) }
    reader.onerror = () => setRetrainError('Could not read that file.')
    reader.readAsText(file)
  }

  const clearDataset = () => {
    setDatasetText(''); setDatasetName('')
    if (fileInput.current) fileInput.current.value = ''
  }

  const doRetrain = async () => {
    setRetrainError(''); setRetrainOk('')
    if (mode === 'real' && !datasetText.trim()) {
      setRetrainError('Choose a labeled dataset file first, or switch to Synthetic.')
      return
    }
    // Optimistically show progress; the poller takes over once the job is live.
    setRetraining(true)
    setRetrainStage('Starting…')
    setRetrainElapsed(0)
    try {
      // Returns 202 as soon as the background job starts — does NOT wait for
      // training to finish. Progress + the final result come from pollTrainStatus.
      await reloadTraining({
        mode,
        datasetContent: mode === 'real' ? datasetText : null,
        datasetFilename: mode === 'real' ? datasetName : '',
      })
      pollTrainStatus()
    } catch (e) {
      // 409 => a job is already running: just attach to it instead of erroring.
      if (e?.response?.status === 409) {
        pollTrainStatus()
        return
      }
      setRetraining(false)
      setRetrainStage('')
      setRetrainError(errMessage(e))
    }
  }

  const measured = metrics?.measured || {}
  const bench = metrics?.benchmark || {}
  const training = metrics?.training || null

  // Prefer real measured numbers; fall back to benchmark reference.
  const acc = (k, fb) => (measured[k] != null ? measured[k] : (bench[k] != null ? bench[k] : fb))
  const modelBars = [
    { model: 'LightGBM', acc: acc('lightgbm_accuracy', 0.97) * 100, primary: true },
    { model: 'XGBoost', acc: acc('xgboost_accuracy', 0.931) * 100 },
    { model: 'AdaBoost', acc: acc('adaboost_accuracy', 0.884) * 100 },
    { model: 'Random Forest', acc: acc('random_forest_accuracy', 0.862) * 100 },
  ]

  const haveMeasured = measured && Object.keys(measured).length > 0
  const macroF1 = measured.lightgbm_macro_f1 != null ? measured.lightgbm_macro_f1 : bench.macro_f1
  const macroPrecision = measured.lightgbm_macro_precision
  const macroRecall = measured.lightgbm_macro_recall

  const cards = [
    {
      icon: Target,
      label: haveMeasured ? 'LightGBM Accuracy (measured)' : 'LightGBM Accuracy',
      value: `${(acc('lightgbm_accuracy', 0.97) * 100).toFixed(1)}%`,
      color: 'text-green-400',
    },
    {
      icon: Award,
      label: haveMeasured ? 'Macro F1 (measured)' : 'Macro F1',
      value: `${((macroF1 || 0.962) * 100).toFixed(1)}%`,
      color: 'text-cyber-accent',
    },
    {
      icon: Activity,
      label: macroRecall != null ? 'Macro Recall (measured)' : 'AUC-ROC (reference)',
      value: macroRecall != null ? `${(macroRecall * 100).toFixed(1)}%` : (bench.roc_auc || 0.99).toFixed(3),
      color: 'text-purple-400',
    },
    {
      icon: Timer,
      label: 'MTTD (reference)',
      value: `${bench.mttd_seconds || 1.8}s`,
      color: 'text-yellow-400',
    },
  ]

  // Real confusion matrix if present, else fallback.
  const confusion = Array.isArray(measured.confusion_matrix) && measured.confusion_matrix.length === 5
    ? measured.confusion_matrix
    : CONFUSION_FALLBACK
  const confusionIsReal = Array.isArray(measured.confusion_matrix)
  const perClass = Array.isArray(measured.per_class) ? measured.per_class : null

  if (error) return <div className="text-red-400 p-6">{error}</div>

  return (
    <div className="space-y-6">
      {/* Honest-evaluation disclosure */}
      <div className="flex items-start gap-2 rounded-xl border border-cyber-accent/30 bg-cyber-accent/5 px-4 py-3 text-sm text-gray-300">
        <Info size={16} className="mt-0.5 shrink-0 text-cyber-accent" />
        <p>
          Numbers labelled <span className="text-cyber-accent font-medium">measured</span> are computed
          on a held-out test set from this session's training run. The data is synthetic but the threat
          classes are generated to <span className="text-gray-100">overlap in feature space</span> — so a
          stealthy exfiltration can resemble benign traffic — which is why the scores land in a realistic
          range with genuine cross-class confusion rather than a suspicious 100%.
          {measured.test_set_size ? ` Test set: ${measured.test_set_size} events.` : ''}
        </p>
      </div>

      {/* ---------------- Training source control ---------------- */}
      <div className="rounded-xl border border-cyber-border bg-cyber-panel p-5">
        <div className="mb-1 flex items-center gap-2">
          <Database size={18} className="text-cyber-accent" />
          <h3 className="font-semibold">Training Data Source</h3>
          {training?.effective_mode && (
            <span className={`ml-auto rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
              training.effective_mode === 'real'
                ? 'border-cyber-accent/40 bg-cyber-accent/10 text-cyber-accent'
                : 'border-blue-500/40 bg-blue-500/10 text-blue-300'
            }`}>
              Active: {training.effective_mode === 'real' ? 'Real dataset' : 'Synthetic'}
            </span>
          )}
        </div>
        <p className="mb-4 text-xs text-gray-500">
          Retrain the four models on whichever source you pick. Switching is a live
          retrain and takes a few seconds; the model hot-swaps when it's ready.
          Synthetic is the zero-config default and always available to revert to.
        </p>

        {/* mode toggle */}
        <div className="mb-4 inline-flex rounded-lg border border-cyber-border bg-cyber-bg p-1">
          <button
            onClick={() => { setMode('synthetic'); setRetrainError(''); setRetrainOk('') }}
            disabled={retraining}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
              mode === 'synthetic' ? 'bg-cyber-accent text-cyber-bg' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <FlaskConical size={15} /> Synthetic
          </button>
          <button
            onClick={() => { setMode('real'); setRetrainError(''); setRetrainOk('') }}
            disabled={retraining}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
              mode === 'real' ? 'bg-cyber-accent text-cyber-bg' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Database size={15} /> Real dataset
          </button>
        </div>

        {/* real-mode file picker */}
        {mode === 'real' && (
          <div className="mb-4">
            <div
              onClick={() => fileInput.current?.click()}
              className="flex cursor-pointer items-center gap-3 rounded-lg border-2 border-dashed border-cyber-border px-4 py-3 transition-colors hover:border-cyber-accent/50"
            >
              <input
                ref={fileInput}
                type="file"
                accept=".json,.jsonl,.ndjson,.csv,.txt,application/json,text/csv"
                className="hidden"
                onChange={(e) => readDataset(e.target.files?.[0])}
              />
              <UploadCloud size={20} className="text-gray-500" />
              <div className="text-sm">
                <span className="font-medium text-cyber-accent">Choose a labeled dataset</span>
                <span className="text-gray-400"> — CloudTrail JSON · JSON array · .jsonl · .csv, up to 8 MB</span>
              </div>
            </div>
            {datasetName && (
              <div className="mt-2 flex items-center gap-2 text-xs text-gray-400">
                <CheckCircle2 size={14} className="text-green-400" />
                {datasetName}
                <button onClick={clearDataset} className="text-gray-500 hover:text-red-400" title="Clear">
                  <X size={14} />
                </button>
              </div>
            )}
            <p className="mt-2 text-xs text-gray-500">
              Each row needs a <code className="text-gray-300">label</code> column (0–4 or C0–C4).
              See <code className="text-gray-300">backend/sample_data/</code> for a ready example and the format note.
            </p>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={doRetrain}
            disabled={retraining || (mode === 'real' && !datasetText.trim())}
            className="flex items-center gap-2 rounded-lg bg-cyber-accent px-4 py-2.5 text-sm font-semibold text-cyber-bg transition-colors hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {retraining ? <Loader2 size={16} className="animate-spin" /> : <RefreshCw size={16} />}
            {retraining
              ? `${retrainStage || 'Retraining'}… (${retrainElapsed}s)`
              : `Retrain (${mode})`}
          </button>
          {training?.dataset && training.effective_mode === 'real' && (
            <span className="text-xs text-gray-500">
              Trained on {training.dataset.rows_used} rows
              {training.dataset.filename ? ` from ${training.dataset.filename}` : ''}
              {training.dataset.rows_skipped ? ` (${training.dataset.rows_skipped} skipped)` : ''}.
            </span>
          )}
        </div>

        {/* How class imbalance was handled for this model */}
        {training?.imbalance_strategy && (
          <p className="mt-3 text-xs text-gray-500">
            Imbalance handling:{' '}
            <span className="font-mono text-gray-300">{training.imbalance_strategy}</span>
            {training.effective_mode === 'real'
              ? ' — real data uses cost-sensitive class weights (not SMOTE), which lifts minority-class recall without fabricating rows.'
              : ' — synthetic classes are evenly sized, so SMOTE balances the train fold.'}
          </p>
        )}

        {/* real-mode fell back to synthetic (startup only) */}
        {training?.fallback_reason && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-2.5 text-sm text-yellow-200">
            <AlertTriangle size={16} className="mt-0.5 shrink-0" />
            <span>Real data was requested but couldn't be used, so synthetic is active: {training.fallback_reason}</span>
          </div>
        )}
        {retrainError && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-sm text-red-300">
            <AlertTriangle size={16} className="mt-0.5 shrink-0" />
            <span>{retrainError}</span>
          </div>
        )}
        {retrainOk && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-green-500/30 bg-green-500/10 px-3 py-2.5 text-sm text-green-300">
            <CheckCircle2 size={16} className="mt-0.5 shrink-0" />
            <span>{retrainOk}</span>
          </div>
        )}
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((c, i) => {
          const Icon = c.icon
          return (
            <div key={i} className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
              <Icon className={c.color} size={22} />
              <p className="text-2xl font-bold mt-3">{c.value}</p>
              <p className="text-xs text-gray-400 mt-1">{c.label}</p>
            </div>
          )
        })}
      </div>

      {/* Cross-validated macro-F1 — the trustworthy headline for imbalanced real data */}
      {measured.cv_macro_f1_mean != null && (
        <div className="rounded-xl border border-cyber-accent/30 bg-cyber-accent/5 p-5">
          <div className="flex flex-wrap items-center gap-3">
            <Award size={18} className="text-cyber-accent" />
            <h3 className="font-semibold">Cross-Validated Macro-F1 — the honest headline</h3>
            <span className="ml-auto font-mono text-2xl font-bold text-cyber-accent">
              {(measured.cv_macro_f1_mean * 100).toFixed(1)}%
              <span className="ml-1 text-sm font-normal text-gray-400">
                ± {(measured.cv_macro_f1_std * 100).toFixed(1)}%
              </span>
            </span>
          </div>
          <p className="mt-2 text-xs text-gray-400">
            Averaged over {measured.cv_folds}-fold stratified cross-validation across the whole
            dataset. On an imbalanced dataset, <span className="text-gray-200">accuracy is
            misleading</span> — a model that always predicts “benign” can score high while
            catching zero attacks. Macro-F1 weights every class equally, and cross-validating it
            removes the luck of a single tiny test split. <span className="text-gray-200">This is
            the number to cite</span>, not the single-split accuracy above.
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Accuracy comparison bar chart */}
        <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
          <h3 className="font-semibold mb-1">Model Accuracy Comparison</h3>
          <p className="text-xs text-gray-500 mb-4">
            {haveMeasured ? 'Measured on the held-out test set this session' : 'Reference baseline'}
          </p>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={modelBars}>
              <XAxis dataKey="model" stroke="#9ca3af" fontSize={11} />
              <YAxis domain={[70, 100]} stroke="#6b7280" fontSize={11} />
              <Tooltip
                contentStyle={{ background: '#0a0e1a', border: '1px solid #1f2937', borderRadius: 8 }}
                formatter={(v) => `${v.toFixed(1)}%`}
              />
              <Bar dataKey="acc" radius={[4, 4, 0, 0]}>
                {modelBars.map((d, i) => (
                  <Cell key={i} fill={d.primary ? '#22d3ee' : '#3b82f6'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Confusion matrix */}
        <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6">
          <h3 className="font-semibold mb-1">Confusion Matrix</h3>
          <p className="text-xs text-gray-500 mb-4">
            {confusionIsReal ? 'Row-normalized, measured on held-out test set' : 'Reference (awaiting live metrics)'}
          </p>
          <div className="overflow-x-auto">
            <table className="text-xs">
              <thead>
                <tr>
                  <th className="p-2"></th>
                  {CLASS_SHORT.map(c => <th key={c} className="p-2 text-gray-400">{c}</th>)}
                </tr>
              </thead>
              <tbody>
                {confusion.map((row, i) => (
                  <tr key={i}>
                    <td className="p-2 text-gray-400 font-semibold">{CLASS_SHORT[i]}</td>
                    {row.map((val, j) => (
                      <td key={j} className="p-1">
                        <div
                          className="w-12 h-12 flex items-center justify-center rounded font-mono"
                          style={{
                            background: `rgba(34, 211, 238, ${val})`,
                            color: val > 0.5 ? '#0a0e1a' : '#9ca3af',
                          }}
                        >
                          {val.toFixed(2)}
                        </div>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-gray-500 mt-3">Rows = actual, Columns = predicted</p>
        </div>
      </div>

      {/* Per-class precision / recall / F1 (real, when available) */}
      {perClass && (
        <div className="bg-cyber-panel border border-cyber-border rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-cyber-border">
            <h3 className="font-semibold">Per-Class Performance (LightGBM, measured)</h3>
            <p className="mt-0.5 text-xs text-gray-500">
              Precision, recall and F1 per threat class on the held-out test set.
              <span className="text-gray-400"> Test n</span> is how many real test
              rows that class had — rows with a small n (highlighted) are
              high-variance, so read their scores as rough, not exact.
            </p>
          </div>
          <table className="w-full text-sm">
            <thead className="bg-cyber-bg text-xs uppercase text-gray-400">
              <tr>
                <th className="px-6 py-3 text-left">Threat Class</th>
                <th className="px-6 py-3 text-left">Precision</th>
                <th className="px-6 py-3 text-left">Recall</th>
                <th className="px-6 py-3 text-left">F1</th>
                <th className="px-6 py-3 text-left">Test n</th>
              </tr>
            </thead>
            <tbody>
              {perClass.map((r) => {
                const n = r.support
                const lowN = typeof n === 'number' && n < 20
                return (
                  <tr key={r.class}
                      className={`border-t border-cyber-border${lowN ? ' bg-amber-500/5' : ''}`}>
                    <td className="px-6 py-3 font-medium text-gray-200">{r.label}</td>
                    <td className="px-6 py-3 font-mono">{(r.precision * 100).toFixed(1)}%</td>
                    <td className="px-6 py-3 font-mono">{(r.recall * 100).toFixed(1)}%</td>
                    <td className="px-6 py-3 font-mono text-cyber-accent">{(r.f1 * 100).toFixed(1)}%</td>
                    <td className={`px-6 py-3 font-mono ${lowN ? 'text-amber-400' : 'text-gray-400'}`}>
                      {n == null ? '—' : n}
                      {lowN && <span className="ml-1 text-[10px] uppercase tracking-wide">low</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          <div className="px-6 py-3 border-t border-cyber-border text-xs text-gray-500">
            A class with only a few test rows (e.g. n=5) can show an extreme
            precision or recall from a single misclassification. The
            cross-validated macro-F1 above averages over folds and is the honest
            headline for this imbalanced dataset.
          </div>
        </div>
      )}
    </div>
  )
}
