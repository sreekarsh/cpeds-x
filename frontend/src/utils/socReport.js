/**
 * CPEDS-X — client-side SOC incident report.
 *
 * Renders the operator's incident history into a clean, print-optimized HTML
 * document inside a hidden iframe, then opens the browser print dialog so the
 * analyst can "Save as PDF". No dependencies, no server round-trip — the report
 * is built from data already loaded in the Incident History tab.
 *
 * The report intentionally uses a light "official document" theme (dark text on
 * white, one cyan accent) rather than the dark console UI: printed dark
 * backgrounds waste ink and read poorly on paper.
 */

const CLASS_NAMES = {
  0: 'C0 · Benign',
  1: 'C1 · Horizontal Escalation',
  2: 'C2 · Vertical Escalation',
  3: 'C3 · Data Exfiltration',
  4: 'C4 · Lateral Movement',
}

const SOURCE_NAMES = {
  live: 'Live simulator',
  scenario: 'Attack scenario',
  analyze: 'Log upload',
}

function esc(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return esc(iso)
  return d.toLocaleString([], {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

/** Compute the summary block the report header needs. */
function summarize(incidents) {
  const total = incidents.length
  const threats = incidents.filter((i) => i.predicted_class !== 0).length
  const contained = incidents.filter((i) => i.action_status === 'CONTAINED').length
  const counts = {}
  for (const i of incidents) {
    counts[i.predicted_class] = (counts[i.predicted_class] || 0) + 1
  }
  // Incidents arrive newest-first; derive the observed window from the ends.
  const newest = total ? incidents[0].created_at : null
  const oldest = total ? incidents[total - 1].created_at : null
  return { total, threats, contained, benign: total - threats, counts, newest, oldest }
}

/** Build the full standalone HTML document for the report. */
function buildReportHtml(incidents, meta) {
  const s = summarize(incidents)
  const now = new Date()
  const reportId = 'CPEDS-X-' + now.toISOString().slice(0, 19).replace(/[-:T]/g, '')
  const analyst = meta.analystName || meta.analystEmail || 'CPEDS-X Operator'

  const distRows = [0, 1, 2, 3, 4]
    .filter((c) => s.counts[c])
    .map((c) => {
      const pct = s.total ? ((s.counts[c] / s.total) * 100).toFixed(1) : '0.0'
      return `<tr>
        <td>${esc(CLASS_NAMES[c])}</td>
        <td class="num">${s.counts[c]}</td>
        <td class="num">${pct}%</td>
      </tr>`
    })
    .join('')

  const rows = incidents
    .map((inc, idx) => {
      const cls = inc.predicted_class
      const threat = cls !== 0
      const conf = (inc.confidence * 100).toFixed(1)
      const contained = inc.action_status === 'CONTAINED'
      return `<tr class="${threat ? 'is-threat' : ''}">
        <td class="num">${idx + 1}</td>
        <td class="mono nowrap">${fmtTime(inc.created_at)}</td>
        <td>${esc(SOURCE_NAMES[inc.source] || inc.source || '—')}</td>
        <td class="mono">${esc(inc.event_name || '—')}</td>
        <td class="mono principal">${esc(inc.principal || 'n/a')}</td>
        <td class="mono">${esc(inc.source_ip || '')}</td>
        <td><span class="chip chip-c${cls}">${esc(CLASS_NAMES[cls] || cls)}</span></td>
        <td class="num">${conf}%</td>
        <td class="${contained ? 'contained' : 'monitored'}">${esc(inc.action_status || '')}</td>
      </tr>`
    })
    .join('')

  const windowLine = s.total
    ? `${fmtTime(s.oldest)} &nbsp;&rarr;&nbsp; ${fmtTime(s.newest)}`
    : 'No incidents recorded'

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${esc(reportId)} &mdash; SOC Incident Report</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #14181f; background: #ffffff; font-size: 12px; line-height: 1.45;
  }
  .page { max-width: 960px; margin: 0 auto; padding: 40px 44px; }
  .mono { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .nowrap { white-space: nowrap; }

  header.masthead {
    display: flex; justify-content: space-between; align-items: flex-start;
    border-bottom: 3px solid #0e7490; padding-bottom: 16px; margin-bottom: 4px;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand .mark {
    width: 34px; height: 34px; border-radius: 8px; background: #0e7490;
    color: #fff; font-weight: 700; font-size: 15px; letter-spacing: .5px;
    display: flex; align-items: center; justify-content: center;
  }
  .brand h1 { margin: 0; font-size: 18px; letter-spacing: .3px; }
  .brand .sub { margin: 2px 0 0; font-size: 11px; color: #5b6572; }
  .docmeta { text-align: right; font-size: 11px; color: #5b6572; }
  .docmeta .rid { font-family: Consolas, monospace; color: #14181f; font-weight: 600; }

  .confidential {
    margin: 14px 0 22px; font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
    color: #b45309; font-weight: 700;
  }

  h2.section {
    font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: #0e7490;
    border-bottom: 1px solid #d8dee6; padding-bottom: 5px; margin: 26px 0 12px;
  }

  .kv { display: grid; grid-template-columns: 150px 1fr; gap: 4px 14px; font-size: 12px; }
  .kv dt { color: #5b6572; }
  .kv dd { margin: 0; font-weight: 500; }

  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 4px 0 6px; }
  .card { border: 1px solid #d8dee6; border-radius: 8px; padding: 12px 14px; }
  .card .lbl { font-size: 10px; text-transform: uppercase; letter-spacing: .6px; color: #5b6572; }
  .card .val { font-size: 24px; font-weight: 700; margin-top: 3px; }
  .card .val.red { color: #b91c1c; }
  .card .val.teal { color: #0e7490; }

  table { width: 100%; border-collapse: collapse; margin-top: 6px; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #e5e9ee; text-align: left; vertical-align: top; }
  th { font-size: 10px; text-transform: uppercase; letter-spacing: .5px; color: #5b6572; background: #f5f7f9; }
  td.principal { max-width: 210px; word-break: break-all; }
  tbody tr.is-threat { background: #fdf3f3; }

  .chip { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 10px; font-weight: 700; white-space: nowrap; }
  .chip-c0 { background: #dcfce7; color: #166534; }
  .chip-c1 { background: #fef9c3; color: #854d0e; }
  .chip-c2 { background: #fee2e2; color: #991b1b; }
  .chip-c3 { background: #f3e8ff; color: #6b21a8; }
  .chip-c4 { background: #ffedd5; color: #9a3412; }
  td.contained { color: #b91c1c; font-weight: 700; }
  td.monitored { color: #5b6572; }

  .dist { max-width: 380px; }
  footer.rep {
    margin-top: 30px; border-top: 1px solid #d8dee6; padding-top: 12px;
    font-size: 10px; color: #5b6572;
  }
  .disclaimer { margin-top: 6px; font-style: italic; }

  @media print {
    .page { padding: 0; max-width: none; }
    thead { display: table-header-group; }
    tbody tr { page-break-inside: avoid; }
    a { color: inherit; text-decoration: none; }
  }
</style>
</head>
<body>
  <div class="page">
    <header class="masthead">
      <div class="brand">
        <div class="mark">CX</div>
        <div>
          <h1>CPEDS-X &mdash; SOC Incident Report</h1>
          <p class="sub">Cloud Privilege Escalation Detection System</p>
        </div>
      </div>
      <div class="docmeta">
        <div class="rid">${esc(reportId)}</div>
        <div>Generated ${esc(fmtTime(now.toISOString()))}</div>
        <div>Analyst: ${esc(analyst)}</div>
      </div>
    </header>

    <div class="confidential">Confidential &middot; For internal security review</div>

    <h2 class="section">Report Metadata</h2>
    <dl class="kv">
      <dt>Prepared for</dt><dd>${esc(analyst)}${meta.analystEmail ? ` &lt;${esc(meta.analystEmail)}&gt;` : ''}</dd>
      <dt>Observation window</dt><dd class="mono">${windowLine}</dd>
      <dt>Incidents in report</dt><dd>${s.total}</dd>
      <dt>Detection engine</dt><dd>LightGBM ensemble + SHAP explainability &middot; auto-containment gate &ge; 75% confidence</dd>
    </dl>

    <h2 class="section">Executive Summary</h2>
    <div class="cards">
      <div class="card"><div class="lbl">Total incidents</div><div class="val">${s.total}</div></div>
      <div class="card"><div class="lbl">Threats detected</div><div class="val red">${s.threats}</div></div>
      <div class="card"><div class="lbl">Auto-contained</div><div class="val teal">${s.contained}</div></div>
      <div class="card"><div class="lbl">Benign</div><div class="val">${s.benign}</div></div>
    </div>

    <h2 class="section">Threat Distribution</h2>
    <table class="dist">
      <thead><tr><th>Class</th><th class="num">Count</th><th class="num">Share</th></tr></thead>
      <tbody>${distRows || '<tr><td colspan="3">No incidents recorded.</td></tr>'}</tbody>
    </table>

    <h2 class="section">Incident Log</h2>
    <table>
      <thead>
        <tr>
          <th class="num">#</th><th>Timestamp</th><th>Source</th><th>Event</th>
          <th>Principal</th><th>Source IP</th><th>Threat Class</th>
          <th class="num">Conf.</th><th>Action</th>
        </tr>
      </thead>
      <tbody>${rows || '<tr><td colspan="9">No incidents to report.</td></tr>'}</tbody>
    </table>

    <footer class="rep">
      <div>CPEDS-X automated SOC report &middot; ${esc(reportId)} &middot; Page generated client-side, no data left the browser.</div>
      <div class="disclaimer">
        Generated by an academic detection system trained on synthetic cloud-audit data.
        Confidence scores are model estimates and should be corroborated before operational action.
      </div>
    </footer>
  </div>
</body>
</html>`
}

/**
 * Generate the report and open the browser's print dialog (Save as PDF).
 * Renders into an off-screen iframe so the SOC console UI is untouched.
 *
 * @param {Array} incidents  incident rows from GET /api/v1/incidents (newest first)
 * @param {Object} meta       { analystName, analystEmail }
 */
export function generateSocReport(incidents, meta = {}) {
  const html = buildReportHtml(Array.isArray(incidents) ? incidents : [], meta)

  const iframe = document.createElement('iframe')
  iframe.setAttribute('aria-hidden', 'true')
  iframe.style.position = 'fixed'
  iframe.style.right = '0'
  iframe.style.bottom = '0'
  iframe.style.width = '0'
  iframe.style.height = '0'
  iframe.style.border = '0'
  document.body.appendChild(iframe)

  const doc = iframe.contentWindow.document
  doc.open()
  doc.write(html)
  doc.close()

  // Remove the iframe after the dialog closes (or is cancelled).
  const cleanup = () => {
    setTimeout(() => {
      if (iframe.parentNode) iframe.parentNode.removeChild(iframe)
    }, 500)
  }

  const trigger = () => {
    try {
      iframe.contentWindow.focus()
      iframe.contentWindow.onafterprint = cleanup
      iframe.contentWindow.print()
      // Fallback cleanup in case onafterprint never fires (some browsers).
      setTimeout(cleanup, 60000)
    } catch (e) {
      cleanup()
      throw e
    }
  }

  // Give the iframe a tick to lay out before invoking print.
  if (doc.readyState === 'complete') {
    setTimeout(trigger, 50)
  } else {
    iframe.onload = () => setTimeout(trigger, 50)
  }
}
