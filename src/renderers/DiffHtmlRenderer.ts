// src/renderers/DiffHtmlRenderer.ts
import type { AuditDiff, FindingChange } from '../history/AuditDiff.js';
import type { DiffRenderer } from './DiffRenderer.js';

function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtDate(d: Date): string {
  return d.toISOString().replace('T', ' ').substring(0, 16);
}

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#2563eb', INFO: '#64748b',
};

const CHANGE_LABELS: Record<string, string> = {
  'new': 'New', 'resolved': 'Resolved', 'severity-changed': 'Severity Changed', 'detail-changed': 'Detail Changed',
};

function renderFindingCard(change: FindingChange): string {
  const f = change.finding;
  const typeColor = change.type === 'new' ? '#dc2626' : change.type === 'resolved' ? '#22c55e' : '#d97706';
  const prevBadge = change.previous
    ? `<span class="risk-badge" style="background:${RISK_COLORS[change.previous.riskLevel] ?? '#64748b'}">${esc(change.previous.riskLevel)}</span> → `
    : '';

  return `
  <div class="finding-card" style="border-left-color:${typeColor}">
    <div class="finding-header">
      <span class="change-badge" style="background:${typeColor}">${CHANGE_LABELS[change.type] ?? change.type}</span>
      ${prevBadge}<span class="risk-badge" style="background:${RISK_COLORS[f.riskLevel] ?? '#64748b'}">${esc(f.riskLevel)}</span>
      <span class="finding-title">${esc(f.title)}</span>
      <span class="finding-category">${esc(f.category)}</span>
    </div>
    ${change.type === 'detail-changed' && change.previous ? `
    <div class="detail-diff">
      <div class="diff-before"><strong>Before:</strong> ${esc(change.previous.detail)}</div>
      <div class="diff-after"><strong>After:</strong> ${esc(f.detail)}</div>
    </div>` : ''}
  </div>`;
}

export class DiffHtmlRenderer implements DiffRenderer {
  readonly format = 'html';
  readonly fileExtension = '.html';

  render(diff: AuditDiff): string {
    const { baseline, current } = diff;
    const scoreDeltaStr = diff.scoreDelta >= 0 ? `+${diff.scoreDelta}` : `${diff.scoreDelta}`;
    const scoreDeltaColor = diff.scoreDelta > 0 ? '#22c55e' : diff.scoreDelta < 0 ? '#dc2626' : '#8b949e';

    const changeCounts = {
      new:               diff.findingChanges.filter((c) => c.type === 'new').length,
      resolved:          diff.findingChanges.filter((c) => c.type === 'resolved').length,
      'severity-changed':diff.findingChanges.filter((c) => c.type === 'severity-changed').length,
      'detail-changed':  diff.findingChanges.filter((c) => c.type === 'detail-changed').length,
    };

    const sectionOrder: Array<FindingChange['type']> = ['new', 'resolved', 'severity-changed', 'detail-changed', 'unchanged'];
    const sections = sectionOrder.map((type) => {
      const changes = diff.findingChanges.filter((c) => c.type === type);
      if (changes.length === 0) return '';
      const sectionClass = type === 'unchanged' ? ' class="unchanged-section"' : '';
      return `
  <section${sectionClass}>
    <h2>${CHANGE_LABELS[type] ?? type} (${changes.length})</h2>
    ${changes.map(renderFindingCard).join('')}
  </section>`;
    }).join('');

    const metricRows = diff.metricDeltas.map((d) => {
      const color = d.direction === 'improved' ? '#22c55e' : d.direction === 'degraded' ? '#dc2626' : '#8b949e';
      const arrow = d.delta > 0 ? '▲' : '▼';
      const deltaStr = d.delta > 0 ? `+${d.delta}` : `${d.delta}`;
      return `<tr>
        <td>${esc(d.label)}</td>
        <td style="text-align:right">${d.before}</td>
        <td style="text-align:right">${d.after}</td>
        <td style="text-align:right;color:${color};font-weight:700">${arrow} ${deltaStr}</td>
      </tr>`;
    }).join('');

    const metricsSection = diff.metricDeltas.length > 0 ? `
  <section>
    <h2>Metric Changes</h2>
    <table class="metric-table">
      <thead><tr><th>Metric</th><th>Before</th><th>After</th><th>Change</th></tr></thead>
      <tbody>${metricRows}</tbody>
    </table>
  </section>` : '';

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SF Audit Diff: ${esc(baseline.orgName)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; max-width: 1000px; margin: 2rem auto; padding: 0 1.25rem 4rem; line-height: 1.6; }
  h1 { color: #f0f6fc; font-size: 1.5rem; font-weight: 700; margin-bottom: 0.4rem; }
  h2 { color: #e6edf3; font-size: 1.1rem; font-weight: 700; margin: 1.5rem 0 0.75rem; }
  .meta { font-size: 0.8rem; color: #8b949e; display: flex; flex-wrap: wrap; gap: 0.5rem 1.25rem; margin-bottom: 1.5rem; }
  .scorecard { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.25rem 2rem; display: flex; gap: 2rem; align-items: center; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .score-delta { font-size: 2.5rem; font-weight: 800; color: ${scoreDeltaColor}; line-height: 1; }
  .grade-delta { font-size: 1.2rem; font-weight: 700; color: #c9d1d9; }
  .summary-counts { display: flex; gap: 1rem; flex-wrap: wrap; }
  .count-badge { background: #1c2128; border: 1px solid #30363d; border-radius: 8px; padding: 0.5rem 1rem; text-align: center; }
  .count-badge .num { font-size: 1.5rem; font-weight: 800; display: block; }
  .count-badge .lbl { font-size: 0.75rem; color: #8b949e; }
  .finding-card { background: #161b22; border: 1px solid #30363d; border-left: 3px solid #30363d; border-radius: 8px; margin-bottom: 0.5rem; padding: 0.75rem 1rem; }
  .finding-header { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .change-badge { padding: 0.15rem 0.6rem; border-radius: 4px; font-size: 0.7rem; font-weight: 800; color: #fff; letter-spacing: 0.04em; }
  .risk-badge { padding: 0.15rem 0.6rem; border-radius: 4px; font-size: 0.7rem; font-weight: 800; color: #fff; }
  .finding-title { flex: 1; font-weight: 600; color: #e6edf3; font-size: 0.9rem; }
  .finding-category { font-size: 0.75rem; color: #8b949e; }
  .detail-diff { margin-top: 0.5rem; font-size: 0.82rem; display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
  .diff-before { background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.3); border-radius: 4px; padding: 0.5rem; }
  .diff-after  { background: rgba(34,197,94,0.1);  border: 1px solid rgba(34,197,94,0.3);  border-radius: 4px; padding: 0.5rem; }
  .unchanged-section { opacity: 0.5; }
  .metric-table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  .metric-table th { background: #1c2128; color: #8b949e; text-align: left; padding: 0.4rem 0.75rem; border-bottom: 1px solid #30363d; font-weight: 600; }
  .metric-table td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #21262d; }
  .metric-table tr:last-child td { border-bottom: none; }
  section { margin-bottom: 2rem; }
</style>
</head>
<body>
  <h1>Salesforce Audit Diff</h1>
  <div class="meta">
    <span>Org: <strong style="color:#c9d1d9">${esc(baseline.orgName)}</strong> (${esc(baseline.orgId)})</span>
    <span>Baseline: ${fmtDate(baseline.generatedAt)}</span>
    <span>Current: ${fmtDate(current.generatedAt)}</span>
  </div>

  <div class="scorecard">
    <div>
      <div class="score-delta">${scoreDeltaStr}</div>
      <div style="font-size:0.8rem;color:#8b949e;margin-top:0.25rem">score change</div>
    </div>
    <div class="grade-delta">${esc(diff.gradeDelta)}</div>
    <div class="summary-counts">
      <div class="count-badge"><span class="num" style="color:#dc2626">${changeCounts.new}</span><span class="lbl">New</span></div>
      <div class="count-badge"><span class="num" style="color:#22c55e">${changeCounts.resolved}</span><span class="lbl">Resolved</span></div>
      <div class="count-badge"><span class="num" style="color:#d97706">${changeCounts['severity-changed']}</span><span class="lbl">Sev. Changed</span></div>
      <div class="count-badge"><span class="num" style="color:#64748b">${changeCounts['detail-changed']}</span><span class="lbl">Detail Changed</span></div>
    </div>
  </div>

  ${metricsSection}
  ${sections}

<script>
  // Toggle unchanged findings visibility
  const unchanged = document.querySelector('.unchanged-section');
  if (unchanged) {
    const toggle = document.createElement('button');
    toggle.textContent = 'Show Unchanged';
    toggle.style.cssText = 'background:#1c2128;border:1px solid #30363d;color:#8b949e;padding:0.3rem 0.75rem;border-radius:20px;cursor:pointer;font-size:0.8rem;margin-bottom:0.75rem';
    unchanged.insertBefore(toggle, unchanged.querySelector('h2').nextSibling);
    let visible = false;
    unchanged.querySelectorAll('.finding-card').forEach(c => c.style.display = 'none');
    toggle.addEventListener('click', () => {
      visible = !visible;
      toggle.textContent = visible ? 'Hide Unchanged' : 'Show Unchanged';
      unchanged.querySelectorAll('.finding-card').forEach(c => c.style.display = visible ? '' : 'none');
    });
  }
</script>
</body>
</html>`;
  }
}
