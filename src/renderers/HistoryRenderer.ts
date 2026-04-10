// src/renderers/HistoryRenderer.ts
import type { AuditResult } from '../findings/AuditResult.js';

function fmtDate(d: Date): string {
  return d.toISOString().replace('T', ' ').substring(0, 16);
}

function countBySeverity(result: AuditResult, level: string): number {
  return result.findings.filter((f) => f.riskLevel === level).length;
}

export class HistoryRenderer {

  renderTable(results: AuditResult[]): string {
    if (results.length === 0) return 'No audit history found.';

    const orgName = results[0].orgName;
    const orgId   = results[0].orgId;

    const header = `Audit History: ${orgName} (${orgId})`;
    const divider = '─'.repeat(Math.max(header.length, 80));
    const colHeader = '  #   Date                  Score   Grade   CRIT   HIGH    MED    LOW   Δ Score';

    const rows = results.map((r, i) => {
      const prev  = i > 0 ? results[i - 1] : null;
      const delta = prev ? (r.healthScore - prev.healthScore >= 0 ? `+${r.healthScore - prev.healthScore}` : `${r.healthScore - prev.healthScore}`) : '—';
      const crit = String(countBySeverity(r, 'CRITICAL')).padStart(4);
      const high = String(countBySeverity(r, 'HIGH')).padStart(4);
      const med  = String(countBySeverity(r, 'MEDIUM')).padStart(6);
      const low  = String(countBySeverity(r, 'LOW')).padStart(6);
      return `  ${String(i + 1).padStart(2)}  ${fmtDate(r.generatedAt).padEnd(20)} ${String(r.healthScore).padStart(5)}   ${r.grade.padEnd(5)} ${crit}   ${high}  ${med}  ${low}  ${String(delta).padStart(7)}`;
    });

    const scores = results.map((r) => r.healthScore);
    const best   = Math.max(...scores);
    const worst  = Math.min(...scores);
    const trend  = scores[scores.length - 1] - scores[0];
    const trendStr = trend >= 0 ? `▲ +${trend}` : `▼ ${trend}`;
    const bestDate  = fmtDate(results[scores.indexOf(best)].generatedAt);
    const worstDate = fmtDate(results[scores.indexOf(worst)].generatedAt);
    const summary = `  Trend: ${trendStr} over ${results.length} audit${results.length !== 1 ? 's' : ''}   Best: ${best} (${bestDate})   Worst: ${worst} (${worstDate})`;

    return [header, divider, colHeader, divider, ...rows, divider, summary].join('\n');
  }

  renderHtml(results: AuditResult[]): string {
    if (results.length === 0) return '<!DOCTYPE html><html><body><p>No audit history found.</p></body></html>';

    const orgName = results[0].orgName;
    const orgId   = results[0].orgId;

    const labels   = JSON.stringify(results.map((r) => fmtDate(r.generatedAt)));
    const scores   = JSON.stringify(results.map((r) => r.healthScore));
    const crits    = JSON.stringify(results.map((r) => countBySeverity(r, 'CRITICAL')));
    const highs    = JSON.stringify(results.map((r) => countBySeverity(r, 'HIGH')));
    const meds     = JSON.stringify(results.map((r) => countBySeverity(r, 'MEDIUM')));
    const lows     = JSON.stringify(results.map((r) => countBySeverity(r, 'LOW')));

    const tableRows = results.map((r, i) => {
      const prev  = i > 0 ? results[i - 1] : null;
      const delta = prev ? (r.healthScore - prev.healthScore >= 0 ? `+${r.healthScore - prev.healthScore}` : `${r.healthScore - prev.healthScore}`) : '—';
      const deltaColor = prev ? (r.healthScore >= prev.healthScore ? '#22c55e' : '#dc2626') : '#8b949e';
      return `<tr>
        <td>${i + 1}</td>
        <td>${fmtDate(r.generatedAt)}</td>
        <td style="text-align:right;font-weight:700">${r.healthScore}</td>
        <td style="text-align:center">${r.grade}</td>
        <td style="text-align:right;color:#dc2626">${countBySeverity(r, 'CRITICAL')}</td>
        <td style="text-align:right;color:#ea580c">${countBySeverity(r, 'HIGH')}</td>
        <td style="text-align:right;color:#d97706">${countBySeverity(r, 'MEDIUM')}</td>
        <td style="text-align:right;color:#2563eb">${countBySeverity(r, 'LOW')}</td>
        <td style="text-align:right;color:${deltaColor};font-weight:700">${delta}</td>
      </tr>`;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SF Audit History — ${orgName}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; max-width: 1100px; margin: 2rem auto; padding: 0 1.25rem 4rem; line-height: 1.6; }
  h1 { color: #f0f6fc; font-size: 1.5rem; font-weight: 700; margin-bottom: 0.4rem; }
  h2 { color: #e6edf3; font-size: 1.1rem; font-weight: 700; margin: 2rem 0 1rem; }
  .meta { font-size: 0.8rem; color: #8b949e; margin-bottom: 2rem; }
  .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
  .chart-box { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 1.25rem; }
  canvas { max-height: 280px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  th { background: #1c2128; color: #8b949e; text-align: left; padding: 0.4rem 0.75rem; border-bottom: 1px solid #30363d; font-weight: 600; }
  td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #21262d; }
  tr:last-child td { border-bottom: none; }
  @media(max-width:640px) { .charts { grid-template-columns: 1fr; } }
</style>
</head>
<body>
  <h1>Salesforce Audit History</h1>
  <div class="meta">Org: <strong style="color:#c9d1d9">${orgName}</strong> (${orgId})</div>

  <div class="charts">
    <div class="chart-box">
      <h2>Score Trend</h2>
      <canvas id="scoreChart"></canvas>
    </div>
    <div class="chart-box">
      <h2>Findings by Severity</h2>
      <canvas id="findingsChart"></canvas>
    </div>
  </div>

  <h2>Run History</h2>
  <table>
    <thead><tr><th>#</th><th>Date</th><th style="text-align:right">Score</th><th style="text-align:center">Grade</th><th style="text-align:right">CRIT</th><th style="text-align:right">HIGH</th><th style="text-align:right">MED</th><th style="text-align:right">LOW</th><th style="text-align:right">Δ Score</th></tr></thead>
    <tbody>${tableRows}</tbody>
  </table>

<script>
const labels = ${labels};
const scores = ${scores};
const crits  = ${crits};
const highs  = ${highs};
const meds   = ${meds};
const lows   = ${lows};

const chartDefaults = { responsive: true, plugins: { legend: { labels: { color: '#8b949e' } } }, scales: { x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }, y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } } } };

new Chart(document.getElementById('scoreChart'), {
  type: 'line',
  data: { labels, datasets: [{ label: 'Health Score', data: scores, borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.1)', tension: 0.3, fill: true, pointRadius: 4 }] },
  options: { ...chartDefaults, scales: { ...chartDefaults.scales, y: { ...chartDefaults.scales.y, min: 0, max: 100 } } },
});

new Chart(document.getElementById('findingsChart'), {
  type: 'bar',
  data: {
    labels,
    datasets: [
      { label: 'CRITICAL', data: crits, backgroundColor: '#dc2626' },
      { label: 'HIGH',     data: highs, backgroundColor: '#ea580c' },
      { label: 'MEDIUM',   data: meds,  backgroundColor: '#d97706' },
      { label: 'LOW',      data: lows,  backgroundColor: '#2563eb' },
    ],
  },
  options: { ...chartDefaults, scales: { ...chartDefaults.scales, x: { ...chartDefaults.scales.x, stacked: true }, y: { ...chartDefaults.scales.y, stacked: true } } },
});
</script>
</body>
</html>`;
  }
}
