import type { AuditResult } from '../findings/AuditResult.js';
import type { AuditRenderer } from './AuditRenderer.js';

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH:     '#ea580c',
  MEDIUM:   '#d97706',
  LOW:      '#2563eb',
  INFO:     '#64748b',
};

const RISK_BG: Record<string, string> = {
  CRITICAL: 'rgba(220,38,38,0.12)',
  HIGH:     'rgba(234,88,12,0.12)',
  MEDIUM:   'rgba(217,119,6,0.12)',
  LOW:      'rgba(37,99,235,0.12)',
  INFO:     'rgba(100,116,139,0.12)',
};

function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export class HtmlRenderer implements AuditRenderer {
  readonly format = 'html';
  readonly fileExtension = '.html';

  render(result: AuditResult): string {
    const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
    const counts = Object.fromEntries(
      levels.map((l) => [l, result.findings.filter((f) => f.riskLevel === l).length]),
    ) as Record<string, number>;

    const gradeColor: Record<string, string> = {
      A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444',
    };

    const summaryBadges = levels
      .map((l) => `<span class="badge" style="background:${RISK_COLORS[l]}">${counts[l]} ${l}</span>`)
      .join('');

    const filterButtons = [
      `<button class="filter-btn active" data-filter="all">All (${result.findings.length})</button>`,
      ...levels.map(
        (l) => `<button class="filter-btn" data-filter="${l}" style="--accent:${RISK_COLORS[l]}">${l} (${counts[l]})</button>`,
      ),
    ].join('\n        ');

    const findingsHtml = result.findings.length === 0
      ? '<p style="color:#64748b;text-align:center;padding:2rem 0">No findings.</p>'
      : result.findings.map((f) => `
      <details class="finding-card" data-risk="${esc(f.riskLevel)}" style="--card-accent:${RISK_COLORS[f.riskLevel]};--card-bg:${RISK_BG[f.riskLevel] ?? 'rgba(100,116,139,0.12)'}">
        <summary class="finding-summary">
          <span class="risk-badge" style="background:${RISK_COLORS[f.riskLevel]}">${esc(f.riskLevel)}</span>
          <span class="finding-title">${esc(f.title)}</span>
          <span class="finding-category">${esc(f.category)}</span>
          <span class="chevron">›</span>
        </summary>
        <div class="finding-body">
          <p class="finding-detail">${esc(f.detail)}</p>
          <div class="remediation-box">
            <strong>Remediation</strong>
            <p>${esc(f.remediation)}</p>
          </div>
          ${f.affectedItems?.length
            ? `<div class="affected-items"><strong>Affected items (${f.affectedItems.length})</strong><ul>${f.affectedItems.map((i) => `<li>${esc(i)}</li>`).join('')}</ul></div>`
            : ''}
        </div>
      </details>`).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SF Security Audit — ${esc(result.orgName)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    max-width: 1000px;
    margin: 2rem auto;
    padding: 0 1.25rem 4rem;
    line-height: 1.6;
  }
  /* Header */
  .header { margin-bottom: 2rem; }
  .header h1 { color: #f0f6fc; font-size: 1.5rem; font-weight: 700; margin-bottom: 0.4rem; }
  .meta { font-size: 0.8rem; color: #8b949e; display: flex; flex-wrap: wrap; gap: 0.5rem 1.25rem; }
  /* Score card */
  .scorecard {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 1.5rem 2rem;
    display: flex;
    align-items: center;
    gap: 2rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
  }
  .score-number {
    font-size: 3.5rem;
    font-weight: 800;
    color: #f0f6fc;
    line-height: 1;
  }
  .score-number span { font-size: 1.25rem; color: #8b949e; font-weight: 400; }
  .grade-badge {
    width: 3rem; height: 3rem;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.5rem; font-weight: 800;
    color: #fff;
    background: ${gradeColor[result.grade] ?? '#64748b'};
  }
  .summary-badges { display: flex; flex-wrap: wrap; gap: 0.5rem; }
  .badge {
    padding: 0.2rem 0.65rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    color: #fff;
  }
  /* Filters */
  .filters { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1.25rem; }
  .filter-btn {
    padding: 0.35rem 0.9rem;
    border-radius: 20px;
    border: 1px solid #30363d;
    background: #161b22;
    color: #8b949e;
    cursor: pointer;
    font-size: 0.8rem;
    font-weight: 600;
    transition: all 0.15s;
  }
  .filter-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .filter-btn.active {
    background: var(--accent, #238636);
    border-color: var(--accent, #238636);
    color: #fff;
  }
  /* Finding cards */
  .finding-card {
    background: var(--card-bg);
    border: 1px solid #30363d;
    border-left: 3px solid var(--card-accent);
    border-radius: 8px;
    margin-bottom: 0.6rem;
    overflow: hidden;
  }
  .finding-card[open] { border-color: var(--card-accent); }
  .finding-summary {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem 1rem;
    cursor: pointer;
    list-style: none;
    user-select: none;
  }
  .finding-summary::-webkit-details-marker { display: none; }
  .finding-summary:hover { background: rgba(255,255,255,0.03); }
  .risk-badge {
    flex-shrink: 0;
    padding: 0.15rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 800;
    color: #fff;
    letter-spacing: 0.04em;
  }
  .finding-title { flex: 1; font-weight: 600; color: #e6edf3; font-size: 0.9rem; }
  .finding-category { font-size: 0.75rem; color: #8b949e; white-space: nowrap; }
  .chevron { color: #8b949e; font-size: 1.2rem; transition: transform 0.2s; }
  .finding-card[open] .chevron { transform: rotate(90deg); }
  .finding-body { padding: 0 1rem 1rem 1rem; border-top: 1px solid #30363d; }
  .finding-detail { color: #c9d1d9; font-size: 0.875rem; padding: 0.75rem 0 0.5rem; }
  .remediation-box {
    background: rgba(35,134,54,0.1);
    border: 1px solid rgba(35,134,54,0.3);
    border-radius: 6px;
    padding: 0.75rem;
    margin-top: 0.5rem;
    font-size: 0.85rem;
  }
  .remediation-box strong { color: #3fb950; display: block; margin-bottom: 0.25rem; }
  .affected-items {
    margin-top: 0.75rem;
    font-size: 0.82rem;
    color: #8b949e;
  }
  .affected-items strong { color: #c9d1d9; display: block; margin-bottom: 0.35rem; }
  .affected-items ul { padding-left: 1.25rem; }
  .affected-items li { margin-bottom: 0.2rem; font-family: 'Menlo', 'Consolas', monospace; }
  /* Empty state */
  .no-findings { color: #8b949e; text-align: center; padding: 3rem 0; }
</style>
</head>
<body>
  <div class="header">
    <h1>Salesforce Security Audit</h1>
    <div class="meta">
      <span>Org: <strong style="color:#c9d1d9">${esc(result.orgName)}</strong></span>
      <span>ID: ${esc(result.orgId)}</span>
      <span>Instance: ${esc(result.instance)}</span>
      <span>Type: ${esc(result.orgType)}${result.isSandbox ? ' (Sandbox)' : ''}</span>
      <span>Generated: ${result.generatedAt.toISOString()}</span>
    </div>
  </div>

  <div class="scorecard">
    <div class="score-number">${result.healthScore}<span>/100</span></div>
    <div class="grade-badge" title="Grade">${esc(result.grade)}</div>
    <div class="summary-badges">${summaryBadges}</div>
  </div>

  <div class="filters">
    ${filterButtons}
  </div>

  <div id="findings-list">
    ${findingsHtml}
  </div>

<script>
  const buttons = document.querySelectorAll('.filter-btn');
  const cards = document.querySelectorAll('.finding-card');

  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      buttons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const filter = btn.dataset.filter;
      cards.forEach(card => {
        card.style.display = (filter === 'all' || card.dataset.risk === filter) ? '' : 'none';
      });
    });
  });
</script>
</body>
</html>`;
  }
}
