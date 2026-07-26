import type { AuditResult } from '../findings/AuditResult.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { AuditRenderer } from './AuditRenderer.js';
import { esc } from './html-utils.js';

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

const PASS_COLOR = '#22c55e';
const PASS_BG    = 'rgba(34,197,94,0.10)';

const GRADE_COLOR: Record<string, string> = {
  A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444',
};

// ── Dashboard helpers ────────────────────────────────────────────────────────

function statusColor(value: number, warnThreshold: number, dangerThreshold: number): string {
  if (value <= warnThreshold) return '#22c55e';
  if (value <= dangerThreshold) return '#d97706';
  return '#dc2626';
}

function progressBar(value: number, max: number, color: string): string {
  if (max === 0) return '';
  const pct = Math.min(100, Math.round((value / max) * 100));
  return `<div class="prog-bar"><div class="prog-fill" style="width:${pct}%;background:${color}"></div></div>`;
}

function metricRow(label: string, value: string | number, color?: string, bar?: string): string {
  const val = color
    ? `<span style="color:${color};font-weight:700">${esc(String(value))}</span>`
    : `<span class="metric-value">${esc(String(value))}</span>`;
  return `<div class="metric-row"><span class="metric-label">${esc(label)}</span><div class="metric-right">${val}${bar ?? ''}</div></div>`;
}

function inventoryCard(title: string, rows: string[]): string {
  return `<div class="inv-card"><div class="inv-card-title">${esc(title)}</div>${rows.join('')}</div>`;
}

function buildScoreRing(score: number, grade: string, color: string): string {
  return `
    <div class="score-ring" style="background:conic-gradient(from -90deg, ${color} ${score}%, #2d3748 ${score}%)" aria-label="Health score ${score} out of 100, grade ${grade}">
      <div class="score-inner">
        <div class="score-num" style="color:${color}">${score}<span>/100</span></div>
        <div class="score-grade" style="background:${color}">${esc(grade)}</div>
      </div>
    </div>`;
}

function buildDonutSvg(counts: Record<string, number>): string {
  const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
  const total = levels.reduce((s, l) => s + (counts[l] ?? 0), 0);
  const cx = 60, cy = 60, R = 44;
  const CIRC = 2 * Math.PI * R;

  if (total === 0) {
    return `<svg width="120" height="120" viewBox="0 0 120 120" aria-hidden="true">
      <circle cx="${cx}" cy="${cy}" r="${R}" fill="none" stroke="#21262d" stroke-width="14" />
      <text x="${cx}" y="${cy + 5}" text-anchor="middle" fill="#22c55e" font-size="12" font-family="system-ui,sans-serif">Clean</text>
    </svg>`;
  }

  let offset = CIRC / 4; // Start from 12 o'clock
  const arcs = levels.map(l => {
    const count = counts[l] ?? 0;
    if (count === 0) return '';
    const dash = (count / total) * CIRC;
    const arc = `<circle cx="${cx}" cy="${cy}" r="${R}" fill="none" stroke="${RISK_COLORS[l]}" stroke-width="14" stroke-dasharray="${dash.toFixed(2)} ${CIRC.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}" />`;
    offset -= dash;
    return arc;
  });

  return `<svg width="120" height="120" viewBox="0 0 120 120" aria-hidden="true">
    <circle cx="${cx}" cy="${cy}" r="${R}" fill="none" stroke="#21262d" stroke-width="14" />
    ${arcs.join('')}
    <text x="${cx}" y="${cy - 5}" text-anchor="middle" fill="#f0f6fc" font-size="20" font-weight="700" font-family="system-ui,sans-serif">${total}</text>
    <text x="${cx}" y="${cy + 14}" text-anchor="middle" fill="#8b949e" font-size="10" font-family="system-ui,sans-serif">findings</text>
  </svg>`;
}

function buildDashboard(result: AuditResult, counts: Record<string, number>): string {
  const m: OrgMetrics = result.metrics;
  const gradeColor = GRADE_COLOR[result.grade] ?? '#64748b';

  const gauge = buildScoreRing(result.healthScore, result.grade, gradeColor);
  const donut = buildDonutSvg(counts);

  const kpiCards = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(l =>
    `<div class="kpi-card" style="border-top:3px solid ${RISK_COLORS[l]}">
      <div class="kpi-value" style="color:${RISK_COLORS[l]}">${counts[l] ?? 0}</div>
      <div class="kpi-label">${l}</div>
    </div>`,
  ).join('');

  // Users & Access
  const modifyColor  = statusColor(m.modifyAllDataUsersCount, 2, 5);
  const viewColor    = statusColor(m.viewAllDataUsersCount, 5, 15);
  const inactiveColor = statusColor(m.inactiveUsers90d, 0, 5);
  const usersCard = inventoryCard('Users & Access', [
    metricRow('Active Users', m.totalActiveUsers),
    metricRow('Modify All Data', m.modifyAllDataUsersCount, modifyColor,
      m.totalActiveUsers > 0 ? progressBar(m.modifyAllDataUsersCount, m.totalActiveUsers, modifyColor) : ''),
    metricRow('View All Data', m.viewAllDataUsersCount, viewColor,
      m.totalActiveUsers > 0 ? progressBar(m.viewAllDataUsersCount, m.totalActiveUsers, viewColor) : ''),
    metricRow('Inactive 90d', m.inactiveUsers90d, inactiveColor),
    metricRow('Profiles', m.profileCount),
    metricRow('Permission Sets', m.permissionSetCount),
  ]);

  // Code Quality
  const covColor = m.codeCoveragePercent >= 75 ? '#22c55e' : m.codeCoveragePercent >= 50 ? '#d97706' : '#dc2626';
  const codeCard = inventoryCard('Code Quality', [
    metricRow('Apex Classes', m.apexClassCount),
    metricRow('Apex Triggers', m.apexTriggerCount),
    metricRow('Code Coverage', `${m.codeCoveragePercent}%`, covColor,
      progressBar(m.codeCoveragePercent, 100, covColor)),
  ]);

  // Integrations
  const insecureColor    = m.insecureRemoteSitesCount > 0 ? '#dc2626' : '#22c55e';
  const unusedCredColor  = statusColor(m.unusedNamedCredentialsCount, 0, 2);
  const integrationsCard = inventoryCard('Integrations', [
    metricRow('Connected Apps', m.connectedAppsCount),
    metricRow('Remote Sites', m.remoteSitesCount),
    metricRow('↳ Insecure', m.insecureRemoteSitesCount, insecureColor,
      m.remoteSitesCount > 0 ? progressBar(m.insecureRemoteSitesCount, m.remoteSitesCount, insecureColor) : ''),
    metricRow('Named Credentials', m.namedCredentialsCount),
    metricRow('↳ Unused', m.unusedNamedCredentialsCount, m.unusedNamedCredentialsCount > 0 ? '#d97706' : '#22c55e',
      m.namedCredentialsCount > 0 ? progressBar(m.unusedNamedCredentialsCount, m.namedCredentialsCount, unusedCredColor) : ''),
  ]);

  // Governance & Events
  const failedColor    = statusColor(m.failedLogins30d, 10, 100);
  const healthChkColor = m.healthCheckScore >= 75 ? '#22c55e' : m.healthCheckScore >= 50 ? '#d97706' : '#dc2626';
  const governanceCard = inventoryCard('Governance & Events', [
    metricRow('Failed Logins (30d)', m.failedLogins30d, failedColor),
    metricRow('SF Health Check', `${m.healthCheckScore}%`, healthChkColor,
      progressBar(m.healthCheckScore, 100, healthChkColor)),
  ]);

  return `
  <div class="dashboard">
    <div class="dash-top">
      <div class="dash-score-panel">
        <div class="gauge-wrap">
          ${gauge}
        </div>
      </div>
      <div class="dash-risk-panel">
        <div class="donut-wrap">
          ${donut}
          <div class="donut-legend">
            ${(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(l =>
              `<div class="legend-row">
                <span class="legend-dot" style="background:${RISK_COLORS[l]}"></span>
                <span>${l}</span>
                <span class="legend-count">${counts[l] ?? 0}</span>
              </div>`,
            ).join('')}
          </div>
        </div>
      </div>
    </div>
    <div class="kpi-strip">${kpiCards}</div>
    <div class="inv-grid">
      ${usersCard}
      ${codeCard}
      ${integrationsCard}
      ${governanceCard}
    </div>
  </div>`;
}

// ── Main renderer ────────────────────────────────────────────────────────────

export class HtmlRenderer implements AuditRenderer {
  readonly format = 'html';
  readonly fileExtension = '.html';

  private renderAttackPaths(result: AuditResult): string {
    if (!result.attackChains || result.attackChains.length === 0) return '';
    const escStr = (s: string): string =>
      s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const cards = result.attackChains
      .map((c) => {
        const conf = c.confidence === 'named' ? '' : ' (potential)';
        const steps = c.steps
          .map((s, i) => `<li><strong>${escStr(s.title ?? s.findingId)}</strong> (${escStr(s.severity ?? '—')}): grants <code>${escStr(s.capability)}</code></li>`)
          .join('');
        return `<div class="attack-chain severity-${c.severity.toLowerCase()}">
  <h3>[${escStr(c.severity)}] ${escStr(c.title)}${conf}</h3>
  <p>${escStr(c.narrative)}</p>
  <ol>${steps}</ol>
  <p class="remediation"><strong>Remediation:</strong> ${escStr(c.remediation)}</p>
</div>`;
      })
      .join('\n');
    return `<section class="attack-paths">
  <h2>Attack Paths (${result.attackChains.length})</h2>
  <p class="subtitle">Combinations of findings that together enable an exploit more severe than any single finding.</p>
  ${cards}
</section>`;
  }

  render(result: AuditResult): string {
    const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
    const counts = Object.fromEntries(
      levels.map((l) => [l, result.findings.filter((f) => f.riskLevel === l).length]),
    ) as Record<string, number>;

    const filterButtons = [
      `<button class="filter-btn active" data-filter="all">All (${result.findings.length})</button>`,
      ...levels.map(
        (l) => `<button class="filter-btn" data-filter="${l}" style="--accent:${RISK_COLORS[l]}">${l} (${counts[l]})</button>`,
      ),
    ].join('\n        ');

    const attackPathsHtml = this.renderAttackPaths(result);

    const findingsHtml = result.findings.length === 0
      ? '<p class="no-findings">No findings.</p>'
      : result.findings.map((f) => {
        const isInconclusive = !!f.inconclusive;
        const cardAccent = isInconclusive ? '#8b949e' : (f.passed ? PASS_COLOR : (RISK_COLORS[f.riskLevel] ?? '#64748b'));
        const cardBg     = isInconclusive ? 'rgba(139,148,158,0.06)' : (f.passed ? PASS_BG : (RISK_BG[f.riskLevel] ?? 'rgba(100,116,139,0.12)'));
        const badgeHtml  = isInconclusive
          ? `<span class="inconclusive-badge">? INCONCLUSIVE</span>`
          : f.passed
            ? `<span class="risk-badge" style="background:${PASS_COLOR}">✓ PASS</span>`
            : `<span class="risk-badge" style="background:${RISK_COLORS[f.riskLevel] ?? '#64748b'}">${esc(f.riskLevel)}</span>`;
        const tagsHtml = f.complianceTags?.length
          ? `<div class="compliance-tags">${f.complianceTags.map((t) => `<span class="compliance-tag">${esc(t)}</span>`).join('')}</div>`
          : '';
        return `
      <details class="finding-card${isInconclusive ? ' is-inconclusive' : ''}" data-risk="${esc(f.riskLevel)}" style="--card-accent:${cardAccent};--card-bg:${cardBg}">
        <summary class="finding-summary">
          ${badgeHtml}
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
          ${f.affectedItems?.length ? (() => {
            const hasUrls  = f.affectedItems!.some((i) => i.url);
            const hasNotes = f.affectedItems!.some((i) => i.note);
            const headers  = ['Item', ...(hasUrls ? ['Setup Link'] : []), ...(hasNotes ? ['Notes'] : [])];
            const thead    = `<tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr>`;
            const tbody    = f.affectedItems!.map((item) => {
              const cells = [
                `<td>${esc(item.label)}</td>`,
                ...(hasUrls  ? [`<td>${item.url ? `<a href="${esc(item.url)}" target="_blank" rel="noopener">Open ↗</a>` : '—'}</td>`] : []),
                ...(hasNotes ? [`<td>${esc(item.note ?? '')}</td>`] : []),
              ];
              return `<tr>${cells.join('')}</tr>`;
            }).join('');
            return `<div class="affected-items"><strong>Affected items (${f.affectedItems!.length})</strong><table class="affected-table"><thead>${thead}</thead><tbody>${tbody}</tbody></table></div>`;
          })() : ''}
          ${tagsHtml}
        </div>
      </details>`;
      }).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SF Security Audit: ${esc(result.orgName)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;700&family=Fira+Sans:wght@300;400;500;600;700&display=swap">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Fira Sans', system-ui, -apple-system, 'Segoe UI', sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    max-width: 1100px;
    margin: 2rem auto;
    padding: 0 1.25rem 4rem;
    line-height: 1.6;
  }

  /* ── Header ── */
  .header { margin-bottom: 1.5rem; }
  .header h1 { color: #f0f6fc; font-size: 1.5rem; font-weight: 700; margin-bottom: 0.4rem; }
  .meta { font-size: 0.8rem; color: #8b949e; display: flex; flex-wrap: wrap; gap: 0.4rem 1.25rem; }

  /* ── Dashboard ── */
  .dashboard { margin-bottom: 2rem; }

  .dash-top {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }
  .dash-score-panel, .dash-risk-panel {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 1.5rem;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  /* Score ring */
  .gauge-wrap { display: flex; align-items: center; justify-content: center; }
  .score-ring {
    width: 152px;
    height: 152px;
    border-radius: 50%;
    padding: 11px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .score-inner {
    width: 100%;
    height: 100%;
    border-radius: 50%;
    background: #161b22;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 0.4rem;
  }
  .score-num {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
    font-family: 'Fira Code', monospace;
  }
  .score-num span { font-size: 0.75rem; color: #8b949e; font-weight: 400; }
  .score-grade {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.75rem;
    height: 1.75rem;
    border-radius: 50%;
    font-size: 0.9rem;
    font-weight: 800;
    color: #fff;
  }

  /* Donut */
  .donut-wrap { display: flex; align-items: center; gap: 1.5rem; }
  .donut-legend { display: flex; flex-direction: column; gap: 0.45rem; }
  .legend-row { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; color: #c9d1d9; }
  .legend-dot { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
  .legend-count { margin-left: auto; font-weight: 700; color: #f0f6fc; padding-left: 1rem; }

  /* KPI strip */
  .kpi-strip {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }
  .kpi-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 1rem 1.25rem;
  }
  .kpi-value { font-size: 2rem; font-weight: 800; line-height: 1; margin-bottom: 0.25rem; }
  .kpi-label { font-size: 0.7rem; font-weight: 700; color: #8b949e; letter-spacing: 0.06em; }

  /* Inventory grid */
  .inv-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 0.75rem;
  }
  .inv-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 1rem 1.25rem;
  }
  .inv-card-title {
    font-size: 0.7rem;
    font-weight: 700;
    color: #8b949e;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    margin-bottom: 0.6rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid #21262d;
  }
  .metric-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.28rem 0;
  }
  .metric-label { flex: 1; font-size: 0.82rem; color: #c9d1d9; }
  .metric-right { display: flex; flex-direction: column; align-items: flex-end; gap: 0.2rem; min-width: 72px; }
  .metric-value { font-size: 0.9rem; font-weight: 700; color: #f0f6fc; }
  .prog-bar { width: 72px; height: 4px; background: #21262d; border-radius: 2px; overflow: hidden; }
  .prog-fill { height: 100%; border-radius: 2px; }

  /* ── Filters ── */
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

  /* ── Finding cards ── */
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
  .finding-body { padding: 0 1rem 1rem; border-top: 1px solid #30363d; }
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
  .affected-items { margin-top: 0.75rem; font-size: 0.82rem; }
  .affected-items strong { color: #c9d1d9; display: block; margin-bottom: 0.5rem; }
  .affected-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
    font-family: 'Menlo', 'Consolas', monospace;
  }
  .affected-table th {
    background: #1c2128;
    color: #8b949e;
    text-align: left;
    padding: 0.4rem 0.6rem;
    border-bottom: 1px solid #30363d;
    font-weight: 600;
    white-space: nowrap;
  }
  .affected-table td {
    padding: 0.35rem 0.6rem;
    border-bottom: 1px solid #21262d;
    color: #c9d1d9;
    vertical-align: top;
    word-break: break-word;
  }
  .affected-table tr:last-child td { border-bottom: none; }
  .affected-table a { color: #58a6ff; text-decoration: none; white-space: nowrap; }
  .affected-table a:hover { text-decoration: underline; }

  .no-findings { color: #8b949e; text-align: center; padding: 3rem 0; }

  /* ── Compliance tags ── */
  .compliance-tags { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.5rem; }
  .compliance-tag {
    font-size: 0.65rem;
    font-weight: 700;
    padding: 0.1rem 0.45rem;
    border-radius: 3px;
    background: rgba(88,166,255,0.12);
    border: 1px solid rgba(88,166,255,0.25);
    color: #58a6ff;
    letter-spacing: 0.03em;
    white-space: nowrap;
  }
  /* ── Inconclusive findings ── */
  .finding-card.is-inconclusive {
    border-left-color: #8b949e !important;
    opacity: 0.8;
  }
  .finding-card.is-inconclusive .finding-summary { background: rgba(139,148,158,0.05); }
  .inconclusive-badge {
    flex-shrink: 0;
    padding: 0.15rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 800;
    color: #8b949e;
    border: 1px dashed #8b949e;
    letter-spacing: 0.04em;
  }
  /* ── Offline footer ── */
  .offline-footer {
    margin-top: 3rem;
    padding: 0.75rem 1rem;
    border-radius: 8px;
    background: rgba(34,197,94,0.05);
    border: 1px solid rgba(34,197,94,0.15);
    font-size: 0.78rem;
    color: #8b949e;
    text-align: center;
  }
  .offline-footer strong { color: #3fb950; }

  /* ── Responsive ── */
  @media (max-width: 680px) {
    .dash-top { grid-template-columns: 1fr; }
    .kpi-strip { grid-template-columns: repeat(2, 1fr); }
    .inv-grid { grid-template-columns: 1fr; }
  }
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

  ${buildDashboard(result, counts)}

  ${attackPathsHtml}

  <div class="filters">
    ${filterButtons}
  </div>

  <div id="findings-list">
    ${findingsHtml}
  </div>

<script>
  const buttons = document.querySelectorAll('.filter-btn');
  const cards   = document.querySelectorAll('.finding-card');

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
  <div class="offline-footer">
    <strong>Offline-first audit:</strong> all analysis performed locally; no data is transmitted outside your Salesforce org. Generated by <a href="https://cloudcounsel.co.nz" style="color:inherit">CloudCounsel SF Audit</a>.
  </div>
</body>
</html>`;
  }
}
