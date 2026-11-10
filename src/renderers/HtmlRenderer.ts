import type { AuditResult } from '../findings/AuditResult.js';
import type { OrgMetrics } from '@cclabsnz/sf-core';
import type { AuditRenderer } from './AuditRenderer.js';
import { esc, DEFAULT_BRANDING, INTERACTIVE_CSP_META } from '@cclabsnz/sf-core';
import { deckFontFaceCss } from './deckFonts.js';
import { renderAttackChainDagSvg } from './AttackChainDagRenderer.js';
import { coverageSummary, coverageAdvice } from '../findings/coverage.js';
import { techniqueLabel } from '../threats/attack.js';
import { unknownMetrics } from '../findings/unknownMetrics.js';

// The report is printed on white, in the executive report's palette. Every severity colour holds
// at least 4.5:1 on white and under white text, so badges and counts stay legible when printed.
const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#b91c1c',
  HIGH:     '#c2410c',
  MEDIUM:   '#a16207',
  LOW:      '#1d4ed8',
  INFO:     '#475569',
};

const GOOD = '#15803d';
const WARN = '#a16207';
const BAD  = '#b91c1c';
const PASS_COLOR = GOOD;
/** Severities drawn as solid tags; the rest are outlined, as in the executive report. */
const SOLID = new Set(['CRITICAL', 'HIGH']);

const GRADE_COLOR: Record<string, string> = {
  A: GOOD, B: '#4d7c0f', C: WARN, D: '#c2410c', F: BAD,
};

// ── Dashboard helpers ────────────────────────────────────────────────────────

/** The grey used for inconclusive findings and counts the audit could not read. */
const UNKNOWN_COLOR = DEFAULT_BRANDING.muted;

function statusColor(value: number, warnThreshold: number, dangerThreshold: number): string {
  if (value <= warnThreshold) return GOOD;
  if (value <= dangerThreshold) return WARN;
  return BAD;
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
    <div class="score-ring" style="background:conic-gradient(from -90deg, ${color} ${score}%, var(--hair) ${score}%)" aria-label="Health score ${score} out of 100, grade ${grade}">
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
      <circle cx="${cx}" cy="${cy}" r="${R}" fill="none" stroke="#e3e6e9" stroke-width="14" />
      <text x="${cx}" y="${cy + 5}" text-anchor="middle" fill="${GOOD}" font-size="12" font-family="'Source Sans 3',system-ui,sans-serif">Clean</text>
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
    <circle cx="${cx}" cy="${cy}" r="${R}" fill="none" stroke="#e3e6e9" stroke-width="14" />
    ${arcs.join('')}
    <text x="${cx}" y="${cy - 3}" text-anchor="middle" fill="${DEFAULT_BRANDING.ink}" font-size="22" font-weight="600" font-family="'Source Serif 4',Georgia,serif">${total}</text>
    <text x="${cx}" y="${cy + 15}" text-anchor="middle" fill="${DEFAULT_BRANDING.muted}" font-size="10" font-family="'Source Sans 3',system-ui,sans-serif">open findings</text>
  </svg>`;
}

/** Open findings per severity: what the score and the executive report count (RULE-079). */
function openCounts(result: AuditResult): Record<string, number> {
  const open = result.findings.filter((f) => !f.passed && !f.inconclusive && !f.notAssessed && !f.waived);
  return Object.fromEntries(
    (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((l) => [l, open.filter((f) => f.riskLevel === l).length]),
  );
}

function buildDashboard(result: AuditResult, counts: Record<string, number>): string {
  const m: OrgMetrics = result.metrics;
  const gradeColor = GRADE_COLOR[result.grade] ?? UNKNOWN_COLOR;

  const gauge = buildScoreRing(result.healthScore, result.grade, gradeColor);
  const donut = buildDonutSvg(counts);

  const kpiCards = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(l =>
    `<div class="kpi-card" style="--sev:${RISK_COLORS[l]}">
      <div class="kpi-value" style="color:${RISK_COLORS[l]}">${counts[l] ?? 0}</div>
      <div class="kpi-label">${l}</div>
    </div>`,
  ).join('');

  // Users & Access. A count the audit could not read is shown as unknown, never as a green 0.
  const unknown = unknownMetrics(result.findings);
  const countRow = (label: string, key: 'modifyAllDataUsersCount' | 'viewAllDataUsersCount', warn: number, danger: number) => {
    if (unknown.has(key)) return metricRow(label, 'unknown', UNKNOWN_COLOR);
    const color = statusColor(m[key], warn, danger);
    return metricRow(label, m[key], color, m.totalActiveUsers > 0 ? progressBar(m[key], m.totalActiveUsers, color) : '');
  };
  const inactiveColor = statusColor(m.inactiveUsers90d, 0, 5);
  const usersCard = inventoryCard('Users & Access', [
    metricRow('Active Users', m.totalActiveUsers),
    countRow('Modify All Data', 'modifyAllDataUsersCount', 2, 5),
    countRow('View All Data', 'viewAllDataUsersCount', 5, 15),
    metricRow('Inactive 90d', m.inactiveUsers90d, inactiveColor),
    metricRow('Profiles', m.profileCount),
    metricRow('Permission Sets', m.permissionSetCount),
  ]);

  // Code Quality
  const covColor = m.codeCoveragePercent >= 75 ? GOOD : m.codeCoveragePercent >= 50 ? WARN : BAD;
  const codeCard = inventoryCard('Code Quality', [
    metricRow('Apex Classes', m.apexClassCount),
    metricRow('Apex Triggers', m.apexTriggerCount),
    metricRow('Code Coverage', `${m.codeCoveragePercent}%`, covColor,
      progressBar(m.codeCoveragePercent, 100, covColor)),
  ]);

  // Integrations
  const insecureColor    = m.insecureRemoteSitesCount > 0 ? BAD : GOOD;
  const unusedCredColor  = statusColor(m.unusedNamedCredentialsCount, 0, 2);
  const integrationsCard = inventoryCard('Integrations', [
    metricRow('Connected Apps', m.connectedAppsCount),
    metricRow('Remote Sites', m.remoteSitesCount),
    metricRow('↳ Insecure', m.insecureRemoteSitesCount, insecureColor,
      m.remoteSitesCount > 0 ? progressBar(m.insecureRemoteSitesCount, m.remoteSitesCount, insecureColor) : ''),
    metricRow('Named Credentials', m.namedCredentialsCount),
    metricRow('↳ Unused', m.unusedNamedCredentialsCount, m.unusedNamedCredentialsCount > 0 ? WARN : GOOD,
      m.namedCredentialsCount > 0 ? progressBar(m.unusedNamedCredentialsCount, m.namedCredentialsCount, unusedCredColor) : ''),
  ]);

  // Governance & Events
  const failedColor    = statusColor(m.failedLogins30d, 10, 100);
  const healthChkColor = m.healthCheckScore >= 75 ? GOOD : m.healthCheckScore >= 50 ? WARN : BAD;
  const governanceCard = inventoryCard('Governance & Events', [
    metricRow('Failed Logins (30d)', m.failedLogins30d, failedColor),
    metricRow('SF Health Check', `${m.healthCheckScore}%`, healthChkColor,
      progressBar(m.healthCheckScore, 100, healthChkColor)),
  ]);

  const waivedBanner = result.waivedFindings?.length
    ? `<div class="waived-banner"><strong>Accepted risks:</strong> ${result.waivedFindings.length} finding(s) waived under an approved waiver and excluded from the score.</div>`
    : '';

  const gradeReasonLine = result.gradeReason
    ? `<div class="grade-reason">Why ${esc(result.grade)}: ${esc(result.gradeReason.replace(/^[A-F]: /, ''))}</div>`
    : '';
  const cov = result.coverage;
  const coverageLine = cov
    ? `<div class="coverage${cov.gradeCapped ? ' is-capped' : ''}" >${esc(coverageSummary(cov))}${cov.notAssessed.length ? `<br>Not assessed: ${cov.notAssessed.map((id) => `<code>${esc(id)}</code>`).join(', ')}<br>${esc(coverageAdvice(cov))}` : ''}</div>`
    : '';

  return `
  ${waivedBanner}
  <div class="dashboard">
    <div class="dash-top">
      <div class="dash-score-panel">
        <div class="gauge-wrap">
          ${gauge}
        </div>
        ${gradeReasonLine}
        ${coverageLine}
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
    const cards = result.attackChains
      .map((c) => {
        const conf = c.confidence === 'named' ? '' : ' (potential)';
        const dagSvg = renderAttackChainDagSvg(c, { theme: 'light' });
        const steps = c.steps
          .map((s) => {
            const technique = s.techniques?.length ? ` → ${esc(s.techniques.map(techniqueLabel).join(' · '))}` : '';
            const grants = s.capabilityInferred ? '' : `: grants <code>${esc(s.capability)}</code>${technique}`;
            const cut = s.breaksChain ? ' <strong>✂ break point</strong>' : '';
            return `<li><strong>${esc(s.title ?? s.findingId)}</strong> (${esc(s.severity ?? '—')})${grants}${cut}</li>`;
          })
          .join('');
        return `<div class="attack-chain severity-${c.severity.toLowerCase()}">
  <h3><span class="risk-badge solid" style="--sev:${RISK_COLORS[c.severity] ?? UNKNOWN_COLOR}">${esc(c.severity)}</span> ${esc(c.title)}${conf}</h3>
  ${c.abuseCase ? `<p><strong>Abuse case:</strong> ${esc(c.abuseCase.actor)} wants to ${esc(c.abuseCase.goal)}.</p>` : ''}
  <p>${esc(c.narrative)}</p>
  ${dagSvg}
  <ol>${steps}</ol>
  ${c.abuseCase
    ? `<p class="remediation"><strong>Breaks the chain:</strong> ${esc(c.abuseCase.breakPoint)}</p>
  <p class="remediation"><strong>Remediation:</strong> ${esc(c.remediation)}</p>`
    : `<p class="remediation"><strong>Recommended fixes:</strong> ${esc(c.remediation)}</p>`}
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
        const cardAccent = isInconclusive ? UNKNOWN_COLOR : (f.passed ? 'var(--hair)' : (RISK_COLORS[f.riskLevel] ?? UNKNOWN_COLOR));
        const badgeHtml  = isInconclusive
          ? `<span class="inconclusive-badge">? INCONCLUSIVE</span>`
          : f.passed
            ? `<span class="risk-badge" style="--sev:${PASS_COLOR}">✓ PASS</span>`
            : `<span class="risk-badge${SOLID.has(f.riskLevel) ? ' solid' : ''}" style="--sev:${RISK_COLORS[f.riskLevel] ?? UNKNOWN_COLOR}">${esc(f.riskLevel)}</span>`;
        const tagsHtml = f.complianceTags?.length
          ? `<div class="compliance-tags">${f.complianceTags.map((t) => `<span class="compliance-tag">${esc(t)}</span>`).join('')}</div>`
          : '';
        return `
      <details class="finding-card${isInconclusive ? ' is-inconclusive' : ''}" data-risk="${esc(f.riskLevel)}" style="--card-accent:${cardAccent}">
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
${INTERACTIVE_CSP_META}
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SF Security Audit: ${esc(result.orgName)}</title>
<style>
${deckFontFaceCss()}
  :root {
    --ink: ${DEFAULT_BRANDING.ink};
    --accent: ${DEFAULT_BRANDING.primary};
    --muted: ${DEFAULT_BRANDING.muted};
    --paper: #ffffff;
    --desk: #eef0f1;
    --hair: #e3e6e9;
    --body: #3a434d;
    --serif: 'Source Serif 4', Georgia, serif;
    --sans: 'Source Sans 3', system-ui, sans-serif;
    --mono: ui-monospace, Menlo, Consolas, monospace;
    --ease: cubic-bezier(0.16, 1, 0.3, 1);
    --shadow: 0 1px 2px rgba(20,30,40,0.06), 0 14px 34px -24px rgba(20,30,40,0.35);
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; background: var(--desk); }
  body {
    font-family: var(--sans);
    font-size: 15px;
    background: var(--desk);
    color: var(--ink);
    max-width: 1100px;
    margin: 0 auto;
    padding: 2.5rem 1.25rem 4rem;
    line-height: 1.5;
    font-variant-numeric: tabular-nums;
  }
  a { color: var(--accent); text-underline-offset: 2px; transition: color 150ms var(--ease); }
  a:hover { color: ${BAD}; }
  code { font-family: var(--mono); font-size: 0.86em; background: color-mix(in srgb, var(--accent) 7%, var(--paper)); padding: 0 3px; }
  strong { font-weight: 650; }

  /* ── Header ── */
  .header { margin-bottom: 1.75rem; }
  .kicker { font-size: 13px; font-weight: 650; color: var(--accent); letter-spacing: 0.01em; }
  .header h1 { font-family: var(--serif); font-size: 2.25rem; font-weight: 600; line-height: 1.12; letter-spacing: -0.012em; margin: 0.35rem 0 0.6rem; }
  .meta { font-size: 0.8rem; color: var(--muted); display: flex; flex-wrap: wrap; gap: 0.3rem 1.25rem; }
  .meta strong { color: var(--ink); }

  /* ── Panels: white paper on the grey desk, as in the executive report ── */
  .dash-score-panel, .dash-risk-panel, .kpi-card, .inv-card, .attack-chain {
    background: var(--paper);
    box-shadow: var(--shadow);
  }

  /* ── Dashboard ── */
  .dashboard { margin-bottom: 2.75rem; }
  .dash-top { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
  .dash-score-panel, .dash-risk-panel { padding: 1.75rem; display: flex; align-items: center; justify-content: center; }
  /* The grade reason and coverage note sit under the gauge, not squeezed beside it. */
  .dash-score-panel { flex-direction: column; text-align: center; }
  .grade-reason { margin-top: 0.9rem; font-size: 0.88rem; font-weight: 600; color: var(--ink); }
  .coverage {
    align-self: stretch; text-align: left; margin-top: 1rem; padding-top: 0.75rem; border-top: 1px solid var(--hair);
    font-size: 0.74rem; line-height: 1.45; color: var(--muted); overflow-wrap: anywhere;
  }
  .coverage code { font-size: 0.95em; }
  .coverage.is-capped { color: ${WARN}; }

  /* Score ring */
  .gauge-wrap { display: flex; align-items: center; justify-content: center; }
  .score-ring { width: 152px; height: 152px; border-radius: 50%; padding: 10px; display: flex; align-items: center; justify-content: center; }
  .score-inner {
    width: 100%; height: 100%; border-radius: 50%; background: var(--paper);
    display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.35rem;
  }
  .score-num { font-family: var(--serif); font-size: 2.4rem; font-weight: 600; line-height: 1; }
  .score-num span { font-family: var(--sans); font-size: 0.75rem; color: var(--muted); font-weight: 400; }
  .score-grade {
    display: inline-flex; align-items: center; justify-content: center;
    width: 1.8rem; height: 1.8rem; border-radius: 6px;
    font-family: var(--serif); font-size: 1rem; font-weight: 700; color: #fff;
  }

  /* Donut */
  .donut-wrap { display: flex; align-items: center; gap: 1.75rem; }
  .donut-legend { display: flex; flex-direction: column; gap: 0.5rem; min-width: 9rem; }
  .legend-row { display: flex; align-items: center; gap: 0.55rem; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.05em; color: var(--muted); }
  .legend-dot { width: 10px; height: 10px; flex-shrink: 0; }
  .legend-count { margin-left: auto; font-size: 0.95rem; font-weight: 700; color: var(--ink); letter-spacing: 0; padding-left: 1rem; }

  /* KPI strip */
  .kpi-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1rem; }
  .kpi-card { border-top: 3px solid var(--sev); padding: 1rem 1.25rem 1.1rem; }
  .kpi-value { font-family: var(--serif); font-size: 2.4rem; font-weight: 600; line-height: 1; margin-bottom: 0.35rem; color: var(--sev); }
  .kpi-label { font-size: 0.72rem; font-weight: 700; color: var(--muted); letter-spacing: 0.06em; }

  /* Inventory grid */
  .inv-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
  .inv-card { padding: 1.1rem 1.35rem 1.2rem; }
  .inv-card-title {
    font-size: 0.72rem; font-weight: 700; color: var(--muted); letter-spacing: 0.06em; text-transform: uppercase;
    margin-bottom: 0.5rem; padding-bottom: 0.5rem; border-bottom: 1.5px solid var(--ink);
  }
  .metric-row { display: flex; align-items: center; gap: 0.5rem; padding: 0.32rem 0; border-bottom: 1px solid var(--hair); }
  .metric-row:last-child { border-bottom: 0; }
  .metric-label { flex: 1; font-size: 0.86rem; color: var(--body); }
  .metric-right { display: flex; flex-direction: column; align-items: flex-end; gap: 0.2rem; min-width: 72px; }
  .metric-value { font-size: 0.92rem; font-weight: 700; color: var(--ink); }
  .prog-bar { width: 72px; height: 4px; background: var(--hair); overflow: hidden; }
  .prog-fill { height: 100%; }

  /* ── Section headings ── */
  .attack-paths h2, .findings-h2 {
    font-family: var(--serif); font-size: 1.75rem; font-weight: 600; line-height: 1.2; letter-spacing: -0.005em;
  }
  .attack-paths h2::after, .findings-h2::after { content: ''; display: block; width: 72px; height: 2px; background: var(--accent); margin: 0.9rem 0 0; }
  .subtitle { color: var(--muted); font-size: 0.9rem; margin: 0.9rem 0 1.25rem; max-width: 70ch; }

  /* ── Attack paths ── */
  .attack-paths { margin-bottom: 2.75rem; }
  .attack-chain { border-left: 3px solid var(--chain); padding: 1.4rem 1.6rem; margin-bottom: 1rem; color: var(--body); font-size: 0.92rem; }
  .attack-chain.severity-critical { --chain: ${RISK_COLORS.CRITICAL}; }
  .attack-chain.severity-high { --chain: ${RISK_COLORS.HIGH}; }
  .attack-chain.severity-medium { --chain: ${RISK_COLORS.MEDIUM}; }
  .attack-chain.severity-low { --chain: ${RISK_COLORS.LOW}; }
  .attack-chain h3 { font-family: var(--serif); font-size: 1.2rem; font-weight: 600; color: var(--ink); line-height: 1.3; margin-bottom: 0.6rem; }
  .attack-chain p { margin-bottom: 0.6rem; max-width: 95ch; }
  .attack-chain svg { max-width: 100%; height: auto; margin: 0.5rem 0 0.75rem; }
  .attack-chain ol { padding-left: 1.3rem; margin-bottom: 0.75rem; }
  .attack-chain li { margin-bottom: 0.3rem; }
  .attack-chain .remediation { border-left: 2px solid var(--accent); padding-left: 0.85rem; }

  /* ── Findings ── */
  .findings-h2 { margin-bottom: 1.25rem; }
  .filters { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1.1rem; }
  .filter-btn {
    font-family: var(--sans);
    padding: 0.3rem 0.85rem;
    border: 1.25px solid var(--hair);
    background: var(--paper);
    color: var(--body);
    cursor: pointer;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    transition: border-color 150ms var(--ease), color 150ms var(--ease), background-color 150ms var(--ease);
  }
  .filter-btn:hover { border-color: var(--accent, var(--ink)); color: var(--ink); }
  .filter-btn:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }
  .filter-btn.active { background: var(--accent, var(--ink)); border-color: var(--accent, var(--ink)); color: #fff; }
  .filter-btn[data-filter="all"] { --accent: var(--ink); }

  .finding-card {
    background: var(--paper);
    border: 1px solid var(--hair);
    border-left: 3px solid var(--card-accent);
    margin-bottom: 0.5rem;
    overflow: hidden;
    transition: box-shadow 200ms var(--ease);
  }
  .finding-card:hover, .finding-card[open] { box-shadow: var(--shadow); }
  .finding-summary {
    display: flex; align-items: center; gap: 0.8rem; padding: 0.75rem 1rem;
    cursor: pointer; list-style: none; user-select: none;
    transition: background-color 150ms var(--ease);
  }
  .finding-summary::-webkit-details-marker { display: none; }
  .finding-summary:hover { background: #f6f7f8; }
  .finding-summary:focus-visible { outline: 2px solid var(--ink); outline-offset: -2px; }
  .risk-badge {
    display: inline-block; flex-shrink: 0; min-width: 4.9rem; text-align: center; vertical-align: 0.15em;
    padding: 0.05rem 0.45rem; font-family: var(--sans); font-size: 0.68rem; font-weight: 700; letter-spacing: 0.05em;
    color: var(--sev); border: 1.25px solid var(--sev); background: var(--paper);
  }
  .risk-badge.solid { background: var(--sev); color: #fff; }
  .attack-chain h3 .risk-badge { min-width: 0; margin-right: 0.35rem; }
  .finding-title { flex: 1; font-weight: 600; color: var(--ink); font-size: 0.93rem; }
  .finding-category { font-size: 0.76rem; color: var(--muted); white-space: nowrap; }
  .chevron { color: var(--muted); font-size: 1.2rem; transition: transform 200ms var(--ease); }
  .finding-card[open] .chevron { transform: rotate(90deg); }
  .finding-body { padding: 0 1rem 1.1rem; border-top: 1px solid var(--hair); }
  .finding-detail { color: var(--body); font-size: 0.9rem; padding: 0.8rem 0 0.5rem; max-width: 95ch; }
  .remediation-box {
    background: color-mix(in srgb, var(--accent) 6%, var(--paper));
    border-left: 2px solid var(--accent);
    padding: 0.7rem 0.9rem;
    margin-top: 0.5rem;
    font-size: 0.88rem;
    color: var(--body);
  }
  .remediation-box strong { color: var(--accent); display: block; margin-bottom: 0.2rem; font-size: 0.72rem; letter-spacing: 0.06em; text-transform: uppercase; }
  .affected-items { margin-top: 0.85rem; font-size: 0.84rem; }
  .affected-items strong { color: var(--ink); display: block; margin-bottom: 0.45rem; }
  .affected-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; font-family: var(--mono); }
  .affected-table th {
    font-family: var(--sans); color: var(--muted); text-align: left; padding: 0 0.6rem 0.4rem 0;
    border-bottom: 1.5px solid var(--ink); font-size: 0.7rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; white-space: nowrap;
  }
  .affected-table td { padding: 0.4rem 0.6rem 0.4rem 0; border-bottom: 1px solid var(--hair); color: var(--body); vertical-align: top; word-break: break-word; }
  .affected-table tr:last-child td { border-bottom: none; }
  .affected-table a { white-space: nowrap; }

  .no-findings { color: var(--muted); text-align: center; padding: 3rem 0; }

  /* ── Compliance tags ── */
  .compliance-tags { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.7rem; }
  .compliance-tag {
    font-size: 0.66rem; font-weight: 700; padding: 0.05rem 0.4rem;
    border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--paper));
    color: var(--accent); letter-spacing: 0.03em; white-space: nowrap;
  }
  /* ── Inconclusive findings ── */
  .finding-card.is-inconclusive { border-left-style: dashed; }
  .finding-card.is-inconclusive .finding-title { color: var(--body); }
  .inconclusive-badge {
    flex-shrink: 0; min-width: 4.9rem; text-align: center;
    padding: 0.08rem 0.45rem; font-size: 0.68rem; font-weight: 700;
    color: var(--muted); border: 1px dashed var(--muted); letter-spacing: 0.05em;
  }
  /* ── Accepted risks ── */
  .waived-banner {
    background: #f0f7f2; border-left: 3px solid ${GOOD}; padding: 0.75rem 1rem; margin-bottom: 1.25rem;
    color: #14532d; font-size: 0.86rem;
  }
  /* ── Offline footer ── */
  .offline-footer {
    margin-top: 3rem; padding-top: 0.85rem; border-top: 1px solid #cfd4d9;
    font-size: 0.78rem; color: var(--muted);
  }
  .offline-footer strong { color: var(--ink); }

  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { transition: none !important; }
  }
  @media print {
    html, body { background: #fff; }
    .dash-score-panel, .dash-risk-panel, .kpi-card, .inv-card, .attack-chain { box-shadow: none; border: 1px solid var(--hair); }
    .filters { display: none; }
  }
  /* ── Responsive ── */
  @media (max-width: 680px) {
    body { padding-top: 1.5rem; }
    .header h1 { font-size: 1.75rem; }
    .dash-top { grid-template-columns: 1fr; }
    .donut-wrap { flex-direction: column; gap: 1rem; }
    .kpi-strip { grid-template-columns: repeat(2, 1fr); }
    .inv-grid { grid-template-columns: 1fr; }
    .finding-summary { flex-wrap: wrap; }
    .finding-category { display: none; }
  }
</style>
</head>
<body>
  <div class="header">
    <div class="kicker">Technical findings</div>
    <h1>Salesforce Security Audit</h1>
    <div class="meta">
      <span>Org: <strong>${esc(result.orgName)}</strong></span>
      <span>ID: ${esc(result.orgId)}</span>
      <span>Instance: ${esc(result.instance)}</span>
      <span>Type: ${esc(result.orgType)}${result.isSandbox ? ' (Sandbox)' : ''}</span>
      <span>Generated: ${result.generatedAt.toISOString()}</span>
    </div>
  </div>

  ${buildDashboard(result, openCounts(result))}

  ${attackPathsHtml}

  <h2 class="findings-h2">All findings (${result.findings.length})</h2>
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
    <strong>Offline-first audit:</strong> all analysis performed locally; no data is transmitted outside your Salesforce org. Generated by <a href="https://github.com/cclabsnz/sf-audit-plugin">sf-audit</a>, built by <a href="https://cloudcounsel.co.nz">CloudCounsel</a>.
  </div>
</body>
</html>`;
  }
}
