import type { AuditResult } from '../findings/AuditResult.js';
import type { OrgMetrics } from '@cclabsnz/sf-core';
import type { AuditRenderer } from './AuditRenderer.js';
import { esc, DEFAULT_BRANDING, INTERACTIVE_CSP_META } from '@cclabsnz/sf-core';
import { deckFontFaceCss } from './deckFonts.js';
import { renderAttackChainDagSvg } from './AttackChainDagRenderer.js';
import { coverageSummary, coverageAdvice } from '../findings/coverage.js';
import { techniqueLabel } from '../threats/attack.js';
import { unknownMetrics } from '../findings/unknownMetrics.js';
import type { Finding } from '../findings/Finding.js';
import type { AttackChain } from '../chains/AttackChain.js';
import { buildActionPlan, planHeadline, EFFORT_LABEL, WAVE_LABEL, WAVE_WHY, type PlannedAction } from '../report/ActionPlan.js';
import { DOMAINS, domainOf } from '../checks/domains.js';

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

// ── Report structure helpers ─────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const OTHER_DOMAIN = 'Other checks';

type Status = 'open' | 'info' | 'waived' | 'inconclusive' | 'passed';

function statusOf(f: Finding): Status {
  if (f.passed) return 'passed';
  if (f.inconclusive || f.notAssessed) return 'inconclusive';
  if (f.waived) return 'waived';
  return f.riskLevel === 'INFO' ? 'info' : 'open';
}

/** Open findings first, worst first; then informational, waived, inconclusive and passed results. */
const STATUS_ORDER: Record<Status, number> = { open: 0, info: 1, waived: 2, inconclusive: 3, passed: 4 };
function byPriority(a: Finding, b: Finding): number {
  return STATUS_ORDER[statusOf(a)] - STATUS_ORDER[statusOf(b)] || (SEV_ORDER[a.riskLevel] ?? 9) - (SEV_ORDER[b.riskLevel] ?? 9);
}

/** A stable, unique anchor per finding, so a ticket can link straight to it. */
function findingAnchors(findings: Finding[]): Map<Finding, string> {
  const used = new Set<string>();
  const out = new Map<Finding, string>();
  for (const f of findings) {
    const base = `f-${String(f.id ?? 'finding').toLowerCase().replace(/[^a-z0-9_-]+/g, '-')}`;
    let a = base;
    for (let n = 2; used.has(a); n++) a = `${base}-${n}`;
    used.add(a);
    out.set(f, a);
  }
  return out;
}

/** Chain labels as the executive report prints them: C1… for named chains, P1… for potential ones. */
function chainLabels(chains: AttackChain[]): string[] {
  let c = 0, p = 0;
  return chains.map((ch) => (ch.abuseCase ? `C${++c}` : `P${++p}`));
}

const slug = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const frameworkOf = (tag: string): string => tag.split(/[-.]/)[0];
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? '' : 's'}`;

function severityBadge(f: Finding): string {
  const st = statusOf(f);
  if (st === 'inconclusive') return '<span class="inconclusive-badge">? INCONCLUSIVE</span>';
  if (st === 'passed') return `<span class="risk-badge" style="--sev:${PASS_COLOR}">✓ PASS</span>`;
  const sev = `<span class="risk-badge${SOLID.has(f.riskLevel) ? ' solid' : ''}" style="--sev:${RISK_COLORS[f.riskLevel] ?? UNKNOWN_COLOR}">${esc(f.riskLevel)}</span>`;
  return st === 'waived' ? `${sev}<span class="waived-mark">waived</span>` : sev;
}

// ── Main renderer ────────────────────────────────────────────────────────────

export class HtmlRenderer implements AuditRenderer {
  readonly format = 'html';
  readonly fileExtension = '.html';

  private renderAttackPaths(result: AuditResult, labels: string[], anchorOfId: Map<string, string>): string {
    if (!result.attackChains || result.attackChains.length === 0) return '';
    const cards = result.attackChains
      .map((c, ci) => {
        const conf = c.confidence === 'named' ? '' : ' (potential)';
        const dagSvg = renderAttackChainDagSvg(c, { theme: 'light' });
        const steps = c.steps
          .map((s) => {
            const technique = s.techniques?.length ? ` → ${esc(s.techniques.map(techniqueLabel).join(' · '))}` : '';
            const grants = s.capabilityInferred ? '' : `: grants <code>${esc(s.capability)}</code>${technique}`;
            const cut = s.breaksChain ? ' <strong>✂ break point</strong>' : '';
            const anchor = anchorOfId.get(s.findingId);
            const name = `<strong>${esc(s.title ?? s.findingId)}</strong>`;
            return `<li>${anchor ? `<a href="#${anchor}">${name}</a>` : name} (${esc(s.severity ?? '—')})${grants}${cut}</li>`;
          })
          .join('');
        return `<div class="attack-chain severity-${c.severity.toLowerCase()}" id="chain-${ci + 1}">
  <h3><span class="risk-badge solid" style="--sev:${RISK_COLORS[c.severity] ?? UNKNOWN_COLOR}">${esc(c.severity)}</span> <span class="chain-label">${labels[ci]}</span> ${esc(c.title)}${conf}</h3>
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
    return `<section class="attack-paths" id="attack-paths">
  <h2>Attack Paths (${result.attackChains.length})</h2>
  <p class="subtitle">Combinations of findings that together enable an exploit more severe than any single finding.</p>
  ${cards}
</section>`;
  }

  /** Option A: the fixes, in the order to do them, each with the findings it closes. */
  private renderPlan(plan: PlannedAction[], headline: string, labels: string[], anchorOf: Map<Finding, string>): string {
    if (plan.length === 0) {
      return `<section class="fix-first" id="fix-first">
  <div class="kicker">Fix first</div>
  <h2 class="sec-h">${esc(headline)}</h2>
</section>`;
    }
    const chip = (i: number, kind: '' | 'part') =>
      `<a class="chip${kind ? ' part' : ''}" href="#chain-${i + 1}">${kind ? 'part of ' : ''}${labels[i]}</a>`;
    let last = 0;
    const rows = plan.map((a, i) => {
      const head = a.wave !== last
        ? `<tr class="wave-h"><td colspan="5">${WAVE_LABEL[a.wave]} <span class="why">· ${WAVE_WHY[a.wave]}</span></td></tr>`
        : '';
      last = a.wave;
      const breaks = [...a.breaks.map((c) => chip(c, '')), ...a.weakens.map((c) => chip(c, 'part'))].join('') || '<span class="none">—</span>';
      const closes = a.fixes
        .map((f) => `<li>${severityBadge(f)}<a href="#${anchorOf.get(f)}">${esc(f.title)}</a></li>`)
        .join('');
      return `${head}<tr>
  <td class="n">${i + 1}</td>
  <td class="act"><b>${esc(a.title)}</b><span class="why-line">${esc(a.detail ?? a.why)}</span><ul class="closes">${closes}</ul></td>
  <td><div class="chips">${breaks}</div></td>
  <td class="num">${a.fixes.length}</td>
  <td class="effort">${EFFORT_LABEL[a.effort]}</td>
</tr>`;
    }).join('');
    return `<section class="fix-first" id="fix-first">
  <div class="kicker">Fix first</div>
  <h2 class="sec-h">${esc(headline)}</h2>
  <p class="subtitle">Each action lists the findings it closes and the attack chains it breaks. Effort is an estimate for planning, not a quote.</p>
  <div class="tbl"><table class="plan">
    <thead><tr><th></th><th>Action</th><th>Breaks</th><th class="num">Closes</th><th>Effort</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>
</section>`;
  }

  /** Option C: one scorecard row per domain, then each domain's findings, with passed checks folded away. */
  private renderDomains(result: AuditResult, card: (f: Finding) => string): string {
    const groups = new Map<string, Finding[]>();
    for (const d of DOMAINS) groups.set(d, []);
    for (const f of result.findings) {
      const d = domainOf(f.checkId) ?? OTHER_DOMAIN;
      if (!groups.has(d)) groups.set(d, []);
      groups.get(d)!.push(f);
    }
    const domains = [...groups.entries()]
      .filter(([, fs]) => fs.length > 0)
      .map(([name, fs]) => {
        const open = fs.filter((f) => statusOf(f) === 'open').sort(byPriority);
        const n = (l: string) => open.filter((f) => f.riskLevel === l).length;
        return { name, fs: [...fs].sort(byPriority), open, worst: open[0]?.riskLevel, counts: { c: n('CRITICAL'), h: n('HIGH'), m: n('MEDIUM'), l: n('LOW') } };
      })
      .sort((a, b) => (SEV_ORDER[a.worst ?? 'INFO'] - SEV_ORDER[b.worst ?? 'INFO']) || b.open.length - a.open.length);

    const claim = (d: (typeof domains)[number]): string => {
      if (d.open.length) {
        const parts = (['c', 'h', 'm', 'l'] as const)
          .filter((k) => d.counts[k])
          .map((k) => `${d.counts[k]} ${{ c: 'critical', h: 'high', m: 'medium', l: 'low' }[k]}`);
        return `${parts.join(', ')} open. Worst: ${d.open[0].title}`;
      }
      const inc = d.fs.filter((f) => statusOf(f) === 'inconclusive').length;
      const passed = d.fs.filter((f) => statusOf(f) === 'passed').length;
      return inc ? `No open findings; ${plural(inc, 'check')} could not be assessed` : `No open findings; ${plural(passed, 'check')} passed`;
    };
    const mark = (d: (typeof domains)[number]): string => d.worst
      ? `<span class="risk-badge${SOLID.has(d.worst) ? ' solid' : ''}" style="--sev:${RISK_COLORS[d.worst]}">${d.worst}</span>`
      : `<span class="risk-badge" style="--sev:${PASS_COLOR}">✓ CLEAR</span>`;
    const bar = (d: (typeof domains)[number]): string => {
      const total = d.fs.length;
      const seg = (k: string, count: number) => (count ? `<i class="b-${k}" style="width:${((count / total) * 100).toFixed(2)}%"></i>` : '');
      const st = (s: Status) => d.fs.filter((f) => statusOf(f) === s).length;
      return `<div class="bar" role="img" aria-label="${esc(d.name)}: ${d.open.length} open of ${total} results">${seg('c', d.counts.c)}${seg('h', d.counts.h)}${seg('m', d.counts.m)}${seg('l', d.counts.l)}${seg('u', st('info') + st('waived') + st('inconclusive'))}${seg('p', st('passed'))}</div>`;
    };
    const withIssues = domains.filter((d) => d.counts.c + d.counts.h > 0).length;
    const scorecard = domains.map((d) => `<a class="dom-row" href="#d-${slug(d.name)}">
  <span class="dom-name">${esc(d.name)}</span>
  <span class="dom-claim">${mark(d)}<span>${esc(claim(d))}</span></span>
  ${bar(d)}
  <span class="dom-counts"><b>${d.open.length}</b> open · ${d.fs.filter((f) => statusOf(f) === 'passed').length} passed</span>
</a>`).join('');
    const sections = domains.map((d) => {
      const shown = d.fs.filter((f) => statusOf(f) !== 'passed');
      const passed = d.fs.filter((f) => statusOf(f) === 'passed');
      return `<section class="domain" id="d-${slug(d.name)}">
  <h3 class="dom-h">${esc(d.name)}</h3>
  <p class="dom-sub">${esc(claim(d))}</p>
  ${shown.map(card).join('')}
  ${passed.length ? `<details class="passed-fold"><summary>${plural(passed.length, 'check')} passed</summary>${passed.map(card).join('')}</details>` : ''}
</section>`;
    }).join('\n');
    return `<section class="by-domain" id="by-domain">
  <div class="kicker">By domain</div>
  <h2 class="sec-h">${withIssues ? `${withIssues} of ${domains.length} domains have critical or high findings` : `No domain has a critical or high finding`}</h2>
  <div class="scorecard">${scorecard}</div>
  <div class="bar-key" aria-hidden="true"><span><i class="b-c"></i>Critical</span><span><i class="b-h"></i>High</span><span><i class="b-m"></i>Medium</span><span><i class="b-l"></i>Low</span><span><i class="b-u"></i>Info, waived or inconclusive</span><span><i class="b-p"></i>Passed</span></div>
  ${sections}
</section>`;
  }

  /** Option D: every result in one table that can be regrouped and searched; links to the full finding. */
  private renderTable(result: AuditResult, labels: string[], anchorOf: Map<Finding, string>): string {
    const chainsOf = new Map<string, string[]>();
    (result.attackChains ?? []).forEach((c, i) => {
      for (const s of c.steps) {
        const list = chainsOf.get(s.findingId) ?? [];
        if (!list.includes(labels[i])) list.push(labels[i]);
        chainsOf.set(s.findingId, list);
      }
    });
    const rows = [...result.findings].sort(byPriority).map((f) => {
      const st = statusOf(f);
      const dom = domainOf(f.checkId) ?? OTHER_DOMAIN;
      const chains = chainsOf.get(f.id) ?? [];
      const fws = [...new Set((f.complianceTags ?? []).map(frameworkOf))];
      const sevKey = st === 'open' ? f.riskLevel : st === 'info' ? 'INFO' : st.toUpperCase();
      return `<tr data-sev="${esc(sevKey)}" data-dom="${esc(dom)}" data-ch="${esc(chains.join(' '))}" data-fw="${esc(fws.join(' '))}" data-st="${st}"${st === 'passed' ? ' hidden' : ''}>
  <td>${severityBadge(f)}</td>
  <td><a href="#${anchorOf.get(f)}">${esc(f.title)}</a><span class="row-dom">${esc(dom)}</span></td>
  <td class="num">${f.affectedItems?.length ?? '—'}</td>
  <td><div class="chips">${chains.map((l) => `<span class="chip">${l}</span>`).join('') || '<span class="none">—</span>'}</div></td>
</tr>`;
    }).join('');
    const passed = result.findings.filter((f) => f.passed).length;
    return `<section class="all-results" id="all-results">
  <div class="kicker">Appendix</div>
  <h2 class="sec-h">All ${plural(result.findings.length, 'result')}, in one table</h2>
  <div class="tools">
    <div class="seg" role="group" aria-label="Group by">
      <button type="button" data-group="sev" aria-pressed="true">Severity</button><button type="button" data-group="dom" aria-pressed="false">Domain</button><button type="button" data-group="ch" aria-pressed="false">Attack chain</button><button type="button" data-group="fw" aria-pressed="false">Framework</button>
    </div>
    <label class="tool-check"><input type="checkbox" id="show-passed"> Include ${plural(passed, 'passed check')}</label>
    <label class="tool-search" for="result-search">Search <input type="search" id="result-search" placeholder="guest, apex, SOC2…" autocomplete="off"></label>
  </div>
  <div class="tbl"><table class="results">
    <thead><tr><th>Status</th><th>Finding</th><th class="num">Affected</th><th>Chains</th></tr></thead>
    <tbody id="results-body">${rows}</tbody>
  </table></div>
  <p class="no-match" id="no-match" hidden>No result matches that search.</p>
</section>`;
  }

  render(result: AuditResult): string {
    const chains = result.attackChains ?? [];
    const labels = chainLabels(chains);
    const anchorOf = findingAnchors(result.findings);
    const anchorOfId = new Map<string, string>();
    for (const [f, a] of anchorOf) if (!anchorOfId.has(f.id)) anchorOfId.set(f.id, a);
    const plan = buildActionPlan(result.findings, chains);
    const openHigh = result.findings.filter((f) => statusOf(f) === 'open' && f.riskLevel === 'HIGH').length;
    const headline = planHeadline(plan, chains, openHigh);

    const attackPathsHtml = this.renderAttackPaths(result, labels, anchorOfId);

    const card = (f: Finding): string => {
        const isInconclusive = !!f.inconclusive;
        const cardAccent = isInconclusive ? UNKNOWN_COLOR : (f.passed ? 'var(--hair)' : (RISK_COLORS[f.riskLevel] ?? UNKNOWN_COLOR));
        const badgeHtml  = severityBadge(f);
        const tagsHtml = f.complianceTags?.length
          ? `<div class="compliance-tags">${f.complianceTags.map((t) => `<span class="compliance-tag">${esc(t)}</span>`).join('')}</div>`
          : '';
        return `
      <details class="finding-card${isInconclusive ? ' is-inconclusive' : ''}" id="${anchorOf.get(f)}" data-risk="${esc(f.riskLevel)}" style="--card-accent:${cardAccent}">
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
    };

    const bodyHtml = result.findings.length === 0
      ? `<p class="no-findings">No findings.</p>
  ${attackPathsHtml}`
      : `${this.renderPlan(plan, headline, labels, anchorOf)}
  ${attackPathsHtml}
  ${this.renderDomains(result, card)}
  ${this.renderTable(result, labels, anchorOf)}`;

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
  .attack-paths h2, .sec-h {
    font-family: var(--serif); font-size: 1.75rem; font-weight: 600; line-height: 1.2; letter-spacing: -0.005em; text-wrap: balance; max-width: 34em;
  }
  .sec-h { margin-top: 0.35rem; }
  .attack-paths h2::after, .sec-h::after { content: ''; display: block; width: 72px; height: 2px; background: var(--accent); margin: 0.9rem 0 0; }
  .fix-first, .by-domain, .all-results { margin-bottom: 3rem; scroll-margin-top: 1rem; }
  .sec-h + .subtitle, .sec-h + .scorecard, .sec-h + .tools, .sec-h + .tbl { margin-top: 1.1rem; }
  .tbl { overflow-x: auto; }
  .num { text-align: right; }
  .none { color: var(--muted); }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; }
  .chip { font-size: 0.72rem; font-weight: 700; padding: 0 5px; border: 1.25px solid var(--crit, #b91c1c); color: ${BAD}; white-space: nowrap; text-decoration: none; background: var(--paper); }
  .chip.part { border-color: #c9ced3; color: var(--body); font-weight: 600; }
  a.chip:hover { background: color-mix(in srgb, ${BAD} 8%, var(--paper)); }

  /* ── Fix first (A) ── */
  table.plan, table.results { width: 100%; border-collapse: collapse; font-size: 0.9rem; background: var(--paper); box-shadow: var(--shadow); }
  table.plan th, table.results th {
    text-align: left; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted);
    padding: 0.85rem 0.75rem 0.5rem; border-bottom: 1.5px solid var(--ink); white-space: nowrap; background: var(--paper);
    position: sticky; top: 0; z-index: 1;
  }
  table.plan td, table.results td { padding: 0.65rem 0.75rem; border-bottom: 1px solid var(--hair); vertical-align: top; }
  table.plan tr.wave-h td { border-bottom: 0; padding: 1rem 0.75rem 0.2rem; font-size: 0.8rem; font-weight: 700; color: var(--accent); }
  table.plan .why { font-weight: 400; color: var(--muted); }
  table.plan .n { width: 2rem; color: var(--muted); font-weight: 700; }
  table.plan .act b { display: block; color: var(--ink); font-weight: 650; }
  table.plan .why-line { display: block; font-size: 0.82rem; color: var(--muted); margin-top: 0.1rem; max-width: 80ch; }
  table.plan .effort { white-space: nowrap; color: var(--body); }
  ul.closes { list-style: none; margin: 0.45rem 0 0; padding: 0; display: grid; gap: 0.25rem; }
  ul.closes li { display: flex; gap: 0.5rem; align-items: baseline; font-size: 0.84rem; }
  ul.closes .risk-badge { min-width: 4.4rem; font-size: 0.62rem; }
  ul.closes a { color: var(--body); }
  ul.closes a:hover { color: var(--accent); }
  .chain-label { font-family: var(--sans); font-size: 0.8rem; font-weight: 700; color: var(--muted); margin-right: 0.15rem; }
  .attack-chain { scroll-margin-top: 1rem; }
  .attack-chain li a { color: inherit; }

  /* ── By domain (C) ── */
  .scorecard { background: var(--paper); box-shadow: var(--shadow); padding: 0.4rem 1.4rem; }
  .dom-row {
    display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr) 8.5rem; grid-template-areas: 'name bar counts' 'claim bar counts';
    gap: 0.15rem 1.5rem; align-items: center; padding: 0.8rem 0; border-bottom: 1px solid var(--hair); color: inherit; text-decoration: none;
    transition: background-color 150ms var(--ease);
  }
  .dom-row:last-child { border-bottom: 0; }
  .dom-row:hover { background: #f6f7f8; }
  .dom-row:hover .dom-claim span { color: var(--accent); }
  .dom-name { grid-area: name; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
  .dom-claim { grid-area: claim; display: flex; gap: 0.6rem; align-items: baseline; font-weight: 600; color: var(--ink); font-size: 0.92rem; min-width: 0; }
  .dom-claim .risk-badge { min-width: 4.9rem; }
  .bar { grid-area: bar; display: flex; height: 12px; background: var(--hair); }
  .bar i, .bar-key i { display: block; height: 100%; }
  .b-c { background: ${RISK_COLORS.CRITICAL}; } .b-h { background: ${RISK_COLORS.HIGH}; } .b-m { background: ${RISK_COLORS.MEDIUM}; } .b-l { background: ${RISK_COLORS.LOW}; }
  .b-u { background: #d4d8dc; } .b-p { background: repeating-linear-gradient(135deg, #b8dcc4 0 3px, #d7ece0 3px 6px); }
  .dom-counts { grid-area: counts; text-align: right; font-size: 0.8rem; color: var(--muted); white-space: nowrap; }
  .dom-counts b { color: var(--ink); }
  .bar-key { display: flex; flex-wrap: wrap; gap: 0.3rem 1rem; margin: 0.7rem 0 2rem; font-size: 0.75rem; color: var(--muted); }
  .bar-key span { display: inline-flex; align-items: center; gap: 0.35rem; }
  .bar-key i { width: 12px; height: 9px; }
  .domain { margin-top: 2rem; scroll-margin-top: 1rem; }
  .dom-h { font-family: var(--serif); font-size: 1.3rem; font-weight: 600; }
  .dom-sub { color: var(--muted); font-size: 0.88rem; margin: 0.2rem 0 0.8rem; max-width: 90ch; }
  .passed-fold { margin-top: 0.6rem; }
  .passed-fold > summary {
    cursor: pointer; list-style: none; font-size: 0.82rem; font-weight: 700; color: ${GOOD}; padding: 0.4rem 0;
  }
  .passed-fold > summary::-webkit-details-marker { display: none; }
  .passed-fold > summary::before { content: '+ '; }
  .passed-fold[open] > summary::before { content: '− '; }
  .passed-fold > summary:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }
  .waived-mark { font-size: 0.66rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted); border: 1px dashed var(--muted); padding: 0.05rem 0.35rem; margin-left: 0.35rem; }

  /* ── All results (D) ── */
  .tools { display: flex; flex-wrap: wrap; gap: 0.6rem 1.25rem; align-items: center; margin-bottom: 0.8rem; }
  .seg { display: inline-flex; border: 1.25px solid #cfd4d9; background: var(--paper); }
  .seg button {
    font: 700 0.78rem var(--sans); color: var(--body); background: transparent; border: 0; border-left: 1px solid #cfd4d9;
    padding: 0.35rem 0.75rem; cursor: pointer; transition: background-color 150ms var(--ease), color 150ms var(--ease);
  }
  .seg button:first-child { border-left: 0; }
  .seg button:hover { color: var(--accent); }
  .seg button[aria-pressed="true"] { background: var(--ink); color: #fff; }
  .seg button:focus-visible, .tools input:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }
  .tool-check, .tool-search { font-size: 0.82rem; color: var(--body); display: inline-flex; gap: 0.4rem; align-items: center; }
  .tool-search input { font: 0.88rem var(--sans); border: 1.25px solid #cfd4d9; padding: 0.3rem 0.55rem; width: 15rem; max-width: 60vw; color: var(--ink); background: var(--paper); }
  table.results tr.grp td { font-size: 0.78rem; font-weight: 700; color: var(--accent); padding-top: 1rem; border-bottom: 1px solid var(--accent); }
  table.results td:nth-child(2) a { color: var(--ink); font-weight: 600; text-decoration: none; }
  table.results td:nth-child(2) a:hover { color: var(--accent); text-decoration: underline; }
  .row-dom { display: block; font-size: 0.76rem; color: var(--muted); }
  .no-match { color: var(--muted); padding: 1rem 0; }
  .finding-card { scroll-margin-top: 1rem; }
  .finding-card:target { box-shadow: 0 0 0 2px var(--accent); }
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
    .tools { display: none; }
    table.plan th, table.results th { position: static; }
    .passed-fold > .finding-card { break-inside: avoid; }
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
    .dom-row { grid-template-columns: 1fr; grid-template-areas: 'name' 'claim' 'bar' 'counts'; }
    .dom-counts { text-align: left; }
    .scorecard { padding: 0.4rem 1rem; }
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

  ${bodyHtml}

<script>
(function () {
  var body = document.getElementById('results-body');
  if (!body) return;
  var rows = Array.prototype.slice.call(body.querySelectorAll('tr[data-st]'));
  var buttons = Array.prototype.slice.call(document.querySelectorAll('.seg button'));
  var search = document.getElementById('result-search');
  var showPassed = document.getElementById('show-passed');
  var noMatch = document.getElementById('no-match');
  var group = 'sev';
  var SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'WAIVED', 'INCONCLUSIVE', 'PASSED'];
  function keys(row) {
    var v = row.dataset[group] || '';
    if (group === 'sev' || group === 'dom') return [v];
    var list = v.split(' ').filter(Boolean);
    return list.length ? list : [group === 'ch' ? 'Not on an attack chain' : 'No framework tag'];
  }
  function render() {
    var term = search.value.trim().toLowerCase();
    var groups = {}, order = [];
    rows.forEach(function (row) {
      var visible = (showPassed.checked || row.dataset.st !== 'passed') &&
        (!term || row.textContent.toLowerCase().indexOf(term) >= 0 || (row.dataset.fw + ' ' + row.dataset.ch).toLowerCase().indexOf(term) >= 0);
      if (!visible) return;
      keys(row).forEach(function (k) { if (!groups[k]) { groups[k] = []; order.push(k); } groups[k].push(row); });
    });
    if (group === 'sev') order.sort(function (a, b) { return SEV.indexOf(a) - SEV.indexOf(b); });
    else order.sort(function (a, b) { return groups[b].length - groups[a].length || a.localeCompare(b, undefined, { numeric: true }); });
    var frag = document.createDocumentFragment();
    order.forEach(function (k) {
      var head = document.createElement('tr');
      head.className = 'grp';
      var cell = document.createElement('td');
      cell.colSpan = 4;
      cell.textContent = k + ' · ' + groups[k].length;
      head.appendChild(cell);
      frag.appendChild(head);
      groups[k].forEach(function (row) { var r = row.cloneNode(true); r.hidden = false; frag.appendChild(r); });
    });
    body.textContent = '';
    body.appendChild(frag);
    noMatch.hidden = order.length > 0;
  }
  buttons.forEach(function (b) {
    b.addEventListener('click', function () {
      group = b.dataset.group;
      buttons.forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
      render();
    });
  });
  search.addEventListener('input', render);
  showPassed.addEventListener('change', render);
  render();
})();
</script>
  <div class="offline-footer">
    <strong>Offline-first audit:</strong> all analysis performed locally; no data is transmitted outside your Salesforce org. Generated by <a href="https://github.com/cclabsnz/sf-audit-plugin">sf-audit</a>, built by <a href="https://cloudcounsel.co.nz">CloudCounsel</a>.
  </div>
</body>
</html>`;
  }
}
