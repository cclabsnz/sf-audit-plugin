import type { AuditResult } from '../findings/AuditResult.js';
import type { Finding } from '../findings/Finding.js';
import type { RiskLevel } from '../findings/RiskLevel.js';
import type { AuditRenderer } from './AuditRenderer.js';
import type { Branding } from '../report/branding.js';
import { esc } from './html-utils.js';
import { fontFaceCss } from '../report/fonts.js';
import { getCheckMeta } from '../findings/CheckMeta.js';
import { selectPriorities } from '../report/ExecutivePriorities.js';
import { buildRoadmap, type Roadmap } from '../report/RemediationRoadmap.js';
import type { Framework } from '../compliance/types.js';
import { buildComplianceMatrix, type FrameworkMatrix } from '../report/ComplianceMatrix.js';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#7d3a3a', HIGH: '#a35a2a', MEDIUM: '#8a6d1f', LOW: '#3a5a82', INFO: '#636770',
};
const SEV_RANK: Record<RiskLevel, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const GRADE_COLOR: Record<string, string> = {
  A: '#4a7d5e', B: '#4a7d5e', C: '#8a6d1f', D: '#a35a2a', F: '#7d3a3a',
};
const SEV_ORDER: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const FRAMEWORK_LABEL: Record<Framework, string> = {
  OWASP: 'OWASP Top 10', SOC2: 'SOC 2', ISO27001: 'ISO/IEC 27001',
  SBS: 'Security Benchmark for Salesforce', PRIVACY_ACT: 'NZ Privacy Act',
  HISO10029: 'HISO 10029', NZISM: 'NZISM', HIPAA: 'HIPAA', GDPR: 'GDPR',
};

export interface ClientReportOptions {
  branding: Branding;
  topN: number;
  frameworks: Framework[];
}

export class ClientReportRenderer implements AuditRenderer {
  public readonly format = 'executive';
  public readonly fileExtension = '.html';
  public readonly filenamePrefix = 'SF_Audit_Executive';

  public constructor(private readonly opts: ClientReportOptions) {}

  public render(result: AuditResult): string {
    const b = this.opts.branding;
    const chains = result.attackChains ?? [];
    const chainIds = new Set<string>();
    for (const c of chains) for (const s of c.steps) chainIds.add(s.findingId);
    const priorities = selectPriorities(result.findings, chainIds, this.opts.topN);
    const roadmap = buildRoadmap(result.findings);
    const matrix = buildComplianceMatrix(result, this.opts.frameworks);

    let n = 0;
    const num = (): string => String(++n).padStart(2, '0');
    const sections = [
      this.summary(result, num()),
      this.prioritiesSection(priorities, chainIds, num()),
      chains.length ? this.scenarios(chains, num()) : '',
      this.roadmapSection(roadmap, num()),
      matrix.length ? this.matrixSection(matrix, num()) : '',
      this.findingsAppendix(result, num()),
    ].join('\n');

    return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Security Audit: ${esc(result.orgName)}</title>
<style>${fontFaceCss()}
:root{--ink:${b.ink};--bg:${b.bg};--bgalt:${b.bgAlt};--muted:${b.muted};--border:${b.border};--primary:${b.primary};
--display:'${b.fontDisplay}',Georgia,serif;--body:'${b.fontBody}',system-ui,sans-serif;--mono:ui-monospace,'SF Mono',Menlo,monospace;}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{font-family:var(--body);color:var(--ink);background:var(--bg);margin:0;line-height:1.6;font-variant-numeric:tabular-nums}
.wrap{max-width:780px;margin:0 auto;padding:64px 44px}
h1{font-family:var(--display);font-size:clamp(38px,6vw,52px);line-height:1.02;letter-spacing:-0.02em;margin:6px 0 0}
h2{font-family:var(--display);font-size:25px;letter-spacing:-0.01em;line-height:1.1;margin:0}
h3{font-family:var(--display);font-size:18px;letter-spacing:-0.01em;margin:0 0 6px}
p{margin:0 0 10px;max-width:68ch}
.label{font-family:var(--mono);text-transform:uppercase;letter-spacing:0.16em;font-size:11px;color:var(--muted)}
.muted{color:var(--muted)}
/* cover */
.cover{padding-bottom:8px}
.meta{font-family:var(--mono);font-size:11px;letter-spacing:0.12em;color:var(--muted);text-transform:uppercase;margin-top:6px}
.prepared{font-family:var(--mono);font-size:11px;letter-spacing:0.08em;color:var(--muted);text-transform:uppercase;margin-top:14px}
/* scorecard */
.scorecard{display:flex;align-items:center;gap:28px;margin:30px 0 8px;padding:24px 28px;background:var(--bgalt);border:1px solid var(--border);border-radius:12px;break-inside:avoid}
.grade{font-family:var(--display);font-size:104px;line-height:0.86;font-weight:400}
.score-num{font-family:var(--display);font-size:34px;line-height:1}
.score-num span{font-size:18px;color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.chip{font-family:var(--mono);font-size:11px;letter-spacing:0.04em;font-weight:600;color:var(--c);border:1px solid var(--c);border-radius:999px;padding:2px 9px;white-space:nowrap}
.chip.solid{background:var(--c);color:#fff;border-color:var(--c)}
.pnum{font-family:var(--mono);color:var(--primary);font-size:13px;letter-spacing:0.05em;margin-right:10px}
/* section markers */
.sec{display:flex;align-items:baseline;gap:14px;margin:56px 0 18px;border-bottom:1px solid var(--border);padding-bottom:10px}
.sec-num{font-family:var(--mono);font-size:13px;letter-spacing:0.1em;color:var(--primary)}
/* cards */
.card{background:var(--bgalt);border:1px solid var(--border);border-left:3px solid var(--c,var(--border));border-radius:8px;padding:16px 18px;margin:12px 0;break-inside:avoid}
.card .row{display:flex;align-items:baseline;justify-content:space-between;gap:12px}
.scenario{border-left-width:3px}
/* roadmap */
.tier{display:flex;align-items:baseline;gap:10px;margin:22px 0 6px}
.tier h3{margin:0}
.count{font-family:var(--mono);font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:1px 8px}
.tier-list{list-style:none;margin:0;padding:0}
.tier-list li{display:flex;align-items:baseline;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px solid var(--border)}
/* findings appendix — denser, quieter */
.find{padding:12px 0;border-bottom:1px solid var(--border)}
.find h3{font-family:var(--body);font-size:15px;font-weight:600;margin:0 0 3px}
.find p{font-size:13px;color:var(--muted);margin:0}
.matrix{width:100%;border-collapse:collapse;margin:8px 0 22px;font-size:13px}
.matrix th{text-align:left;font-family:var(--mono);text-transform:uppercase;letter-spacing:0.08em;font-size:10px;color:var(--muted);border-bottom:1px solid var(--border);padding:6px 8px}
.matrix td{border-bottom:1px solid var(--border);padding:7px 8px;vertical-align:top}
.matrix .cid{font-family:var(--mono);font-size:12px;color:var(--primary);white-space:nowrap}
.matrix .st{text-align:right;white-space:nowrap}
footer{margin-top:56px;border-top:1px solid var(--border);padding-top:18px;color:var(--muted);font-size:12px;line-height:1.55}
footer .label{display:block;margin-bottom:6px;color:var(--ink)}
@page{margin:18mm}
@media print{.wrap{padding:0 0 24px}.sec{break-after:avoid}.card,.scorecard{break-inside:avoid}}
</style></head><body><div class="wrap">
${this.cover(result, b)}
${sections}
${this.footer(b)}
</div></body></html>`;
  }

  private chip(sev: RiskLevel, text: string): string {
    const solid = sev === 'CRITICAL' ? ' solid' : '';
    return `<span class="chip${solid}" style="--c:${SEV_COLOR[sev]}">${esc(text)}</span>`;
  }

  private sectionHead(numStr: string, title: string): string {
    return `<div class="sec"><span class="sec-num">${numStr} /</span><h2>${esc(title)}</h2></div>`;
  }

  private cover(r: AuditResult, b: Branding): string {
    const meta = [r.orgName, r.orgType, r.orgId, r.generatedAt.toISOString().slice(0, 10)]
      .map((s) => esc(String(s))).join(' · ');
    const counts = SEV_ORDER
      .map((l) => ({ l, n: r.findings.filter((f) => f.riskLevel === l && !f.passed && !f.inconclusive).length }))
      .filter((c) => c.n > 0)
      .map((c) => this.chip(c.l, `${c.n} ${c.l}`)).join('');
    const prepared = b.preparedFor ? ` for ${esc(b.preparedFor)}` : '';
    return `<header class="cover">
<div class="label">${esc(b.firmName)}</div>
<h1>Salesforce Security Audit</h1>
<div class="meta">${meta}</div>
<div class="scorecard" style="border-left:4px solid ${GRADE_COLOR[r.grade] ?? b.primary}">
  <div class="grade" style="color:${GRADE_COLOR[r.grade] ?? b.primary}">${esc(r.grade)}</div>
  <div>
    <div class="label">Security grade · health score</div>
    <div class="score-num">${r.healthScore}<span>/100</span></div>
    <div class="chips">${counts || this.chip('LOW', 'No active findings')}</div>
  </div>
</div>
<div class="prepared">Prepared by ${esc(b.firmName)}${prepared}</div></header>`;
  }

  private summary(r: AuditResult, numStr: string): string {
    const incon = r.findings.filter((f) => f.inconclusive).length;
    const active = r.findings.filter((f) => !f.passed && !f.inconclusive).length;
    return `${this.sectionHead(numStr, 'Executive Summary')}
<p>This audit assessed the org’s security configuration and scored it <strong>${r.healthScore}/100 (Grade ${esc(r.grade)})</strong> across ${active} active finding${active === 1 ? '' : 's'}${incon ? `, with ${incon} inconclusive (insufficient access)` : ''}. The priorities below are the highest-impact items to address first; the remediation roadmap groups every fix by effort. See Scope &amp; Liability for the basis and limits of this assessment.</p>`;
  }

  private prioritiesSection(priorities: Finding[], chainIds: Set<string>, numStr: string): string {
    const head = this.sectionHead(numStr, 'Executive Priorities');
    if (priorities.length === 0) return `${head}<p class="muted">No active findings to prioritise.</p>`;
    const items = priorities.map((f, i) => {
      const meta = f.checkId ? getCheckMeta(f.checkId) : undefined;
      const chained = chainIds.has(f.id) ? '<p class="muted">Part of an attack chain. See Attack Scenarios.</p>' : '';
      const impact = meta ? `<p><strong>Impact:</strong> ${esc(meta.impact)}</p>` : '';
      return `<div class="card" style="--c:${SEV_COLOR[f.riskLevel]}">
<div class="row"><h3><span class="pnum">${String(i + 1).padStart(2, '0')}</span>${esc(f.title)}</h3>${this.chip(f.riskLevel, f.riskLevel)}</div>
${impact}${chained}<p><strong>Fix:</strong> ${esc(f.remediation)}</p></div>`;
    }).join('');
    return `${head}<p class="muted">Focus areas, highest impact first.</p>${items}`;
  }

  private scenarios(chains: NonNullable<AuditResult['attackChains']>, numStr: string): string {
    const items = chains.map((c) => `<div class="card scenario" style="--c:${SEV_COLOR[c.severity]}">
<div class="row"><h3>${esc(c.title)}</h3>${this.chip(c.severity, c.severity)}</div>
<p>${esc(c.narrative)}</p><p><strong>Breaks the chain:</strong> ${esc(c.remediation)}</p></div>`).join('');
    return `${this.sectionHead(numStr, 'Attack Scenarios')}<p class="muted">How findings combine into real attack paths.</p>${items}`;
  }

  private roadmapSection(roadmap: Roadmap, numStr: string): string {
    const tier = (label: string, sub: string, arr: Finding[]): string => {
      if (arr.length === 0) return '';
      const rows = arr.map((f) =>
        `<li><span>${esc(f.title)}</span>${this.chip(f.riskLevel, f.riskLevel)}</li>`).join('');
      return `<div class="tier"><h3>${esc(label)}</h3><span class="count">${arr.length} · ${esc(sub)}</span></div><ul class="tier-list">${rows}</ul>`;
    };
    return `${this.sectionHead(numStr, 'Remediation Roadmap')}
${tier('Quick wins', '≤1 day', roadmap.quick)}
${tier('Moderate', 'days', roadmap.moderate)}
${tier('Projects', 'weeks', roadmap.project)}`;
  }

  private worst(findings: Finding[]): RiskLevel | undefined {
    return findings.slice().sort((a, b) => SEV_RANK[a.riskLevel] - SEV_RANK[b.riskLevel])[0]?.riskLevel;
  }

  private matrixSection(matrix: FrameworkMatrix[], numStr: string): string {
    const blocks = matrix.map((fm) => {
      const rows = fm.rows.map((row) => {
        const w = this.worst(row.findings);
        const status = w
          ? this.chip(w, `${row.findings.length} finding${row.findings.length === 1 ? '' : 's'}`)
          : '<span class="muted">No findings detected</span>';
        return `<tr><td class="cid">${esc(row.control.id)}</td><td>${esc(row.control.title)}</td><td class="st">${status}</td></tr>`;
      }).join('');
      return `<h3>${esc(FRAMEWORK_LABEL[fm.framework])} <span class="muted">· ${esc(fm.version)}</span></h3>
<table class="matrix"><thead><tr><th>Control</th><th>Requirement area</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`;
    }).join('');
    return `${this.sectionHead(numStr, 'Compliance Coverage')}<p class="muted">Findings mapped to framework controls. “No findings detected” is not an attestation of compliance. See Scope &amp; Liability.</p>${blocks}`;
  }

  private findingsAppendix(r: AuditResult, numStr: string): string {
    const rows = r.findings.map((f) => {
      const tag = f.inconclusive ? this.chip('INFO', 'inconclusive') : f.passed ? this.chip('INFO', 'passed') : this.chip(f.riskLevel, f.riskLevel);
      return `<div class="find"><div class="row"><h3>${esc(f.title)}</h3>${tag}</div>
<p>${esc(f.detail)}</p><p><strong>Remediation:</strong> ${esc(f.remediation)}</p></div>`;
    }).join('');
    return `${this.sectionHead(numStr, 'All Findings')}${rows}`;
  }

  private footer(b: Branding): string {
    return `<footer><span class="label">Scope &amp; Liability</span>
Read-only, point-in-time configuration review: not a penetration test, not a code audit. The grade is a prioritisation aid, not a certification. Validate findings before remediation. © ${new Date().getFullYear()} ${esc(b.firmName)} · ${esc(b.contact)}</footer>`;
  }
}
