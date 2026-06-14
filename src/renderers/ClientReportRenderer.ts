import type { AuditResult } from '../findings/AuditResult.js';
import type { Finding } from '../findings/Finding.js';
import type { AuditRenderer } from './AuditRenderer.js';
import type { Branding } from '../report/branding.js';
import { esc } from './html-utils.js';
import { fontFaceCss } from '../report/fonts.js';
import { getCheckMeta } from '../findings/CheckMeta.js';
import { selectPriorities } from '../report/ExecutivePriorities.js';
import { buildRoadmap, type Roadmap } from '../report/RemediationRoadmap.js';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#7d3a3a', HIGH: '#a35a2a', MEDIUM: '#8a6d1f', LOW: '#3a5a82', INFO: '#636770',
};

export interface ClientReportOptions {
  branding: Branding;
  topN: number;
}

export class ClientReportRenderer implements AuditRenderer {
  public readonly format = 'executive';
  public readonly fileExtension = '.html';
  public readonly filenamePrefix = 'SF_Audit_Executive';

  public constructor(private readonly opts: ClientReportOptions) {}

  public render(result: AuditResult): string {
    const b = this.opts.branding;
    const chainIds = new Set<string>();
    for (const c of result.attackChains ?? []) for (const s of c.steps) chainIds.add(s.findingId);
    const priorities = selectPriorities(result.findings, chainIds, this.opts.topN);
    const roadmap = buildRoadmap(result.findings);

    return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Security Audit — ${esc(result.orgName)}</title>
<style>${fontFaceCss()}
:root{--ink:${b.ink};--bg:${b.bg};--bgalt:${b.bgAlt};--muted:${b.muted};--border:${b.border};--primary:${b.primary};}
*{box-sizing:border-box}
body{font-family:'${b.fontBody}',system-ui,sans-serif;color:var(--ink);background:var(--bg);margin:0;line-height:1.55}
.wrap{max-width:820px;margin:0 auto;padding:48px 40px}
h1,h2,h3{font-family:'${b.fontDisplay}',Georgia,serif;letter-spacing:-0.01em;line-height:1.15}
h1{font-size:34px;margin:0 0 4px} h2{font-size:24px;margin:40px 0 12px;border-bottom:1px solid var(--border);padding-bottom:6px}
h3{font-size:18px;margin:18px 0 4px}
.eyebrow{font-family:'${b.fontDisplay}',serif;color:var(--primary);font-size:13px}
.grade{font-family:'${b.fontDisplay}',serif;font-size:64px;color:var(--primary);line-height:1}
.muted{color:var(--muted)} .sev{font-weight:700;font-size:12px}
.card{background:var(--bgalt);border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin:10px 0}
.tier{font-family:'${b.fontDisplay}',serif;color:var(--primary);margin-top:14px}
footer{margin-top:48px;border-top:1px solid var(--border);padding-top:16px;color:var(--muted);font-size:12px}
@page{margin:18mm} @media print{.wrap{padding:0}h2{break-after:avoid}.card{break-inside:avoid}}
</style></head><body><div class="wrap">
${this.cover(result, b)}
${this.summary(result)}
${this.prioritiesSection(priorities, chainIds)}
${this.scenarios(result)}
${this.roadmapSection(roadmap)}
${this.findingsAppendix(result)}
${this.footer(b)}
</div></body></html>`;
  }

  private cover(r: AuditResult, b: Branding): string {
    const prepared = b.preparedFor ? ` for ${esc(b.preparedFor)}` : '';
    return `<header><div class="eyebrow">${esc(b.firmName)}</div>
<h1>Salesforce Security Audit</h1>
<p class="muted">${esc(r.orgName)} · ${esc(r.orgType)} · ${esc(r.orgId)} · ${r.generatedAt.toISOString().slice(0, 10)}</p>
<div class="grade">${esc(r.grade)}</div><p class="muted">Health score ${r.healthScore}/100 · Prepared by ${esc(b.firmName)}${prepared}</p></header>`;
  }

  private summary(r: AuditResult): string {
    const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
    const counts = levels
      .map((l) => `${r.findings.filter((f) => f.riskLevel === l && !f.passed && !f.inconclusive).length} ${l}`)
      .join(' · ');
    const incon = r.findings.filter((f) => f.inconclusive).length;
    return `<h2>Executive Summary</h2><p>This audit assessed the org’s security configuration and scored it <strong>${r.healthScore}/100 (Grade ${esc(r.grade)})</strong>. Findings by severity: ${counts}${incon ? ` · ${incon} inconclusive` : ''}. The priorities below are the highest-impact items to address first; see Scope &amp; Liability for the basis and limits of this assessment.</p>`;
  }

  private prioritiesSection(priorities: Finding[], chainIds: Set<string>): string {
    if (priorities.length === 0) return '<h2>Executive Priorities</h2><p class="muted">No active findings.</p>';
    const items = priorities.map((f, i) => {
      const meta = f.checkId ? getCheckMeta(f.checkId) : undefined;
      const chained = chainIds.has(f.id) ? '<p class="muted">Part of an attack chain — see Attack Scenarios.</p>' : '';
      const impact = meta ? `<p><strong>Impact:</strong> ${esc(meta.impact)}</p>` : '';
      return `<div class="card"><h3>${i + 1}. ${esc(f.title)} <span class="sev" style="color:${SEV_COLOR[f.riskLevel]}">${f.riskLevel}</span></h3>
${impact}${chained}<p><strong>Fix:</strong> ${esc(f.remediation)}</p></div>`;
    }).join('');
    return `<h2>Executive Priorities</h2><p class="muted">Focus areas, highest impact first.</p>${items}`;
  }

  private scenarios(r: AuditResult): string {
    const chains = r.attackChains ?? [];
    if (chains.length === 0) return '';
    const items = chains.map((c) => `<div class="card"><h3>${esc(c.title)} <span class="sev" style="color:${SEV_COLOR[c.severity]}">${c.severity}</span></h3>
<p>${esc(c.narrative)}</p><p><strong>Breaks the chain:</strong> ${esc(c.remediation)}</p></div>`).join('');
    return `<h2>Attack Scenarios</h2><p class="muted">How findings combine into real attack paths.</p>${items}`;
  }

  private roadmapSection(roadmap: Roadmap): string {
    const tier = (label: string, arr: Finding[]): string => {
      if (arr.length === 0) return '';
      const rows = arr.map((f) => `<li>${esc(f.title)} <span class="sev" style="color:${SEV_COLOR[f.riskLevel]}">${f.riskLevel}</span></li>`).join('');
      return `<div class="tier">${label}</div><ul>${rows}</ul>`;
    };
    return `<h2>Remediation Roadmap</h2>
${tier('Quick wins (≤1 day)', roadmap.quick)}
${tier('Moderate (days)', roadmap.moderate)}
${tier('Projects (weeks)', roadmap.project)}`;
  }

  private findingsAppendix(r: AuditResult): string {
    const rows = r.findings.map((f) => {
      const tag = f.inconclusive ? ' <span class="muted">(inconclusive)</span>' : f.passed ? ' <span class="muted">(passed)</span>' : '';
      return `<div class="card"><h3>${esc(f.title)} <span class="sev" style="color:${SEV_COLOR[f.riskLevel]}">${f.riskLevel}</span>${tag}</h3>
<p>${esc(f.detail)}</p><p class="muted"><strong>Remediation:</strong> ${esc(f.remediation)}</p></div>`;
    }).join('');
    return `<h2>All Findings</h2>${rows}`;
  }

  private footer(b: Branding): string {
    return `<footer><strong>Scope &amp; Liability.</strong> Read-only, point-in-time configuration review — not a penetration test, not a code audit. The grade is a prioritisation aid, not a certification. Validate findings before remediation. © ${new Date().getFullYear()} ${esc(b.firmName)} · ${esc(b.contact)}</footer>`;
  }
}
