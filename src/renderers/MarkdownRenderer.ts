import type { AuditResult } from '../findings/AuditResult.js';
import type { AuditRenderer } from './AuditRenderer.js';
import { coverageSummary, coverageAdvice } from '../findings/coverage.js';
import type { Finding } from '../findings/Finding.js';
import { techniqueLabel } from '../threats/attack.js';
import { buildThreatView, threatRowStatusText, PRIVACY_COST_OF_LOGGING, type ThreatRow } from '../threats/view.js';

function escapeMdCell(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function threatTags(f: Finding): string {
  const parts: string[] = [];
  if (f.threats?.stride?.length) parts.push(`STRIDE ${f.threats.stride.join(' · ')}`);
  if (f.threats?.linddun?.length) parts.push(`LINDDUN ${f.threats.linddun.join(' · ')}`);
  if (f.threats?.attack?.length) parts.push(`ATT&CK ${f.threats.attack.join(' · ')}`);
  if (f.threats?.detects?.length) parts.push(`leaves unobserved: ${f.threats.detects.map(techniqueLabel).join(' · ')}`);
  return parts.join(' | ');
}

function threatTable(lines: string[], rows: ThreatRow<string>[]): void {
  lines.push('| Category | Coverage | Findings |');
  lines.push('| --- | --- | --- |');
  for (const r of rows) {
    const titles = r.findings.map((f) => escapeMdCell(f.title)).join('; ') || '—';
    lines.push(`| ${r.category}: ${r.name} | ${threatRowStatusText(r)} | ${titles} |`);
  }
}

export class MarkdownRenderer implements AuditRenderer {
  readonly format = 'md';
  readonly fileExtension = '.md';

  render(result: AuditResult): string {
    const lines: string[] = [];
    lines.push(`# Salesforce Security Audit Report`);
    lines.push(`**Org:** ${result.orgName} (${result.orgId})`);
    lines.push(`**Generated:** ${result.generatedAt.toISOString()}`);
    lines.push(`**Instance:** ${result.instance} | **Type:** ${result.orgType}${result.isSandbox ? ' (Sandbox)' : ''}`);
    lines.push(`**Health Score:** ${result.healthScore}/100 | **Grade:** ${result.grade}${result.gradeReason ? ` (${result.gradeReason})` : ''}`);
    if (result.coverage) {
      lines.push('');
      lines.push(`**${coverageSummary(result.coverage)}**`);
      if (result.coverage.notAssessed.length > 0) {
        lines.push(`Not assessed: ${result.coverage.notAssessed.map((id) => `\`${id}\``).join(', ')}`);
        lines.push('');
        lines.push(coverageAdvice(result.coverage));
      }
    }
    lines.push('');
    if (result.attackChains && result.attackChains.length > 0) {
      lines.push(`## Attack Paths (${result.attackChains.length})`);
      lines.push('');
      lines.push('_Combinations of findings that together enable an exploit more severe than any single finding._');
      lines.push('');
      for (const c of result.attackChains) {
        const conf = c.confidence === 'named' ? '' : ' _(potential)_';
        lines.push(`### [${c.severity}] ${c.title}${conf}`);
        lines.push('');
        if (c.abuseCase) {
          lines.push(`**Abuse case:** ${c.abuseCase.actor} wants to ${c.abuseCase.goal}.`);
          lines.push('');
        }
        lines.push(c.narrative);
        lines.push('');
        lines.push('**Steps:**');
        lines.push('');
        c.steps.forEach((s, i) => {
          const technique = s.techniques?.length ? ` → ${s.techniques.map(techniqueLabel).join(' · ')}` : '';
          const grants = s.capabilityInferred ? '' : `: grants \`${s.capability}\`${technique}`;
          const cut = s.breaksChain ? ' ✂ _break point_' : '';
          lines.push(`${i + 1}. **${s.title ?? s.findingId}** (${s.severity ?? '—'})${grants}${cut}`);
        });
        lines.push('');
        if (c.abuseCase) {
          lines.push(`**Breaks the chain:** ${c.abuseCase.breakPoint}`);
          lines.push('');
          lines.push(`**Remediation:** ${c.remediation}`);
        } else {
          lines.push(`**Recommended fixes:** ${c.remediation}`);
        }
        lines.push('');
        lines.push('---');
        lines.push('');
      }
    }
    lines.push(`## Findings (${result.findings.length})`);
    lines.push('');

    if (result.findings.length === 0) {
      lines.push('_No findings._');
    } else {
      for (const f of result.findings) {
        const levelLabel = f.inconclusive ? 'INCONCLUSIVE' : f.riskLevel;
        lines.push(`### [${levelLabel}] ${f.title}`);
        lines.push(`**Category:** ${f.category}`);
        lines.push('');
        lines.push(f.detail);
        lines.push('');
        lines.push(`**Remediation:** ${f.remediation}`);
        if (f.complianceTags?.length) {
          lines.push('');
          lines.push(`**Compliance:** ${f.complianceTags.join(' · ')}`);
        }
        const threats = threatTags(f);
        if (threats) {
          lines.push('');
          lines.push(`**Threats:** ${threats}`);
        }
        if (f.affectedItems?.length) {
          const hasUrls = f.affectedItems.some((i) => i.url);
          const hasNotes = f.affectedItems.some((i) => i.note);
          const headers = ['Item', ...(hasUrls ? ['Setup Link'] : []), ...(hasNotes ? ['Notes'] : [])];
          lines.push('');
          lines.push(`**Affected items (${f.affectedItems.length}):**`);
          lines.push('');
          lines.push(`| ${headers.join(' | ')} |`);
          lines.push(`| ${headers.map(() => '---').join(' | ')} |`);
          for (const item of f.affectedItems) {
            const cells = [
              escapeMdCell(item.label),
              ...(hasUrls ? [item.url ? `[Open ↗](${item.url})` : '—'] : []),
              ...(hasNotes ? [escapeMdCell(item.note ?? '')] : []),
            ];
            lines.push(`| ${cells.join(' | ')} |`);
          }
        }
        lines.push('');
        lines.push('---');
        lines.push('');
      }
    }

    const view = buildThreatView(result.findings);
    lines.push('');
    lines.push('## Threat View');
    lines.push('');
    lines.push('_Findings grouped by threat category. Coverage shows what this run looked at, not that a threat is absent._');
    lines.push('');
    lines.push('### STRIDE');
    lines.push('');
    threatTable(lines, view.stride);
    if (view.linddun) {
      lines.push('');
      lines.push('### LINDDUN (privacy)');
      lines.push('');
      threatTable(lines, view.linddun);
    }
    if (view.dualReadings.length > 0) {
      lines.push('');
      lines.push('### Logging, read both ways');
      lines.push('');
      lines.push(`Each of these is a repudiation gap (STRIDE R). ${PRIVACY_COST_OF_LOGGING}`);
      lines.push('');
      for (const f of view.dualReadings) lines.push(`- ${f.title}`);
    }

    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('> **Offline-first audit:** all analysis is performed locally; no data is transmitted outside your Salesforce org. Generated by [sf-audit](https://github.com/cclabsnz/sf-audit-plugin), built by [CloudCounsel](https://cloudcounsel.co.nz).');
    lines.push('');

    return lines.join('\n');
  }
}
