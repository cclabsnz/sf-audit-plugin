import type { AuditResult } from '../findings/AuditResult.js';
import type { AuditRenderer } from './AuditRenderer.js';

function escapeMdCell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
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
    lines.push(`**Health Score:** ${result.healthScore}/100 | **Grade:** ${result.grade}`);
    lines.push('');
    lines.push(`## Findings (${result.findings.length})`);
    lines.push('');

    if (result.findings.length === 0) {
      lines.push('_No findings._');
    } else {
      for (const f of result.findings) {
        lines.push(`### [${f.riskLevel}] ${f.title}`);
        lines.push(`**Category:** ${f.category}`);
        lines.push('');
        lines.push(f.detail);
        lines.push('');
        lines.push(`**Remediation:** ${f.remediation}`);
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

    return lines.join('\n');
  }
}
