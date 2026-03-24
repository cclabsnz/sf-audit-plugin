import type { AuditResult } from '../findings/AuditResult.js';
import type { AuditRenderer } from './AuditRenderer.js';

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#d97706',
  LOW: '#2563eb',
  INFO: '#64748b',
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
    const findingsHtml =
      result.findings.length === 0
        ? '<p style="color:#94a3b8">No findings.</p>'
        : result.findings
            .map(
              (f) => `
  <div style="background:#1a1a2e;border:1px solid #334155;border-radius:8px;padding:1rem;margin:0.75rem 0">
    <span style="background:${RISK_COLORS[f.riskLevel] ?? '#666'};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:700;margin-right:0.5rem">${esc(f.riskLevel)}</span>
    <strong>${esc(f.title)}</strong>
    <p style="color:#94a3b8;font-size:0.85rem;margin:0.25rem 0 0">${esc(f.category)}</p>
    <p style="margin:0.5rem 0">${esc(f.detail)}</p>
    <p style="margin:0"><strong>Remediation:</strong> ${esc(f.remediation)}</p>
    ${f.affectedItems?.length ? `<p style="margin:0.25rem 0 0;font-size:0.85rem;color:#94a3b8"><strong>Affected:</strong> ${f.affectedItems.map(esc).join(', ')}</p>` : ''}
  </div>`,
            )
            .join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SF Security Audit — ${esc(result.orgName)}</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background:#0f1117; color:#e2e8f0; max-width:960px; margin:2rem auto; padding:0 1rem; }
  h1 { color:#fff; font-size:1.5rem; margin:0 0 0.25rem }
  .meta { color:#94a3b8; font-size:0.875rem; margin:0 0 1.5rem }
  .score { font-size:2.5rem; font-weight:700; margin:0 0 0.25rem }
  .grade { font-size:1.1rem; color:#94a3b8 }
  h2 { color:#cbd5e1; font-size:1.1rem; margin:1.5rem 0 0.5rem }
</style>
</head>
<body>
<h1>Salesforce Security Audit</h1>
<p class="meta">
  Org: <strong>${esc(result.orgName)}</strong> (${esc(result.orgId)}) &nbsp;·&nbsp;
  Instance: ${esc(result.instance)} &nbsp;·&nbsp;
  Type: ${esc(result.orgType)}${result.isSandbox ? ' (Sandbox)' : ''} &nbsp;·&nbsp;
  Generated: ${result.generatedAt.toISOString()}
</p>
<p class="score">${result.healthScore}<span style="font-size:1rem;color:#64748b">/100</span></p>
<p class="grade">Grade: <strong>${result.grade}</strong> &nbsp;·&nbsp; ${result.findings.length} finding${result.findings.length !== 1 ? 's' : ''}</p>
<h2>Findings</h2>
${findingsHtml}
</body>
</html>`;
  }
}
