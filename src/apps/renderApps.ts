import type { AppFinding } from './types.js';

export function renderJson(findings: AppFinding[]): string {
  return JSON.stringify(findings, null, 2);
}

export function renderMarkdown(findings: AppFinding[]): string {
  const lines = ['| App | Category | Confidence | Used | Over-granted | Scope |', '|---|---|---|---|---|---|'];
  for (const f of findings) {
    lines.push(
      `| ${f.app.name} | ${f.app.category} | ${f.app.confidence} | ${f.used.objects.length} objs | ` +
        `${f.overGrant.unusedObjects.length} objs | ${f.overGrant.scopeDowngrade ?? '-'} |`,
    );
  }
  return lines.join('\n');
}

export function renderTable(findings: AppFinding[]): string {
  const rows = findings.map((f) =>
    [
      f.app.name,
      f.app.category,
      f.app.confidence,
      `${f.used.objects.length}`,
      `${f.overGrant.unusedObjects.length}`,
      f.overGrant.scopeDowngrade ?? '-',
    ].join('  '),
  );
  return ['App  Category  Confidence  Used  OverGranted  Scope', ...rows].join('\n');
}
