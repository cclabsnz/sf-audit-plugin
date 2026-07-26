import { fontFaceCss, type Branding } from '@cclabsnz/sf-core';

export interface DocumentOptions {
  title: string;
  subtitle?: string;
  branding: Branding;
  bodyHtml: string;
  generatedAt: string;
}

/**
 * The shared OrgIntel report shell: a full branded HTML document built from the core report
 * primitives (fontFaceCss, branding tokens). Reused by every `sf intel` HTML report so the
 * house style stays consistent. Self-contained (fonts inlined as data URIs) and print-friendly.
 */
export function htmlDocument(opts: DocumentOptions): string {
  const b = opts.branding;
  const generated = new Date(opts.generatedAt).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escAttr(opts.title)}</title>
<style>
${fontFaceCss()}
:root{
  --primary:${b.primary}; --ink:${b.ink}; --bg:${b.bg}; --bgAlt:${b.bgAlt};
  --muted:${b.muted}; --border:${b.border};
}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:'${b.fontBody}',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  font-size:15px;line-height:1.55}
.wrap{max-width:960px;margin:0 auto;padding:48px 40px 72px}
header.masthead{border-bottom:2px solid var(--primary);padding-bottom:20px;margin-bottom:32px}
.firm{font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:var(--primary);font-weight:600}
h1{font-family:'${b.fontDisplay}',Georgia,serif;font-weight:400;font-size:34px;margin:.35em 0 .1em}
.subtitle{color:var(--muted);font-size:15px;margin:0}
h2{font-family:'${b.fontDisplay}',Georgia,serif;font-weight:400;font-size:22px;
  margin:40px 0 14px;padding-bottom:6px;border-bottom:1px solid var(--border)}
table{width:100%;border-collapse:collapse;margin:6px 0 18px;font-size:14px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:600}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.chip{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;line-height:1.6}
.chip.full{background:#e3efe3;color:#2f6b34}
.chip.partial{background:#fbf1dd;color:#8a6d1e}
.chip.none{background:#f6e5e3;color:#9a3b30}
.tier{display:inline-flex;align-items:center;justify-content:center;width:64px;height:64px;
  border-radius:14px;background:var(--primary);color:#fff;font-family:'${b.fontDisplay}',serif;font-size:38px}
.tier-wrap{display:flex;gap:18px;align-items:center;margin:8px 0 4px}
.tier-label{font-size:14px;color:var(--muted);max-width:640px}
.kv{display:grid;grid-template-columns:190px 1fr;gap:2px 16px;margin:6px 0 8px;font-size:14px}
.kv dt{color:var(--muted)}
.kv dd{margin:0}
.rec{border-left:3px solid var(--primary);background:var(--bgAlt);padding:10px 14px;margin:8px 0;border-radius:0 6px 6px 0}
.rec .rt{font-weight:600}
.rec .rp{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.muted{color:var(--muted)}
footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:12px;display:flex;justify-content:space-between}
</style>
</head>
<body>
<div class="wrap">
<header class="masthead">
  <div class="firm">${escAttr(b.firmName)} · OrgIntel</div>
  <h1>${escAttr(opts.title)}</h1>
  ${opts.subtitle ? `<p class="subtitle">${escAttr(opts.subtitle)}</p>` : ''}
</header>
${opts.bodyHtml}
<footer>
  <span>${escAttr(b.contact)}</span>
  <span>Generated ${escAttr(generated)} · deterministic, local-only</span>
</footer>
</div>
</body>
</html>`;
}

function escAttr(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
