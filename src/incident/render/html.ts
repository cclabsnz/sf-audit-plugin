// src/incident/render/html.ts
import { esc, fontFaceCss, type Branding } from '@cclabsnz/sf-core';
import { chartJsScript } from '../../renderers/chartAsset.js';
import { toolCreditHtml } from '../../renderers/toolCredit.js';
import type { IncidentResult } from '../analyse/index.js';
import type { buildEvidence } from './evidence.js';
import { CLASSIFICATION_LABEL, RESULT_LABEL, auraCollectedDays, coveredDays } from './labels.js';
import { NOTHING_ASSESSED, WITHIN_BASELINE, reportLimits, waveSentence } from './markdown.js';

type Ev = ReturnType<typeof buildEvidence>;

const RESULT_TONE: Record<string, string> = { 'access-gained': 'high', 'content-returned': 'medium', 'no-evidence': 'low', 'not-assessed': 'muted' };

function timelineData(r: IncidentResult) {
  const days = coveredDays(r.coverage.logs, r.volumes.map((v) => v.day));
  const aura = auraCollectedDays(r.coverage.logs);
  // null for a day whose AuraRequest log was not collected: Chart.js leaves a gap, never a zero.
  const series = r.guests.filter((g) => r.volumes.some((v) => v.guestId15 === g.id15)).map((g) => ({
    label: g.siteNames[0] ?? g.username,
    data: days.map((d) => (aura.has(d) ? r.volumes.find((v) => v.guestId15 === g.id15 && v.day === d)?.controllerCalls ?? 0 : null)),
  }));
  return { days, series, waveDays: [...new Set(r.waves.flatMap((w) => w.wave.days))] };
}

const RESULT_ORDER = ['access-gained', 'content-returned', 'no-evidence', 'not-assessed'];
const CHART_COLOURS = ['#175cd3', '#b54708', '#067647', '#667085', '#0e7090'];

const n = (v: number): string => v.toLocaleString('en-NZ');
const plural = (v: number, one: string, many = `${one}s`): string => `${n(v)} ${v === 1 ? one : many}`;
const stamp = (iso: string): string => iso.replace('T', ' ');

export function renderHtml(r: IncidentResult, ev: Ev, b: Branding): string {
  const tally = RESULT_ORDER.map((k) => ({ k, count: r.waves.filter((w) => w.result === k).length }))
    .filter((t) => t.count > 0)
    .map((t) => `<span class="chip tone-${RESULT_TONE[t.k]}">${n(t.count)} ${esc(RESULT_LABEL[t.k as keyof typeof RESULT_LABEL] ?? t.k)}</span>`).join('');
  const classes = [...new Set(r.waves.map((w) => w.classification))]
    .map((c) => `${r.waves.filter((w) => w.classification === c).length} ${CLASSIFICATION_LABEL[c].toLowerCase()}`).join(' · ');
  const scorecard = `<div class="scorecard"><div class="big">${n(r.waves.length)}</div>
    <div><div class="label">${r.waves.length === 1 ? 'Wave of guest traffic examined' : 'Waves of guest traffic examined'}</div>
    <div class="chips">${tally || '<span class="chip tone-muted">Nothing assessed</span>'}</div>
    <p class="tally">${r.waves.length === 0 ? esc(NOTHING_ASSESSED) : classes ? esc(classes) : ''}</p></div></div>`;
  const waves = r.waves.map((w) => `
    <article class="wave tone-${RESULT_TONE[w.result]}">
      <header><span class="wid">${esc(w.wave.id)}</span><h3>${esc(w.wave.site)}</h3><span class="days">${esc(w.wave.days.join(', '))}</span></header>
      <div class="verdict"><div><span class="label">Classification</span><strong>${esc(CLASSIFICATION_LABEL[w.classification])}</strong></div>
        <div><span class="label">Result</span><span class="chip solid tone-${RESULT_TONE[w.result]}">${esc(RESULT_LABEL[w.result])}</span></div></div>
      <p class="evidence">${esc(waveSentence(w, ev))}</p>
    </article>`).join('');
  const limits = reportLimits(r).map((l) => `<li>${esc(l)}</li>`).join('');
  const steps = [...new Set(r.waves.flatMap((w) => w.nextSteps))].map((s) => `<li>${esc(s)}</li>`).join('');
  const detail = r.waves.map((w) => `
    <div class="detail"><h3><span class="pnum">${esc(w.wave.id)}</span>${esc(w.wave.site)} · ${esc(w.wave.days.join(', '))}</h3>
      <div class="tablewrap"><table class="grid"><thead><tr><th>Block</th><th>Active (UTC)</th><th class="n">Controller calls</th><th>Volume</th><th class="n">Empty UA</th><th>Markers</th><th>Hosting</th></tr></thead><tbody>
      ${w.actors.map((a) => `<tr><td class="mono">${esc(a.block)} <small>(${plural(a.ips.length, 'IP')})</small></td><td>${esc(stamp(a.firstSeen.slice(0, 16)))} – ${esc(a.lastSeen.slice(11, 16))}</td><td class="n">${n(a.controllerCalls)}</td><td>${a.steady ? 'steady' : 'irregular'}</td><td class="n">${(a.emptyUaShare * 100).toFixed(0)}%</td><td>${esc(a.markers.join(', ') || '—')}</td><td>${esc(a.hostingAssessed ? (a.hosting ?? 'none matched') : 'not assessed')}</td></tr>`).join('') || '<tr><td colspan="7">No actor blocks above the outlier threshold.</td></tr>'}
      </tbody></table></div><p class="ref">${esc(ev.ref(`${w.wave.id}:actors`))}</p>
      <p>Actions by class: ${Object.entries(w.actions.byClass).map(([k, v]) => `${esc(k)} <b>${n(v)}</b>`).join(' · ')} <span class="ref">${esc(ev.ref(`${w.wave.id}:actions`))}</span></p>
      <p>Self-registrations during the actor window: ${w.outcomes.selfRegistrationsInActorWindow.length ? `${n(w.outcomes.selfRegistrationsInActorWindow.length)}, listed for review; the audit trail records no IP, so they are not attributed` : 'none'} <span class="ref">${esc(ev.ref(`${w.wave.id}:selfreg`))}</span></p>
      ${w.outcomes.selfRegistrationsInActorWindow.length ? `<ul>${w.outcomes.selfRegistrationsInActorWindow.map((x) => `<li><span class="mono">${esc(stamp(x.createdDate))}</span> ${esc(x.display)} <small>(by ${esc(x.createdBy)})</small></li>`).join('')}</ul>` : ''}
      <p>Empty-reply size <b>${w.responses.emptySize === null || w.responses.emptySize === undefined ? 'unknown' : `${n(w.responses.emptySize)} bytes`}</b> (±${w.responses.band}${w.responses.emptySizeInferred ? ', inferred from the replies under test' : ''}); <b>${n(w.responses.returnedContent.length)}</b> of ${n(w.responses.dataAccessCalls)} data-access replies from any guest IP were larger <span class="ref">${esc(ev.ref(`${w.wave.id}:returned`))}</span>.</p>
    </div>`).join('');
  const config = r.config.periods.map((p) => `<tr><td>${esc(p.label)}</td><td>${Object.entries(p.bySite).map(([s, cs]) => `${esc(s)} <b>${cs.length}</b>`).join(', ') || 'none'}${p.shared.length ? ` <small>(${p.shared.length} shared, not counted per site)</small>` : ''}</td></tr>`).join('');
  const asym = r.config.asymmetries.map((a) => `<p class="callout">${esc(a.site)} was hit again in ${esc(a.waveId)} after ${a.changes} change(s) in ${esc(a.period)}, while ${esc(a.comparedSite)} received ${a.comparedChanges}.</p>`).join('');
  const coverage = r.coverage.logs.filter((l) => l.status !== 'collected').map((l) => `<tr><td>${esc(l.type)}</td><td>${esc(l.day)}</td><td>${esc(l.status)}</td></tr>`).join('');
  const evidenceIndex = ev.tables.map((t) => `<li><b>${esc(t.id)}</b><span>${esc(t.title)} <small>(${plural(t.rows.length, 'row')})</small></span></li>`).join('');
  const chart = JSON.stringify({ ...timelineData(r), colours: CHART_COLOURS, ink: b.ink, muted: b.muted, border: b.border, font: b.fontBody }).replace(/</g, '\\u003c');
  const sec = (num: string, title: string): string => `<div class="sh"><span class="sec-num">${num} /</span><h2>${title}</h2></div>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Guest-access incident report: ${esc(r.orgName)}</title>
<style>${fontFaceCss()}
:root{--ink:${b.ink};--bg:${b.bg};--bgalt:${b.bgAlt};--muted:${b.muted};--border:${b.border};--primary:${b.primary};
--display:'${b.fontDisplay}',Georgia,serif;--body:'${b.fontBody}',system-ui,sans-serif;--mono:ui-monospace,'SF Mono',Menlo,monospace;
--high:#b42318;--medium:#b54708;--low:#067647;--unknown:#475467;}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 var(--body);font-variant-numeric:tabular-nums}
.wrap{max-width:860px;margin:0 auto;padding:64px 44px}
h1{font-family:var(--display);font-size:clamp(34px,6vw,52px);line-height:1.02;letter-spacing:-0.02em;margin:6px 0 0}
h2{font-family:var(--display);font-size:25px;letter-spacing:-0.01em;line-height:1.1;margin:0}
h3{font-family:var(--display);font-size:18px;letter-spacing:-0.01em;line-height:1.25;margin:0 0 6px}
p{margin:0 0 10px;max-width:70ch}
.label{font-family:var(--mono);text-transform:uppercase;letter-spacing:0.16em;font-size:11px;color:var(--muted)}
.meta{font-family:var(--mono);font-size:11px;letter-spacing:0.12em;color:var(--muted);text-transform:uppercase;margin-top:8px;line-height:1.7}
.muted{color:var(--muted)}small{color:var(--muted)}
.cover{padding-bottom:8px}
.scorecard{display:flex;align-items:center;gap:28px;margin:30px 0 8px;padding:22px 28px;background:var(--bgalt);border:1px solid var(--border);border-radius:12px;break-inside:avoid}
.big{font-family:var(--display);font-size:96px;line-height:0.86;font-weight:400}
.tally{margin:10px 0 0;font-size:13px;color:var(--muted)}
.scorecard>div{min-width:0}.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.chip{--c:var(--unknown);font-family:var(--mono);font-size:11px;letter-spacing:0.04em;font-weight:600;color:var(--c);border:1px solid var(--c);border-radius:999px;padding:2px 9px}
.chip.solid{background:var(--c);color:#fff}
.chip.tone-high{--c:var(--high)}.chip.tone-medium{--c:var(--medium)}.chip.tone-low{--c:var(--low)}.chip.tone-muted{--c:var(--unknown)}
.sh{display:flex;align-items:baseline;gap:14px;margin:56px 0 18px;border-bottom:1px solid var(--border);padding-bottom:10px;break-after:avoid}
.sec-num{font-family:var(--mono);font-size:13px;letter-spacing:0.1em;color:var(--primary)}
.waves{display:grid;gap:12px;margin:18px 0 22px}
.wave{--c:var(--unknown);border:1px solid var(--border);border-left:4px solid var(--c);border-radius:8px;padding:14px 18px 6px;background:var(--bgalt)}
.tone-high{--c:var(--high)}.tone-medium{--c:var(--medium)}.tone-low{--c:var(--low)}
.wave header{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}.wave h3{margin:0}
.wid,.pnum{font-family:var(--mono);font-weight:600;font-size:12px;letter-spacing:0.05em;color:var(--primary);margin-right:10px}.wave .wid{margin:0;color:var(--muted)}
.days{margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--muted)}
.verdict{display:flex;flex-wrap:wrap;gap:8px 40px;margin:12px 0 10px}.verdict .label{display:block;margin-bottom:3px}.verdict strong{display:block;font-weight:600}
.evidence{font-size:14px}
.limits{border:1px solid var(--border);border-left:4px solid var(--ink);border-radius:8px;padding:14px 20px 6px;background:var(--bg)}
.limits ul{padding-left:18px;margin:8px 0 10px}.limits li{margin-bottom:5px;max-width:70ch}
.steps{margin:28px 0 0}.steps h3{margin-bottom:8px}.steps ol{padding-left:22px;margin:0}.steps li{margin-bottom:5px;max-width:70ch}
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0}
th{text-align:left;font-family:var(--mono);text-transform:uppercase;letter-spacing:0.05em;font-size:10px;font-weight:400;color:var(--muted);border-bottom:1px solid var(--border);padding:6px 14px 6px 0;vertical-align:bottom;line-height:1.3}
td{padding:7px 14px 7px 0;border-bottom:1px solid var(--border);vertical-align:top}
th.n,td.n{text-align:right}td.n{font-variant-numeric:tabular-nums}td.mono{font-family:var(--mono);font-size:12px;white-space:nowrap}
.grid{font-size:12.5px}.grid td:nth-child(2){min-width:9em}
.detail{margin:0 0 30px}.detail h3{font-size:16px}
.ref{color:var(--muted);font:12px var(--mono)}
.callout{border-left:3px solid var(--medium);padding:8px 14px;background:var(--bgalt);border-radius:0 6px 6px 0}
.key{display:inline-block;width:12px;height:12px;background:rgba(181,71,8,0.18);border:1px solid rgba(181,71,8,0.5);vertical-align:-1px;margin-right:4px}
.chartbox{position:relative;border:1px solid var(--border);border-radius:8px;padding:12px;background:var(--bgalt);break-inside:avoid}
.chartbox canvas{display:block;width:100%}
.credit{margin-top:40px;font-size:12px}.credit a{color:inherit}
.method{padding-left:18px}.method li{margin-bottom:4px;max-width:70ch}
.index{list-style:none;margin:8px 0 0;padding:0;columns:2;column-gap:32px;font-size:13px}
.index li{display:flex;gap:10px;padding:4px 0;border-bottom:1px solid var(--border);break-inside:avoid}.index b{font-family:var(--mono);font-size:12px;color:var(--primary);min-width:34px;font-weight:600}
code{font-family:var(--mono);font-size:12px;word-break:break-all;text-transform:none;letter-spacing:0}
@media(max-width:600px){.wrap{padding:36px 18px}.scorecard{flex-direction:column;align-items:flex-start;gap:12px}.big{font-size:72px}.days{margin-left:0;flex-basis:100%}.index{columns:1}}
@page{margin:18mm}
@media print{.wrap{padding:0 0 24px;max-width:none}.sh{margin-top:36px}.wave,.detail,.limits,.scorecard{break-inside:avoid}.tablewrap{overflow:visible}}
</style></head><body><div class="wrap">
<header class="cover"><div class="label">${esc(b.firmName)}</div><h1>Guest-access incident report</h1>
<div class="meta">${esc(r.orgName)} · collected ${esc(stamp(r.collectedAt))}${b.preparedFor ? ` · prepared for ${esc(b.preparedFor)}` : ''}</div>
${scorecard}</header>
<section id="summary">${sec('01', 'Summary')}
${r.waves.length === 0 ? `<p>${esc(NOTHING_ASSESSED)}</p>` : r.withinBaseline ? `<p>${esc(WITHIN_BASELINE)}</p>` : ''}
<div class="waves">${waves}</div>
<div class="limits"><h3>What this report can't tell you</h3><ul>${limits}</ul></div>
<div class="steps"><h3>Recommended next steps</h3><ol>${steps}</ol></div></section>
<section id="timeline">${sec('02', 'Timeline')}<p>Guest controller calls per day, one line per site. <span class="key"></span>Shaded days are the wave days. A gap in a line is a day whose AuraRequest log was not collected. ${esc(ev.ref('volumes'))}</p><div class="chartbox"><canvas id="tl" height="130" role="img" aria-label="Guest controller calls per day, by site">Chart needs JavaScript. The daily counts are in the volumes evidence table.</canvas></div></section>
<section id="detail">${sec('03', 'Wave detail')}${detail}</section>
<section id="config">${sec('04', 'Configuration changes')}<div class="tablewrap"><table><thead><tr><th>Period</th><th>Changes by site</th></tr></thead><tbody>${config}</tbody></table></div>${asym}<p class="ref">${esc(ev.ref('config'))}</p></section>
<section id="method">${sec('05', 'Method and evidence')}
<ul class="method"><li>The primary measure is AuraRequest rows carrying a controller action; page loads are counted separately.</li>
<li>Other event types record the same traffic at different layers. They corroborate and are never added together.</li>
<li>The anomaly detector's TotalControllerEvents is its own sample and is not compared with log counts.</li>
<li>Reply sizes come from the Sites log, reduced to one row per request id before joining. Bodies are never logged.</li></ul>
${coverage ? `<h3>Gaps in collection</h3><div class="tablewrap"><table><thead><tr><th>Type</th><th>Day</th><th>Status</th></tr></thead><tbody>${coverage}</tbody></table></div>` : ''}
<p class="meta">Bundle manifest sha256 <code>${esc(r.manifestSha256)}</code></p>
<h3>Evidence index</h3><ul class="index">${evidenceIndex}</ul></section>
<p class="credit muted">${toolCreditHtml('incident-report')}</p>
</div>
<script>${chartJsScript()}</script>
<script>(function(){var d=${chart};var c=document.getElementById('tl');if(!c||!window.Chart)return;
Chart.defaults.font.family="'"+d.font+"',system-ui,sans-serif";Chart.defaults.color=d.muted;
var shade={id:'shade',beforeDraw:function(ch){var x=ch.scales.x,a=ch.chartArea,ctx=ch.ctx;ctx.save();ctx.fillStyle='rgba(181,71,8,0.12)';
d.days.forEach(function(day,i){if(d.waveDays.indexOf(day)<0)return;var w=x.getPixelForValue(1)-x.getPixelForValue(0);ctx.fillRect(x.getPixelForValue(i)-w/2,a.top,w,a.bottom-a.top);});ctx.restore();}};
new Chart(c,{type:'line',data:{labels:d.days,datasets:d.series.map(function(s,i){var col=d.colours[i%d.colours.length];return{label:s.label,data:s.data,tension:0.2,pointRadius:3,borderWidth:2,borderColor:col,backgroundColor:col};})},
options:{animation:false,responsive:true,plugins:{legend:{position:'bottom',labels:{usePointStyle:true,boxWidth:8}}},scales:{y:{beginAtZero:true,grid:{color:d.border},title:{display:true,text:'Controller calls'}},x:{grid:{display:false}}}},plugins:[shade]});})();</script>
</body></html>`;
}
