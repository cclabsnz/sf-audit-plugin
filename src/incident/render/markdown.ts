// src/incident/render/markdown.ts
import type { IncidentResult } from '../analyse/index.js';
import type { buildEvidence } from './evidence.js';
import { CLASSIFICATION_LABEL, RESULT_LABEL } from './labels.js';

type Ev = ReturnType<typeof buildEvidence>;

/** Makes an org-sourced value safe to interpolate into Markdown (tables, headings, raw HTML). */
export const md = (s: string): string => s.replace(/\r?\n/g, ' ').replace(/\|/g, '\\|').replace(/</g, '&lt;');

export const NOTHING_ASSESSED = 'No Guest User Anomaly waves were found in the collected period, so nothing was assessed.';
export const WITHIN_BASELINE = 'Guest traffic stayed within baseline on every collected day.';

/** The "What this report can't tell you" box: org-wide limits plus every wave's, deduplicated. */
export function reportLimits(r: IncidentResult): string[] {
  return [...new Set([...r.globalLimits, ...r.waves.flatMap((w) => w.limits)])];
}

export function waveSentence(w: IncidentResult['waves'][number], ev: Ev): string {
  const id = w.wave.id;
  const spike = w.spikes.find((s) => s.isSpike);
  const parts: string[] = [];
  if (spike) parts.push(`${spike.controllerCalls.toLocaleString('en-NZ')} guest controller calls on ${spike.day}, ${spike.ratio!.toFixed(1)}× baseline ${ev.ref(`${id}:spike`)}`);
  if (w.actors.length) parts.push(`${w.actors.length} actor block(s), led by ${md(w.actors[0].block)} ${ev.ref(`${id}:actors`)}`);
  parts.push(`${w.outcomes.successfulLogins} successful login(s) from actor IPs ${ev.ref(`${id}:logins`)}`);
  parts.push(`${w.responses.returnedContent.length} of ${w.responses.dataAccessCalls} data-access replies larger than empty ${ev.ref(`${id}:returned`)}`);
  if (w.outcomes.identityLinks.length) parts.push(`actor IP later signed in as a user created through a guest site ${ev.ref(`${id}:links`)}`);
  return parts.join('; ') + '.';
}

export function renderMarkdown(r: IncidentResult, ev: Ev): string {
  const L: string[] = [];
  L.push(`# Guest-access incident report: ${md(r.orgName)}`, '', `Collected ${r.collectedAt}. Bundle manifest sha256 \`${r.manifestSha256}\`.`, '');
  L.push('## Summary', '');
  if (r.waves.length === 0) L.push(NOTHING_ASSESSED, '');
  else if (r.withinBaseline) L.push(WITHIN_BASELINE, '');
  for (const w of r.waves) {
    L.push(`### ${w.wave.id}: ${md(w.wave.site)}, ${w.wave.days.join(', ')}`, '',
      `- **Classification:** ${CLASSIFICATION_LABEL[w.classification]}`,
      `- **Result:** ${RESULT_LABEL[w.result]}`,
      `- **Evidence:** ${waveSentence(w, ev)}`, '');
  }
  L.push("### What this report can't tell you", '');
  for (const l of reportLimits(r)) L.push(`- ${md(l)}`);
  L.push('', '### Recommended next steps', '');
  for (const s of [...new Set(r.waves.flatMap((w) => w.nextSteps))]) L.push(`- ${md(s)}`);
  L.push('', '## Timeline', '', `Controller calls per guest user per day ${ev.ref('volumes')}.`, '', '| Day | Guest | Controller calls | Page loads |', '|---|---|---:|---:|');
  for (const v of r.volumes) L.push(`| ${v.day} | ${md(r.guests.find((g) => g.id15 === v.guestId15)?.siteNames[0] ?? v.guestId15)} | ${v.controllerCalls} | ${v.pageLoads} |`);
  for (const w of r.waves) {
    L.push('', `## ${w.wave.id} detail`, '', `Actors ${ev.ref(`${w.wave.id}:actors`)}:`, '');
    for (const a of w.actors) L.push(`- ${md(a.block)} (${a.ips.length} IPs), ${a.firstSeen} to ${a.lastSeen}, ${a.controllerCalls} controller calls, ${a.steady ? 'steady' : 'irregular'} volume, ${(a.emptyUaShare * 100).toFixed(0)}% empty user agent${a.markers.length ? `, scanner markers: ${md(a.markers.join(', '))}` : ''}${a.hostingAssessed ? `, hosting: ${md(a.hosting ?? 'none matched')}` : ''}.`);
    L.push('', `Actions by class ${ev.ref(`${w.wave.id}:actions`)}: ${Object.entries(w.actions.byClass).map(([k, v]) => `${k} ${v}`).join(', ')}.`);
    L.push(`Empty-reply size ${w.responses.emptySize ?? 'unknown'} bytes (±${w.responses.band}${w.responses.emptySizeInferred ? ', inferred from the replies under test' : ''}); ${w.responses.returnedContent.length} of ${w.responses.dataAccessCalls} data-access replies from any guest IP were larger ${ev.ref(`${w.wave.id}:returned`)}.`);
  }
  L.push('', '## Configuration changes', '', `${ev.ref('config')}`, '');
  for (const p of r.config.periods) L.push(`- **${md(p.label)}:** ${Object.entries(p.bySite).map(([s, cs]) => `${md(s)} ${cs.length}`).join(', ') || 'none'}${p.shared.length ? `; ${p.shared.length} change(s) to labels shared by several sites, not counted per site` : ''}`);
  for (const a of r.config.asymmetries) L.push(`- ${md(a.site)} was hit again in ${a.waveId} after ${a.changes} change(s) in ${md(a.period)}, while ${md(a.comparedSite)} received ${a.comparedChanges}.`);
  L.push('', '## Method', '',
    '- The primary measure is AuraRequest rows that carry a controller action. Page loads are counted separately.',
    '- Other event types record the same traffic at different layers; they corroborate and are never added together.',
    '- The anomaly detector\'s TotalControllerEvents is its own sample and is not compared with log counts.',
    '- Reply sizes come from the Sites log, reduced to one row per request id before joining. Bodies are never logged.',
    '', '### Gaps in collection', '');
  const gaps = r.coverage.logs.filter((l) => l.status !== 'collected');
  if (gaps.length) for (const g of gaps) L.push(`- ${md(g.type)} ${g.day} ${g.status}`);
  else L.push('None');
  L.push('', '## Evidence index', '');
  for (const t of ev.tables) L.push(`- **${t.id}** ${t.title} (${t.rows.length} rows)`);
  return L.join('\n') + '\n';
}
