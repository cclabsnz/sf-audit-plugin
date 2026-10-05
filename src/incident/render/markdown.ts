// src/incident/render/markdown.ts
import type { IncidentResult } from '../analyse/index.js';
import type { buildEvidence } from './evidence.js';
import { CLASSIFICATION_LABEL, RESULT_LABEL } from './labels.js';

type Ev = ReturnType<typeof buildEvidence>;

export function waveSentence(w: IncidentResult['waves'][number], ev: Ev): string {
  const id = w.wave.id;
  const spike = w.spikes.find((s) => s.isSpike);
  const parts: string[] = [];
  if (spike) parts.push(`${spike.controllerCalls.toLocaleString('en-NZ')} guest controller calls on ${spike.day}, ${spike.ratio!.toFixed(1)}× baseline ${ev.ref(`${id}:spike`)}`);
  if (w.actors.length) parts.push(`${w.actors.length} actor block(s), led by ${w.actors[0].block} ${ev.ref(`${id}:actors`)}`);
  parts.push(`${w.outcomes.successfulLogins} successful login(s) from actor IPs ${ev.ref(`${id}:logins`)}`);
  parts.push(`${w.responses.returnedContent.length} of ${w.responses.dataAccessCalls} data-access replies larger than empty ${ev.ref(`${id}:returned`)}`);
  if (w.outcomes.identityLinks.length) parts.push(`actor IP later signed in as a user created through a guest site ${ev.ref(`${id}:links`)}`);
  return parts.join('; ') + '.';
}

export function renderMarkdown(r: IncidentResult, ev: Ev): string {
  const L: string[] = [];
  L.push(`# Guest-access incident report: ${r.orgName}`, '', `Collected ${r.collectedAt}. Bundle manifest sha256 \`${r.manifestSha256}\`.`, '');
  L.push('## Summary', '');
  if (r.withinBaseline) L.push('Guest traffic stayed within baseline on every collected day.', '');
  for (const w of r.waves) {
    L.push(`### ${w.wave.id}: ${w.wave.site}, ${w.wave.days.join(', ')}`, '',
      `- **Classification:** ${CLASSIFICATION_LABEL[w.classification]}`,
      `- **Result:** ${RESULT_LABEL[w.result]}`,
      `- **Evidence:** ${waveSentence(w, ev)}`, '');
  }
  L.push("### What this report can't tell you", '');
  for (const l of [...new Set(r.waves.flatMap((w) => w.limits))]) L.push(`- ${l}`);
  L.push('', '### Recommended next steps', '');
  for (const s of [...new Set(r.waves.flatMap((w) => w.nextSteps))]) L.push(`- ${s}`);
  L.push('', '## Timeline', '', `Controller calls per guest user per day ${ev.ref('volumes')}.`, '', '| Day | Guest | Controller calls | Page loads |', '|---|---|---:|---:|');
  for (const v of r.volumes) L.push(`| ${v.day} | ${r.guests.find((g) => g.id15 === v.guestId15)?.siteNames[0] ?? v.guestId15} | ${v.controllerCalls} | ${v.pageLoads} |`);
  for (const w of r.waves) {
    L.push('', `## ${w.wave.id} detail`, '', `Actors ${ev.ref(`${w.wave.id}:actors`)}:`, '');
    for (const a of w.actors) L.push(`- ${a.block} (${a.ips.length} IPs), ${a.firstSeen} to ${a.lastSeen}, ${a.controllerCalls} controller calls, ${a.steady ? 'steady' : 'irregular'} volume, ${(a.emptyUaShare * 100).toFixed(0)}% empty user agent${a.markers.length ? `, scanner markers: ${a.markers.join(', ')}` : ''}${a.hostingAssessed ? `, hosting: ${a.hosting ?? 'none matched'}` : ''}.`);
    L.push('', `Actions by class ${ev.ref(`${w.wave.id}:actions`)}: ${Object.entries(w.actions.byClass).map(([k, v]) => `${k} ${v}`).join(', ')}.`);
    L.push(`Empty-reply size ${w.responses.emptySize ?? 'unknown'} bytes (±${w.responses.band}).`);
  }
  L.push('', '## Configuration changes', '', `${ev.ref('config')}`, '');
  for (const p of r.config.periods) L.push(`- **${p.label}:** ${Object.entries(p.bySite).map(([s, cs]) => `${s} ${cs.length}`).join(', ') || 'none'}${p.shared.length ? `; ${p.shared.length} change(s) to labels shared by several sites, not counted per site` : ''}`);
  for (const a of r.config.asymmetries) L.push(`- ${a.site} was hit again in ${a.waveId} after ${a.changes} change(s) in ${a.period}, while ${a.comparedSite} received ${a.comparedChanges}.`);
  L.push('', '## Method', '',
    '- The primary measure is AuraRequest rows that carry a controller action. Page loads are counted separately.',
    '- Other event types record the same traffic at different layers; they corroborate and are never added together.',
    '- The anomaly detector\'s TotalControllerEvents is its own sample and is not compared with log counts.',
    '- Reply sizes come from the Sites log, reduced to one row per request id before joining. Bodies are never logged.',
    '', '## Evidence index', '');
  for (const t of ev.tables) L.push(`- **${t.id}** ${t.title} (${t.rows.length} rows)`);
  return L.join('\n') + '\n';
}
