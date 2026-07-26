import { esc, type Branding } from '@cclabsnz/sf-core';
import type { ProbeResult, CoverageRow, Recommendation, ObjectHistoryCoverage } from '../probe/types.js';
import { htmlDocument } from './shell.js';

const TIER_BLURB: Record<string, string> = {
  A: 'Richest evidence: full Event Monitoring and Field Audit Trail. Process behaviour is highly observable.',
  B: 'Standard behavioural tables are readable with data — history and process rows are queryable.',
  C: 'Metadata and snapshots only. The org is describable, but little behavioural data is readable.',
  D: 'No evidence is currently readable. Prospective collection is recommended to build a baseline.',
};

export function renderProbeHtml(result: ProbeResult, branding: Branding): string {
  const subtitle = `${result.org.name} · ${result.org.organizationType}${
    result.org.isSandbox ? ' · Sandbox' : ''
  }`;
  const body = [
    tierSection(result),
    orgSection(result),
    coverageSection(result.coverage),
    eventMonitoringSection(result),
    fieldHistorySection(result),
    behavioralSection(result),
    recommendationsSection(result.recommendations),
  ].join('\n');

  return htmlDocument({
    title: 'Org Capability Probe',
    subtitle,
    branding,
    bodyHtml: body,
    generatedAt: result.provenance.generatedAt,
  });
}

function tierSection(r: ProbeResult): string {
  return `<section>
  <div class="tier-wrap">
    <div class="tier">${esc(r.evidenceTier)}</div>
    <div class="tier-label"><strong>Evidence tier ${esc(r.evidenceTier)}.</strong> ${esc(
      TIER_BLURB[r.evidenceTier] ?? '',
    )}</div>
  </div>
</section>`;
}

function orgSection(r: ProbeResult): string {
  const o = r.org;
  const rows: Array<[string, string]> = [
    ['Organization', `${o.name} (${o.orgId})`],
    ['Edition', o.organizationType],
    ['Type', o.isSandbox ? 'Sandbox' : 'Production'],
    ['Namespace', o.namespace ?? '—'],
    ['API version', o.apiVersion],
    ['Instance', o.instanceUrl],
  ];
  return `<h2>Org</h2>
<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`;
}

function coverageSection(rows: CoverageRow[]): string {
  const body = rows
    .map(
      (r) => `<tr><td>${esc(r.source)}</td><td>${chip(r.status)}</td><td>${esc(r.detail)}</td></tr>`,
    )
    .join('');
  return `<h2>Evidence coverage</h2>
<table><thead><tr><th>Source</th><th>Status</th><th>Detail</th></tr></thead><tbody>${body}</tbody></table>`;
}

function eventMonitoringSection(r: ProbeResult): string {
  const em = r.eventMonitoring;
  const types = em.eventTypes.length > 0 ? em.eventTypes.join(', ') : '—';
  return `<h2>Event Monitoring</h2>
<dl class="kv">
  <dt>Level</dt><dd>${esc(em.level)}</dd>
  <dt>Access</dt><dd>${esc(em.access)}</dd>
  <dt>Intervals</dt><dd>${esc(em.intervals.join(', ') || '—')}</dd>
  <dt>Event types (${em.eventTypeCount})</dt><dd>${esc(types)}</dd>
</dl>
<p class="muted">${esc(em.note)}</p>`;
}

function fieldHistorySection(r: ProbeResult): string {
  const fh = r.fieldHistory;
  const tracked = fh.objects.filter((o) => o.historyTrackingEnabled);
  const rows = tracked.length > 0 ? tracked.map(objectRow).join('') : `<tr><td colspan="4" class="muted">No objects have history tracking enabled.</td></tr>`;
  return `<h2>Field history</h2>
<p class="muted">${esc(fh.note)}</p>
<table><thead><tr><th>Object</th><th>Custom</th><th>Tracked fields</th><th>Fields (12mo changes)</th></tr></thead>
<tbody>${rows}</tbody></table>`;
}

function objectRow(o: ObjectHistoryCoverage): string {
  const count = o.trackedFieldCount === null ? '?' : String(o.trackedFieldCount);
  const cap = o.atCap ? ' <span class="chip partial">at cap</span>' : '';
  const fields = o.trackedFields.length > 0 ? o.trackedFields.join(', ') : '—';
  return `<tr><td>${esc(o.object)}</td><td>${o.custom ? 'yes' : 'no'}</td><td class="num">${esc(
    count,
  )}${cap}</td><td>${esc(fields)}</td></tr>`;
}

function behavioralSection(r: ProbeResult): string {
  const rows = r.behavioralTables.tables
    .map((t) => {
      const count = t.rowCount12mo === null ? '—' : t.rowCount12mo.toLocaleString('en-US');
      const extra = t.extra
        ? Object.entries(t.extra)
            .map(([k, v]) => `${k}: ${v}`)
            .join(', ')
        : t.note ?? '';
      return `<tr><td>${esc(t.name)}</td><td>${chip(
        t.access === 'ok' ? 'full' : t.access === 'no-access' ? 'partial' : 'none',
      )}</td><td class="num">${esc(count)}</td><td class="muted">${esc(extra)}</td></tr>`;
    })
    .join('');
  return `<h2>Behavioral tables <span class="muted" style="font-size:13px">(rows created, last 12 months)</span></h2>
<table><thead><tr><th>Table</th><th>Access</th><th>Rows (12mo)</th><th>Notes</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function recommendationsSection(recs: Recommendation[]): string {
  if (recs.length === 0) {
    return `<h2>Recommendations</h2><p class="muted">No coverage gaps detected — this org already exposes strong process evidence.</p>`;
  }
  const items = recs
    .map(
      (rec) => `<div class="rec"><div class="rp">${esc(rec.priority)} priority</div><div class="rt">${esc(
        rec.title,
      )}</div><div>${esc(rec.detail)}</div></div>`,
    )
    .join('');
  return `<h2>Recommendations — flip these switches to see more</h2>${items}`;
}

function chip(status: string): string {
  const cls = status === 'full' ? 'full' : status === 'partial' ? 'partial' : 'none';
  return `<span class="chip ${cls}">${esc(status)}</span>`;
}
