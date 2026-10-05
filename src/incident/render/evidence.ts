// src/incident/render/evidence.ts
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { csvLine } from '../csv.js';
import type { IncidentResult } from '../analyse/index.js';

export interface EvidenceTable { id: string; key: string; title: string; columns: string[]; rows: string[][] }

/** Every number in the report cites one of these tables; ids are assigned in a fixed order. */
export function buildEvidence(r: IncidentResult): { tables: EvidenceTable[]; ref(key: string): string } {
  const raw: Array<Omit<EvidenceTable, 'id'>> = [];
  raw.push({ key: 'volumes', title: 'Guest controller calls and page loads per day', columns: ['day', 'guest', 'controller_calls', 'page_loads'],
    rows: r.volumes.map((v) => [v.day, v.guestId15, String(v.controllerCalls), String(v.pageLoads)]) });
  for (const w of r.waves) {
    const id = w.wave.id;
    raw.push({ key: `${id}:spike`, title: `${id} spike assessment`, columns: ['day', 'controller_calls', 'baseline_median', 'ratio', 'detector_sample'],
      rows: w.spikes.map((s) => [s.day, String(s.controllerCalls), String(s.baselineMedian ?? ''), s.ratio === null ? '' : s.ratio.toFixed(2), String(s.detectorSample ?? '')]) });
    raw.push({ key: `${id}:actors`, title: `${id} actors`, columns: ['actor', 'block', 'ips', 'first_seen', 'last_seen', 'controller_calls', 'steady', 'empty_ua_share', 'markers', 'hosting'],
      rows: w.actors.map((a) => [a.id, a.block, a.ips.join(' '), a.firstSeen, a.lastSeen, String(a.controllerCalls), String(a.steady), a.emptyUaShare.toFixed(2), a.markers.join(' '), a.hostingAssessed ? (a.hosting ?? 'none') : 'not assessed']) });
    raw.push({ key: `${id}:actions`, title: `${id} actions invoked by actors`, columns: ['action', 'class', 'count'],
      rows: w.actions.byName.map((x) => [x.name, x.cls, String(x.count)]) });
    raw.push({ key: `${id}:returned`, title: `${id} data-access replies larger than the empty size`, columns: ['timestamp', 'request_id', 'ip', 'actor', 'size_bytes', 'actions'],
      rows: w.responses.returnedContent.map((x) => [x.timestamp, x.requestId, x.ip, x.actorId || '(none isolated)', String(x.size), x.actions.join(' ')]) });
    raw.push({ key: `${id}:logins`, title: `${id} logins from actor IPs (no date bound)`, columns: ['login_time', 'ip', 'user', 'status', 'actor'],
      rows: w.outcomes.actorLogins.map((l) => [l.loginTime, l.sourceIp, l.userId15, l.status, l.actorId]) });
    raw.push({ key: `${id}:links`, title: `${id} identity links`, columns: ['ip', 'user', 'name', 'email', 'created', 'created_by', 'login_time'],
      rows: w.outcomes.identityLinks.map((l) => [l.ip, l.userId15, l.userName, l.email, l.userCreatedDate, l.createdByGuest, l.loginTime]) });
  }
  raw.push({ key: 'config', title: 'Guest-access configuration changes by period and site', columns: ['period', 'site', 'at', 'by', 'section', 'change'],
    rows: r.config.periods.flatMap((p) => [
      ...Object.entries(p.bySite).flatMap(([site, cs]) => cs.map((c) => [p.label, site, c.at, c.by, c.section ?? '', c.display])),
      ...p.shared.map((c) => [p.label, '(shared by several sites)', c.at, c.by, c.section ?? '', c.display]),
    ]) });
  raw.push({ key: 'coverage', title: 'Collection coverage', columns: ['type', 'day', 'status', 'total_rows', 'guest_rows', 'malformed', 'detail'],
    rows: r.coverage.logs.map((l) => [l.type, l.day, l.status, String(l.totalRows), String(l.guestRows), String(l.malformed), l.detail ?? '']) });
  const tables = raw.map((t, i) => ({ id: `E${i + 1}`, ...t }));
  const byKey = new Map(tables.map((t) => [t.key, t.id]));
  return { tables, ref: (key) => (byKey.has(key) ? `[${byKey.get(key)}]` : '') };
}

/** Spreadsheet formula-injection guard, applied to written files only (csvLine stays raw for the log filter). */
const neutralise = (c: string): string => (/^[=+\-@\t\r]/.test(c) ? `'${c}` : c);

export function writeEvidence(dir: string, tables: EvidenceTable[]): string[] {
  mkdirSync(join(dir, 'evidence'), { recursive: true });
  return tables.map((t) => {
    const p = join(dir, 'evidence', `${t.id}.csv`);
    writeFileSync(p, csvLine(t.columns.map(neutralise)) + t.rows.map((row) => csvLine(row.map(neutralise))).join(''));
    return p;
  });
}
