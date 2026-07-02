import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import type { EventLogAccess } from '../../context/AuditCache.js';
import { classifyEventLogAccessError } from '../eventLogAccess.js';

interface GuestUser {
  Id: string;
}
interface EventLogFileRec {
  Id: string;
  EventType: string;
  LogDate: string;
  LogFileLength: number;
}

/** One normalized guest request parsed from an EventLogFile CSV row. */
interface GuestReq {
  ip: string;
  eventType: string;
  query: string; // GraphQL/SOQL body, '' when the event type has none
}

// EventLogFile types that carry unauthenticated guest request traffic. Sites is
// the primary guest-page channel; AuraRequest and GraphQlQueryExecution are the
// data-access vectors abused for recon and bulk read.
const GUEST_EVENT_TYPES = ['Sites', 'AuraRequest', 'GraphQlQueryExecution'];

// Illustrative seed of publicly-documented datacenter/hosting network prefixes.
// NON-EXHAUSTIVE and heuristic — this is a starting example, NOT a curated threat
// feed. Replace/extend it from your own IP-reputation source. The rationale:
// legitimate portal visitors browse from consumer ISPs, so guest *data* access
// from datacenter/VPN egress is a useful abuse signal. Matched by string prefix
// on CLIENT_IP. (Ranges below are well-known cloud provider blocks.)
const HOSTING_ANONYMIZER_PREFIXES = [
  '2604:a880:', // DigitalOcean (IPv6)
  '137.184.',   // DigitalOcean
  '146.190.',   // DigitalOcean
  '159.223.',   // DigitalOcean
  '165.227.',   // DigitalOcean
];

const MAX_FILES = 20; // cap blobs downloaded per run
const MAX_FILE_BYTES = 60 * 1024 * 1024; // skip individual blobs larger than this
const BURST_THRESHOLD = 100; // guest requests from a single IP in the window
const RECON_DISTINCT_ENTITIES = 5; // distinct objects totalCount-probed from one IP

export class GuestTrafficAnomalyCheck implements SecurityCheck {
  readonly id = 'guest-traffic-anomaly';
  readonly name = 'Guest Traffic Anomaly';
  readonly category = 'Threat Detection';
  readonly description =
    'Scans recent EventLogFile guest requests for anonymizer/hosting source IPs, single-IP bursts, and GraphQL totalCount reconnaissance sweeps';

  // Reuse EventMonitoringCheck's EventLogFile probe (enabled? readable?) instead of re-querying.
  readonly dependsOnCache = ['eventLogSummary'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const setupUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/EventLogFile/home`;

    // Guest user ids — needed to attribute EventLogFile rows to guests.
    let guests: GuestUser[];
    try {
      guests = await ctx.soql.queryAll<GuestUser>(
        "SELECT Id FROM User WHERE UserType = 'Guest' AND IsActive = true",
      );
    } catch {
      findings.push(this.inconclusive('guest-traffic-anomaly-users-inaccessible', 'Guest users could not be queried'));
      return { findings };
    }
    if (guests.length === 0) {
      findings.push({
        id: 'guest-traffic-anomaly-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active guest users',
        detail: 'There are no active guest users, so there is no guest request traffic to analyze.',
        remediation: 'If a public site is added later, re-run to baseline guest traffic.',
      });
      return { findings };
    }
    // EventLogFile stores the 15- or 18-char id; compare on the 15-char prefix.
    const guestIds = new Set(guests.map((g) => g.Id.slice(0, 15)));

    // Reuse EventMonitoringCheck's cached EventLogFile probe (no extra API call):
    // decide whether it is even worth downloading blobs, and phrase the blind spot
    // precisely when Event Monitoring is off or the audit user can't read the logs.
    const summary = ctx.cache.eventLogSummary;
    if (summary && summary.accessible === false) {
      findings.push(this.accessBlind(summary.accessError ?? 'unknown', setupUrl));
      return { findings };
    }
    if (summary && summary.accessible === true) {
      if (summary.totalFiles === 0) {
        findings.push(this.noLogs('Event Monitoring is enabled but produced no EventLogFile blobs in the retention window.', setupUrl));
        return { findings };
      }
      if (!summary.eventTypes.some((t) => GUEST_EVENT_TYPES.includes(t))) {
        findings.push({
          id: 'guest-traffic-anomaly-clean',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'No guest request event types captured by Event Monitoring',
          detail: `Event Monitoring is active but captured none of ${GUEST_EVENT_TYPES.join('/')} recently, so there is no guest request traffic to analyze.`,
          remediation: 'Confirm the guest-facing site is live and that Sites/AuraRequest/GraphQlQueryExecution event types are captured.',
        });
        return { findings };
      }
    }

    // Which guest event-log blobs exist in the retention window.
    let files: EventLogFileRec[];
    try {
      const inList = GUEST_EVENT_TYPES.map((t) => `'${t}'`).join(', ');
      files = await ctx.soql.queryAll<EventLogFileRec>(
        `SELECT Id, EventType, LogDate, LogFileLength FROM EventLogFile
         WHERE EventType IN (${inList}) AND LogDate = LAST_N_DAYS:2 AND Interval = 'Daily'
         ORDER BY LogDate DESC`,
      );
    } catch (e) {
      // Standalone path (EventMonitoringCheck not in this run): classify the failure
      // so "is Event Monitoring enabled / does the user have permission?" is still answered.
      findings.push(this.accessBlind(classifyEventLogAccessError(e), setupUrl));
      return { findings };
    }

    if (files.length === 0) {
      findings.push(this.noLogs('No Sites/AuraRequest/GraphQlQueryExecution EventLogFile blobs were found in the last 2 days. Without Event Monitoring, retention is ~1 day, so absence here is BLIND, not proof of no abuse.', setupUrl));
      return { findings };
    }

    // Download + parse blobs (bounded), keeping only guest rows.
    const reqs: GuestReq[] = [];
    let parsedFiles = 0;
    for (const f of files.slice(0, MAX_FILES)) {
      if (f.LogFileLength > MAX_FILE_BYTES) continue;
      let csv: string;
      try {
        csv = await ctx.rest.get<string>(`/sobjects/EventLogFile/${f.Id}/LogFile`);
      } catch {
        continue;
      }
      if (typeof csv !== 'string' || csv.length === 0) continue;
      parsedFiles++;
      this.parseGuestRows(csv, f.EventType, guestIds, reqs);
    }

    if (parsedFiles === 0) {
      findings.push(this.inconclusive('guest-traffic-anomaly-blobs-unreadable', 'Guest event-log blobs could not be downloaded'));
      return { findings };
    }
    if (reqs.length === 0) {
      findings.push({
        id: 'guest-traffic-anomaly-clean',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `No guest requests in ${parsedFiles} event-log file(s)`,
        detail: 'The available guest event logs contained no rows attributable to an active guest user in the window.',
        remediation: 'Continue forwarding guest event logs to a SIEM for anomaly alerting.',
      });
      return { findings };
    }

    // --- Aggregate per source IP ------------------------------------------------
    const byIp = new Map<string, { total: number; reconEntities: Set<string>; anonymizer: boolean }>();
    for (const r of reqs) {
      if (!r.ip) continue;
      const agg = byIp.get(r.ip) ?? { total: 0, reconEntities: new Set<string>(), anonymizer: this.isHostingOrAnonymizer(r.ip) };
      agg.total++;
      if (r.eventType === 'GraphQlQueryExecution' && /totalcount/i.test(r.query)) {
        const entity = this.extractEntity(r.query);
        if (entity) agg.reconEntities.add(entity);
      }
      byIp.set(r.ip, agg);
    }

    const reconIps = [...byIp.entries()].filter(([, a]) => a.reconEntities.size >= RECON_DISTINCT_ENTITIES);
    const anonymizerIps = [...byIp.entries()].filter(([, a]) => a.anonymizer);
    const burstIps = [...byIp.entries()].filter(([, a]) => a.total >= BURST_THRESHOLD);

    if (reconIps.length > 0) {
      findings.push({
        id: 'guest-traffic-anomaly-recon',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${reconIps.length} source IP(s) ran a GraphQL object-enumeration (totalCount) sweep as a guest`,
        detail:
          'These unauthenticated source IPs issued GraphQL queries that request only totalCount across many distinct objects — the signature of reconnaissance that maps the guest-readable data surface before bulk extraction. This is exactly the pre-attack recon pattern seen through aura://RecordUiController/ACTION$executeGraphQL on Experience Cloud sites.',
        remediation:
          'Treat these IPs as hostile and block them at the WAF/CDN. Then close the surface they were mapping: set external OWD to Private, strip guest object read permissions, and enforce "Secure guest user record access". Enable Threat Detection storage and a Transaction Security Policy to catch this in real time.',
        affectedItems: reconIps
          .sort((a, b) => b[1].reconEntities.size - a[1].reconEntities.size)
          .slice(0, 20)
          .map(([ip, a]) => ({
            label: `${ip} — probed ${a.reconEntities.size} objects (${a.total} requests)`,
            note: [...a.reconEntities].slice(0, 12).join(', ') + (a.anonymizer ? ' [hosting/anonymizer IP]' : ''),
          })),
      });
    }

    if (anonymizerIps.length > 0) {
      findings.push({
        id: 'guest-traffic-anomaly-anonymizer',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${anonymizerIps.length} guest source IP(s) originate from hosting/anonymizer ranges`,
        detail:
          'Guest (unauthenticated) requests arrived from datacenter/VPN/anonymizer egress ranges. Legitimate portal visitors browse from consumer ISPs; automated scraping and exfiltration typically egress from hosting or VPN infrastructure. (The prefix list is a heuristic seed — corroborate against a full IP-reputation feed.)',
        remediation:
          'Correlate these IPs with what they accessed, block hostile ranges at the WAF/CDN, and consider geo/ASN restrictions for a geographically-bounded audience. Feed a maintained IP-reputation list into your SIEM alerting.',
        affectedItems: anonymizerIps
          .sort((a, b) => b[1].total - a[1].total)
          .slice(0, 20)
          .map(([ip, a]) => ({ label: `${ip} — ${a.total} guest request(s)`, note: a.reconEntities.size ? `also probed ${a.reconEntities.size} objects` : undefined })),
      });
    }

    if (burstIps.length > 0) {
      findings.push({
        id: 'guest-traffic-anomaly-burst',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${burstIps.length} source IP(s) generated high-volume guest request bursts`,
        detail:
          `A single source IP issued ${BURST_THRESHOLD}+ guest requests in the window, consistent with automated hammering (page/Aura endpoint flooding) rather than human browsing.`,
        remediation:
          'Rate-limit the Sites/Aura endpoints at the WAF/CDN and review whether these bursts correspond to scraping or a denial-of-service attempt.',
        affectedItems: burstIps
          .sort((a, b) => b[1].total - a[1].total)
          .slice(0, 20)
          .map(([ip, a]) => ({ label: `${ip} — ${a.total} guest request(s)`, note: a.anonymizer ? 'hosting/anonymizer IP' : undefined })),
      });
    }

    if (findings.length === 0) {
      findings.push({
        id: 'guest-traffic-anomaly-clean',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `No anomalous guest traffic in ${reqs.length} request(s)`,
        detail: `Analyzed ${reqs.length} guest request(s) across ${parsedFiles} event-log file(s): no hosting/anonymizer IPs, no totalCount recon sweeps, and no single-IP bursts above ${BURST_THRESHOLD}.`,
        remediation: 'Continue forwarding guest event logs to a SIEM; EventLogFile retention is short (~1–30 days), so durable alerting must live outside the org.',
      });
    }

    return { findings };
  }

  /** Parse an EventLogFile CSV, pushing guest-attributed rows into `out`. */
  private parseGuestRows(csv: string, eventType: string, guestIds: Set<string>, out: GuestReq[]): void {
    const rows = this.parseCsv(csv);
    if (rows.length < 2) return;
    const header = rows[0];
    const idx = (names: string[]) => names.map((n) => header.indexOf(n)).find((i) => i >= 0) ?? -1;
    const iUser = idx(['USER_ID_DERIVED', 'USER_ID']);
    const iIp = idx(['CLIENT_IP', 'SOURCE_IP']);
    const iQuery = idx(['QUERY', 'SOQL_QUERY']);
    if (iUser < 0) return; // cannot attribute to a guest
    for (let r = 1; r < rows.length; r++) {
      const row = rows[r];
      const uid = (row[iUser] ?? '').slice(0, 15);
      if (!guestIds.has(uid)) continue;
      out.push({
        ip: iIp >= 0 ? row[iIp] ?? '' : '',
        eventType,
        query: iQuery >= 0 ? row[iQuery] ?? '' : '',
      });
    }
  }

  /** Minimal RFC-4180-ish CSV parser (handles quoted fields and embedded commas/quotes). */
  private parseCsv(text: string): string[][] {
    const rows: string[][] = [];
    let field = '';
    let row: string[] = [];
    let inQuotes = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (inQuotes) {
        if (c === '"') {
          if (text[i + 1] === '"') { field += '"'; i++; }
          else inQuotes = false;
        } else field += c;
      } else if (c === '"') {
        inQuotes = true;
      } else if (c === ',') {
        row.push(field); field = '';
      } else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(field); field = '';
        if (row.length > 1 || row[0] !== '') rows.push(row);
        row = [];
      } else field += c;
    }
    if (field !== '' || row.length > 0) { row.push(field); rows.push(row); }
    return rows;
  }

  private isHostingOrAnonymizer(ip: string): boolean {
    return HOSTING_ANONYMIZER_PREFIXES.some((p) => ip.startsWith(p));
  }

  /** Object name from a UI-API GraphQL body: `uiapi { query { <Entity> ... } }`. */
  private extractEntity(query: string): string | null {
    const m = query.match(/uiapi\s*\{\s*query\s*\{\s*(\w+)/i);
    return m ? m[1] : null;
  }

  private inconclusive(id: string, what: string): Finding {
    return {
      id,
      category: this.category,
      riskLevel: 'INFO',
      inconclusive: true,
      title: `${what} (insufficient access)`,
      detail: 'The audit user could not gather guest request logs. This may indicate Event Monitoring is not licensed or the audit user lacks "View Event Log Files".',
      remediation: 'Grant "View Event Log Files" and ensure Event Monitoring is enabled, then re-run.',
    };
  }

  /** Blind spot: EventLogFile unreadable — distinguishes "not enabled" from "no permission". */
  private accessBlind(reason: EventLogAccess, setupUrl: string): Finding {
    const base = {
      id: 'guest-traffic-anomaly-inaccessible',
      category: this.category,
      riskLevel: 'INFO' as const,
      inconclusive: true,
      affectedItems: [{ label: 'Event Monitoring', url: setupUrl }],
    };
    if (reason === 'not-enabled') {
      return {
        ...base,
        title: 'Event Monitoring not enabled — guest traffic cannot be analyzed (BLIND)',
        detail:
          'EventLogFile is not accessible because Event Monitoring is not licensed/enabled in this org, so no guest request logs are captured. Anonymizer-IP, burst, and recon analysis cannot run — this is a blind spot, not an all-clear.',
        remediation:
          'License and enable Event Monitoring (Setup → Event Monitoring Settings), then forward guest event logs to a SIEM for durable retention and alerting.',
      };
    }
    if (reason === 'no-permission') {
      return {
        ...base,
        title: 'Audit user lacks "View Event Log Files" — guest traffic cannot be analyzed (BLIND)',
        detail:
          'Event Monitoring appears enabled, but the running audit user cannot read EventLogFile (missing the "View Event Log Files" permission). Guest request logs exist but are unreadable to this user, so the result is blind, not clean.',
        remediation: 'Grant the audit user the "View Event Log Files" permission (plus "API Enabled"), then re-run.',
      };
    }
    return {
      ...base,
      title: 'Guest request logs could not be read — analysis skipped (BLIND)',
      detail:
        'EventLogFile could not be queried, and the cause could not be attributed to a missing licence or a missing permission. The result is blind, not clean.',
      remediation: 'Verify Event Monitoring is enabled and the audit user holds "View Event Log Files", then re-run.',
    };
  }

  /** Event Monitoring readable, but no guest blobs in the (short) retention window. */
  private noLogs(detail: string, setupUrl: string): Finding {
    return {
      id: 'guest-traffic-anomaly-no-logs',
      category: this.category,
      riskLevel: 'LOW',
      passed: true,
      title: 'No guest event logs in the retention window',
      detail: `${detail} Stream logs to a SIEM for durable coverage.`,
      remediation: 'Enable Event Monitoring and forward guest event logs to a SIEM so this analysis has a durable window.',
      affectedItems: [{ label: 'Event Monitoring', url: setupUrl }],
    };
  }
}
