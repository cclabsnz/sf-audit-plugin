// src/commands/audit/timeline.ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { EventBaselineStore } from '@cclabsnz/sf-core';
import { parseWindow } from '../../timeline/parseWindow.js';
import { loadCaptures, resolveOrgId } from '../../timeline/loadCaptures.js';
import { assessCoverage } from '../../timeline/CaptureIndex.js';
import { correlate, DEFAULT_MAX_CARDINALITY, type Seed } from '../../timeline/CorrelationEngine.js';
import { normaliseRow } from '../../timeline/normalise.js';
import { renderCsv, renderJson, renderSummary } from '../../timeline/render.js';
import type { JoinKeyType } from '../../timeline/JoinKeys.js';
import type { EventSource } from '../../timeline/EventRow.js';

export interface TimelineResult {
  orgId: string;
  window: string;
  rows: number;
  coverage: string;
  refusals: number;
  written: string[];
}

/** `ip:1.2.3.4` — typed rather than inferred, so a value is never guessed at. */
const SEED_PREFIXES: Record<string, JoinKeyType> = {
  ip: 'clientIp',
  user: 'userId',
  session: 'sessionKey',
  request: 'requestId',
  login: 'loginKey',
  transaction: 'transactionId',
  event: 'eventIdentifier',
};

function parseSeed(raw: string): Seed {
  const at = raw.indexOf(':');
  const prefix = at === -1 ? '' : raw.slice(0, at);
  const type = SEED_PREFIXES[prefix];
  if (!type) {
    throw new Error(
      `Unrecognised seed "${raw}". Use one of ${Object.keys(SEED_PREFIXES).map((p) => `${p}:`).join(' ')} — ` +
        'for example ip:203.0.113.50. Types are explicit so a value is never guessed at.',
    );
  }
  const value = raw.slice(at + 1).trim();
  if (value === '') throw new Error(`Seed "${raw}" has no value.`);
  return { type, value };
}

export default class AuditTimelineCommand extends SfCommand<TimelineResult> {
  public static summary = 'Reconstruct one actor\'s activity across event types from local captures';
  public static description =
    'Correlates a seed (an address, user, session, request or transaction) across every captured EventLogFile type ' +
    'and Real-Time Event object, and writes a defensible timeline. Runs entirely offline against captures written ' +
    'by `sf audit events pull` — it opens no org connection, so it still works long after the org\'s retention ' +
    'window has expired or its credentials have been revoked. Attribution is recorded per row, expansion through ' +
    'shared identities is refused by default, and every output states what was captured so an empty result is ' +
    'never mistaken for a quiet one.';

  public static examples = [
    '<%= config.bin %> <%= command.id %> --window 2026-08-02T04:00Z/PT1H --seed ip:203.0.113.50',
    '<%= config.bin %> <%= command.id %> --org-id 00Dxx0000000000EAA --window 2026-08-02T04:00Z/PT1H --seed ip:203.0.113.50',
    '<%= config.bin %> <%= command.id %> --org-id 00Dxx0000000000EAA --window 2026-08-02T04:00Z/PT1H --seed user:005xx1 --allow-shared-identity',
    '<%= config.bin %> <%= command.id %> --org-id 00Dxx0000000000EAA --window 2026-08-02T04:00Z/PT2H --seed request:abc --format json',
  ];

  public static flags = {
    // Deliberately not requiredOrg(): this command reads disk and must not need, or take, a
    // live connection. The org id names which capture directory to read, and is optional
    // because the capture store is keyed by it — with one org captured there is nothing to
    // disambiguate, and making someone retype an eighteen-character id they cannot check by
    // eye only invites a typo that reads back as "no captures found".
    'org-id': Flags.string({
      summary: 'Org id whose captures to read. Inferred when only one org has captures. No org connection is opened.',
    }),
    input: Flags.string({
      summary: 'Capture base directory. Defaults to the events-pull location.',
    }),
    window: Flags.string({
      summary: 'ISO 8601 interval, <start>/<duration> or <start>/<end>.',
      required: true,
      helpValue: '2026-08-02T04:00Z/PT1H',
    }),
    seed: Flags.string({
      summary: 'Typed seed, repeatable: ip: user: session: request: transaction: event:',
      multiple: true,
      helpValue: 'ip:203.0.113.50',
    }),
    'allow-shared-identity': Flags.boolean({
      summary: 'Expand through identities shared by many actors. Off by default.',
      default: false,
    }),
    'max-cardinality': Flags.integer({
      summary: 'Distinct-actor ceiling above which a key is not expanded.',
      default: DEFAULT_MAX_CARDINALITY,
    }),
    format: Flags.string({
      summary: 'Comma-separated: csv,json,md. All three by default.',
      default: 'csv,json,md',
    }),
    output: Flags.string({
      summary: 'Directory to write the timeline into.',
      default: '.',
    }),
  };

  public async run(): Promise<TimelineResult> {
    const { flags } = await this.parse(AuditTimelineCommand);

    const window = parseWindow(flags.window);
    const seeds = (flags.seed ?? []).map(parseSeed);
    const base = flags.input ?? EventBaselineStore.defaultRoot();
    const orgId = resolveOrgId(base, flags['org-id']);

    const loaded = loadCaptures({
      base, orgId, date: window.date, hours: window.hours,
      startMs: window.startMs, endMs: window.endMs,
    });

    // Fail fast rather than reporting a confident emptiness. An operator who has not captured
    // the window needs the command that captures it, not a clean bill of health.
    if (!loaded.windowPresent) {
      throw new Error(
        `No captures for ${flags.window} under ${path.join(base, orgId)}.\n` +
          'The org is captured but not that window. Capture it:  sf audit events pull --target-org <alias>',
      );
    }

    const coverage = assessCoverage({ coverage: loaded.coverage });
    const result = correlate(loaded.rows, seeds, {
      maxCardinality: flags['max-cardinality'],
      allowSharedIdentity: flags['allow-shared-identity'],
    });

    const rows = result.rows.map((correlated, i) =>
      normaliseRow(correlated.row, {
        seq: i + 1,
        attribution: correlated.attribution,
        source: (correlated.row.__source as EventSource) ?? 'EventLogFile',
      }),
    );

    const output = {
      window: flags.window,
      seeds,
      rows,
      refusals: result.refusals,
      expandedThrough: result.expandedThrough,
      coverage,
    };

    const formats = new Set(flags.format.split(',').map((f) => f.trim().toLowerCase()).filter(Boolean));
    fs.mkdirSync(flags.output, { recursive: true });

    const written: string[] = [];
    const write = (name: string, body: string): void => {
      const target = path.join(flags.output, name);
      fs.writeFileSync(target, body, 'utf-8');
      written.push(target);
    };

    if (formats.has('csv')) write('timeline.csv', renderCsv(output));
    if (formats.has('json')) write('timeline.json', renderJson(output));
    if (formats.has('md')) write('summary.md', renderSummary(output));

    // Coverage first on the console too, for the same reason it leads the file outputs.
    if (!flags['org-id']) this.log(`Org: ${orgId} (only org with captures under ${base})`);
    this.log(coverage.banner());
    this.log('');
    this.log(coverage.statement(rows.length));
    if (loaded.malformed > 0 || loaded.unreadable > 0) {
      this.log(`Skipped ${loaded.malformed} unparseable line(s) and ${loaded.unreadable} unreadable file(s).`);
    }
    if (loaded.undated > 0) {
      // Kept rather than dropped, and said out loud: these rows could not be placed in or out
      // of the window, so a reader needs to know they are here on sufferance.
      this.log(`${loaded.undated} row(s) had no readable timestamp and were kept regardless of the window.`);
    }
    for (const refusal of result.refusals) {
      this.log(
        `Expansion refused: ${refusal.type} ${refusal.value} is shared by ${refusal.cardinality} ` +
          `distinct addresses (threshold ${refusal.threshold}). Override with --allow-shared-identity.`,
      );
    }
    for (const target of written) this.log(`Written: ${target}`);

    return {
      orgId,
      window: flags.window,
      rows: rows.length,
      coverage: coverage.state,
      refusals: result.refusals.length,
      written,
    };
  }
}
