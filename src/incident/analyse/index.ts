// src/incident/analyse/index.ts
import { readFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { loadBundle } from '../bundleIo.js';
import { DEFAULTS, REQUIRED_LOG_TYPES, type AuditCoverage, type BundleManifest, type Classification, type GuestUser, type LogCoverage, type RunningUserLimits, type WaveOutcome } from '../model.js';
import { loadIpRanges } from '../ipRanges.js';
import { findActors } from './actors.js';
import { summariseActionCounts, type ActionSummary } from './actions.js';
import { assessSpikes, computeDayVolumes, type DayVolume } from './baseline.js';
import { computeConfigDelta, type Asymmetry, type Period } from './configDelta.js';
import { computeOutcomes } from './outcomes.js';
import { analyseResponses } from './responses.js';
import { classify, globalLimitsFor, limitsFor, nextStepsFor, outcomeOf, type VerdictInput } from './verdict.js';

export { FORBIDDEN_WORDS } from './verdict.js';

export interface WaveResult extends VerdictInput {
  actions: ActionSummary;
  classification: Classification;
  result: WaveOutcome;
  limits: string[];
  nextSteps: string[];
  asymmetries: Asymmetry[];
}

export interface IncidentResult {
  orgId: string;
  orgName: string;
  collectedAt: string;
  manifestSha256: string;
  guests: GuestUser[];
  volumes: DayVolume[];
  waves: WaveResult[];
  /** Org-wide limits, shown with the per-wave limits even when there are zero waves. */
  globalLimits: string[];
  config: { periods: Period[]; asymmetries: Asymmetry[] };
  coverage: { logs: LogCoverage[]; audit: AuditCoverage; limits: RunningUserLimits; detectorAvailable: boolean; ipRanges: string[] };
  withinBaseline: boolean;
}

function requiredPresent(m: BundleManifest, days: string[]): boolean {
  return days.every((d) => REQUIRED_LOG_TYPES.every((t) => m.logs.some((l) => l.type === t && l.day === d && l.status === 'collected')));
}

export async function analyseBundle(dir: string, opts: { spikeRatio?: number } = {}): Promise<IncidentResult> {
  const b = await loadBundle(dir);
  const m = b.manifest;
  const ranges = m.ipRangeFiles.length
    ? loadIpRanges(m.ipRangeFiles.map((rel) => ({ name: basename(rel), text: readFileSync(join(dir, rel), 'utf-8') })))
    : null;
  const volumes = await computeDayVolumes(b);
  const config = computeConfigDelta(b.audit, m.guests, m.waves);

  const waves: WaveResult[] = [];
  for (const wave of m.waves) {
    const actors = await findActors(b, wave, ranges);
    const v: VerdictInput = {
      wave,
      spikes: assessSpikes(b, volumes, wave, opts.spikeRatio ?? DEFAULTS.spikeRatio),
      actors,
      responses: await analyseResponses(b, wave, actors),
      outcomes: computeOutcomes(b, wave, actors),
      requiredLogsPresent: requiredPresent(m, wave.days),
    };
    const asymmetries = config.asymmetries.filter((a) => a.waveId === wave.id);
    waves.push({
      ...v,
      actions: summariseActionCounts(actors.map((a) => a.actionCounts)),
      classification: classify(v),
      result: outcomeOf(v),
      limits: limitsFor(v),
      nextSteps: nextStepsFor(v, asymmetries, m),
      asymmetries,
    });
  }

  return {
    orgId: m.orgId,
    orgName: m.orgName,
    collectedAt: m.collectedAt,
    manifestSha256: b.manifestSha256,
    guests: m.guests,
    volumes,
    waves,
    globalLimits: globalLimitsFor(m),
    config,
    coverage: { logs: m.logs, audit: m.audit, limits: m.limits, detectorAvailable: m.detectorAvailable, ipRanges: m.ipRangeFiles },
    // Zero waves, or a wave with no baseline, is "nothing assessed", never "within baseline".
    withinBaseline: waves.length > 0 && waves.every((w) => w.requiredLogsPresent
      && w.spikes.every((s) => s.baselineMedian !== null)
      && !w.spikes.some((s) => s.isSpike)
      && w.actors.length === 0),
  };
}
