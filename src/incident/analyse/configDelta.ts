import type { AuditRow, GuestUser, Wave } from '../model.js';
import { isSelfRegistration } from './outcomes.js';

export interface ConfigChange { at: string; by: string; section: string | null; display: string; sites: string[] }
export interface Period { label: string; from: string | null; to: string | null; bySite: Record<string, ConfigChange[]> }
export interface Asymmetry { waveId: string; site: string; changes: number; comparedSite: string; comparedChanges: number; period: string }

function siteOf(g: GuestUser): string { return g.siteNames[0] ?? g.username; }

function sitesTouched(row: AuditRow, guests: GuestUser[]): string[] {
  const text = row.display.toLowerCase();
  return guests.filter((g) => [g.profileName, g.name, ...g.permissionSetLabels, ...g.siteNames]
    .some((label) => label && text.includes(label.toLowerCase()))).map(siteOf);
}

export function computeConfigDelta(audit: AuditRow[], guests: GuestUser[], waves: Wave[]): { periods: Period[]; asymmetries: Asymmetry[] } {
  const changes: ConfigChange[] = audit.filter((r) => !isSelfRegistration(r))
    .map((r) => ({ at: r.createdDate, by: r.createdBy, section: r.section, display: r.display, sites: sitesTouched(r, guests) }))
    .filter((c) => c.sites.length > 0)
    .sort((a, c) => a.at.localeCompare(c.at));

  // Merge waves into distinct windows (several sites can share a day).
  const spans = [...new Map(waves.map((w) => [`${w.days[0]}|${w.days[w.days.length - 1]}`, [w.days[0], w.days[w.days.length - 1]] as const])).values()]
    .sort((a, c) => a[0].localeCompare(c[0]));
  const bounds: Array<{ label: string; from: string | null; to: string | null }> = [];
  if (spans.length) bounds.push({ label: `Before ${spans[0][0]}`, from: null, to: spans[0][0] });
  for (let i = 1; i < spans.length; i++) bounds.push({ label: `${spans[i - 1][1]} to ${spans[i][0]}`, from: spans[i - 1][1], to: spans[i][0] });
  if (spans.length) bounds.push({ label: `After ${spans[spans.length - 1][1]}`, from: spans[spans.length - 1][1], to: null });

  const dayEnd = (d: string) => `${d}T23:59:59.999Z`;
  const periods: Period[] = bounds.map((p) => {
    const bySite: Record<string, ConfigChange[]> = {};
    for (const c of changes) {
      const afterFrom = p.from === null || c.at > dayEnd(p.from);
      const beforeTo = p.to === null || c.at < `${p.to}T00:00:00.000Z`;
      if (!afterFrom || !beforeTo) continue;
      for (const s of c.sites) (bySite[s] ??= []).push(c);
    }
    return { label: p.label, from: p.from, to: p.to, bySite };
  });

  const asymmetries: Asymmetry[] = [];
  for (const w of waves) {
    const period = periods.find((p) => p.from !== null && p.to === w.days[0]);
    if (!period) continue;
    const hitBefore = new Set(waves.filter((x) => x.days[x.days.length - 1] <= period.from!).map((x) => x.site));
    const own = period.bySite[w.site]?.length ?? 0;
    for (const other of [...hitBefore].filter((s) => s !== w.site).sort()) {
      const theirs = period.bySite[other]?.length ?? 0;
      if (theirs > own) asymmetries.push({ waveId: w.id, site: w.site, changes: own, comparedSite: other, comparedChanges: theirs, period: period.label });
    }
  }
  return { periods, asymmetries };
}
