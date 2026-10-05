import type { AuditRow, GuestUser, Wave } from '../model.js';
import { isSelfRegistration } from './outcomes.js';

export interface ConfigChange { at: string; by: string; section: string | null; display: string; sites: string[] }
export interface Period { label: string; from: string | null; to: string | null; bySite: Record<string, ConfigChange[]>; shared: ConfigChange[] }
export interface Asymmetry { waveId: string; site: string; changes: number; comparedSite: string; comparedChanges: number; period: string }

function siteOf(g: GuestUser): string { return g.siteNames[0] ?? g.username; }

function labelsOf(g: GuestUser): string[] {
  return [g.profileName, g.name, ...g.permissionSetLabels, ...g.siteNames].filter((l) => !!l && l.trim() !== '');
}

function mentions(text: string, label: string): boolean {
  const esc = label.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^A-Za-z0-9])${esc}($|[^A-Za-z0-9])`, 'i').test(text);
}

/**
 * Sites credited with a change. Labels belonging to more than one guest are "shared" and never
 * attribute a change; `onlyShared` is true when a change matched solely through shared labels.
 */
function sitesTouched(row: AuditRow, guests: GuestUser[]): { sites: string[]; onlyShared: boolean } {
  const owners = new Map<string, Set<string>>();
  for (const g of guests) for (const l of labelsOf(g)) {
    const k = l.trim().toLowerCase();
    if (!owners.has(k)) owners.set(k, new Set());
    owners.get(k)!.add(g.id15);
  }
  const sites = new Set<string>();
  let sharedHit = false;
  for (const g of guests) for (const l of labelsOf(g)) {
    if (!mentions(row.display, l)) continue;
    if ((owners.get(l.trim().toLowerCase())?.size ?? 0) > 1) sharedHit = true;
    else sites.add(siteOf(g));
  }
  return { sites: [...sites], onlyShared: sites.size === 0 && sharedHit };
}

export function computeConfigDelta(audit: AuditRow[], guests: GuestUser[], waves: Wave[]): { periods: Period[]; asymmetries: Asymmetry[] } {
  const changes: Array<ConfigChange & { onlyShared: boolean }> = audit.filter((r) => !isSelfRegistration(r))
    .map((r) => ({ at: r.createdDate, by: r.createdBy, section: r.section, display: r.display, ...sitesTouched(r, guests) }))
    .filter((c) => c.sites.length > 0 || c.onlyShared)
    .sort((a, c) => a.at.localeCompare(c.at));

  // Merge waves into distinct windows (several sites can share a day).
  const spans = [...new Map(waves.map((w) => [`${w.days[0]}|${w.days[w.days.length - 1]}`, [w.days[0], w.days[w.days.length - 1]] as const])).values()]
    .sort((a, c) => a[0].localeCompare(c[0]));
  const bounds: Array<{ label: string; from: string | null; to: string | null }> = [];
  if (spans.length) bounds.push({ label: `Before ${spans[0][0]}`, from: null, to: spans[0][0] });
  for (let i = 1; i < spans.length; i++) bounds.push({ label: `${spans[i - 1][1]} to ${spans[i][0]}`, from: spans[i - 1][1], to: spans[i][0] });
  if (spans.length) bounds.push({ label: `After ${spans[spans.length - 1][1]}`, from: spans[spans.length - 1][1], to: null });

  const periods: Period[] = bounds.map((p) => {
    const bySite: Record<string, ConfigChange[]> = {};
    const shared: ConfigChange[] = [];
    for (const { onlyShared, ...c } of changes) {
      const day = c.at.slice(0, 10);
      if (!((p.from === null || day > p.from) && (p.to === null || day < p.to))) continue;
      if (onlyShared) shared.push(c);
      else for (const s of c.sites) (bySite[s] ??= []).push(c);
    }
    return { label: p.label, from: p.from, to: p.to, bySite, shared };
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
