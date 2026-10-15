import * as fs from 'node:fs';
import * as path from 'node:path';
import { z } from 'zod';
import { MAX_WAIVER_DAYS, waiversConfigSchema, type EvaluatedWaiver, type WaiverEntry } from './WaiverModel.js';

const DAY_MS = 24 * 60 * 60 * 1000;

/** The only file picked up without --waivers. Its path is always reported, so a waiver is never silent. */
export const DEFAULT_WAIVER_FILE = '.sfaudit-waivers.json';

const norm = (s: string): string => s.trim().toLowerCase();

export class WaiverLoader {
  private readonly evaluatedWaivers: EvaluatedWaiver[] = [];

  /**
   * @param source the file the waivers came from, or undefined when none was loaded. Reported to
   *   the user so a waiver file picked up from the working directory is never applied silently.
   */
  public constructor(
    waivers: WaiverEntry[],
    now: Date = new Date(),
    public readonly source?: string,
  ) {
    for (const w of waivers) {
      const expiry = new Date(w.expiresAt);
      this.evaluatedWaivers.push({
        ...w,
        isExpired: now.getTime() > expiry.getTime(),
        daysRemaining: Math.ceil((expiry.getTime() - now.getTime()) / DAY_MS),
      });
    }
  }

  public get waivers(): readonly EvaluatedWaiver[] {
    return this.evaluatedWaivers;
  }

  public get activeWaivers(): EvaluatedWaiver[] {
    return this.evaluatedWaivers.filter((w) => !w.isExpired);
  }

  public get expiredWaivers(): EvaluatedWaiver[] {
    return this.evaluatedWaivers.filter((w) => w.isExpired);
  }

  /**
   * The waiver covering one entity of one finding, preferring an active waiver over an expired
   * one. Matching is exact (case- and whitespace-insensitive): the entity must equal an affected
   * item's label, or, for a finding with no affected items, the finding id itself. There are no
   * wildcards or partial matches, so a waiver can never cover more than the entity it names.
   */
  public findMatchingWaiver(checkId: string, findingId: string, entityName: string): EvaluatedWaiver | undefined {
    const target = norm(entityName);
    if (target === '') return undefined;
    const candidates = this.evaluatedWaivers.filter(
      (w) =>
        w.checkId === checkId &&
        (w.findingId === undefined || w.findingId === findingId) &&
        norm(w.entity) === target,
    );
    return candidates.find((w) => !w.isExpired) ?? candidates[0];
  }

  /**
   * Loads waivers from an explicit path, or from `.sfaudit-waivers.json` in the working directory.
   * Rejects any waiver that runs longer than MAX_WAIVER_DAYS from `now`.
   */
  public static load(explicitPath?: string, now: Date = new Date()): WaiverLoader {
    let targetPath = explicitPath;
    if (!targetPath) {
      const candidate = path.resolve(process.cwd(), DEFAULT_WAIVER_FILE);
      if (fs.existsSync(candidate)) targetPath = candidate;
    }
    if (!targetPath) return new WaiverLoader([], now);
    if (!fs.existsSync(targetPath)) {
      throw new Error(`Waiver file '${targetPath}' does not exist.`);
    }

    let raw: string;
    try {
      raw = fs.readFileSync(targetPath, 'utf-8');
    } catch (err) {
      throw new Error(`Cannot read waiver file '${targetPath}': ${err instanceof Error ? err.message : String(err)}`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(`Invalid JSON in waiver file '${targetPath}': ${err instanceof Error ? err.message : String(err)}`);
    }

    let config;
    try {
      config = waiversConfigSchema.parse(parsed);
    } catch (err) {
      if (err instanceof z.ZodError) {
        const details = err.issues.map((i) => `  - ${i.path.join('.') || 'root'}: ${i.message}`).join('\n');
        throw new Error(`Malformed waiver configuration in '${targetPath}':\n${details}`);
      }
      throw err;
    }

    const limit = now.getTime() + MAX_WAIVER_DAYS * DAY_MS;
    const tooLong = config.waivers
      .map((w, i) => ({ w, i }))
      .filter(({ w }) => new Date(w.expiresAt).getTime() > limit);
    if (tooLong.length > 0) {
      const details = tooLong.map(({ w, i }) => `  - waivers.${i}.expiresAt: ${w.expiresAt}`).join('\n');
      throw new Error(
        `Waivers in '${targetPath}' expire more than ${MAX_WAIVER_DAYS} days from now. Re-approve them with a nearer date:\n${details}`,
      );
    }

    return new WaiverLoader(config.waivers, now, targetPath);
  }
}
