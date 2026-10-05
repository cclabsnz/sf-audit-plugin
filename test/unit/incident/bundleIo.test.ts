import { describe, it, expect } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { sha256File, writeJsonAtomic, loadBundle, BundleIntegrityError, BUNDLE_PATHS, logPath } from '../../../src/incident/bundleIo.js';
import { csvLine } from '../../../src/incident/csv.js';
import type { BundleManifest } from '../../../src/incident/model.js';

async function makeBundle(): Promise<string> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-bundle-'));
  const files: Record<string, string> = {};
  const put = async (rel: string, body: string) => {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
    files[rel] = await sha256File(p);
  };
  await put(BUNDLE_PATHS.anomalies, '[]');
  await put(BUNDLE_PATHS.audit, '[]');
  await put(BUNDLE_PATHS.loginsByDay, '[]');
  await put(BUNDLE_PATHS.followUp, '{"logins":[],"users":[]}');
  await put(logPath('AuraRequest', '2026-01-02'), csvLine(['USER_ID']) + csvLine(['005xx000000gstA']));
  const manifest: BundleManifest = {
    version: 1, orgId: '00Dxx0000000000EAA', orgName: 'Test', collectedAt: '2026-01-05T00:00:00Z', sinceDays: 30,
    detectorAvailable: true, waves: [], guests: [],
    logs: [{ type: 'AuraRequest', day: '2026-01-02', status: 'collected', totalRows: 1, guestRows: 1, guestRowsByUser: {}, malformed: 0, file: logPath('AuraRequest', '2026-01-02') }],
    audit: { from: '2026-01-01', to: '2026-01-05', truncatedWindows: [], inaccessible: false },
    limits: { queryAllFiles: true, viewAllData: true }, ipRangeFiles: [], files,
  };
  writeJsonAtomic(path.join(dir, BUNDLE_PATHS.manifest), manifest);
  return dir;
}

describe('bundleIo', () => {
  it('loads a bundle and iterates log rows', async () => {
    const b = await loadBundle(await makeBundle());
    expect(b.hasLog('AuraRequest', '2026-01-02')).toBe(true);
    expect(b.hasLog('Sites', '2026-01-02')).toBe(false);
    const rows: Array<Record<string, string>> = [];
    for await (const r of b.rows('AuraRequest', '2026-01-02')) rows.push(r);
    expect(rows).toEqual([{ USER_ID: '005xx000000gstA' }]);
    expect(b.manifestSha256).toMatch(/^[0-9a-f]{64}$/);
  });
  it('yields no rows for a log that was not collected', async () => {
    const b = await loadBundle(await makeBundle());
    const rows = [];
    for await (const r of b.rows('Sites', '2026-01-02')) rows.push(r);
    expect(rows).toEqual([]);
  });
  it('refuses a bundle whose files changed or vanished, naming them', async () => {
    const dir = await makeBundle();
    fs.appendFileSync(path.join(dir, logPath('AuraRequest', '2026-01-02')), csvLine(['tampered']));
    fs.rmSync(path.join(dir, BUNDLE_PATHS.audit));
    await expect(loadBundle(dir)).rejects.toBeInstanceOf(BundleIntegrityError);
    await loadBundle(dir).catch((e: BundleIntegrityError) => {
      expect(e.files.sort()).toEqual([BUNDLE_PATHS.audit, logPath('AuraRequest', '2026-01-02')].sort());
    });
  });
});
