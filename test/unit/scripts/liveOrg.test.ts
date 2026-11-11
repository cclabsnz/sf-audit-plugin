import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'live-org-'));
const file = (name: string, data: unknown) => {
  const p = join(dir, name);
  writeFileSync(p, JSON.stringify(data));
  return p;
};
const run = (script: string, args: string[]) => {
  try {
    return { code: 0, out: execFileSync('node', [join('scripts', script), ...args], { encoding: 'utf8', stdio: 'pipe' }) };
  } catch (e) {
    const err = e as { status: number; stdout: string; stderr: string };
    return { code: err.status, out: err.stdout + err.stderr };
  }
};

const f = (checkId: string, id: string, extra: Record<string, unknown> = {}) =>
  ({ checkId, id, riskLevel: 'HIGH', title: 'Secret title', detail: 'org detail', remediation: 'r', affectedItems: [{ label: 'Acme_Object__c' }], ...extra });
const report = (findings: unknown[], coverage = { percent: 97, notAssessed: ['mfa-registration'] }) => ({ grade: 'C', findings, coverage });

describe('scripts/live-org-check.mjs', () => {
  const base = report([f('apex-sharing', 'apex-no-sharing-declaration'), f('guest-user-access', 'guest-user-sharing-exposure', { passed: true })]);

  it('records a baseline of statuses only, then matches it', () => {
    const b = join(dir, 'baseline.json');
    expect(run('live-org-check.mjs', [file('r1.json', base), b, '--write-baseline']).code).toBe(0);
    const saved = JSON.parse(readFileSync(b, 'utf8'));
    expect(saved.findings).toEqual({
      'apex-sharing/apex-no-sharing-declaration': 'open:HIGH',
      'guest-user-access/guest-user-sharing-exposure': 'passed',
    });
    expect(saved.allowUnassessed).toEqual(['mfa-registration']);
    const r = run('live-org-check.mjs', [file('r2.json', base), b]);
    expect(r.code).toBe(0);
    expect(r.out).toContain('Every finding matches the baseline');
  });

  // The failure this exists for: a check that stops finding something reads as a pass.
  it('fails when a finding changes status, appears or disappears, naming ids only', () => {
    const b = file('b.json', { minCoverage: 90, allowUnassessed: ['mfa-registration'], findings: {
      'apex-sharing/apex-no-sharing-declaration': 'open:HIGH', 'guest-user-access/guest-user-sharing-exposure': 'open:HIGH', 'x/old': 'passed',
    } });
    const r = run('live-org-check.mjs', [file('r3.json', base), b]);
    expect(r.code).toBe(1);
    expect(r.out).toContain('changed    guest-user-access/guest-user-sharing-exposure: open:HIGH -> passed');
    expect(r.out).toContain('gone       x/old');
    expect(r.out).not.toMatch(/Secret title|org detail|Acme_Object__c/);
  });

  it('fails on a rejected query or crashed check, low coverage, and unexpected unassessed checks', () => {
    const b = file('b2.json', { minCoverage: 95, allowUnassessed: [], findings: {} });
    const r = run('live-org-check.mjs', [file('r4.json', report(
      [f('remote-sites', 'remote-sites-error', { title: 'Remote Sites: query rejected by the org' })],
      { percent: 80, notAssessed: ['mfa-registration'] },
    )), b]);
    expect(r.code).toBe(1);
    expect(r.out).toContain('check failed or its query was rejected: remote-sites');
    expect(r.out).toContain('coverage 80% is below the 95% floor');
    expect(r.out).toContain('not assessed: mfa-registration');
  });

  // Some finding ids embed org values; the baseline and the log must not carry them.
  it('hashes a finding id that embeds an org value, keeps plain ids readable, and compares chains', () => {
    const b = join(dir, 'b-hash.json');
    const r = report([
      f('agent-user-privilege', 'agent-user-privilege-005xx0000000001AAA'),
      f('trusted-url-hygiene', 'trusted-url-hygiene-unresolvable-cdn.acme.example'),
      f('apex-sharing', 'apex-no-sharing-declaration'),
      f('apex-sharing', 'apex-no-sharing-declaration', { riskLevel: 'LOW' }),
    ]);
    (r as Record<string, unknown>).attackChains = [{ id: 'unauth-bulk-exfil', confidence: 'named', severity: 'CRITICAL' }];
    run('live-org-check.mjs', [file('r-hash.json', r), b, '--write-baseline']);
    const text = readFileSync(b, 'utf8');
    expect(text).not.toMatch(/005xx|acme\.example/);
    const keys = Object.keys(JSON.parse(text).findings);
    expect(keys).toEqual(expect.arrayContaining([
      'apex-sharing/apex-no-sharing-declaration', 'apex-sharing/apex-no-sharing-declaration~2', 'chain/unauth-bulk-exfil',
    ]));
    expect(keys.filter((k) => /\/#[0-9a-f]{12}$/.test(k))).toHaveLength(2);
    // A chain that disappears is drift.
    delete (r as Record<string, unknown>).attackChains;
    const out = run('live-org-check.mjs', [file('r-hash2.json', r), b]);
    expect(out.code).toBe(1);
    expect(out.out).toContain('gone       chain/unauth-bulk-exfil');
  });

  it('resets the coverage floor when the baseline is re-recorded', () => {
    const b = file('b-floor.json', { minCoverage: 99, allowUnassessed: [], findings: {} });
    run('live-org-check.mjs', [file('r-floor.json', base), b, '--write-baseline']);
    expect(JSON.parse(readFileSync(b, 'utf8')).minCoverage).toBe(95);
  });

  it('refuses a digest or summary, and a missing baseline', () => {
    expect(run('live-org-check.mjs', [file('d.json', { result: { grade: 'B', actions: [] } }), join(dir, 'none.json')]).code).toBe(2);
    expect(run('live-org-check.mjs', [file('r5.json', base), join(dir, 'missing.json')]).code).toBe(2);
  });
});

describe('scripts/schema-drift.mjs', () => {
  const snap = (extra: Record<string, unknown> = {}) => ({
    apiVersion: '68.0', edition: 'Developer Edition',
    soql: { LoginHistory: { LoginType: { filterable: true, aggregatable: true, type: 'picklist', values: ['Application', 'Remote Access 2.0'] }, ...extra } },
    tooling: {},
  });

  it('passes when the snapshots match', () => {
    expect(run('schema-drift.mjs', [file('s1.json', snap()), file('s2.json', snap())]).code).toBe(0);
  });

  it('reports added, removed and retyped fields and changed picklist values', () => {
    const fresh = snap({ NewField: { filterable: true, aggregatable: false, type: 'string' } });
    (fresh.soql.LoginHistory.LoginType as { values: string[] }).values = ['Application', 'Remote Access 3.0'];
    fresh.apiVersion = '69.0';
    const r = run('schema-drift.mjs', [file('s3.json', snap()), file('s4.json', fresh)]);
    expect(r.code).toBe(1);
    expect(r.out).toContain('soql LoginHistory.NewField: added');
    expect(r.out).toContain('picklist values removed: Remote Access 2.0');
    expect(r.out).toContain('picklist values added: Remote Access 3.0');
    expect(r.out).toContain('API version 68.0 -> 69.0');
  });
});
