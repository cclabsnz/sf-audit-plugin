import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { WaiverLoader } from '../../../src/waivers/WaiverLoader.js';
import { applyWaivers } from '../../../src/waivers/applyWaivers.js';
import { resolveExitCode } from '../../../src/findings/exitCode.js';
import type { Finding } from '../../../src/findings/Finding.js';

describe('Waiver System (GAP-01)', () => {
  const baseFinding: Finding = {
    id: 'flows-autolaunched-without-sharing',
    checkId: 'flows-without-sharing',
    category: 'flows',
    riskLevel: 'HIGH',
    title: 'Autolaunched flow running in system mode without sharing',
    detail: 'Flow Order_Processor runs in system mode without sharing.',
    remediation: 'Change flow to user mode or with sharing.',
    affectedItems: [{ label: 'Flow:Order_Processor' }, { label: 'Flow:Payment_Webhook' }],
  };

  it('applies active waiver: suppresses exit code on --fail-on HIGH for waived entity while un-waived entity still fails', () => {
    const futureDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const loader = new WaiverLoader([
      {
        checkId: 'flows-without-sharing',
        entity: 'Flow:Order_Processor',
        reason: 'Legacy integration without user context; scheduled for refactor Q3',
        approvedBy: 'security-lead@example.com',
        expiresAt: futureDate,
      },
    ]);

    // Finding with only Order_Processor (waived)
    const singleEntityFinding: Finding = {
      ...baseFinding,
      affectedItems: [{ label: 'Flow:Order_Processor' }],
    };

    const res = applyWaivers([singleEntityFinding], loader);
    expect(res.waivedFindings).toHaveLength(1);
    expect(res.findings[0].waived).toBe(true);

    // Assert that --fail-on HIGH returns 0 when the only finding is waived
    const exitCode = resolveExitCode(res.findings, { failOn: 'HIGH' });
    expect(exitCode).toBe(0);

    // Finding with an un-waived entity (Payment_Webhook) still triggers exit code 1
    const multiEntityFinding: Finding = { ...baseFinding };
    const resMulti = applyWaivers([multiEntityFinding], loader);
    expect(resMulti.findings[0].waived).toBeFalsy();
    expect(resMulti.findings[0].affectedItems?.[0].note).toContain('[WAIVED');
    expect(resMulti.findings[0].affectedItems?.[1].note).toBeUndefined();

    const exitCodeMulti = resolveExitCode(resMulti.findings, { failOn: 'HIGH' });
    expect(exitCodeMulti).toBe(1);
  });

  it('fails check and flags [WAIVER EXPIRED] when waiver expiration date is in the past', () => {
    const pastDate = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();
    const loader = new WaiverLoader([
      {
        checkId: 'flows-without-sharing',
        entity: 'Flow:Order_Processor',
        reason: 'Temporary waiver for migration window',
        approvedBy: 'architect@example.com',
        expiresAt: pastDate,
      },
    ]);

    const singleEntityFinding: Finding = {
      ...baseFinding,
      affectedItems: [{ label: 'Flow:Order_Processor' }],
    };

    const res = applyWaivers([singleEntityFinding], loader);
    expect(res.waivedFindings).toHaveLength(0);
    expect(res.findings[0].waived).toBeFalsy();
    expect(res.findings[0].affectedItems?.[0].note).toContain('[WAIVER EXPIRED]');

    // Expired waiver must trigger non-zero exit code on --fail-on HIGH
    const exitCode = resolveExitCode(res.findings, { failOn: 'HIGH' });
    expect(exitCode).toBe(1);
  });

  it('fails fast with actionable schema path error when waiver file is malformed', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-waiver-test-'));
    const badWaiverFile = path.join(tmpDir, 'bad-waivers.json');
    try {
      fs.writeFileSync(
        badWaiverFile,
        JSON.stringify({
          waivers: [
            {
              checkId: 'flows-without-sharing',
              // Missing 'entity', 'reason', 'approvedBy', 'expiresAt'
            },
          ],
        }),
      );

      expect(() => WaiverLoader.load(badWaiverFile)).toThrow(/Malformed waiver configuration/);
      expect(() => WaiverLoader.load(badWaiverFile)).toThrow(/waivers\.0/);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe('Waiver matching and limits', () => {
  const inDays = (n: number) => new Date(Date.now() + n * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const waiver = (over: Record<string, unknown> = {}) => ({
    checkId: 'flows-without-sharing',
    entity: 'Flow:Order_Processor',
    reason: 'Accepted until refactor',
    approvedBy: 'security-lead',
    expiresAt: inDays(30),
    ...over,
  });
  const finding = (over: Partial<Finding> = {}): Finding => ({
    id: 'flows-autolaunched-without-sharing',
    checkId: 'flows-without-sharing',
    category: 'flows',
    riskLevel: 'HIGH',
    title: 't',
    detail: 'd',
    remediation: 'r',
    affectedItems: [{ label: 'Flow:Order_Processor' }],
    ...over,
  });

  it('never matches by prefix or substring: an entity of "Flow:" covers nothing', () => {
    const loader = new WaiverLoader([waiver({ entity: 'Flow:' }) as any]);
    const res = applyWaivers([finding(), finding({ affectedItems: [{ label: 'Flow:Payment_Webhook' }] })], loader);
    expect(res.waivedFindings).toHaveLength(0);
  });

  it('does not let an empty or short item label match a longer entity', () => {
    const loader = new WaiverLoader([waiver() as any]);
    const res = applyWaivers([finding({ affectedItems: [{ label: '' }] }), finding({ affectedItems: [{ label: 'Flow' }] })], loader);
    expect(res.waivedFindings).toHaveLength(0);
  });

  it('matches case- and whitespace-insensitively, and only the named entity', () => {
    const loader = new WaiverLoader([waiver({ entity: '  flow:order_processor ' }) as any]);
    const res = applyWaivers([finding()], loader);
    expect(res.waivedFindings).toHaveLength(1);
  });

  it('matches a finding with no affected items only by its own id', () => {
    const loader = new WaiverLoader([waiver({ entity: 'flows-autolaunched-without-sharing' }) as any]);
    const itemless = finding({ affectedItems: undefined });
    expect(applyWaivers([itemless], loader).waivedFindings).toHaveLength(1);
    const byFragment = new WaiverLoader([waiver({ entity: 'flows' }) as any]);
    expect(applyWaivers([itemless], byFragment).waivedFindings).toHaveLength(0);
  });

  it('prefers an active waiver over an expired one for the same entity', () => {
    const loader = new WaiverLoader([waiver({ expiresAt: inDays(-3) }) as any, waiver({ expiresAt: inDays(10) }) as any]);
    expect(applyWaivers([finding()], loader).waivedFindings).toHaveLength(1);
  });

  it('does not waive a CRITICAL finding unless the waiver acknowledges it', () => {
    const critical = finding({ riskLevel: 'CRITICAL' });
    const plain = applyWaivers([critical], new WaiverLoader([waiver() as any]));
    expect(plain.waivedFindings).toHaveLength(0);
    expect(plain.unacknowledgedCriticalCount).toBe(1);
    expect(plain.findings[0].affectedItems?.[0].note).toContain('acknowledgeCritical');
    expect(resolveExitCode(plain.findings, { failOn: 'CRITICAL' })).toBe(1);

    const acknowledged = applyWaivers([critical], new WaiverLoader([waiver({ acknowledgeCritical: true }) as any]));
    expect(acknowledged.waivedFindings).toHaveLength(1);
  });

  describe('loading', () => {
    let dir: string;
    beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-waiver-load-')); });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));
    const write = (body: unknown) => {
      const p = path.join(dir, 'w.json');
      fs.writeFileSync(p, JSON.stringify(body));
      return p;
    };

    it('rejects a waiver that runs more than a year', () => {
      const p = write({ waivers: [waiver({ expiresAt: '9999-12-31' })] });
      expect(() => WaiverLoader.load(p)).toThrow(/more than 365 days/);
    });

    it('rejects a non-ISO expiry that Date.parse would accept', () => {
      const p = write({ waivers: [waiver({ expiresAt: 'March 1 2027' })] });
      expect(() => WaiverLoader.load(p)).toThrow(/ISO 8601/);
    });

    it('rejects unknown keys instead of silently dropping a typo', () => {
      const p = write({ waivers: [{ ...waiver(), expiresOn: inDays(5) }] });
      expect(() => WaiverLoader.load(p)).toThrow(/Malformed waiver configuration/);
    });

    it('fails when an explicit --waivers path does not exist', () => {
      expect(() => WaiverLoader.load(path.join(dir, 'missing.json'))).toThrow(/does not exist/);
    });

    it('reports where the waivers came from', () => {
      const p = write({ waivers: [waiver()] });
      expect(WaiverLoader.load(p).source).toBe(p);
    });
  });
});
