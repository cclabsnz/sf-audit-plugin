import { Parser } from '@oclif/core';
import SecurityAuditCommand from '../../../src/commands/audit/security.js';
import { isCiEnvironment, shouldArchiveHistory } from '../../../src/history/archivePolicy.js';

describe('security command --no-history / --keep-history', () => {
  // Parse with the command's real flag definitions (minus target-org, which needs an
  // authenticated org), so a rename or an oclif negation quirk shows up here.
  const { 'target-org': _org, ...flags } = SecurityAuditCommand.flags;
  const parse = async (argv: string[]) =>
    (await Parser.parse(argv, { flags, strict: true })).flags as Record<string, unknown>;

  it('both flags default to false', async () => {
    const f = await parse([]);
    expect(f['no-history']).toBe(false);
    expect(f['keep-history']).toBe(false);
  });

  it('parses the literal --no-history flag as true, not as a negation', async () => {
    expect((await parse(['--no-history']))['no-history']).toBe(true);
  });

  it('parses --keep-history as true', async () => {
    expect((await parse(['--keep-history']))['keep-history']).toBe(true);
  });

  it('rejects --history, which oclif negation conventions might suggest exists', async () => {
    await expect(parse(['--history'])).rejects.toThrow();
  });
});

describe('isCiEnvironment', () => {
  it('is false with no CI variables', () => {
    expect(isCiEnvironment({})).toBe(false);
  });

  it.each(['true', 'TRUE', '1', 'yes'])('treats CI=%s as CI', (v) => {
    expect(isCiEnvironment({ CI: v })).toBe(true);
  });

  it.each(['false', '0', '', 'off'])('does not treat CI=%j as CI', (v) => {
    expect(isCiEnvironment({ CI: v })).toBe(false);
  });

  it('detects GitHub Actions, Azure Pipelines and Jenkins without CI set', () => {
    expect(isCiEnvironment({ GITHUB_ACTIONS: 'true' })).toBe(true);
    expect(isCiEnvironment({ TF_BUILD: 'True' })).toBe(true);
    expect(isCiEnvironment({ JENKINS_URL: 'https://ci.example.test/' })).toBe(true);
  });
});

describe('shouldArchiveHistory', () => {
  const local = {};
  const ci = { CI: 'true' };

  it('archives on a normal local run', () => {
    expect(shouldArchiveHistory({}, local)).toBe(true);
  });

  it('skips when --no-history is passed locally', () => {
    expect(shouldArchiveHistory({ 'no-history': true }, local)).toBe(false);
  });

  it('skips in CI by default', () => {
    expect(shouldArchiveHistory({}, ci)).toBe(false);
    expect(shouldArchiveHistory({}, { CI: '1' })).toBe(false);
  });

  it('--keep-history archives in CI', () => {
    expect(shouldArchiveHistory({ 'keep-history': true }, ci)).toBe(true);
  });

  it('--keep-history wins over --no-history', () => {
    expect(shouldArchiveHistory({ 'keep-history': true, 'no-history': true }, local)).toBe(true);
    expect(shouldArchiveHistory({ 'keep-history': true, 'no-history': true }, ci)).toBe(true);
  });

  it('reads process.env when no env is given', () => {
    const saved = process.env.CI;
    try {
      process.env.CI = 'true';
      expect(shouldArchiveHistory({})).toBe(false);
    } finally {
      if (saved === undefined) delete process.env.CI;
      else process.env.CI = saved;
    }
  });
});
