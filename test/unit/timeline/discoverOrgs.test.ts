import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { discoverCapturedOrgs, resolveOrgId } from '../../../src/timeline/loadCaptures.js';

/**
 * Working out which org to read without being told.
 *
 * The capture store is keyed by org id, so the directory names already hold the answer. Making
 * an operator retype an eighteen-character id they can neither remember nor check is friction
 * for its own sake — and a mistyped one produces "no captures found" rather than an error that
 * names the mistake.
 *
 * Reading directory names keeps the command offline. Resolving an alias would mean asking
 * Salesforce, and the whole value of this command is that it still works when the org is
 * unreachable or its credentials are gone.
 */
describe('discoverCapturedOrgs', () => {
  let dir: string;

  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'discover-orgs-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  const org = (id: string) => fs.mkdirSync(path.join(dir, id), { recursive: true });

  it('finds a captured org by its directory name', () => {
    org('00Dxx0000000000EAA');

    expect(discoverCapturedOrgs(dir)).toEqual(['00Dxx0000000000EAA']);
  });

  it('finds several, sorted so the listing is stable', () => {
    org('00Dxx0000000002EAA');
    org('00Dxx0000000001EAA');

    expect(discoverCapturedOrgs(dir)).toEqual(['00Dxx0000000001EAA', '00Dxx0000000002EAA']);
  });

  it('ignores directories that are not org ids', () => {
    // The base directory is the operator's own; it may hold notes, exports, anything.
    org('00Dxx0000000000EAA');
    org('scratch-notes');
    fs.writeFileSync(path.join(dir, 'readme.txt'), 'x');

    expect(discoverCapturedOrgs(dir)).toEqual(['00Dxx0000000000EAA']);
  });

  it('accepts both the 15 and 18 character forms', () => {
    org('00Dxx0000000001');
    org('00Dxx0000000002EAA');

    expect(discoverCapturedOrgs(dir)).toHaveLength(2);
  });

  it('returns nothing for a base directory that does not exist', () => {
    expect(discoverCapturedOrgs(path.join(dir, 'nope'))).toEqual([]);
  });
});

describe('resolveOrgId', () => {
  let dir: string;

  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'resolve-org-')); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  const org = (id: string) => fs.mkdirSync(path.join(dir, id), { recursive: true });

  it('uses an explicit id even when others are captured', () => {
    org('00Dxx0000000001EAA');
    org('00Dxx0000000002EAA');

    expect(resolveOrgId(dir, '00Dxx0000000002EAA')).toBe('00Dxx0000000002EAA');
  });

  it('infers the only captured org when none was given', () => {
    org('00Dxx0000000001EAA');

    expect(resolveOrgId(dir, undefined)).toBe('00Dxx0000000001EAA');
  });

  it('refuses to guess between several, and lists them', () => {
    org('00Dxx0000000001EAA');
    org('00Dxx0000000002EAA');

    // Picking one would silently analyse the wrong org, and the output would look right.
    expect(() => resolveOrgId(dir, undefined)).toThrow(/00Dxx0000000001EAA[\s\S]*00Dxx0000000002EAA/);
    expect(() => resolveOrgId(dir, undefined)).toThrow(/--org-id/);
  });

  it('says how to capture when nothing has been captured at all', () => {
    expect(() => resolveOrgId(dir, undefined)).toThrow(/events pull/);
  });

  it('names the mistake when an explicit id was never captured', () => {
    // "No captures found" would send the operator looking for a missing window rather than a
    // typo in the id.
    org('00Dxx0000000001EAA');

    expect(() => resolveOrgId(dir, '00Dxx0000000009EAA')).toThrow(/00Dxx0000000009EAA/);
    expect(() => resolveOrgId(dir, '00Dxx0000000009EAA')).toThrow(/00Dxx0000000001EAA/);
  });
});
