import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CHECKS } from '../../../src/checks/registry.js';
import { DOMAINS, domainOf } from '../../../src/checks/domains.js';

/**
 * The HTML report groups findings by these domains, so the map has to cover every registered check
 * and agree with docs/CHECKS.md, which is where clients read which domain a check is in.
 */

const CHECKS_DOC = readFileSync(join(process.cwd(), 'docs/CHECKS.md'), 'utf8').split('## Known limitations')[0];

function docCountByDomain(): Map<string, number> {
  const out = new Map<string, number>();
  let domain = '';
  for (const line of CHECKS_DOC.split('\n')) {
    const h = /^## (.+)$/.exec(line);
    if (h) { domain = h[1].trim(); continue; }
    if (domain && line.startsWith('| ') && !/^\|\s*(Check\b|:?-{2,})/.test(line)) out.set(domain, (out.get(domain) ?? 0) + 1);
  }
  return out;
}

describe('check domains', () => {
  it('lists the same ten domains as docs/CHECKS.md, in the same order', () => {
    expect([...DOMAINS]).toEqual([...docCountByDomain().keys()]);
  });

  it('gives every registered check a domain', () => {
    expect(CHECKS.filter((c) => domainOf(c.id) === undefined).map((c) => c.id)).toEqual([]);
  });

  it('puts the same number of checks in each domain as docs/CHECKS.md', () => {
    const mapped = new Map<string, number>();
    for (const c of CHECKS) mapped.set(domainOf(c.id)!, (mapped.get(domainOf(c.id)!) ?? 0) + 1);
    expect(Object.fromEntries(mapped)).toEqual(Object.fromEntries(docCountByDomain()));
  });

  it('has no domain for an id no check has', () => {
    expect(domainOf('not-a-check')).toBeUndefined();
    expect(domainOf(undefined)).toBeUndefined();
  });
});
