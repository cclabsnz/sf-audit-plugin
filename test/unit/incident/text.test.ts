import { describe, it, expect } from '@jest/globals';
import { containsWord, replaceInsensitive } from '../../../src/incident/text.js';

describe('containsWord', () => {
  it('matches whole words case-insensitively and treats metacharacters literally', () => {
    expect(containsWord('Changed profile Site A Guest Profile', 'site a')).toBe(true);
    expect(containsWord('Changed profile Site AB Guest Profile', 'Site A')).toBe(false);
    expect(containsWord('Repair log updated', 'AIR')).toBe(false);
    expect(containsWord('Granted (Files+) access', '(Files+)')).toBe(true);
    expect(containsWord('Sitea.b', 'a.b')).toBe(false);
    expect(containsWord('anything', '')).toBe(false);
  });
});

describe('replaceInsensitive', () => {
  it('replaces every occurrence regardless of case, literally', () => {
    expect(replaceInsensitive('Confirm with Test Tester; test tester agreed', 'Test Tester', 'ID1')).toBe('Confirm with ID1; ID1 agreed');
    expect(replaceInsensitive('a.b and axb', 'a.b', 'X')).toBe('X and axb');
    expect(replaceInsensitive('nothing here', 'zzz', 'X')).toBe('nothing here');
  });
});
