import { esc } from '../../../src/renderers/html-utils.js';

describe('esc', () => {
  it('escapes HTML-significant characters', () => {
    expect(esc('<a href="x">&')).toBe('&lt;a href=&quot;x&quot;&gt;&amp;');
  });
  it('returns plain text unchanged', () => {
    expect(esc('plain text 123')).toBe('plain text 123');
  });
});
