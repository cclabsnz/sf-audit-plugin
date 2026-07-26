import { fontFaceCss } from '../../../src/report/fonts.js';

describe('fontFaceCss', () => {
  it('emits @font-face blocks with embedded woff2 data URIs', () => {
    const css = fontFaceCss();
    expect(css).toContain('@font-face');
    expect(css).toContain("font-family: 'DM Sans'");
    expect(css).toContain("font-family: 'DM Serif Display'");
    expect(css).toContain('data:font/woff2;base64,');
    expect(css).not.toContain('http');
  });
});
