import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const requireFrom = createRequire(import.meta.url);

let cached: string | null = null;

// Latin plus latin-ext, so macron vowels in NZ names (ā, ē, ī, ō, ū) stay in the face.
const LATIN = 'U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD';
const LATIN_EXT = 'U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF';

function face(family: string, file: string, descriptors: string, range: string): string {
  const data = readFileSync(requireFrom.resolve(file)).toString('base64');
  return `@font-face{font-family:'${family}';font-style:normal;${descriptors}font-display:swap;src:url(data:font/woff2;base64,${data}) format('woff2');unicode-range:${range};}`;
}

/**
 * Source Serif 4 (headlines) and Source Sans 3 (text) for the executive deck, embedded as data URIs
 * so the report never fetches a font. Read from the pinned @fontsource-variable packages, like the
 * Chart.js bundle, so the versions stay visible to `pnpm audit` and Dependabot.
 */
export function deckFontFaceCss(): string {
  if (cached !== null) return cached;
  cached = (['latin', 'latin-ext'] as const).flatMap((sub) => {
    const range = sub === 'latin' ? LATIN : LATIN_EXT;
    return [
      face('Source Serif 4', `@fontsource-variable/source-serif-4/files/source-serif-4-${sub}-wght-normal.woff2`, 'font-weight:200 900;', range),
      face('Source Sans 3', `@fontsource-variable/source-sans-3/files/source-sans-3-${sub}-wght-normal.woff2`, 'font-weight:200 900;', range),
    ];
  }).join('\n');
  return cached;
}
