import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
// Resolves to <packageRoot>/src/assets/fonts from both lib/report (compiled) and src/report (ts-jest).
const FONT_DIR = join(HERE, '..', '..', 'src', 'assets', 'fonts');

function dataUri(file: string): string {
  const buf = readFileSync(join(FONT_DIR, file));
  return `data:font/woff2;base64,${buf.toString('base64')}`;
}

function face(family: string, style: string, file: string, weight?: number): string {
  const w = weight === undefined ? '' : `font-weight:${weight};`;
  return `@font-face{font-family: '${family}';font-style:${style};${w}font-display:swap;src:url(${dataUri(file)}) format('woff2');}`;
}

export function fontFaceCss(): string {
  return [
    face('DM Sans', 'normal', 'dm-sans-normal-latin.woff2'),
    face('DM Sans', 'italic', 'dm-sans-italic-latin.woff2'),
    face('DM Serif Display', 'normal', 'dm-serif-display-normal-latin.woff2'),
    face('DM Serif Display', 'italic', 'dm-serif-display-italic-latin.woff2'),
  ].join('\n');
}

/**
 * Fira Sans/Fira Code faces for the sf-audit HTML reports, embedded as data URIs so a
 * generated report never calls out to Google Fonts when a client opens it. Only the
 * weights the report stylesheet actually uses are shipped (400/600/700 Sans, 400 Code);
 * `font-weight: 800` resolves to the 700 face, matching the previous CDN behaviour.
 */
export function firaFontFaceCss(): string {
  return [
    face('Fira Sans', 'normal', 'fira-sans-400-latin.woff2', 400),
    face('Fira Sans', 'normal', 'fira-sans-600-latin.woff2', 600),
    face('Fira Sans', 'normal', 'fira-sans-700-latin.woff2', 700),
    face('Fira Code', 'normal', 'fira-code-400-latin.woff2', 400),
  ].join('\n');
}
