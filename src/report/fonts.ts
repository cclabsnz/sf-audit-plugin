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

function face(family: string, style: string, file: string): string {
  return `@font-face{font-family: '${family}';font-style:${style};font-display:swap;src:url(${dataUri(file)}) format('woff2');}`;
}

export function fontFaceCss(): string {
  return [
    face('DM Sans', 'normal', 'dm-sans-normal-latin.woff2'),
    face('DM Sans', 'italic', 'dm-sans-italic-latin.woff2'),
    face('DM Serif Display', 'normal', 'dm-serif-display-normal-latin.woff2'),
    face('DM Serif Display', 'italic', 'dm-serif-display-italic-latin.woff2'),
  ].join('\n');
}
