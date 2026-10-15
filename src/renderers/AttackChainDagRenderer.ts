// src/renderers/AttackChainDagRenderer.ts
//
// Draws an attack chain as an inline SVG strip of step cards joined by arrows, with the step whose
// fix breaks the chain marked as the cut-point. The executive report runs under a strict CSP (no
// script, inline style only), so the output is self-contained: no <script>, no event handlers, no
// <foreignObject>, no external references. Every chain/step string is escaped before it is placed
// in text or an attribute; colours come only from fixed lookup tables.
import { esc } from '@cclabsnz/sf-core';
import type { AttackChain, AttackChainStep } from '../chains/AttackChain.js';

export interface DagRenderOptions {
  theme?: 'dark' | 'light';
}

// Severity accents per theme. The light set is darker so the "STEP n · SEV" label stays legible
// on a white card (the dark set's yellow/blue fall well below 3:1 on white).
const SEV_COLORS: Record<'dark' | 'light', Record<string, string>> = {
  dark: { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#60a5fa', INFO: '#94a3b8' },
  light: { CRITICAL: '#b91c1c', HIGH: '#c2410c', MEDIUM: '#a16207', LOW: '#1d4ed8', INFO: '#475569' },
};

/** Cards per row before the strip wraps, so long chains stay readable when scaled to page width. */
const MAX_PER_ROW = 4;

export function identifyCutPointIndex(chain: AttackChain): number {
  if (!chain.steps || chain.steps.length === 0) return 0;
  const rem = (chain.remediation || '').toLowerCase();

  for (let i = 0; i < chain.steps.length; i++) {
    const s = chain.steps[i];
    if (s.findingId && rem.includes(s.findingId.toLowerCase())) return i;
    if (s.title && rem.includes(s.title.toLowerCase())) return i;
  }

  const sevRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  let bestIdx = 0;
  let bestRank = -1;
  for (let i = 0; i < chain.steps.length; i++) {
    const rank = sevRank[chain.steps[i].severity ?? 'LOW'] ?? 1;
    if (rank > bestRank) {
      bestRank = rank;
      bestIdx = i;
    }
  }
  return bestIdx;
}

/** Truncate by code point (never splitting a surrogate pair); escaping happens after. */
function truncate(str: string, maxLen: number): string {
  const chars = Array.from(str);
  return chars.length > maxLen ? chars.slice(0, maxLen - 1).join('') + '…' : str;
}

export function renderAttackChainDagSvg(chain: AttackChain, opts: DagRenderOptions = {}): string {
  const theme = opts.theme === 'light' ? 'light' : 'dark';
  const steps = chain.steps ?? [];
  if (steps.length === 0) return '';

  const cutPointIdx = identifyCutPointIndex(chain);

  const cardW = 220;
  const cardH = 96;
  const gap = 52;
  const rowGap = 44;
  const padX = 24;
  const padY = 24;
  const cols = Math.min(steps.length, MAX_PER_ROW);
  const rows = Math.ceil(steps.length / cols);
  const totalW = padX * 2 + cols * cardW + (cols - 1) * gap;
  const totalH = padY * 2 + rows * cardH + (rows - 1) * rowGap;
  const posOf = (idx: number): { x: number; y: number } => ({
    x: padX + (idx % cols) * (cardW + gap),
    y: padY + Math.floor(idx / cols) * (cardH + rowGap),
  });

  const isDark = theme === 'dark';
  const sevColors = SEV_COLORS[theme];
  const cardBg = isDark ? '#1e293b' : '#ffffff';
  const cardBorder = isDark ? '#334155' : '#cbd5e1';
  const textColor = isDark ? '#f8fafc' : '#0f172a';
  const mutedColor = isDark ? '#94a3b8' : '#475569';
  const pillBg = isDark ? '#0f172a' : '#f1f5f9';
  const arrowColor = isDark ? '#64748b' : '#94a3b8';
  const cutAccent = isDark ? '#ef4444' : '#dc2626';

  const markerId = `dag-arrow-${String(chain.id).replace(/[^a-zA-Z0-9_-]/g, '_')}-${theme}`;

  const nodesSvg = steps
    .map((step: AttackChainStep, idx: number) => {
      const { x, y } = posOf(idx);
      const isCut = idx === cutPointIdx;
      const sevRaw = String(step.severity ?? 'LOW');
      const sevCol = sevColors[sevRaw] ?? sevColors.INFO;
      const sev = esc(truncate(sevRaw, 10));
      const title = esc(truncate(String(step.title || step.findingId || ''), 26));
      const cap = esc(truncate(String(step.capability ?? ''), 24));

      const stroke = isCut ? cutAccent : cardBorder;
      const strokeWidth = isCut ? '2.5' : '1';
      const dash = isCut ? ' stroke-dasharray="4 2"' : '';

      const cutBadge = isCut
        ? `<g transform="translate(${x + cardW - 84}, ${y - 10})">
            <rect width="80" height="18" rx="4" fill="${cutAccent}" />
            <text x="40" y="12" fill="#ffffff" font-size="9" font-weight="700" text-anchor="middle" font-family="system-ui, sans-serif">✂ CUT-POINT</text>
          </g>`
        : '';

      const cutNote = isCut
        ? `<text x="${x + 10}" y="${y + cardH - 10}" fill="${cutAccent}" font-size="9" font-weight="600" font-family="system-ui, sans-serif">★ Remediating breaks chain</text>`
        : '';

      return `<g class="dag-node${isCut ? ' dag-cut-point' : ''}">
        <rect x="${x}" y="${y}" width="${cardW}" height="${cardH}" rx="8" fill="${cardBg}" stroke="${stroke}" stroke-width="${strokeWidth}"${dash} />
        ${cutBadge}
        <circle cx="${x + 18}" cy="${y + 20}" r="4" fill="${sevCol}" />
        <text x="${x + 28}" y="${y + 24}" fill="${sevCol}" font-size="10" font-weight="700" font-family="system-ui, sans-serif">STEP ${idx + 1} · ${sev}</text>
        <text x="${x + 10}" y="${y + 44}" fill="${textColor}" font-size="12" font-weight="600" font-family="system-ui, sans-serif">${title}</text>
        <rect x="${x + 10}" y="${y + 54}" width="${cardW - 20}" height="18" rx="4" fill="${pillBg}" />
        <text x="${x + 16}" y="${y + 67}" fill="${mutedColor}" font-size="10" font-family="ui-monospace, monospace">grants: ${cap}</text>
        ${cutNote}
      </g>`;
    })
    .join('\n');

  const arrowsSvg = steps
    .slice(0, -1)
    .map((_, idx: number) => {
      const from = posOf(idx);
      const to = posOf(idx + 1);
      let d: string;
      if (from.y === to.y) {
        // Same row: straight right-pointing arrow across the gap.
        const centerY = from.y + cardH / 2;
        d = `M ${from.x + cardW} ${centerY} L ${to.x - 6} ${centerY}`;
      } else {
        // Row wrap: drop from the bottom of the last card, run back left, enter the next row's first card.
        const sx = from.x + cardW / 2;
        const ex = to.x + cardW / 2;
        const midY = from.y + cardH + rowGap / 2;
        d = `M ${sx} ${from.y + cardH} L ${sx} ${midY} L ${ex} ${midY} L ${ex} ${to.y - 6}`;
      }
      return `<path d="${d}" stroke="${arrowColor}" stroke-width="2" marker-end="url(#${markerId})" fill="none" />`;
    })
    .join('\n');

  return `<svg class="attack-chain-dag" role="img" aria-label="${esc(`Attack chain diagram: ${chain.title ?? ''}`)}" viewBox="0 0 ${totalW} ${totalH}" width="100%" style="max-width:${totalW}px;display:block;margin:16px 0;">
  <defs>
    <marker id="${markerId}" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 8 5 L 0 9 z" fill="${arrowColor}" />
    </marker>
  </defs>
  <g class="dag-arrows">${arrowsSvg}</g>
  <g class="dag-nodes">${nodesSvg}</g>
</svg>`;
}
