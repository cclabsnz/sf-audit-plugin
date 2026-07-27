export interface Point {
  x: number;
  y: number;
}

export interface LayoutEdge {
  from: string;
  to: string;
}

export interface LayoutOptions {
  width?: number;
  height?: number;
  iterations?: number;
}

/**
 * Deterministic force-directed layout (Fruchterman–Reingold style). Nodes are seeded on a
 * circle by sorted index — no randomness — so the same graph always yields the same picture,
 * keeping "same org in, same picture out" true for the visual layer.
 *
 * Called for three distinct coordinate spaces, each laid out independently: the HTML report's
 * top-N picture, the manifest's L0 landscape (clusters against each other), and the manifest's
 * L1 domains (one space per cluster). Coordinates are only comparable within one space.
 */
export function computeLayout(nodes: string[], edges: LayoutEdge[], opts: LayoutOptions = {}): Map<string, Point> {
  const width = opts.width ?? 960;
  const height = opts.height ?? 600;
  const iterations = opts.iterations ?? 300;
  const ordered = [...nodes].sort();
  const n = ordered.length;
  const pos = new Map<string, Point>();
  if (n === 0) return pos;
  if (n === 1) {
    pos.set(ordered[0], { x: round(width / 2), y: round(height / 2) });
    return pos;
  }

  const area = width * height;
  const k = Math.sqrt(area / n);
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) / 2.5;

  // Deterministic circular seed.
  const p = ordered.map((_, i) => ({
    x: cx + radius * Math.cos((2 * Math.PI * i) / n),
    y: cy + radius * Math.sin((2 * Math.PI * i) / n),
  }));
  const idx = new Map(ordered.map((name, i) => [name, i]));
  const links = edges
    .map((e) => [idx.get(e.from), idx.get(e.to)] as [number | undefined, number | undefined])
    .filter((l): l is [number, number] => l[0] !== undefined && l[1] !== undefined);

  let temp = width / 10;
  const cool = temp / (iterations + 1);

  for (let it = 0; it < iterations; it++) {
    const disp = p.map(() => ({ x: 0, y: 0 }));

    // Repulsion between all pairs.
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let dx = p[i].x - p[j].x;
        let dy = p[i].y - p[j].y;
        let dist = Math.hypot(dx, dy) || 0.01;
        const force = (k * k) / dist;
        dx = (dx / dist) * force;
        dy = (dy / dist) * force;
        disp[i].x += dx;
        disp[i].y += dy;
        disp[j].x -= dx;
        disp[j].y -= dy;
      }
    }

    // Attraction along edges.
    for (const [a, b] of links) {
      let dx = p[a].x - p[b].x;
      let dy = p[a].y - p[b].y;
      const dist = Math.hypot(dx, dy) || 0.01;
      const force = (dist * dist) / k;
      dx = (dx / dist) * force;
      dy = (dy / dist) * force;
      disp[a].x -= dx;
      disp[a].y -= dy;
      disp[b].x += dx;
      disp[b].y += dy;
    }

    // Apply, bounded by temperature and canvas.
    for (let i = 0; i < n; i++) {
      const d = Math.hypot(disp[i].x, disp[i].y) || 0.01;
      p[i].x += (disp[i].x / d) * Math.min(d, temp);
      p[i].y += (disp[i].y / d) * Math.min(d, temp);
      p[i].x = Math.max(40, Math.min(width - 40, p[i].x));
      p[i].y = Math.max(40, Math.min(height - 40, p[i].y));
    }
    temp -= cool;
  }

  ordered.forEach((name, i) => pos.set(name, { x: round(p[i].x), y: round(p[i].y) }));
  return pos;
}

function round(n: number): number {
  return Math.round(n * 10) / 10;
}
