import { esc, type Branding } from '@cclabsnz/sf-core';
import type { CouplingGraph, CouplingGraphEdge } from '@cclabsnz/sf-core';
import type { Cluster } from '../map/graph/clusters.js';
import type { Point } from '../map/graph/layout.js';
import { htmlDocument } from './shell.js';

export interface MapAnchorRow {
  object: string;
  label: string;
  score: number;
}

export interface MapReportInput {
  orgName: string;
  couplingGraph: CouplingGraph;
  clusters: Cluster[];
  layout: Map<string, Point>;
  anchors?: MapAnchorRow[];
  evidenceTier: string;
  flowsAnalyzed: number;
  apexClassesAnalyzed: number;
  apexTriggersAnalyzed: number;
  generatedAt: string;
  branding: Branding;
}

const CLUSTER_COLORS = ['#3a5a82', '#7a5c3e', '#4f7a52', '#82406a', '#5a6b8a', '#8a6d1e', '#4a7d7d', '#6a4a8a'];

export function renderMapHtml(input: MapReportInput): string {
  const body = [
    summarySection(input),
    graphSection(input),
    couplingTableSection(input.couplingGraph.edges),
    anchorSection(input.anchors),
    clusterSection(input.clusters, input.couplingGraph),
  ].join('\n');

  return htmlDocument({
    title: 'Cross-Object Coupling Map',
    subtitle: input.orgName,
    branding: input.branding,
    bodyHtml: body,
    generatedAt: input.generatedAt,
  });
}

function summarySection(i: MapReportInput): string {
  const rows: Array<[string, string]> = [
    ['Evidence tier', i.evidenceTier],
    ['Objects', String(i.couplingGraph.nodes.length)],
    ['Coupled pairs', String(i.couplingGraph.edges.length)],
    ['Domains (clusters)', String(i.clusters.length)],
    ['Flows analysed', String(i.flowsAnalyzed)],
    ['Apex classes / triggers', `${i.apexClassesAnalyzed} / ${i.apexTriggersAnalyzed}`],
  ];
  return `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`;
}

function graphSection(i: MapReportInput): string {
  const clusterOf = new Map<string, number>();
  i.clusters.forEach((c, idx) => c.objects.forEach((o) => clusterOf.set(o, idx)));

  const degree = new Map<string, number>();
  for (const e of i.couplingGraph.edges) {
    degree.set(e.from, (degree.get(e.from) ?? 0) + e.weight);
    degree.set(e.to, (degree.get(e.to) ?? 0) + e.weight);
  }

  const laidOut = new Set(i.layout.keys());
  const lines = i.couplingGraph.edges
    .filter((e) => laidOut.has(e.from) && laidOut.has(e.to))
    .map((e) => {
      const a = i.layout.get(e.from)!;
      const b = i.layout.get(e.to)!;
      const w = Math.min(6, 0.6 + e.weight * 0.6);
      return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="var(--border)" stroke-width="${w.toFixed(1)}" stroke-opacity="0.7"/>`;
    })
    .join('');

  const nodes = [...i.layout.entries()]
    .map(([obj, p]) => {
      const r = Math.min(26, 8 + (degree.get(obj) ?? 0) * 1.5);
      const color = CLUSTER_COLORS[(clusterOf.get(obj) ?? 0) % CLUSTER_COLORS.length];
      return `<g><circle cx="${p.x}" cy="${p.y}" r="${r.toFixed(1)}" fill="${color}" fill-opacity="0.85"/>` +
        `<text x="${p.x}" y="${(p.y + r + 12).toFixed(1)}" text-anchor="middle" font-size="11" fill="var(--ink)">${esc(obj)}</text></g>`;
    })
    .join('');

  if (i.layout.size === 0) {
    return `<h2>Coupling graph</h2><p class="muted">No coupled objects were found to visualise.</p>`;
  }
  return `<h2>Coupling graph <span class="muted" style="font-size:13px">(top ${i.layout.size} objects)</span></h2>
<svg viewBox="0 0 960 600" width="100%" style="border:1px solid var(--border);border-radius:8px;background:var(--bgAlt)" role="img" aria-label="Cross-object coupling graph">
${lines}
${nodes}
</svg>`;
}

function couplingTableSection(edges: CouplingGraphEdge[]): string {
  const top = edges.slice(0, 25);
  const rows = top
    .map((e) => {
      const conf = e.components.some((c) => c.confidence === 'high') ? 'high' : 'approximate';
      const comps = e.components.map((c) => `${c.type}:${c.name}`).slice(0, 3).join(', ') + (e.components.length > 3 ? ` +${e.components.length - 3}` : '');
      return `<tr><td>${esc(e.from)} ↔ ${esc(e.to)}</td><td class="num">${e.weight}</td><td>${esc(e.operations.join(', '))}</td><td class="muted">${esc(comps)}</td><td>${chip(conf)}</td></tr>`;
    })
    .join('');
  return `<h2>Process backbones <span class="muted" style="font-size:13px">(top coupled object pairs)</span></h2>
<table><thead><tr><th>Object pair</th><th>Weight</th><th>Operations</th><th>Via</th><th>Confidence</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function anchorSection(anchors?: MapAnchorRow[]): string {
  if (!anchors || anchors.length === 0) {
    return `<h2>Process anchors</h2><p class="muted">No cached <code>intel discover</code> results found. Run <code>sf intel discover</code> first to include ranked anchors here.</p>`;
  }
  const rows = anchors
    .slice(0, 10)
    .map((a) => `<tr><td>${esc(a.label)} (${esc(a.object)})</td><td class="num">${a.score.toFixed(3)}</td></tr>`)
    .join('');
  return `<h2>Process anchors <span class="muted" style="font-size:13px">(from cached discover)</span></h2>
<table><thead><tr><th>Object</th><th>Score</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function clusterSection(clusters: Cluster[], graph: CouplingGraph): string {
  const labelOf = new Map(graph.nodes.map((n) => [n.object, n.object]));
  const rows = clusters
    .slice(0, 12)
    .map((c, idx) => {
      const color = CLUSTER_COLORS[idx % CLUSTER_COLORS.length];
      return `<tr><td><span class="chip" style="background:${color};color:#fff">${esc(c.anchorObject)}</span></td><td>${c.objects.length}</td><td class="muted">${esc(c.objects.slice(0, 8).map((o) => labelOf.get(o) ?? o).join(', '))}${c.objects.length > 8 ? ' …' : ''}</td></tr>`;
    })
    .join('');
  return `<h2>Domains</h2>
<table><thead><tr><th>Anchor</th><th>Objects</th><th>Members</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function chip(status: string): string {
  const cls = status === 'high' ? 'full' : 'partial';
  return `<span class="chip ${cls}">${esc(status)}</span>`;
}
