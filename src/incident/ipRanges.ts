/**
 * Hosting-provider classification from range files the user downloads and passes with
 * --ip-ranges. The plugin never fetches them: the authenticated org is its only network
 * destination (docs/TRUST.md), and network-egress.test.ts enforces that. IPv4 only.
 */
interface Range { base: number; bits: number; label: string }

export interface IpRangeSet { lookup(ip: string): string | null; sources: string[] }

function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function cidr(prefix: string, label: string): Range | null {
  const [addr, bitsText] = prefix.split('/');
  const base = ipv4ToInt(addr);
  const bits = Number(bitsText);
  if (base === null || !bitsText?.trim() || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  return { base, bits, label };
}

export function parseIpRangeFile(name: string, text: string): Range[] {
  const out: Range[] = [];
  const push = (r: Range | null) => { if (r) out.push(r); };
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) {
    const j = JSON.parse(trimmed) as {
      prefixes?: Array<{ ip_prefix?: string; region?: string; service?: string; ipv4Prefix?: string; scope?: string }>;
      values?: Array<{ name: string; properties?: { addressPrefixes?: string[] } }>;
    };
    for (const p of j.prefixes ?? []) {
      if (p.ip_prefix) push(cidr(p.ip_prefix, `AWS ${p.region ?? ''} (${p.service ?? ''})`.replace(' ()', '')));
      else if (p.ipv4Prefix) push(cidr(p.ipv4Prefix, `GCP ${p.scope ?? ''}`.trim()));
    }
    for (const v of j.values ?? []) for (const a of v.properties?.addressPrefixes ?? []) push(cidr(a, `Azure ${v.name}`));
    return out;
  }
  for (const line of trimmed.split(/\r?\n/)) {
    const l = line.trim();
    if (l && !l.startsWith('#')) push(cidr(l.includes('/') ? l : `${l}/32`, name));
  }
  return out;
}

export function loadIpRanges(files: Array<{ name: string; text: string }>): IpRangeSet {
  const ranges = files.flatMap((f) => parseIpRangeFile(f.name, f.text)).sort((a, b) => b.bits - a.bits);
  return {
    sources: files.map((f) => f.name),
    lookup(ip: string): string | null {
      const n = ipv4ToInt(ip);
      if (n === null) return null;
      for (const r of ranges) {
        const mask = r.bits === 0 ? 0 : (~0 << (32 - r.bits)) >>> 0;
        if (((n & mask) >>> 0) === ((r.base & mask) >>> 0)) return r.label;
      }
      return null;
    },
  };
}

/** The original file name of a bundled range file: collect stores it as `ip-ranges/{index}-{name}`. */
export function rangeFileName(rel: string): string {
  return (rel.split('/').pop() ?? rel).replace(/^\d+-/, '');
}
