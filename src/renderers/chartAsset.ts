import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

const requireFrom = createRequire(import.meta.url);

let cached: string | null = null;

/**
 * The Chart.js UMD bundle, read from the pinned `chart.js` dependency so it can be inlined
 * into a generated report. An audit deliverable must never fetch script from a third-party
 * CDN: the report carries sensitive org findings, is often opened on locked-down machines,
 * and a compromised CDN would otherwise execute arbitrary JS in that page.
 *
 * Resolved from the dependency rather than vendored as a committed blob so the version stays
 * visible to `pnpm audit`/dependabot. The UMD file itself is not in chart.js's `exports` map,
 * so it is located relative to the resolved main entry.
 */
export function chartJsScript(): string {
  if (cached !== null) return cached;
  const umd = join(dirname(requireFrom.resolve('chart.js')), 'chart.umd.min.js');
  // A literal `</script` in the bundle would close the tag early. Chart.js has none today;
  // escape defensively so a future version cannot silently break the report.
  cached = readFileSync(umd, 'utf8').replace(/<\/script/gi, '<\\/script');
  return cached;
}
