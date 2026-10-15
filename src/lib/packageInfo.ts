import { createRequire } from 'node:module';

/**
 * This plugin's own name and version, read from its package.json so that output which
 * identifies the tool (e.g. the SARIF driver) never drifts from the published release.
 *
 * Resolved relative to this module, which sits two levels below the package root in both
 * `src/lib/` (tests) and `lib/lib/` (the published build). package.json always ships in the
 * npm tarball, whatever `files` says.
 */
const requireFrom = createRequire(import.meta.url);

export interface PackageInfo {
  name: string;
  version: string;
}

let cached: PackageInfo | undefined;

export function packageInfo(): PackageInfo {
  if (cached) return cached;
  const pkg = requireFrom('../../package.json') as { name: string; version: string };
  cached = { name: pkg.name, version: pkg.version };
  return cached;
}
