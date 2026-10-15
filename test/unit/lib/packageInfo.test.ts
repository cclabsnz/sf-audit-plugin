import { readFileSync } from 'node:fs';
import { packageInfo } from '../../../src/lib/packageInfo.js';

it('reports the name and version from the package root package.json', () => {
  const pkg = JSON.parse(readFileSync(new URL('../../../package.json', import.meta.url), 'utf-8')) as {
    name: string;
    version: string;
  };
  expect(packageInfo()).toEqual({ name: pkg.name, version: pkg.version });
});
