import { describe, it, expect } from '@jest/globals';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * The analysis path never reaches an org.
 *
 * This is a design constraint rather than a preference, and it is worth enforcing mechanically
 * because it degrades silently. Every module under src/timeline/ is unit-testable from plain
 * fixtures precisely because none of them can open a connection; the day one imports a client to
 * "just look something up", the tests keep passing and the property is gone.
 *
 * It also underwrites a promise the command makes to its operator: `sf audit timeline` reads
 * local captures and nothing else, so it is safe to run long after an incident, against an org
 * whose credentials have since been revoked.
 */
const TIMELINE_DIR = path.join(process.cwd(), 'src', 'timeline');

const sources = fs
  .readdirSync(TIMELINE_DIR)
  .filter((f) => f.endsWith('.ts'))
  .map((f) => ({ file: f, text: fs.readFileSync(path.join(TIMELINE_DIR, f), 'utf-8') }));

describe('src/timeline is offline by construction', () => {
  it('has sources to check, so this suite cannot pass vacuously', () => {
    expect(sources.length).toBeGreaterThan(5);
  });

  it.each(sources.map((s) => s.file))('%s imports no org client', (file) => {
    const { text } = sources.find((s) => s.file === file)!;

    expect(text).not.toMatch(/from '.*\/api\//);
    expect(text).not.toMatch(/\bSoqlClient\b|\bToolingClient\b|\bRestClient\b|\bMetadataClient\b/);
    expect(text).not.toMatch(/\bAuditContext\b/);
  });

  it.each(sources.map((s) => s.file))('%s does not import a Connection', (file) => {
    const { text } = sources.find((s) => s.file === file)!;

    expect(text).not.toMatch(/\bConnection\b/);
  });

  it('imports from sf-core only for types and pure helpers, never a client', () => {
    for (const { file, text } of sources) {
      const coreImports = [...text.matchAll(/import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+'@cclabsnz\/sf-core'/g)]
        .flatMap((m) => m[1].split(','))
        .map((s) => s.replace(/\btype\b/, '').trim())
        .filter(Boolean);

      for (const imported of coreImports) {
        expect({ file, imported }).not.toMatchObject({ imported: expect.stringMatching(/Client|Connection|Context/) });
      }
    }
  });
});
