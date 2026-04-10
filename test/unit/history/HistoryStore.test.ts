// test/unit/history/HistoryStore.test.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { HistoryStore } from '../../../src/history/HistoryStore.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-23T15:10:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 64,
    grade: 'D',
    ...overrides,
  };
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-audit-test-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('HistoryStore', () => {
  describe('archive', () => {
    it('writes a JSON file to {root}/{orgId}/', () => {
      const store = new HistoryStore(tmpDir);
      const result = makeResult();
      store.archive(result);

      const orgDir = path.join(tmpDir, result.orgId);
      const files = fs.readdirSync(orgDir);
      expect(files).toHaveLength(1);
      expect(files[0]).toMatch(/^sf-audit-00D000000000001-\d+-[a-z0-9]+\.json$/);
    });

    it('stores valid JSON that round-trips to AuditResult', () => {
      const store = new HistoryStore(tmpDir);
      const result = makeResult({ healthScore: 77, grade: 'C' });
      store.archive(result);

      const orgDir = path.join(tmpDir, result.orgId);
      const file = path.join(orgDir, fs.readdirSync(orgDir)[0]);
      const parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
      expect(parsed.healthScore).toBe(77);
      expect(parsed.grade).toBe('C');
    });

    it('does not throw when the directory is read-only', () => {
      // Make tmpDir read-only so archive() cannot create subdirectory
      fs.chmodSync(tmpDir, 0o444);
      const store = new HistoryStore(tmpDir);
      expect(() => store.archive(makeResult())).not.toThrow();
      fs.chmodSync(tmpDir, 0o755); // restore so afterEach cleanup works
    });
  });

  describe('list', () => {
    it('returns results sorted oldest to newest', () => {
      const store = new HistoryStore(tmpDir);
      const older = makeResult({ generatedAt: new Date('2026-03-01T00:00:00Z'), healthScore: 50 });
      const newer = makeResult({ generatedAt: new Date('2026-04-01T00:00:00Z'), healthScore: 80 });
      store.archive(older);
      // Small delay between archives to get different timestamps in filenames
      store.archive(newer);

      const list = store.list('00D000000000001', tmpDir);
      expect(list).toHaveLength(2);
      expect(list[0].healthScore).toBe(50);
      expect(list[1].healthScore).toBe(80);
    });

    it('returns empty array when no reports exist', () => {
      const store = new HistoryStore(tmpDir);
      expect(store.list('00DNONEXISTENT', tmpDir)).toEqual([]);
    });

    it('restores generatedAt as a Date object', () => {
      const store = new HistoryStore(tmpDir);
      store.archive(makeResult({ generatedAt: new Date('2026-03-01T12:00:00Z') }));
      const [loaded] = store.list('00D000000000001', tmpDir);
      expect(loaded.generatedAt).toBeInstanceOf(Date);
      expect(loaded.generatedAt.toISOString()).toBe('2026-03-01T12:00:00.000Z');
    });
  });

  describe('latest', () => {
    it('returns the most recent result', () => {
      const store = new HistoryStore(tmpDir);
      store.archive(makeResult({ generatedAt: new Date('2026-03-01T00:00:00Z'), healthScore: 50 }));
      store.archive(makeResult({ generatedAt: new Date('2026-04-01T00:00:00Z'), healthScore: 80 }));
      expect(store.latest('00D000000000001', tmpDir)?.healthScore).toBe(80);
    });

    it('returns null when no reports exist', () => {
      const store = new HistoryStore(tmpDir);
      expect(store.latest('00DNONEXISTENT', tmpDir)).toBeNull();
    });
  });

  describe('load', () => {
    it('loads an arbitrary JSON file path', () => {
      const store = new HistoryStore(tmpDir);
      const result = makeResult({ healthScore: 90, grade: 'A' });
      store.archive(result);
      const orgDir = path.join(tmpDir, result.orgId);
      const filePath = path.join(orgDir, fs.readdirSync(orgDir)[0]);

      const loaded = store.load(filePath);
      expect(loaded.healthScore).toBe(90);
      expect(loaded.generatedAt).toBeInstanceOf(Date);
    });

    it('throws when file does not exist', () => {
      const store = new HistoryStore(tmpDir);
      expect(() => store.load('/nonexistent/path.json')).toThrow();
    });
  });
});
