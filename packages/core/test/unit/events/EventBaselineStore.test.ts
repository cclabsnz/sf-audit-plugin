import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { EventBaselineStore } from '../../../src/events/EventBaselineStore.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-event-baseline-test-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('EventBaselineStore', () => {
  describe('defaultRoot', () => {
    it('resolves under ~/.sf/event-baseline', () => {
      expect(EventBaselineStore.defaultRoot()).toBe(path.join(os.homedir(), '.sf', 'event-baseline'));
    });
  });

  describe('save', () => {
    it('writes the CSV to {root}/{orgId}/{EventType}/{LogDate}-{Id}.csv and returns the path', () => {
      const store = new EventBaselineStore(tmpDir);
      const csv = 'EVENT_TYPE,TIMESTAMP\nLogin,20260707T101500.000Z\n';
      const saved = store.save('00Dxx', 'Login', '2026-07-07', '0AT0001', csv);

      const expected = path.join(tmpDir, '00Dxx', 'Login', '2026-07-07-0AT0001.csv');
      expect(saved).toBe(expected);
      expect(fs.readFileSync(expected, 'utf-8')).toBe(csv);
    });

    it('does not throw when the root is read-only (best-effort, like HistoryStore)', () => {
      fs.chmodSync(tmpDir, 0o444);
      const store = new EventBaselineStore(tmpDir);
      expect(() => store.save('00Dxx', 'Login', '2026-07-07', '0AT0001', 'x')).not.toThrow();
      fs.chmodSync(tmpDir, 0o755);
    });
  });

  describe('has', () => {
    it('reports false before a save and true after (dedup)', () => {
      const store = new EventBaselineStore(tmpDir);
      expect(store.has('00Dxx', 'Login', '2026-07-07', '0AT0001')).toBe(false);
      store.save('00Dxx', 'Login', '2026-07-07', '0AT0001', 'x');
      expect(store.has('00Dxx', 'Login', '2026-07-07', '0AT0001')).toBe(true);
    });
  });

  describe('writeManifest', () => {
    it('writes a JSON manifest under {root}/{orgId}/_manifests/ that round-trips', () => {
      const store = new EventBaselineStore(tmpDir);
      const manifest = { orgId: '00Dxx', pulled: [{ id: '0AT0001', bytes: 12 }] };
      const manifestPath = store.writeManifest('00Dxx', manifest);

      expect(manifestPath).toContain(path.join('00Dxx', '_manifests'));
      expect(manifestPath.endsWith('.json')).toBe(true);
      expect(JSON.parse(fs.readFileSync(manifestPath, 'utf-8'))).toEqual(manifest);
    });
  });
});
