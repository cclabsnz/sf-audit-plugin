import { renderJson, renderMarkdown, renderTable } from '../../../src/apps/renderApps.js';
import type { AppFinding } from '../../../src/apps/types.js';

const f: AppFinding[] = [{
  app: { appId: '0H4app1', name: 'IMMS NIS Integration', category: 'Org-custom', confidence: 'resolved' },
  window: { since: 30, attributionRatePct: 90 },
  used: { appId: '0H4app1', objects: [{ object: 'Account', verbs: ['read'] }], requests: 100, rowsProcessed: 500, userIds: ['005U1'], soapOnly: false },
  granted: { appId: '0H4app1', scope: 'full', objects: [], runAsUsers: ['005U1'], multiUserInteractive: false },
  overGrant: { unusedObjects: ['Case'], unusedVerbs: [], scopeDowngrade: 'full -> api', dormant: false },
  recommendation: { permissionSet: { objectPermissions: [{ object: 'Account', read: true, create: false, edit: false, delete: false }] } },
  notes: ['note'],
}];

describe('renderApps', () => {
  it('renderJson round-trips', () => {
    expect(JSON.parse(renderJson(f))[0].app.name).toBe('IMMS NIS Integration');
  });
  it('renderTable shows the app name and category', () => {
    const t = renderTable(f);
    expect(t).toContain('IMMS NIS Integration');
    expect(t).toContain('Org-custom');
  });
  it('renderMarkdown shows the scope downgrade advice', () => {
    expect(renderMarkdown(f)).toContain('full -> api');
  });
});
