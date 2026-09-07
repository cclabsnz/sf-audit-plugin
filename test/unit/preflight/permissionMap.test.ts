import { CHECKS } from '../../../src/checks/registry.js';
import {
  AUDIT_PERMISSIONS,
  buildPreflight,
  checksRequiring,
  type AuditPermission,
} from '../../../src/preflight/permissionMap.js';

const ALL_GRANTED: Record<AuditPermission, boolean> = {
  ApiEnabled: true,
  ViewSetup: true,
  ViewAllUsers: true,
  ViewHealthCheckScreen: true,
  AuthorApex: true,
  ViewEventLogFiles: true,
};

describe('checksRequiring', () => {
  it('derives Apex-body checks from the registry, not a hand-written list', () => {
    const ids = checksRequiring('AuthorApex');
    expect(ids).toContain('apex-sharing');
    expect(ids).toContain('code-security');
  });

  it('derives the Health Check dependants', () => {
    expect(checksRequiring('ViewHealthCheckScreen')).toEqual(
      expect.arrayContaining(['health-check', 'session-hardening', 'password-session-policy']),
    );
  });

  it('derives the Event Monitoring dependants', () => {
    expect(checksRequiring('ViewEventLogFiles')).toEqual(
      expect.arrayContaining(['event-monitoring', 'siem-integration']),
    );
  });

  it('only ever names checks that exist in the registry', () => {
    const known = new Set(CHECKS.map((c) => c.id));
    for (const perm of Object.keys(AUDIT_PERMISSIONS) as AuditPermission[]) {
      for (const id of checksRequiring(perm)) {
        expect(known).toContain(id);
      }
    }
  });

  it('returns no per-check list for broad permissions', () => {
    // ViewSetup underpins most of the surface; enumerating it would imply a precision
    // the mapping does not have.
    expect(checksRequiring('ViewSetup')).toEqual([]);
  });
});

describe('buildPreflight', () => {
  it('reports a fully permissioned user as ready with nothing missing', () => {
    const p = buildPreflight(ALL_GRANTED);
    expect(p.canRun).toBe(true);
    expect(p.missing).toHaveLength(0);
    expect(p.willBeInconclusive).toHaveLength(0);
  });

  it('reports the audit as unable to run without ApiEnabled', () => {
    const p = buildPreflight({ ...ALL_GRANTED, ApiEnabled: false });
    expect(p.canRun).toBe(false);
    expect(p.missing.find((m) => m.permission === 'ApiEnabled')?.blocking).toBe(true);
  });

  it('names the checks that will come back inconclusive', () => {
    const p = buildPreflight({ ...ALL_GRANTED, AuthorApex: false });
    expect(p.canRun).toBe(true);
    expect(p.willBeInconclusive).toContain('apex-sharing');
    expect(p.missing.map((m) => m.permission)).toEqual(['AuthorApex']);
  });

  it('does not double-count a check blocked by two missing permissions', () => {
    const p = buildPreflight({ ...ALL_GRANTED, AuthorApex: false, ViewHealthCheckScreen: false });
    expect(new Set(p.willBeInconclusive).size).toBe(p.willBeInconclusive.length);
  });

  it('carries the remediation for each missing permission', () => {
    const p = buildPreflight({ ...ALL_GRANTED, ViewEventLogFiles: false });
    expect(p.missing[0].impact).toMatch(/.+/);
    expect(p.missing[0].label).toMatch(/.+/);
  });
});
