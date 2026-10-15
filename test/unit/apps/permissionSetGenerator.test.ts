import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generatePermissionSetXml, sanitizePermissionSetName, emitPermissionSets, permissionSetNames } from '../../../src/apps/permissionSetGenerator.js';
import type { AppFinding } from '../../../src/apps/types.js';

describe('permissionSetGenerator', () => {
  const sampleFinding: AppFinding = {
    app: {
      appId: '0H40000000001',
      name: 'Data Loader & ETL',
      category: 'Installed-package',
      confidence: 'resolved',
    },
    window: { since: 14, attributionRatePct: 90 },
    used: {
      appId: '0H40000000001',
      objects: [
        { object: 'Account', verbs: ['read', 'write'] },
        { object: 'Contact', verbs: ['read'] },
      ],
      requests: 50,
      rowsProcessed: 1000,
      userIds: ['005001'],
      soapOnly: false,
    },
    granted: {
      appId: '0H40000000001',
      scope: 'full',
      objects: [],
      runAsUsers: ['005001'],
      multiUserInteractive: false,
    },
    overGrant: {
      unusedObjects: [],
      unusedVerbs: [],
      scopeDowngrade: null,
      dormant: false,
    },
    recommendation: {
      asserted: true,
      permissionSet: {
        objectPermissions: [
          { object: 'Account', read: true, create: true, edit: true, delete: false },
          { object: 'Contact', read: true, create: false, edit: false, delete: false },
        ],
      },
    },
    notes: [],
  };

  const withApp = (name: string, extra: Partial<AppFinding['recommendation']> = {}): AppFinding => ({
    ...sampleFinding,
    app: { ...sampleFinding.app, name },
    recommendation: { ...sampleFinding.recommendation, ...extra },
  });
  const API_NAME = /^[A-Za-z](?:[A-Za-z0-9]|_(?!_))*(?<!_)$/;

  it('sanitizes permission set names into valid API-name stems', () => {
    expect(sanitizePermissionSetName('Data Loader & ETL')).toBe('Data_Loader_ETL');
    expect(sanitizePermissionSetName('___My_App___')).toBe('My_App');
    expect(sanitizePermissionSetName('!!!')).toBe('App');
    expect(sanitizePermissionSetName('3rd Party Sync')).toBe('App_3rd_Party_Sync');
    expect(sanitizePermissionSetName('a__b')).toBe('a_b');
  });

  it('gives every finding a unique, deployable API name', () => {
    const names = permissionSetNames([
      withApp('Data Loader & ETL'),
      withApp('Data Loader / ETL'),
      withApp('data loader etl'),
      withApp('9to5 Connector'),
      withApp('x'.repeat(120)),
      withApp('x'.repeat(120) + ' other'),
    ]);
    expect(new Set(names.map((n) => n.toLowerCase())).size).toBe(names.length);
    for (const n of names) {
      expect(n).toMatch(API_NAME);
      expect(n.length).toBeLessThanOrEqual(80);
    }
    expect(names[0]).toBe('Data_Loader_ETL_LeastPrivilege');
    expect(names[1]).toBe('Data_Loader_ETL_LeastPrivilege_2');
    expect(names[2]).toBe('data_loader_etl_LeastPrivilege_3');
  });

  it('generates valid Salesforce .permissionset-meta.xml content', () => {
    const xml = generatePermissionSetXml(sampleFinding);
    expect(xml).toContain('<PermissionSet xmlns="http://soap.sforce.com/2006/04/metadata">');
    expect(xml).toContain('<label>Data Loader &amp; ETL Least Privilege</label>');
    expect(xml).toContain('<object>Account</object>');
    expect(xml).toContain('<allowCreate>true</allowCreate>');
    expect(xml).toContain('<allowEdit>true</allowEdit>');
    expect(xml).toContain('<allowDelete>false</allowDelete>');
    expect(xml).toContain('<object>Contact</object>');
    expect(xml).toContain('<allowCreate>false</allowCreate>');
  });

  it('escapes markup and drops XML-invalid control characters from app names', () => {
    const xml = generatePermissionSetXml(withApp('<x>]]></label>"\'&\u0001'));
    expect(xml).toContain('<label>&lt;x&gt;]]&gt;&lt;/label&gt;&quot;&apos;&amp; Least Privilege</label>');
    expect(xml.includes('\u0001')).toBe(false);
    expect(xml.match(/<label>/g)).toHaveLength(1);
  });

  it('escapes object names the same way', () => {
    const xml = generatePermissionSetXml(
      withApp('Odd', { permissionSet: { objectPermissions: [{ object: 'A<b>&\u0002', read: true, create: false, edit: false, delete: false }] } }),
    );
    expect(xml).toContain('<object>A&lt;b&gt;&amp;</object>');
  });

  it('caps the label at 80 characters', () => {
    const label = /<label>(.*)<\/label>/.exec(generatePermissionSetXml(withApp('y'.repeat(200))))![1];
    expect(label.length).toBeLessThanOrEqual(80);
    expect(label.endsWith(' Least Privilege')).toBe(true);
  });

  it('implies read for write and edit for delete, which Salesforce requires', () => {
    const xml = generatePermissionSetXml(
      withApp('Writer', {
        permissionSet: { objectPermissions: [{ object: 'Case', read: false, create: true, edit: true, delete: true }] },
      }),
    );
    expect(xml).toContain('<allowEdit>true</allowEdit>');
    expect(xml).toContain('<allowRead>true</allowRead>');
  });

  it('emits files to target directory', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'permset-test-'));
    try {
      const { written } = emitPermissionSets([sampleFinding], tmp);
      expect(written.length).toBe(1);
      expect(written[0]).toContain('Data_Loader_ETL_LeastPrivilege.permissionset-meta.xml');
      const content = readFileSync(written[0], 'utf-8');
      expect(content).toContain('<object>Account</object>');
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('writes one file per app even when names sanitise to the same stem', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'permset-test-'));
    try {
      const { written } = emitPermissionSets([withApp('Sync & Co'), withApp('Sync / Co')], tmp);
      expect(new Set(written).size).toBe(2);
      expect(readdirSync(tmp)).toHaveLength(2);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('skips apps whose recommendation was held back, and writes nothing for them', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'permset-test-'));
    try {
      const { written, skipped } = emitPermissionSets([withApp('Thin Data', { asserted: false }), withApp('Solid')], tmp);
      expect(skipped).toEqual(['Thin Data']);
      expect(written).toHaveLength(1);
      expect(readdirSync(tmp)).toEqual(['Solid_LeastPrivilege.permissionset-meta.xml']);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
