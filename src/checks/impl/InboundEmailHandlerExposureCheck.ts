import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface EmailServicesFunctionRecord {
  Id: string;
  FunctionName: string;
  IsActive: boolean;
  RunAsUserId?: string | null;
  ApexClassId?: string | null;
  AuthenticationFailureAction?: string | number | null;
}

interface EmailServicesAddressRecord {
  Id: string;
  FunctionId: string;
  LocalPart: string;
  EmailDomainName?: string | null;
  IsActive: boolean;
  AuthorizedSenders?: string | null;
}

interface UserRecord {
  Id: string;
  Username: string;
  Profile?: { Name?: string };
}

interface ApexClassRecord {
  Id: string;
  Name: string;
  Body?: string | null;
}

export class InboundEmailHandlerExposureCheck implements SecurityCheck {
  readonly id = 'inbound-email-handler-exposure';
  readonly name = 'Inbound Email Handler Unauthenticated Execution';
  readonly category = 'External Connectivity';
  readonly description =
    'Detects active inbound email services open to all senders without SPF/DKIM verification executing Apex under privileged users.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const emailToApexUrl = `${baseUrl}/lightning/setup/EmailToApex/home`;

    let functions: EmailServicesFunctionRecord[] = [];
    try {
      functions = await ctx.soql.queryAll<EmailServicesFunctionRecord>(
        'SELECT Id, FunctionName, IsActive, RunAsUserId, ApexClassId, AuthenticationFailureAction FROM EmailServicesFunction WHERE IsActive = true',
      );
    } catch (err) {
      // This object exists in every org, so a failure is lack of access, never an absent feature.
      findings.push({
        id: 'inbound-email-handler-exposure-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Email Services Functions could not be queried',
        detail: `Query to EmailServicesFunction failed: ${err instanceof Error ? err.message : String(err)}`,
        remediation: 'Grant the audit user "View Setup and Configuration".',
      });
      return { findings };
    }

    if (functions.length === 0) {
      findings.push({
        id: 'inbound-email-handler-exposure-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active inbound Email-to-Apex services found',
        detail: 'Zero active EmailServicesFunction records exist in the org.',
        remediation: 'When creating inbound email services, enforce sender restrictions and SPF/DKIM verification.',
      });
      return { findings };
    }

    // Query active EmailServicesAddress records
    let addresses: EmailServicesAddressRecord[] = [];
    addresses = await ctx.soql.queryAll<EmailServicesAddressRecord>(
      'SELECT Id, FunctionId, LocalPart, EmailDomainName, IsActive, AuthorizedSenders FROM EmailServicesAddress WHERE IsActive = true',
    );

    const addressesByFunction = new Map<string, EmailServicesAddressRecord[]>();
    for (const a of addresses) {
      const list = addressesByFunction.get(a.FunctionId) ?? [];
      list.push(a);
      addressesByFunction.set(a.FunctionId, list);
    }

    // Query RunAs users
    const runAsUserIds = [
      ...new Set(functions.map((f) => f.RunAsUserId).filter((id): id is string => Boolean(id))),
    ];
    let adminUsers = new Set<string>();
    let userDetails = new Map<string, string>();
    if (runAsUserIds.length > 0) {
      const users = await ctx.soql.queryAll<UserRecord>(
        `SELECT Id, Username, Profile.Name FROM User WHERE Id IN ('${runAsUserIds.join("','")}')`,
      );
      for (const u of users) {
        const prof = u.Profile?.Name ?? '';
        userDetails.set(u.Id, `${u.Username} (${prof})`);
        if (prof === 'System Administrator' || prof.toLowerCase().includes('admin')) {
          adminUsers.add(u.Id);
        }
      }
    }

    // Query Apex Classes
    const apexClassIds = [
      ...new Set(functions.map((f) => f.ApexClassId).filter((id): id is string => Boolean(id))),
    ];
    let classBodies = new Map<string, string>();
    let classNames = new Map<string, string>();
    if (apexClassIds.length > 0) {
      const classes = await ctx.soql.queryAll<ApexClassRecord>(
        `SELECT Id, Name, Body FROM ApexClass WHERE Id IN ('${apexClassIds.join("','")}')`,
      );
      for (const c of classes) {
        classNames.set(c.Id, c.Name);
        classBodies.set(c.Id, c.Body ?? '');
      }
    }

    const exposedFunctions: Array<{
      func: EmailServicesFunctionRecord;
      address: string;
      reason: string;
    }> = [];

    for (const fn of functions) {
      const funcAddresses = addressesByFunction.get(fn.Id) ?? [];
      // Check 1: Any address with empty/blank AuthorizedSenders
      const openAddress = funcAddresses.find(
        (a) => !a.AuthorizedSenders || a.AuthorizedSenders.trim() === '',
      );

      // Check 2: AuthenticationFailureAction is 0 or '0' (None / accept even spoofed emails)
      const authFailureAction = String(fn.AuthenticationFailureAction ?? '0');
      const acceptsSpoofedEmail = authFailureAction === '0' || authFailureAction === '';

      // Check 3: RunAsUserId is admin or class runs without sharing / performs DML
      const isRunAsAdmin = fn.RunAsUserId ? adminUsers.has(fn.RunAsUserId) : false;
      const classBody = fn.ApexClassId ? classBodies.get(fn.ApexClassId) ?? '' : '';
      const isWithoutSharing = /without\s+sharing/i.test(classBody);
      const hasDmlOrDynamicSoql =
        /insert\s+|update\s+|upsert\s+|delete\s+|Database\.execute/i.test(classBody);

      if (openAddress && acceptsSpoofedEmail && (isRunAsAdmin || isWithoutSharing || hasDmlOrDynamicSoql)) {
        const addrStr = `${openAddress.LocalPart}${openAddress.EmailDomainName ? '@' + openAddress.EmailDomainName : ''}`;
        const reasons = [
          'No sender restriction (AuthorizedSenders is blank)',
          'AuthenticationFailureAction is set to None (accepts spoofed SPF/DKIM)',
          isRunAsAdmin ? 'Runs as System Administrator' : '',
          isWithoutSharing ? 'Apex runs without sharing' : '',
        ]
          .filter(Boolean)
          .join('; ');

        exposedFunctions.push({
          func: fn,
          address: addrStr,
          reason: reasons,
        });
      }
    }

    if (exposedFunctions.length > 0) {
      findings.push({
        id: 'inbound-email-handler-unauthenticated-execution',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${exposedFunctions.length} inbound email service(s) allow unauthenticated remote Apex execution`,
        detail:
          'Active EmailServicesFunction records accept messages from any internet sender with no SPF/DKIM authentication enforcement (AuthenticationFailureAction = 0 / None) and execute under a privileged System Administrator or in an Apex class running without sharing. An external attacker sending an email can trigger unauthenticated backend DML or privilege escalation.',
        remediation:
          'Configure "Accept Email From" with an authorized domain allowlist, set the Failure Action to "Bounce message" or "Discard message" upon SPF/DKIM verification failure, and run the service under a least-privileged execution user.',
        affectedItems: exposedFunctions.map((item) => ({
          label: `${item.func.FunctionName} (${item.address})`,
          url: emailToApexUrl,
          note: item.reason,
        })),
      });
    } else {
      findings.push({
        id: 'inbound-email-handler-exposure-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Inbound email services enforce sender restrictions and authentication controls',
        detail: `${functions.length} active inbound email service(s) inspected; all require authentication, enforce sender allowlists, or execute under constrained least-privilege contexts.`,
        remediation: 'Continue enforcing sender allowlists and bounce/discard policies on SPF/DKIM failure.',
      });
    }

    return { findings };
  }
}
