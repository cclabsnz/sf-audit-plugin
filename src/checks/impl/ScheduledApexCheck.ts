import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ApexJobRecord {
  Id: string;
  JobType: string;
  Status: string;
  CreatedById: string;
  ApexClass: { Name: string };
}

interface CreatorUserRecord {
  Id: string;
  Username: string;
  Profile: { Name: string };
}

export class ScheduledApexCheck implements SecurityCheck {
  readonly id = 'scheduled-apex';
  readonly name = 'Scheduled and Batch Apex';
  readonly category = 'Code Security';
  readonly description = 'Lists active scheduled and batch Apex jobs running in the org';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const apexJobsUrl = `${baseUrl}/lightning/setup/ScheduledJobs/home`;
    const apexClassesUrl = `${baseUrl}/lightning/setup/ApexClasses/home`;

    // Query all active scheduled/batch Apex jobs
    const jobs = await ctx.soql.queryAll<ApexJobRecord>(`
      SELECT Id, ApexClass.Name, JobType, Status, CreatedById
      FROM AsyncApexJob
      WHERE JobType IN ('ScheduledApex', 'BatchApex')
        AND Status NOT IN ('Aborted', 'Failed', 'Completed')
    `);

    const totalJobs = jobs.length;

    // If there are jobs, get creator profiles
    let creatorMap: Record<string, CreatorUserRecord> = {};
    if (jobs.length > 0) {
      const creatorIds = [...new Set(jobs.map((j: ApexJobRecord) => j.CreatedById))];
      const inClause = creatorIds.map((id) => `'${id}'`).join(',');

      const creators = await ctx.soql.query<CreatorUserRecord>(`
        SELECT Id, Username, Profile.Name FROM User WHERE Id IN (${inClause})
      `);

      creators.records.forEach((u: CreatorUserRecord) => {
        creatorMap[u.Id] = u;
      });
    }

    // Find privileged admin jobs
    const privilegedJobs = jobs.filter((job: ApexJobRecord) => {
      const creator = creatorMap[job.CreatedById];
      if (!creator) return false;
      const profileName = creator.Profile.Name || '';
      return (
        profileName.toLowerCase().includes('admin') ||
        profileName.toLowerCase().includes('system administrator')
      );
    });

    if (privilegedJobs.length > 0) {
      findings.push({
        id: 'scheduled-apex-privileged',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${privilegedJobs.length} scheduled/batch Apex job(s) are running under privileged accounts`,
        detail: 'Scheduled Apex jobs running under administrator accounts execute with elevated privileges and may persist after the original user is deactivated.',
        remediation: 'Assign a dedicated integration user with minimum necessary permissions to own scheduled jobs.',
        affectedItems: privilegedJobs.map((job: ApexJobRecord) => ({
          label: `${job.ApexClass.Name} (${job.JobType})`,
          url: apexJobsUrl,
          note: `Owner: ${creatorMap[job.CreatedById].Username} [${creatorMap[job.CreatedById].Profile.Name}] — reassign to a dedicated integration user`,
        })),
      });
    }

    // Always emit INFO finding
    findings.push({
      id: 'scheduled-apex-inventory',
      category: this.category,
      riskLevel: 'INFO',
      title: `${totalJobs} active scheduled/batch Apex job(s) found`,
      detail: 'This is an inventory of currently active scheduled and batch Apex jobs in the org.',
      remediation: 'Periodically review scheduled jobs to ensure all active automation is expected and authorized.',
      affectedItems: jobs.length > 0 ? jobs.map((job: ApexJobRecord) => ({
        label: `${job.ApexClass.Name} (${job.JobType})`,
        url: apexJobsUrl,
        note: `Class: ${job.ApexClass.Name}`,
      })) : undefined,
    });

    return { findings };
  }
}
