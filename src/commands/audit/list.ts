import { SfCommand } from '@salesforce/sf-plugins-core';
import { CHECKS } from '../../checks/registry.js';

type CheckRow = { id: string; name: string; category: string; description: string };

export default class AuditListCommand extends SfCommand<CheckRow[]> {
  public static summary = 'List all available security checks';
  public static description = 'Displays all security checks that will run during sf audit security, with their IDs and descriptions.';
  public static examples = [
    '<%= config.bin %> <%= command.id %>',
  ];

  public async run(): Promise<CheckRow[]> {
    const rows: CheckRow[] = CHECKS.map((c) => ({
      id: c.id,
      name: c.name,
      category: c.category,
      description: c.description,
    }));

    // Group by category for readability
    const byCategory = new Map<string, CheckRow[]>();
    for (const row of rows) {
      if (!byCategory.has(row.category)) byCategory.set(row.category, []);
      byCategory.get(row.category)!.push(row);
    }

    this.log(`${CHECKS.length} security checks available:\n`);
    for (const [category, checks] of byCategory) {
      this.log(`${category}`);
      this.log('─'.repeat(category.length));
      for (const c of checks) {
        this.log(`  ${c.id.padEnd(32)} ${c.description}`);
      }
      this.log('');
    }

    return rows;
  }
}
