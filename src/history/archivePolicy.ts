/**
 * Whether `sf audit security` should auto-archive its result to the local history store.
 *
 * A CI runner is usually ephemeral, so archiving there only writes org data to a disk
 * nobody reads again, and on a shared self-hosted runner it leaves that data behind for
 * the next job. Archiving is therefore off in CI unless the caller opts back in.
 */

export interface ArchiveFlags {
  'no-history'?: boolean;
  'keep-history'?: boolean;
}

/** Values of `CI` that mean "not CI". Anything else non-empty (`true`, `1`, `yes`...) counts. */
const FALSY = new Set(['', '0', 'false', 'no', 'off']);

/**
 * Detect a CI environment. `CI` is the de-facto convention (GitHub Actions, GitLab,
 * CircleCI, Buildkite, Travis, Bitbucket all set it); the others cover runners that don't.
 */
export function isCiEnvironment(env: NodeJS.ProcessEnv = process.env): boolean {
  const ci = env.CI;
  if (ci !== undefined && !FALSY.has(ci.trim().toLowerCase())) return true;
  if (env.GITHUB_ACTIONS === 'true') return true;
  if (env.TF_BUILD !== undefined && env.TF_BUILD !== '') return true; // Azure Pipelines
  if (env.JENKINS_URL !== undefined && env.JENKINS_URL !== '') return true;
  return false;
}

/** `--keep-history` always wins; otherwise `--no-history` or a detected CI run skips the archive. */
export function shouldArchiveHistory(flags: ArchiveFlags, env: NodeJS.ProcessEnv = process.env): boolean {
  if (flags['keep-history']) return true;
  if (flags['no-history']) return false;
  return !isCiEnvironment(env);
}
