import type { FindingThreats } from './types.js';
import { CHECK_STRIDE_MAP } from './stride.js';
import { CHECK_LINDDUN_MAP } from './linddun.js';

/**
 * The threat categories for a finding of this check. A category list the check set inline on the
 * finding replaces the check-level entry for that taxonomy; the other taxonomy still comes from
 * the maps.
 */
export function threatsFor(checkId: string, inline?: FindingThreats): FindingThreats | undefined {
  const stride = inline?.stride ?? CHECK_STRIDE_MAP[checkId];
  const linddun = inline?.linddun ?? CHECK_LINDDUN_MAP[checkId];
  const out: FindingThreats = {};
  if (stride?.length) out.stride = [...stride];
  if (linddun?.length) out.linddun = [...linddun];
  return out.stride || out.linddun ? out : undefined;
}
