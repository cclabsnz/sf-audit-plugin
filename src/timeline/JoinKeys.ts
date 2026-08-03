/**
 * The values that tie one actor's rows together across event types.
 *
 * Every field is optional by construction, and that is the point. A key is present only when it
 * carries something usable; anything blank comes back `undefined` and can never reach the
 * correlation frontier.
 */
export interface JoinKeys {
  requestId?: string;
  clientIp?: string;
  sessionKey?: string;
  loginKey?: string;
  userId?: string;
}

/**
 * Read a key from a raw event row, or `undefined` if it is unusable.
 *
 * Unusable means absent, null, or whitespace — not merely falsy. `'0'` is a legitimate
 * identifier and a truthiness check would silently drop it.
 *
 * Trimming matters as much as rejecting: `' req-1 '` and `'req-1'` are the same request, and
 * treating them as two keys would split one actor's rows across two frontier values and
 * under-report rather than over-report.
 */
function usable(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Extract the join keys from a raw ELF or Real-Time Event row.
 *
 * This function is the whole of Invariant 1. A blank value never becomes a key, so the
 * correlation engine cannot expand through one — it has no opportunity to get this wrong, and
 * no obligation to remember the rule.
 *
 * The failure this prevents is specific and was observed: a blank REQUEST_ID admitted to the
 * join set stops behaving like an identifier and starts behaving like a wildcard, matching every
 * other row whose REQUEST_ID is also blank. During the 2026-08-02 reconstruction that turned
 * 2 genuinely related rows into 25, most of them other people's sessions.
 */
export function joinKeysOf(row: Record<string, unknown>): JoinKeys {
  return {
    requestId: usable(row.REQUEST_ID),
    // ELF spells it CLIENT_IP, Real-Time Events spell it SourceIp. ApexExecution carries
    // CLIENT_IP as a column but leaves it empty in practice, so an unusable value must fall
    // through rather than shadow a SourceIp that would have identified the row.
    clientIp: usable(row.CLIENT_IP) ?? usable(row.SourceIp),
    sessionKey: usable(row.SESSION_KEY),
    loginKey: usable(row.LOGIN_KEY),
    userId: usable(row.USER_ID),
  };
}
