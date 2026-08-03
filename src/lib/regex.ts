/**
 * Escape a string so it matches literally inside a regular expression.
 *
 * This tool builds patterns out of names it reads from a customer org, and those names are not
 * constrained the way developer identifiers are: a Named Credential's MasterLabel is free text
 * somebody typed into Setup. Interpolated raw, it stops being a name and becomes a pattern.
 *
 * The consequences are all silent or fatal, never obvious. `Billing (Prod` throws and takes the
 * whole check down. `Rate [v2]` becomes a character class, so the tool answers a question nobody
 * asked and reports a credential as used when it is not. `(a+)+` backtracks catastrophically -
 * thirty characters of input took thirty seconds to match.
 *
 * Escaping the interpolated value fixes all three, because the value was always meant to be
 * matched as text.
 */
export function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
