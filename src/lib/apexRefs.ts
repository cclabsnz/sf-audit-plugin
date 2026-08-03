/**
 * Does `source` reference `callout:<name>` as a whole token?
 *
 * Apex names a Named Credential as `callout:MyCredential`. Matching that used to interpolate the
 * credential's name into a regular expression, which was the wrong tool twice over: MasterLabel
 * is free text from Setup, so an unescaped bracket crashed the check and an unescaped quantifier
 * quietly matched something other than the credential. Escaping fixed the behaviour but left a
 * pattern compiled from customer data on every call.
 *
 * A literal search cannot misbehave whatever the label contains, and there is nothing here a
 * regular expression was buying: the name is matched as text, and the trailing check is the same
 * word boundary `\b` would have applied.
 */
const WORD = /[a-z0-9_]/;

export function referencesCallout(source: string, name: string): boolean {
  if (name.length === 0) return false;

  // Case-insensitive, matching Apex's own treatment of these references.
  const haystack = source.toLowerCase();
  const needle = `callout:${name}`.toLowerCase();

  for (let i = haystack.indexOf(needle); i !== -1; i = haystack.indexOf(needle, i + 1)) {
    const next = haystack[i + needle.length];
    // End of source, or a non-word character, is a boundary — so `callout:Foo` does not count
    // as a reference to a credential named `Fo`.
    if (next === undefined || !WORD.test(next)) return true;
  }
  return false;
}
