/**
 * Plain-string matching for values that come from the org (site labels, user names). Built
 * without RegExp so no org-controlled text ever becomes a pattern.
 */

const isWordChar = (c: string | undefined): boolean => c !== undefined && /[A-Za-z0-9]/.test(c);

/**
 * Every start index of `needle` in `text`, compared case-insensitively slice by slice. Searching
 * a lowercased copy would drift: some characters lengthen when lowercased (U+0130 'İ').
 */
function indexesOf(text: string, needle: string): number[] {
  const out: number[] = [];
  if (!needle) return out;
  const n = needle.toLowerCase();
  for (let i = 0; i + needle.length <= text.length;) {
    if (text.slice(i, i + needle.length).toLowerCase() === n) { out.push(i); i += needle.length; } else i++;
  }
  return out;
}

/** True when `needle` occurs in `text` bounded by non-alphanumerics or the string edges. */
export function containsWord(text: string, needle: string): boolean {
  const n = needle.trim();
  return indexesOf(text, n).some((i) => !isWordChar(text[i - 1]) && !isWordChar(text[i + n.length]));
}

/** Replaces every case-insensitive occurrence of `needle` in `text` with `replacement`. */
export function replaceInsensitive(text: string, needle: string, replacement: string): string {
  const hits = indexesOf(text, needle);
  if (hits.length === 0) return text;
  let out = '';
  let last = 0;
  for (const i of hits) {
    out += text.slice(last, i) + replacement;
    last = i + needle.length;
  }
  return out + text.slice(last);
}
