/**
 * Minimal, dependency-free XML → object parser, scoped to what Flow metadata needs.
 * Repeated sibling tags become arrays; nested elements become objects; leaf text becomes
 * a string. Attributes are ignored except `xsi:nil="true"` (element becomes null). This is
 * deliberately not a general XML parser — it handles elements, text, entities, comments,
 * CDATA, self-closing tags, and the XML declaration, which is the full surface Flow XML uses.
 */
export type XmlValue = string | null | XmlObject;
export interface XmlObject {
  [tag: string]: XmlValue | XmlValue[];
}

const ENTITIES: Record<string, string> = {
  '&lt;': '<',
  '&gt;': '>',
  '&amp;': '&',
  '&quot;': '"',
  '&apos;': "'",
};

function decodeEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&(?:lt|gt|amp|quot|apos);/g, (m) => ENTITIES[m]);
}

interface Element {
  tag: string;
  nil: boolean;
  children: Element[];
  text: string;
}

class Parser {
  private pos = 0;
  constructor(private readonly s: string) {}

  parse(): Element {
    this.skipProlog();
    const root = this.parseElement();
    if (!root) throw new Error('No root element found in XML');
    return root;
  }

  private skipProlog(): void {
    // XML declaration, comments, doctype, and leading whitespace before the root.
    for (;;) {
      this.skipWs();
      if (this.s.startsWith('<?', this.pos)) {
        this.pos = this.s.indexOf('?>', this.pos) + 2;
      } else if (this.s.startsWith('<!--', this.pos)) {
        this.pos = this.s.indexOf('-->', this.pos) + 3;
      } else if (this.s.startsWith('<!', this.pos)) {
        this.pos = this.s.indexOf('>', this.pos) + 1;
      } else {
        break;
      }
    }
  }

  private skipWs(): void {
    while (this.pos < this.s.length && /\s/.test(this.s[this.pos])) this.pos++;
  }

  private parseElement(): Element | null {
    this.skipWs();
    if (this.s[this.pos] !== '<') return null;
    const gt = this.s.indexOf('>', this.pos);
    let tagContent = this.s.slice(this.pos + 1, gt);
    const selfClosing = tagContent.endsWith('/');
    if (selfClosing) tagContent = tagContent.slice(0, -1);
    this.pos = gt + 1;

    const tag = tagContent.trim().split(/\s+/)[0];
    const nil = /xsi:nil\s*=\s*"true"/.test(tagContent);
    const el: Element = { tag, nil, children: [], text: '' };
    if (selfClosing) return el;

    // Read children/text until the matching close tag.
    for (;;) {
      const lt = this.s.indexOf('<', this.pos);
      if (lt === -1) throw new Error(`Unclosed element <${tag}>`);
      el.text += decodeEntities(this.s.slice(this.pos, lt));
      this.pos = lt;

      if (this.s.startsWith('</', this.pos)) {
        this.pos = this.s.indexOf('>', this.pos) + 1;
        break;
      }
      if (this.s.startsWith('<!--', this.pos)) {
        this.pos = this.s.indexOf('-->', this.pos) + 3;
        continue;
      }
      if (this.s.startsWith('<![CDATA[', this.pos)) {
        const end = this.s.indexOf(']]>', this.pos);
        el.text += this.s.slice(this.pos + 9, end);
        this.pos = end + 3;
        continue;
      }
      const child = this.parseElement();
      if (child) el.children.push(child);
    }
    return el;
  }
}

function toValue(el: Element): XmlValue {
  if (el.nil) return null;
  if (el.children.length === 0) return el.text.trim();

  const obj: XmlObject = {};
  for (const child of el.children) {
    const value = toValue(child);
    const existing = obj[child.tag];
    if (existing === undefined) {
      obj[child.tag] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      obj[child.tag] = [existing, value];
    }
  }
  return obj;
}

/** Parse an XML document, returning `{ [rootTag]: value }`. */
export function parseXml(xml: string): XmlObject {
  const root = new Parser(xml).parse();
  return { [root.tag]: toValue(root) };
}
