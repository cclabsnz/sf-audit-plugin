# intent/

One file per intent. Humans write these; agents may draft, humans sign off.

- Heading: `# INT-001 <title>` (3–4 digit ids, never reused)
- Must-nevers: `- MN-001: <line the business says can never be crossed>`
- Keep it short. The *rules* live in `spec/`, the *proof* lives in `tests/`.

A must-never with no rule, or no hidden test, fails CI (`scripts/ist-link-check.mjs`).
