import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// GitHub runs `run:` steps with `bash -e` unless `shell: bash` is explicit, which adds
// -o pipefail. Without it `check | tee` passes whatever `check` returns: a verification
// step that can never fail.
describe('workflows that pipe a command declare shell: bash or set pipefail', () => {
  const dir = join(process.cwd(), '.github', 'workflows');
  const files = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f));
  it.each(files)('%s', (name) => {
    const text = readFileSync(join(dir, name), 'utf8');
    const pipes = text.split('\n').filter((l) => !l.trim().startsWith('#') && /\S\s*\|\s*(tee|grep|head|node|jq)\b/.test(l));
    if (pipes.length > 0) expect({ name, pipefail: /^\s*shell:\s*bash\s*$/m.test(text) || /set -[a-z]*o pipefail/.test(text) }).toEqual({ name, pipefail: true });
  });
});
