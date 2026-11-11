import { execFileSync } from 'node:child_process';

// A merge resolved by hand can leave a marker behind; with merge.conflictstyle = zdiff3 the base
// marker (|||||||) is easy to miss, and three once reached CHANGELOG.md on main.
describe('tracked files carry no merge conflict markers', () => {
  it('finds none', () => {
    let out = '';
    try {
      out = execFileSync('git', ['grep', '-nE', '^(<<<<<<< |\\|\\|\\|\\|\\|\\|\\| |>>>>>>> |=======$)', '--', '.', ':!node_modules', ':!test/unit/noConflictMarkers.test.ts'], { encoding: 'utf8' });
    } catch (err) {
      // git grep exits 1 when nothing matches.
      if ((err as { status?: number }).status !== 1) throw err;
    }
    expect(out.split('\n').filter(Boolean)).toEqual([]);
  });
});
