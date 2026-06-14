import { CHECK_CONTROL_MAP } from '../../../src/compliance/mapping.js';
import { getControl } from '../../../src/compliance/catalogs/index.js';

it('every mapped control id exists in a catalog', () => {
  const dangling: string[] = [];
  for (const ids of Object.values(CHECK_CONTROL_MAP)) {
    for (const id of ids) if (!getControl(id)) dangling.push(id);
  }
  expect(dangling).toEqual([]);
});
