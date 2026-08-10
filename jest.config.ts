import type { Config } from 'jest';

// Transforms are swc, not ts-jest: TypeScript 7 is the native (Go) compiler and no longer
// exposes the JavaScript compiler API ts-jest is built on (ts-jest's peer range is still
// `>=4.3 <7`). swc only strips types, so type errors no longer fail as a side effect of
// running a test — `npm run typecheck` (tsc --noEmit over src + test) covers that instead
// and runs ahead of jest in `npm test`. Keep both; neither alone is sufficient.
const config: Config = {
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': [
      '@swc/jest',
      {
        jsc: {
          // Mirrors tsconfig.json: target ES2022, and `useDefineForClassFields` matching
          // what tsc emits for that target, so class-field semantics are identical under
          // test and in the built output.
          target: 'es2022',
          parser: { syntax: 'typescript', tsx: false },
          transform: { useDefineForClassFields: true },
        },
        // ESM out, to match `extensionsToTreatAsEsm` and the package's NodeNext modules.
        module: { type: 'es6' },
        sourceMaps: true,
      },
    ],
  },
  testMatch: ['**/*.test.ts'],
};

export default config;
