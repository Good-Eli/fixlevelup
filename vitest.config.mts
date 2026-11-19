import { defineConfig } from 'vitest/config';

export default defineConfig({
  oxc: {
    decorator: { legacy: true, emitDecoratorMetadata: true },
    assumptions: { setPublicClassFields: true },
    typescript: { removeClassFieldsWithoutInitializer: true },
  },
  test: {
    name: 'foundation',
    environment: 'node',
    include: ['packages/tooling/tests/**/*.test.ts', 'apps/api/tests/**/*.test.ts', 'apps/web/tests/**/*.test.ts', 'apps/miniapp/tests/**/*.test.ts', 'apps/miniapp/tests/**/*.test.tsx'],
    globals: false,
    passWithNoTests: false,
    maxWorkers: 2,
    testTimeout: 10_000,
  },
});
